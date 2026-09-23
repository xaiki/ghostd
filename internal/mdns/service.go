//go:build mdns

package mdns

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/xaiki/ghostd/internal/wellknown"
)

// Service owns the advertising sockets. It binds the mDNS port exclusively — no
// SO_REUSEADDR, no SO_REUSEPORT — so it can never quietly share the port with
// another mDNS daemon: if avahi still holds it, Apply fails with the bind error
// instead of two responders disagreeing about the same names.
type Service struct {
	// NAT installs the DNAT table; nil drives nft.
	NAT   NATRunner
	mu    sync.Mutex
	cfg   Config
	run   *running
	Addrs func(iface string) ([]netip.Prefix, error)
}

func NewService() *Service { return &Service{Addrs: InterfaceAddrs} }

func (s *Service) Config() Config { s.mu.Lock(); defer s.mu.Unlock(); return s.cfg }

type running struct {
	a      answerer
	ifaces map[int]net.Interface
	c4     *ipv4.PacketConn
	c6     *ipv6.PacketConn
	done   chan struct{}
	wg     sync.WaitGroup

	// testSend captures replies instead of using sockets.
	testSend func(*dns.Msg)
	// testForward captures reflected messages (destination interface index).
	testForward func(ifIndex int, m *dns.Msg)

	advertise map[int]bool
	// relays are the effective from->to pairs a path connects, indexed by the
	// interface a record is heard on and the interface a question is heard on.
	relays    []*relay
	byFrom    map[int][]*relay
	byTo      map[int][]*relay
	nats      []*natRule
	natRunner NATRunner
	// testEmit captures everything sent outward (interface index, message).
	testEmit func(ifIndex int, m *dns.Msg)

	mu      sync.Mutex
	probing bool
	clash   string
}

// Apply replaces the advertised set. On any failure — a missing interface, a
// bound port, a name already claimed on the LAN — the previous set keeps
// running and nothing is left half-started.
func (s *Service) Apply(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.run
	if old != nil {
		old.stop() // goodbye, and release the port for the replacement
		s.run = nil
	}
	if cfg.Empty() {
		s.cfg = cfg
		return nil
	}
	r, err := s.start(cfg)
	if err != nil {
		if old != nil {
			if restored, rerr := s.start(s.cfg); rerr == nil {
				s.run = restored
			} else {
				log.Printf("mdns: could not restore previous advertisement: %v", rerr)
			}
		}
		return err
	}
	s.run, s.cfg = r, cfg
	return nil
}

func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.run != nil {
		s.run.stop()
		s.run = nil
	}
}

// plan is a config's rules resolved against the interfaces the host has: the
// relay edges a pattern expands to, the interfaces they name, and a NAT rule per
// translated pair.
type plan struct {
	ifaces    map[int]net.Interface
	advertise map[int]bool
	edges     []*relaying
	nats      []*natRule
}

// endpointLimit bounds what one pattern may stand for. A pattern is how the
// container bridges are named; a token that matches the whole interface table (a
// bare "*", or a container host's many veths) would otherwise join the mDNS
// group on every interface and build a relay pair for each, so it is refused
// rather than obeyed.
const endpointLimit = 32

// endpoints returns the interfaces one rule endpoint names: the interface
// itself, or every interface a pattern matches. A pattern is the same token the
// input chain admits container mDNS with (internal/nft/render.go matches the
// bridges with `iifname "podman*"`), resolved here against the interfaces that
// exist now — Podman picks a bridge's own name, so no inventory can hold it.
//
// A pattern that stands for nothing is an error, never an empty relay: the
// watcher retries an apply that failed every few seconds, so a bridge that is
// not up yet is picked up when it is, where a silent success would leave the
// host relaying nothing and read as converged.
func endpoints(name string, all []net.Interface) ([]net.Interface, error) {
	if !strings.ContainsAny(name, "*?[") {
		for _, i := range all {
			if i.Name != name {
				continue
			}
			if i.Flags&net.FlagMulticast == 0 {
				return nil, fmt.Errorf("mdns: interface %s is not multicast capable", name)
			}
			return []net.Interface{i}, nil
		}
		return nil, fmt.Errorf("mdns: interface %s: not found", name)
	}
	var out []net.Interface
	unusable := 0
	for _, i := range all {
		matched, err := path.Match(name, i.Name)
		if err != nil {
			return nil, fmt.Errorf("mdns: bad interface pattern %q: %w", name, err)
		}
		if !matched {
			continue
		}
		if i.Flags&net.FlagMulticast == 0 || i.Flags&net.FlagUp == 0 {
			unusable++
			continue
		}
		out = append(out, i)
	}
	switch {
	case len(out) > endpointLimit:
		return nil, fmt.Errorf("mdns: pattern %q matches %d interfaces, more than %d", name, len(out), endpointLimit)
	case len(out) == 0:
		return nil, fmt.Errorf("mdns: pattern %q matches no usable interface (%d matched but were not up and multicast capable)", name, unusable)
	}
	return out, nil
}

// planRules resolves a config's rules against the interfaces the host has. An
// endpoint names an interface, or a pattern that stands for every interface it
// matches, so one rule naming `podman*` becomes one rule per container bridge.
// Resolution happens here and nowhere else: the config keeps what it was given,
// which is what the operator — and the stack diffing its own document — reads
// back.
func planRules(cfg Config, all []net.Interface, addrs func(string) ([]netip.Prefix, error), reserved map[string]bool) (*plan, error) {
	pl := &plan{ifaces: map[int]net.Interface{}, advertise: map[int]bool{}}
	// The advertised half names its interfaces: the records are data an operator
	// supplies, and where ghostd answers for them is explicit.
	if len(cfg.Records) > 0 {
		for _, name := range cfg.Interfaces {
			matched, err := endpoints(name, all)
			if err != nil {
				return nil, err
			}
			pl.ifaces[matched[0].Index] = matched[0]
			pl.advertise[matched[0].Index] = true
		}
	}
	pools := map[int]*ports{}
	for _, rule := range cfg.Reflect {
		froms, err := endpoints(rule.From, all)
		if err != nil {
			return nil, err
		}
		tos, err := endpoints(rule.To, all)
		if err != nil {
			return nil, err
		}
		for _, resolved := range append(append([]net.Interface{}, froms...), tos...) {
			pl.ifaces[resolved.Index] = resolved
		}
		for _, from := range froms {
			for _, to := range tos {
				if from.Index == to.Index {
					continue // a domain is never its own peer
				}
				if rule.Advertise == nil {
					pl.edges = append(pl.edges, &relaying{cfg: rule, from: from.Index, to: to.Index})
					continue
				}
				// One port namespace per published-on interface: every rule
				// publishing there allocates from it, so two sources can never be
				// handed the same DNAT port. Keyed by interface, so two rules that
				// reach one by different endpoints share it too.
				pool := pools[to.Index]
				if pool == nil {
					pool = newPorts()
					pools[to.Index] = pool
				}
				n, err := newNATRule(rule, from, to, pool, func() []netip.Prefix {
					subnet, _ := addrs(from.Name)
					return subnet
				}, reserved)
				if err != nil {
					return nil, err
				}
				pl.nats = append(pl.nats, n)
			}
		}
	}
	return pl, nil
}

func (s *Service) start(cfg Config) (*running, error) {
	addrsFor := s.Addrs
	if addrsFor == nil {
		addrsFor = InterfaceAddrs
	}
	all, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("mdns: cannot enumerate interfaces: %w", err)
	}
	// A name ghostd advertises itself is not one a container may take over.
	reserved := map[string]bool{}
	if cfg.Host != "" {
		reserved[cfg.Host] = true
	}
	pl, err := planRules(cfg, all, addrsFor, reserved)
	if err != nil {
		return nil, err
	}
	r := &running{a: answerer{cfg: cfg, addrs: addrsFor}, ifaces: pl.ifaces, advertise: pl.advertise, done: make(chan struct{}),
		byFrom: map[int][]*relay{}, byTo: map[int][]*relay{}, nats: pl.nats}
	r.relays = planRelays(pl.edges)
	for _, p := range r.relays {
		r.byFrom[p.from] = append(r.byFrom[p.from], p)
		r.byTo[p.to] = append(r.byTo[p.to], p)
	}
	pc4, err := net.ListenPacket("udp4", wellknown.HostPort("0.0.0.0", wellknown.PortMDNS))
	if err != nil {
		return nil, fmt.Errorf("mdns: cannot bind UDP %d (is another mDNS daemon running?): %w", wellknown.PortMDNS, err)
	}
	r.c4 = ipv4.NewPacketConn(pc4)
	r.c4.SetControlMessage(ipv4.FlagInterface|ipv4.FlagDst, true)
	r.c4.SetMulticastTTL(255)
	r.c4.SetMulticastLoopback(false)
	for _, i := range r.ifaces {
		i := i
		if err := r.c4.JoinGroup(&i, &net.UDPAddr{IP: group4.IP}); err != nil {
			pc4.Close()
			return nil, fmt.Errorf("mdns: join on %s: %w", i.Name, err)
		}
	}
	if pc6, err := net.ListenPacket("udp6", wellknown.HostPort("::", wellknown.PortMDNS)); err == nil {
		r.c6 = ipv6.NewPacketConn(pc6)
		r.c6.SetControlMessage(ipv6.FlagInterface|ipv6.FlagDst, true)
		r.c6.SetMulticastHopLimit(255)
		r.c6.SetMulticastLoopback(false)
		for _, i := range r.ifaces {
			i := i
			_ = r.c6.JoinGroup(&i, &net.UDPAddr{IP: group6.IP})
		}
	}
	r.natRunner = s.NAT
	if r.natRunner == nil {
		r.natRunner = nftRunner{}
	}
	r.probing = len(cfg.Records) > 0
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.serve4() }()
	if r.c6 != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.serve6() }()
	}
	if len(r.nats) > 0 {
		r.applyNAT() // an empty table: nothing to map until a container announces
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.runNAT() }()
	}
	if len(cfg.Records) == 0 {
		return r, nil // a pure reflector claims no names: nothing to probe or announce
	}
	// Probe: ask for every name we are about to claim, three times. Anyone who
	// answers already owns it, and we must not advertise over them.
	names := r.a.hostNames()
	for _, rec := range cfg.Records {
		names = append(names, r.a.instanceName(rec))
	}
	for n := 0; n < 3; n++ {
		q := new(dns.Msg)
		for _, name := range names {
			q.Question = append(q.Question, dns.Question{Name: name, Qtype: dns.TypeANY, Qclass: dns.ClassINET | 0x8000})
		}
		for idx := range r.advertise {
			r.send4(q, idx, group4)
		}
		time.Sleep(probeGap)
	}
	r.mu.Lock()
	clash := r.clash
	r.probing = false
	r.mu.Unlock()
	if clash != "" {
		r.stopNoGoodbye()
		return nil, fmt.Errorf("mdns: name %s is already advertised by another host on the LAN; refusing to advertise over it", clash)
	}
	r.announce(ttlService)
	go func() {
		time.Sleep(time.Second)
		select {
		case <-r.done:
		default:
			r.announce(ttlService)
		}
	}()
	return r, nil
}

func (r *running) send4(m *dns.Msg, ifIndex int, dst *net.UDPAddr) {
	wire, err := m.Pack()
	if err != nil {
		return
	}
	r.c4.WriteTo(wire, &ipv4.ControlMessage{IfIndex: ifIndex}, dst)
}
func (r *running) send6(m *dns.Msg, ifIndex int, dst *net.UDPAddr) {
	if r.c6 == nil {
		return
	}
	wire, err := m.Pack()
	if err != nil {
		return
	}
	r.c6.WriteTo(wire, &ipv6.ControlMessage{IfIndex: ifIndex}, dst)
}

func (r *running) announce(ttl uint32) {
	for idx := range r.advertise {
		i := r.ifaces[idx]
		m := new(dns.Msg)
		m.Response, m.Authoritative = true, true
		m.Answer = r.a.all(i.Name, ttl)
		r.send4(m, i.Index, group4)
		r.send6(m, i.Index, group6)
	}
}

func (r *running) stop() {
	r.stopNAT()
	r.announce(0) // goodbye
	r.stopNoGoodbye()
}
func (r *running) stopNoGoodbye() {
	select {
	case <-r.done:
		return
	default:
		close(r.done)
	}
	r.c4.Close()
	if r.c6 != nil {
		r.c6.Close()
	}
	r.wg.Wait()
}

func (r *running) ownAddress(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, i := range r.ifaces {
		if list, err := r.a.addrs(i.Name); err == nil {
			for _, p := range list {
				if p.Addr() == addr {
					return true
				}
			}
		}
	}
	return false
}

func (r *running) handle(data []byte, src *net.UDPAddr, ifIndex int, v6 bool) {
	i, ok := r.ifaces[ifIndex]
	if !ok || r.ownAddress(src.IP) {
		return
	}
	m := new(dns.Msg)
	if m.Unpack(data) != nil {
		return
	}
	r.reflect(m, ifIndex, v6)
	r.natLearn(m, ifIndex)
	r.natAnswer(m, src, ifIndex, v6)
	if !r.advertise[ifIndex] {
		return
	}
	if m.Response {
		r.mu.Lock()
		if r.probing {
			if c := r.a.conflicts(m); c != "" && r.clash == "" {
				r.clash = c
			}
		}
		r.mu.Unlock()
		return
	}
	if resp := r.a.Answer(m, i.Name); resp != nil {
		r.reply(m, resp, src, ifIndex, v6)
	}
}

// reply sends resp to a querier the way RFC 6762 asks: multicast, or unicast for a
// QU question or a legacy resolver (short TTLs, no cache-flush bit).
func (r *running) reply(m, resp *dns.Msg, src *net.UDPAddr, ifIndex int, v6 bool) {
	unicast := src.Port != wellknown.PortMDNS
	for _, q := range m.Question {
		if q.Qclass&0x8000 != 0 {
			unicast = true
		}
	}
	dst := group4
	if v6 {
		dst = group6
	}
	if unicast {
		dst = src
		resp.Id = m.Id
		resp.Question = m.Question
		if src.Port != wellknown.PortMDNS {
			for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Extra...) {
				h := rr.Header()
				h.Class = dns.ClassINET
				if h.Ttl > 10 {
					h.Ttl = 10
				}
			}
		}
	}
	if r.testSend != nil {
		r.testSend(resp)
		return
	}
	if v6 {
		r.send6(resp, ifIndex, dst)
	} else {
		r.send4(resp, ifIndex, dst)
	}
}

func (r *running) serve4() {
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := r.c4.ReadFrom(buf)
		if err != nil {
			return
		}
		if cm == nil {
			continue
		}
		if udp, ok := src.(*net.UDPAddr); ok {
			r.handle(append([]byte(nil), buf[:n]...), udp, cm.IfIndex, false)
		}
	}
}
func (r *running) serve6() {
	buf := make([]byte, 9000)
	for {
		n, cm, src, err := r.c6.ReadFrom(buf)
		if err != nil {
			return
		}
		if cm == nil {
			continue
		}
		if udp, ok := src.(*net.UDPAddr); ok {
			r.handle(append([]byte(nil), buf[:n]...), udp, cm.IfIndex, true)
		}
	}
}

// reflect relays one packet out of the domain it was heard on, through every
// pair that domain composes into. A record goes out to every domain its source
// reaches; a question goes back along every pair that reaches the domain it was
// asked on. Nothing is re-received, so there is no path for a packet to loop on.
func (r *running) reflect(m *dns.Msg, ifIndex int, v6 bool) {
	if m.Response {
		for _, p := range r.byFrom[ifIndex] {
			if resp := p.f.Responses(m); resp != nil {
				r.forward(resp, p.to, v6)
			}
		}
		return
	}
	for _, p := range r.byTo[ifIndex] {
		if q := p.f.Queries(m); q != nil {
			r.forward(q, p.from, v6)
		}
	}
}

func (r *running) forward(m *dns.Msg, ifIndex int, v6 bool) {
	if r.testForward != nil {
		r.testForward(ifIndex, m)
		return
	}
	if v6 {
		r.send6(m, ifIndex, group6)
	} else {
		r.send4(m, ifIndex, group4)
	}
}

// emit multicasts a message out of one interface (both families).
func (r *running) emit(ifIndex int, m *dns.Msg) {
	if r.testEmit != nil {
		r.testEmit(ifIndex, m)
		return
	}
	r.send4(m, ifIndex, group4)
	r.send6(m, ifIndex, group6)
}

var logf = log.Printf

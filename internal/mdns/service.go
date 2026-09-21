//go:build mdns

package mdns

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Service owns the advertising sockets. It binds UDP 5353 exclusively — no
// SO_REUSEADDR, no SO_REUSEPORT — so it can never quietly share the port with
// another mDNS daemon: if avahi still holds it, Apply fails with the bind error
// instead of two responders disagreeing about the same names.
type Service struct {
	mu    sync.Mutex
	cfg   Config
	run   *running
	Addrs func(iface string) ([]netip.Addr, error)
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

func (s *Service) start(cfg Config) (*running, error) {
	r := &running{a: answerer{cfg: cfg, addrs: s.Addrs}, ifaces: map[int]net.Interface{}, done: make(chan struct{})}
	for _, name := range cfg.Interfaces {
		i, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("mdns: interface %s: %w", name, err)
		}
		if i.Flags&net.FlagMulticast == 0 {
			return nil, fmt.Errorf("mdns: interface %s is not multicast capable", name)
		}
		r.ifaces[i.Index] = *i
	}
	pc4, err := net.ListenPacket("udp4", "0.0.0.0:5353")
	if err != nil {
		return nil, fmt.Errorf("mdns: cannot bind UDP 5353 (is another mDNS daemon running?): %w", err)
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
	if pc6, err := net.ListenPacket("udp6", "[::]:5353"); err == nil {
		r.c6 = ipv6.NewPacketConn(pc6)
		r.c6.SetControlMessage(ipv6.FlagInterface|ipv6.FlagDst, true)
		r.c6.SetMulticastHopLimit(255)
		r.c6.SetMulticastLoopback(false)
		for _, i := range r.ifaces {
			i := i
			_ = r.c6.JoinGroup(&i, &net.UDPAddr{IP: group6.IP})
		}
	}
	r.probing = true
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.serve4() }()
	if r.c6 != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); r.serve6() }()
	}
	// Probe: ask for every name we are about to claim, three times. Anyone who
	// answers already owns it, and we must not advertise over them.
	names := []string{r.a.hostName()}
	for _, rec := range cfg.Records {
		names = append(names, r.a.instanceName(rec))
	}
	for n := 0; n < 3; n++ {
		q := new(dns.Msg)
		for _, name := range names {
			q.Question = append(q.Question, dns.Question{Name: name, Qtype: dns.TypeANY, Qclass: dns.ClassINET | 0x8000})
		}
		for _, i := range r.ifaces {
			r.send4(q, i.Index, group4)
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
	for _, i := range r.ifaces {
		m := new(dns.Msg)
		m.Response, m.Authoritative = true, true
		m.Answer = r.a.all(i.Name, ttl)
		r.send4(m, i.Index, group4)
		r.send6(m, i.Index, group6)
	}
}

func (r *running) stop() {
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
			for _, a := range list {
				if a == addr {
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
	resp := r.a.Answer(m, i.Name)
	if resp == nil {
		return
	}
	unicast := src.Port != 5353
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
		if src.Port != 5353 {
			// Legacy unicast (RFC 6762 6.7): a plain DNS resolver is asking. Its
			// answers must carry short TTLs and no cache-flush bit, or a stub
			// resolver rejects them for a class mismatch.
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

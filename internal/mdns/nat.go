//go:build mdns

package mdns

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// mDNS NAT: a container's own advertisements, made findable from the LAN.
//
// A service a container advertises on its bridge names a bridge-private address,
// so reflecting it as-is would send LAN clients to somewhere they cannot reach.
// The NAT does what a router would: ghostd re-advertises the instance on the LAN
// with its own LAN address and a port from a per-network pool, and installs a
// DNAT (in its own nft table) from that port to the container's address and port.
// A LAN client browsing _ipp._tcp finds "Printer" at ghostd:20017 and its
// connection lands in the container, with no host networking and nothing
// published by hand.
//
// State is learned, not configured: it follows what the container announces
// (including goodbyes) and expires with the records' own lifetimes.

// NATConfig turns on outward advertisement for one container network.
type NATConfig struct {
	// Services are the DNS-SD classes whose instances are re-advertised.
	Services []string `json:"services"`
	// Ports is the pool of LAN-side ports ("20000-20999") the instances are mapped
	// to; each (container address, port) gets a stable one.
	Ports string `json:"ports"`
}

func (n NATConfig) portRange() (lo, hi int, err error) {
	a, b, ok := strings.Cut(n.Ports, "-")
	if !ok {
		return 0, 0, fmt.Errorf("ports must look like 20000-20999")
	}
	lo, e1 := strconv.Atoi(a)
	hi, e2 := strconv.Atoi(b)
	if e1 != nil || e2 != nil || lo < 1024 || hi > 65535 || hi < lo || hi-lo > 4095 {
		return 0, 0, fmt.Errorf("ports must be 1024..65535, at most 4096 of them")
	}
	return lo, hi, nil
}

func (n NATConfig) validate() error {
	if len(n.Services) == 0 || len(n.Services) > 32 {
		return fmt.Errorf("nat needs 1..32 services")
	}
	for _, s := range n.Services {
		if !serviceRE.MatchString(s) {
			return fmt.Errorf("nat: %q is not a service class like _ipp._tcp", s)
		}
	}
	_, _, err := n.portRange()
	return err
}

// natMapping is one DNAT: LAN port to a container endpoint.
type natMapping struct {
	lan     string
	proto   string // tcp | udp
	port    int
	target  netip.Addr
	tport   int
	network string
}

// NATRunner applies the DNAT table; the default drives nft.
type NATRunner interface {
	Apply(ctx context.Context, script string) error
}

type nftRunner struct{}

func (nftRunner) Apply(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

const natTable = "ghostd_mdns_nat"

// renderNAT is the whole table, replaced atomically; an empty set removes it.
func renderNAT(maps []natMapping) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", natTable, natTable)
	if len(maps) == 0 {
		return b.String()
	}
	sort.Slice(maps, func(i, j int) bool {
		if maps[i].lan != maps[j].lan {
			return maps[i].lan < maps[j].lan
		}
		if maps[i].proto != maps[j].proto {
			return maps[i].proto < maps[j].proto
		}
		return maps[i].port < maps[j].port
	})
	fmt.Fprintf(&b, "table inet %s {\n  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n", natTable)
	for _, m := range maps {
		fmt.Fprintf(&b, "    iifname %q %s dport %d dnat ip to %s:%d\n", m.lan, m.proto, m.port, m.target, m.tport)
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

// natInstance is one learned container service instance.
type natInstance struct {
	service  string // _ipp._tcp
	instance string
	txt      []string
	subtypes map[string]bool
	port     int    // the container's port
	host     string // normalized SRV target in the container's namespace
	ip       netip.Addr
	hostPort int
	expires  time.Time
}

func (i *natInstance) key() string { return norm(i.instance + "." + i.service + ".local.") }

type natRule struct {
	mu       sync.Mutex
	cfg      ReflectRule
	f        *filter
	lo, hi   int
	insts    map[string]*natInstance
	hosts    map[string]natHost
	used     map[int]string // LAN port -> instance key
	lanIndex int
	label    string
	now      func() time.Time
}

type natHost struct {
	ip  netip.Addr
	exp time.Time
}

func newNATRule(cfg ReflectRule, lanIndex int) (*natRule, error) {
	lo, hi, err := cfg.Advertise.portRange()
	if err != nil {
		return nil, err
	}
	return &natRule{cfg: cfg, f: newFilter(cfg.Advertise.Services), lo: lo, hi: hi, insts: map[string]*natInstance{}, hosts: map[string]natHost{},
		used: map[int]string{}, lanIndex: lanIndex, label: natLabel(cfg.Network), now: time.Now}, nil
}

// natLabel is the .local host name the LAN sees for a network's services.
func natLabel(network string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(network) {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteRune('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "container"
	}
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

func protoOf(service string) string {
	if strings.HasSuffix(service, "._udp") {
		return "udp"
	}
	return "tcp"
}

// allocate gives an instance a stable LAN port: hashed from what identifies it,
// probing forward past ports in use.
func (n *natRule) allocate(i *natInstance) bool {
	h := fnv.New32a()
	fmt.Fprintf(h, "%s|%s|%d", n.cfg.Network, i.ip, i.port)
	size := n.hi - n.lo + 1
	start := int(h.Sum32() % uint32(size))
	for k := 0; k < size; k++ {
		p := n.lo + (start+k)%size
		if owner, taken := n.used[p]; !taken || owner == i.key() {
			n.used[p] = i.key()
			i.hostPort = p
			return true
		}
	}
	return false
}

// learn folds one container response into the rule's state and reports whether
// the set of mappings or records changed.
func (n *natRule) learn(m *dns.Msg) (changed bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	all := append(append([]dns.RR{}, m.Answer...), m.Extra...)
	ensure := func(name string) *natInstance {
		class, ok := classOf(name)
		if !ok || !n.f.allow[class] {
			return nil
		}
		key := norm(name)
		if i := n.insts[key]; i != nil {
			return i
		}
		i := &natInstance{service: class, instance: unescapeKeepCase(name, class), subtypes: map[string]bool{}}
		n.insts[key] = i
		return i
	}
	for _, rr := range all {
		h := rr.Header()
		switch v := rr.(type) {
		case *dns.A:
			if ip, ok := netip.AddrFromSlice(v.A.To4()); ok {
				if h.Ttl == 0 {
					delete(n.hosts, norm(h.Name))
				} else {
					n.hosts[norm(h.Name)] = natHost{ip, now.Add(time.Duration(h.Ttl) * time.Second)}
				}
			}
		case *dns.PTR:
			class, ok := classOf(h.Name)
			if !ok || !n.f.allow[class] {
				continue
			}
			if h.Ttl == 0 {
				if i := n.insts[norm(v.Ptr)]; i != nil {
					n.drop(i)
					changed = true
				}
				continue
			}
			if i := ensure(v.Ptr); i != nil && strings.Contains(norm(h.Name), "._sub.") {
				sub := strings.SplitN(norm(h.Name), ".", 2)[0]
				if !i.subtypes[sub] {
					i.subtypes[sub] = true
					changed = true
				}
			}
		case *dns.SRV:
			if h.Ttl == 0 {
				if i := n.insts[norm(h.Name)]; i != nil {
					n.drop(i)
					changed = true
				}
				continue
			}
			if i := ensure(h.Name); i != nil {
				host := norm(v.Target)
				if i.host != host || i.port != int(v.Port) {
					i.host, i.port = host, int(v.Port)
					changed = true
				}
				i.expires = now.Add(time.Duration(h.Ttl) * time.Second)
			}
		case *dns.TXT:
			if i := ensure(h.Name); i != nil && h.Ttl > 0 {
				if strings.Join(i.txt, "\x00") != strings.Join(v.Txt, "\x00") {
					i.txt = append([]string(nil), v.Txt...)
					changed = true
				}
			}
		}
	}
	// An instance is publishable once its host's address is known and a LAN port is set.
	for _, i := range n.insts {
		host, ok := n.hosts[i.host]
		if !ok || !now.Before(host.exp) || i.port == 0 {
			continue
		}
		if i.ip != host.ip || i.hostPort == 0 {
			if i.hostPort != 0 {
				delete(n.used, i.hostPort)
				i.hostPort = 0
			}
			i.ip = host.ip
			if !n.allocate(i) {
				continue
			}
			changed = true
		}
	}
	return changed
}

func (n *natRule) drop(i *natInstance) {
	if i.hostPort != 0 {
		delete(n.used, i.hostPort)
	}
	delete(n.insts, i.key())
}

// expire removes instances whose records lapsed, reporting whether any did.
func (n *natRule) expire() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	changed := false
	for _, i := range n.insts {
		if !i.expires.IsZero() && !now.Before(i.expires) {
			n.drop(i)
			changed = true
		}
	}
	for h, e := range n.hosts {
		if !now.Before(e.exp) {
			delete(n.hosts, h)
		}
	}
	return changed
}

// published lists the instances ready to be advertised and mapped.
func (n *natRule) published() []*natInstance {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []*natInstance
	for _, i := range n.insts {
		if i.hostPort != 0 && i.ip.IsValid() {
			c := *i
			out = append(out, &c)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].key() < out[b].key() })
	return out
}

func (n *natRule) mappings() []natMapping {
	var out []natMapping
	for _, i := range n.published() {
		out = append(out, natMapping{lan: n.cfg.LAN, proto: protoOf(i.service), port: i.hostPort, target: i.ip, tport: i.port, network: n.cfg.Network})
	}
	return out
}

// answerer builds the LAN-facing view: every instance on this rule's host name,
// at ghostd's LAN address and the mapped port. Only IPv4 is mapped, so only IPv4
// addresses are published.
func (n *natRule) answerer(addrs func(string) ([]netip.Addr, error)) answerer {
	cfg := Config{Host: n.label}
	for _, i := range n.published() {
		var subs []string
		for s := range i.subtypes {
			subs = append(subs, s)
		}
		sort.Strings(subs)
		cfg.Records = append(cfg.Records, Record{Service: i.service, Instance: i.instance, Port: uint16(i.hostPort), TXT: i.txt, Subtypes: subs})
	}
	return answerer{cfg: cfg, addrs: func(iface string) ([]netip.Addr, error) {
		all, err := addrs(iface)
		var v4 []netip.Addr
		for _, a := range all {
			if a.Is4() {
				v4 = append(v4, a)
			}
		}
		return v4, err
	}}
}

// unescapeKeepCase recovers the instance's display name from an owner name.
func unescapeKeepCase(name, class string) string {
	raw := strings.TrimSuffix(name, ".")
	raw = strings.TrimSuffix(raw, ".local")
	raw = strings.TrimSuffix(raw, "."+class)
	// undo \DDD and \c escapes without lower-casing
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '\\' && i+1 < len(raw) {
			if i+3 < len(raw) && raw[i+1] >= '0' && raw[i+1] <= '9' && raw[i+2] >= '0' && raw[i+2] <= '9' && raw[i+3] >= '0' && raw[i+3] <= '9' {
				n := int(raw[i+1]-'0')*100 + int(raw[i+2]-'0')*10 + int(raw[i+3]-'0')
				if n < 256 {
					b.WriteByte(byte(n))
					i += 3
					continue
				}
			}
			i++
		}
		b.WriteByte(raw[i])
	}
	return b.String()
}

// applyNAT recomputes the DNAT table from every rule and installs it.
func (r *running) applyNAT() {
	if len(r.nats) == 0 {
		return
	}
	var maps []natMapping
	for _, n := range r.nats {
		maps = append(maps, n.mappings()...)
	}
	script := renderNAT(maps)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.natRunner.Apply(ctx, script); err != nil {
		logf("mdns nat: %v", err)
	}
}

// announceNAT (re)announces a rule's instances on its LAN interface.
func (r *running) announceNAT(n *natRule, ttl uint32) {
	a := n.answerer(r.a.addrs)
	name := ""
	if i, ok := r.ifaces[n.lanIndex]; ok {
		name = i.Name
	}
	rrs := a.all(name, ttl)
	if len(rrs) == 0 {
		return
	}
	m := new(dns.Msg)
	m.Response, m.Authoritative = true, true
	m.Answer = rrs
	r.emit(n.lanIndex, m)
}

// natLearn is called for a container network's responses.
func (r *running) natLearn(m *dns.Msg, ifIndex int) {
	for _, n := range r.nats {
		if ifIndex != n.cfgNet(r) || !m.Response {
			continue
		}
		if n.learn(m) {
			r.applyNAT()
			r.announceNAT(n, ttlService)
		}
	}
}

func (n *natRule) cfgNet(r *running) int {
	for _, rule := range r.rules {
		if rule.cfg.Network == n.cfg.Network {
			return rule.net
		}
	}
	return -1
}

// natAnswer answers LAN queries for the classes a rule re-advertises, from what
// it learned, and asks the container network when it has nothing yet.
func (r *running) natAnswer(m *dns.Msg, src *net.UDPAddr, ifIndex int, v6 bool) {
	if m.Response {
		return
	}
	for _, n := range r.nats {
		if ifIndex != n.lanIndex {
			continue
		}
		// Answer from what is already known (the service classes and the rule's host
		// name), and ask the container network to refresh the cache: its answers are
		// learned and announced.
		if resp := n.answerer(r.a.addrs).Answer(m, r.ifaces[ifIndex].Name); resp != nil {
			r.reply(m, resp, src, ifIndex, v6)
		}
		if q := n.f.Queries(m); q != nil {
			if ctr := n.cfgNet(r); ctr >= 0 {
				r.forward(q, ctr, v6)
			}
		}
	}
}

// runNAT sweeps expired instances every few seconds.
func (r *running) runNAT() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case <-t.C:
			for _, n := range r.nats {
				if n.expire() {
					r.applyNAT()
					r.announceNAT(n, ttlService)
				}
			}
		}
	}
}

// stopNAT withdraws everything: goodbyes on the LAN and an empty table.
func (r *running) stopNAT() {
	for _, n := range r.nats {
		r.announceNAT(n, 0)
	}
	if len(r.nats) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		r.natRunner.Apply(ctx, renderNAT(nil))
	}
}

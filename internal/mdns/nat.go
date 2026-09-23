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

// mDNS NAT: a domain's own advertisements, made findable where their addresses
// do not reach.
//
// A service a container advertises on its bridge names a bridge-private address,
// so relaying it as-is would send clients on the other domain to somewhere they
// cannot reach. The NAT does what a router would: ghostd re-advertises the
// instance on the destination interface with its own address there and a port
// from a pool, and installs a DNAT (in its own nft table) from that port to the
// source's address and port. A client browsing _ipp._tcp finds "Printer" at
// ghostd:20017 and its connection lands in the container, with no host
// networking and nothing published by hand. The container's own host name comes
// with it, so the destination resolves what the container's records already
// name; only an address the source announced on its own interface is translated,
// and the DNAT rewrites only traffic addressed to ghostd itself.
//
// State is learned, not configured: it follows what the source announces
// (including goodbyes) and expires with the records' own lifetimes.

// NATConfig turns on translation for one relay rule.
type NATConfig struct {
	// Services are the DNS-SD classes whose instances are re-advertised.
	Services []string `json:"services"`
	// Ports is the pool of ports ("20000-20999") the instances are mapped to on
	// the published-on interface; each (source address, port) gets a stable one.
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

// ports is the DNAT port namespace of one published-on interface. Every rule
// that publishes there allocates from the same set: the DNAT rules match on
// interface and destination port, so two rules sharing a port would leave one of
// them silently unreachable (the first match wins).
type ports struct {
	mu   sync.Mutex
	used map[int]string // port -> owner
}

func newPorts() *ports { return &ports{used: map[int]string{}} }

// natMapping is one DNAT: a port on the published-on interface, to a source endpoint.
type natMapping struct {
	to     string
	proto  string // tcp | udp
	port   int
	target netip.Addr
	tport  int
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
		if maps[i].to != maps[j].to {
			return maps[i].to < maps[j].to
		}
		if maps[i].proto != maps[j].proto {
			return maps[i].proto < maps[j].proto
		}
		return maps[i].port < maps[j].port
	})
	fmt.Fprintf(&b, "table inet %s {\n  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n", natTable)
	for _, m := range maps {
		fmt.Fprintf(&b, "    iifname %q fib daddr type local %s dport %d dnat ip to %s:%d\n", m.to, m.proto, m.port, m.target, m.tport)
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
	mu     sync.Mutex
	cfg    ReflectRule
	f      *filter
	lo, hi int
	insts  map[string]*natInstance
	hosts  map[string]natHost
	pool   *ports
	// from and to are the interfaces this rule resolved to: the source whose
	// instances are learned, and the one they are published on. A rule that named
	// a pattern has one natRule per pair, each with its own names, so two bridges
	// never share a published host name or a pool slot.
	from  net.Interface
	to    net.Interface
	label string
	// subnet is the source domain's own addressing, read when a mapping is made:
	// an address a source announced elsewhere (its loopback, another network)
	// names somewhere a client must not be sent. Read lazily, so an interface
	// that only gains its address later still maps.
	subnet func() []netip.Prefix
	// reserved are the host names ghostd advertises itself: a container may not
	// take one over on the published-on interface.
	reserved map[string]bool
	now      func() time.Time
	// removed holds instances that left (goodbye or expiry) since the last
	// announcement, so the destination is told with TTL-0 records rather than left
	// to cache.
	removed []*natInstance
}

// natHost is one container host's announced addresses, as of one announcement.
type natHost struct {
	ips []netip.Addr
	exp time.Time
}

func newNATRule(cfg ReflectRule, from, to net.Interface, pool *ports, subnet func() []netip.Prefix, reserved map[string]bool) (*natRule, error) {
	lo, hi, err := cfg.Advertise.portRange()
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		subnet = func() []netip.Prefix { return nil }
	}
	if pool == nil {
		pool = newPorts()
	}
	return &natRule{cfg: cfg, f: newFilter(cfg.Advertise.Services), lo: lo, hi: hi, insts: map[string]*natInstance{}, hosts: map[string]natHost{},
		pool: pool, from: from, to: to, label: natLabel(from.Name), subnet: subnet, reserved: reserved, now: time.Now}, nil
}

// owner is what holds a pooled port: the source it is learned from and the
// instance, so two rules publishing on one interface can never share a port. The
// source is the resolved interface, not the endpoint as written: two bridges a
// pattern stood for are two sources, and an instance of the same name on each is
// not the same instance.
func (n *natRule) owner(i *natInstance) string { return n.from.Name + "|" + i.key() }

// natLabel is the .local host name the destination sees for a source's services.
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

// allocate gives an instance a stable port: hashed from what identifies it,
// probing forward past ports in use. The namespace is the interface's, shared
// with every other rule publishing there.
func (n *natRule) allocate(i *natInstance) bool {
	h := fnv.New32a()
	fmt.Fprintf(h, "%s|%s|%d", n.from.Name, i.ip, i.port)
	size := n.hi - n.lo + 1
	start := int(h.Sum32() % uint32(size))
	owner := n.owner(i)
	n.pool.mu.Lock()
	defer n.pool.mu.Unlock()
	for k := 0; k < size; k++ {
		p := n.lo + (start+k)%size
		if held, taken := n.pool.used[p]; !taken || held == owner {
			n.pool.used[p] = owner
			i.hostPort = p
			return true
		}
	}
	return false
}

// release frees the pooled port an instance holds, leaving its hostPort as it
// was so a goodbye can still name the port it is withdrawing.
func (n *natRule) release(i *natInstance) {
	if i.hostPort == 0 {
		return
	}
	owner := n.owner(i)
	n.pool.mu.Lock()
	if n.pool.used[i.hostPort] == owner {
		delete(n.pool.used, i.hostPort)
	}
	n.pool.mu.Unlock()
}

// held reports which owner holds a port, for tests and diagnostics.
func (p *ports) held(port int) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	owner, ok := p.used[port]
	return owner, ok
}

// mapTarget is the address a container's service is mapped to: one of the
// addresses it announced, on the rule's own network. Its other addresses — its
// loopback, an address of another network — are ignored rather than translated:
// a NAT sends a LAN client to the host that asked, not to a third party.
func mapTarget(subnet []netip.Prefix, ips []netip.Addr) (netip.Addr, bool) {
	for _, ip := range ips {
		if !ip.Is4() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		for _, p := range subnet {
			if p.Contains(ip) {
				return ip, true
			}
		}
	}
	return netip.Addr{}, false
}

// learn folds one container response into the rule's state and reports whether
// the set of mappings or records changed.
func (n *natRule) learn(m *dns.Msg) (changed bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	all := append(append([]dns.RR{}, m.Answer...), m.Extra...)
	// A host may be announced with more than one address in one message (its
	// bridge address and, say, its loopback): they are collected per host and
	// replace what was known, so a container that moves keeps only what it
	// announces now.
	announced := map[string]natHost{}
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
				host := norm(h.Name)
				if h.Ttl == 0 {
					delete(n.hosts, host)
					continue
				}
				a := announced[host]
				a.ips = append(a.ips, ip)
				if exp := now.Add(time.Duration(h.Ttl) * time.Second); exp.After(a.exp) {
					a.exp = exp
				}
				announced[host] = a
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
	for host, a := range announced {
		n.hosts[host] = a
	}
	// An instance is publishable once its host's address is known and a LAN port is set.
	subnet := n.subnet()
	for _, i := range n.insts {
		host, ok := n.hosts[i.host]
		if !ok || !now.Before(host.exp) || i.port == 0 {
			continue
		}
		ip, ok := mapTarget(subnet, host.ips)
		if !ok {
			continue // nothing announced is on this network: keep the last address we verified
		}
		if i.ip != ip || i.hostPort == 0 {
			n.release(i)
			i.hostPort = 0
			i.ip = ip
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
		n.release(i)
		c := *i
		n.removed = append(n.removed, &c)
	}
	delete(n.insts, i.key())
}

// takeRemoved returns and clears the instances withdrawn since the last call.
func (n *natRule) takeRemoved() []*natInstance {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := n.removed
	n.removed = nil
	return out
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
		out = append(out, natMapping{to: n.to.Name, proto: protoOf(i.service), port: i.hostPort, target: i.ip, tport: i.port})
	}
	return out
}

// hostLabel is the .local host the destination sees an instance under: the name
// the source itself advertised, so a client resolves what the source's own
// records — and anything they point at — already name. A name ghostd advertises
// itself is never taken over, and anything that is not one plain label keeps the
// source interface's name instead.
func (n *natRule) hostLabel(i *natInstance) string {
	label, ok := strings.CutSuffix(i.host, ".local.")
	if !ok || !hostRE.MatchString(label) || n.reserved[label] {
		return n.label
	}
	return label
}

// answerer builds the destination-facing view: every instance in its own host
// name, at ghostd's address on that interface and the mapped port. Only IPv4 is
// mapped, so only IPv4 addresses are published.
func (n *natRule) answerer(addrs func(string) ([]netip.Prefix, error)) answerer {
	return n.answererFor(n.published(), addrs)
}

func (n *natRule) answererFor(insts []*natInstance, addrs func(string) ([]netip.Prefix, error)) answerer {
	cfg := Config{Host: n.label}
	for _, i := range insts {
		var subs []string
		for s := range i.subtypes {
			subs = append(subs, s)
		}
		sort.Strings(subs)
		cfg.Records = append(cfg.Records, Record{Service: i.service, Instance: i.instance, Host: n.hostLabel(i), Port: uint16(i.hostPort), TXT: i.txt, Subtypes: subs})
	}
	return answerer{cfg: cfg, addrs: func(iface string) ([]netip.Prefix, error) {
		all, err := addrs(iface)
		var v4 []netip.Prefix
		for _, p := range all {
			if p.Addr().Is4() {
				v4 = append(v4, p)
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

// announceNAT (re)announces a rule's instances on the interface they are
// published on.
func (r *running) announceNAT(n *natRule, ttl uint32) {
	a := n.answerer(r.a.addrs)
	name := ""
	if i, ok := r.ifaces[n.to.Index]; ok {
		name = i.Name
	}
	if rrs := a.all(name, ttl); len(rrs) > 0 {
		m := new(dns.Msg)
		m.Response, m.Authoritative = true, true
		m.Answer = rrs
		r.emit(n.to.Index, m)
	}
	// Whatever left since the last announcement is withdrawn explicitly (TTL 0), so
	// caches on that interface drop it now instead of after its lifetime.
	if gone := n.takeRemoved(); len(gone) > 0 && ttl != 0 {
		bye := n.answererFor(gone, r.a.addrs).all(name, 0)
		var srvOnly []dns.RR
		for _, rr := range bye {
			switch rr.Header().Rrtype {
			case dns.TypePTR, dns.TypeSRV, dns.TypeTXT:
				srvOnly = append(srvOnly, rr) // the host's address record may still serve others
			}
		}
		if len(srvOnly) > 0 {
			m := new(dns.Msg)
			m.Response, m.Authoritative = true, true
			m.Answer = srvOnly
			r.emit(n.to.Index, m)
		}
	}
}

// natLearn is called for a source interface's responses.
func (r *running) natLearn(m *dns.Msg, ifIndex int) {
	for _, n := range r.nats {
		if ifIndex != n.from.Index || !m.Response {
			continue
		}
		if n.learn(m) {
			r.applyNAT()
			r.announceNAT(n, ttlService)
		}
	}
}

// natAnswer answers queries on the published-on interface for the classes a rule
// re-advertises, from what it learned, and asks the source interface when it has
// nothing yet.
func (r *running) natAnswer(m *dns.Msg, src *net.UDPAddr, ifIndex int, v6 bool) {
	if m.Response {
		return
	}
	for _, n := range r.nats {
		if ifIndex != n.to.Index {
			continue
		}
		// Answer from what is already known (the service classes and the rule's host
		// name), and ask the source interface to refresh the cache: its answers are
		// learned and announced.
		if resp := n.answerer(r.a.addrs).Answer(m, r.ifaces[ifIndex].Name); resp != nil {
			r.reply(m, resp, src, ifIndex, v6)
		}
		if q := n.f.Queries(m); q != nil {
			r.forward(q, n.from.Index, v6)
		}
	}
}

// natSweep is how often expired instances are swept.
var natSweep = 5 * time.Second

// runNAT sweeps expired instances every few seconds.
func (r *running) runNAT() {
	t := time.NewTicker(natSweep)
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

//go:build mdns

package mdns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func containerAnnouncement(host string, ip string, instance string, port uint16, ttl uint32) *dns.Msg {
	mk := func(name string, t uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET | 0x8000, Ttl: ttl}
	}
	inst := instance + "._ipp._tcp.local."
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.PTR{Hdr: mk("_ipp._tcp.local.", dns.TypePTR), Ptr: inst},
		&dns.PTR{Hdr: mk("_universal._sub._ipp._tcp.local.", dns.TypePTR), Ptr: inst},
	}
	m.Extra = []dns.RR{
		&dns.SRV{Hdr: mk(inst, dns.TypeSRV), Port: port, Target: host + ".local."},
		&dns.TXT{Hdr: mk(inst, dns.TypeTXT), Txt: []string{"rp=ipp/print"}},
		&dns.A{Hdr: mk(host+".local.", dns.TypeA), A: net.ParseIP(ip)},
	}
	return m
}

// ctrSubnet is the container network the announcements below live on.
func ctrSubnet() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("10.90.0.0/24")} }

func natRuleFor(t *testing.T) *natRule {
	t.Helper()
	n, err := newNATRule(ReflectRule{LAN: "lab0", Network: "ctr0", Advertise: &NATConfig{Services: []string{"_ipp._tcp"}, Ports: "20000-20099"}}, 1, ctrSubnet, nil)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestNATLearnsAndMapsContainerServices(t *testing.T) {
	n := natRuleFor(t)
	if !n.learn(containerAnnouncement("printer", "10.90.0.10", "Office", 631, 120)) {
		t.Fatal("a new instance must change the mappings")
	}
	pub := n.published()
	if len(pub) != 1 || pub[0].hostPort < 20000 || pub[0].hostPort > 20099 || pub[0].ip.String() != "10.90.0.10" || pub[0].port != 631 || !pub[0].subtypes["_universal"] || pub[0].txt[0] != "rp=ipp/print" {
		t.Fatalf("%+v", pub)
	}
	first := pub[0].hostPort
	if n.learn(containerAnnouncement("printer", "10.90.0.10", "Office", 631, 120)) {
		t.Fatal("a repeated announcement changed nothing and must not reconfigure NAT")
	}
	if n.published()[0].hostPort != first {
		t.Fatal("the LAN port must be stable")
	}
	// A second instance from another container gets its own port.
	n.learn(containerAnnouncement("second", "10.90.0.11", "Back Office", 631, 120))
	pub = n.published()
	if len(pub) != 2 || pub[0].hostPort == pub[1].hostPort {
		t.Fatal("two containers advertising the same port need distinct LAN ports:", pub)
	}
	// Goodbye withdraws exactly that instance and frees its port.
	if !n.learn(containerAnnouncement("printer", "10.90.0.10", "Office", 631, 0)) {
		t.Fatal("a goodbye must change the mappings")
	}
	if pub = n.published(); len(pub) != 1 || pub[0].instance != "Back Office" {
		t.Fatal(pub)
	}
	if _, used := n.used[first]; used {
		t.Fatal("goodbye did not free the port")
	}
	// Expiry.
	now := time.Now().Add(10 * time.Minute)
	n.now = func() time.Time { return now }
	if !n.expire() || len(n.published()) != 0 {
		t.Fatal("expired instance still published")
	}
}

func TestNATIgnoresWhatIsNotAllowedOrIncomplete(t *testing.T) {
	n := natRuleFor(t)
	m := containerAnnouncement("printer", "10.90.0.10", "Office", 631, 120)
	// A class the network is not allowed to advertise.
	other := new(dns.Msg)
	other.Response = true
	other.Answer = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: "_smb._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 120}, Ptr: "Share._smb._tcp.local."}}
	other.Extra = []dns.RR{&dns.SRV{Hdr: dns.RR_Header{Name: "Share._smb._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}, Port: 445, Target: "printer.local."}}
	n.learn(other)
	if len(n.published()) != 0 {
		t.Fatal("a class outside the rule was advertised")
	}
	// SRV before the host's address is known is held until the A arrives.
	srvOnly := containerAnnouncement("printer", "10.90.0.10", "Office", 631, 120)
	srvOnly.Extra = srvOnly.Extra[:2] // drop the A
	n.learn(srvOnly)
	if len(n.published()) != 0 {
		t.Fatal("advertised a service with no known address to map to")
	}
	n.learn(m)
	if len(n.published()) != 1 {
		t.Fatal("did not complete once the address arrived")
	}
}

func TestNATPortPoolExhaustionAndRange(t *testing.T) {
	n, _ := newNATRule(ReflectRule{LAN: "lab0", Network: "ctr0", Advertise: &NATConfig{Services: []string{"_ipp._tcp"}, Ports: "20000-20001"}}, 1, ctrSubnet, nil)
	for i, ip := range []string{"10.90.0.10", "10.90.0.11", "10.90.0.12"} {
		n.learn(containerAnnouncement("h"+string(rune('a'+i)), ip, "P"+string(rune('a'+i)), 631, 120))
	}
	if len(n.published()) != 2 {
		t.Fatal("a pool of two ports maps two instances, never a third:", len(n.published()))
	}
	for _, bad := range []string{"", "20000", "80-90", "20000-70000", "20100-20000", "1024-9999"} {
		if _, _, err := (NATConfig{Ports: bad}).portRange(); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRenderNATIsOneAtomicTable(t *testing.T) {
	if got := renderNAT(nil); !strings.Contains(got, "delete table inet ghostd_mdns_nat") || strings.Contains(got, "chain") {
		t.Fatal("an empty set must remove the table:", got)
	}
	got := renderNAT([]natMapping{
		{lan: "eth0", proto: "tcp", port: 20002, target: netip.MustParseAddr("10.90.0.11"), tport: 631},
		{lan: "eth0", proto: "tcp", port: 20001, target: netip.MustParseAddr("10.90.0.10"), tport: 631},
	})
	i1, i2 := strings.Index(got, "dport 20001"), strings.Index(got, "dport 20002")
	if i1 < 0 || i2 < i1 || !strings.Contains(got, `iifname "eth0" fib daddr type local tcp dport 20001 dnat ip to 10.90.0.10:631`) {
		t.Fatal(got)
	}
	// The redirect is scoped to traffic addressed to ghostd: a pool port is not a
	// reason to rewrite a flow meant for somebody else on the same LAN.
	if strings.Contains(got, `iifname "eth0" tcp dport`) || !strings.Contains(got, "fib daddr type local") {
		t.Fatal("a pool port would intercept traffic not addressed to ghostd:", got)
	}
}

type fakeNAT struct {
	mu      sync.Mutex
	scripts []string
}

func (f *fakeNAT) Apply(_ context.Context, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, s)
	return nil
}
func (f *fakeNAT) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scripts) == 0 {
		return ""
	}
	return f.scripts[len(f.scripts)-1]
}

func TestContainerServiceIsReadvertisedOnTheLANAndMapped(t *testing.T) {
	fake := &fakeNAT{}
	rule := ReflectRule{LAN: "lab0", Network: "ctr0", Advertise: &NATConfig{Services: []string{"_ipp._tcp"}, Ports: "20000-20099"}}
	n, _ := newNATRule(rule, 1, ctrSubnet, nil)
	r := &running{
		a: answerer{cfg: Config{}, addrs: func(iface string) ([]netip.Prefix, error) {
			if iface == "lab0" {
				return []netip.Prefix{netip.MustParsePrefix("10.77.0.1/24"), netip.MustParsePrefix("fd77::1/64")}, nil
			}
			return []netip.Prefix{netip.MustParsePrefix("10.90.0.1/24")}, nil
		}},
		ifaces: map[int]net.Interface{1: {Index: 1, Name: "lab0"}, 10: {Index: 10, Name: "ctr0"}}, advertise: map[int]bool{}, done: make(chan struct{}),
		nats: []*natRule{n}, natRunner: fake,
		rules: []*reflectRule{{cfg: rule, f: newFilter(nil), lan: 1, net: 10}},
	}
	var emitted []*dns.Msg
	r.testEmit = func(idx int, m *dns.Msg) {
		if idx == 1 {
			emitted = append(emitted, m)
		}
	}
	pack := func(m *dns.Msg) []byte { b, _ := m.Pack(); return b }
	// The container announces on its bridge.
	r.handle(pack(containerAnnouncement("printer", "10.90.0.10", "Office", 631, 120)), &net.UDPAddr{IP: net.ParseIP("10.90.0.10"), Port: 5353}, 10, false)
	pub := n.published()
	if len(pub) != 1 {
		t.Fatal(pub)
	}
	port := pub[0].hostPort
	if got := fake.last(); !strings.Contains(got, `iifname "lab0" fib daddr type local tcp dport `) || !strings.Contains(got, "dnat ip to 10.90.0.10:631") {
		t.Fatal("no DNAT installed:", got)
	}
	if len(emitted) == 0 {
		t.Fatal("nothing announced on the LAN")
	}
	all := emitted[len(emitted)-1]
	var srv *dns.SRV
	var addrs []string
	for _, rr := range append(append([]dns.RR{}, all.Answer...), all.Extra...) {
		switch v := rr.(type) {
		case *dns.SRV:
			srv = v
		case *dns.A:
			addrs = append(addrs, v.A.String())
		case *dns.AAAA:
			t.Fatal("IPv6 is not mapped, so it must not be published:", v)
		}
	}
	if srv == nil || int(srv.Port) != port || srv.Target != "printer.local." {
		t.Fatalf("SRV must point at ghostd's port and the name the container advertised: %+v", srv)
	}
	if len(addrs) != 1 || addrs[0] != "10.77.0.1" {
		t.Fatalf("the LAN must be told ghostd's address, never the container's: %v", addrs)
	}
	for _, rr := range all.Answer {
		if strings.Contains(rr.String(), "10.90.0.10") {
			t.Fatal("the container's private address leaked to the LAN:", rr)
		}
	}
	// A LAN client asks: answered from the cache, and the question is relayed to the container network.
	var replies []*dns.Msg
	r.testSend = func(m *dns.Msg) { replies = append(replies, m) }
	var forwarded []int
	r.testForward = func(idx int, m *dns.Msg) { forwarded = append(forwarded, idx) }
	q := new(dns.Msg)
	q.SetQuestion("_ipp._tcp.local.", dns.TypePTR)
	r.handle(pack(q), &net.UDPAddr{IP: net.ParseIP("10.77.0.60"), Port: 5353}, 1, false)
	if len(replies) != 1 || len(replies[0].Answer) != 1 {
		t.Fatal("LAN browse not answered from the NAT cache:", replies)
	}
	if len(forwarded) != 1 || forwarded[0] != 10 {
		t.Fatal("the LAN query was not relayed to the container network:", forwarded)
	}
	// A class nobody advertises through the NAT gets no answer and is not relayed.
	replies, forwarded = nil, nil
	q.SetQuestion("_smb._tcp.local.", dns.TypePTR)
	r.handle(pack(q), &net.UDPAddr{IP: net.ParseIP("10.77.0.60"), Port: 5353}, 1, false)
	if len(replies) != 0 || len(forwarded) != 0 {
		t.Fatal("a class outside the rule was answered or relayed")
	}
	// The LAN resolves the name the container advertised: the address it is
	// answered with is ghostd's, so a client holding the container's own name (its
	// TXT records, a previously browsed URL) still lands in the container.
	replies = nil
	q.SetQuestion("printer.local.", dns.TypeA)
	r.handle(pack(q), &net.UDPAddr{IP: net.ParseIP("10.77.0.60"), Port: 5353}, 1, false)
	if len(replies) != 1 || len(replies[0].Answer) != 1 || replies[0].Answer[0].(*dns.A).A.String() != "10.77.0.1" {
		t.Fatal("the container's own host name is not answered with ghostd's address:", replies)
	}
	// The container says goodbye: withdrawn on the LAN and unmapped.
	emitted = nil
	r.handle(pack(containerAnnouncement("printer", "10.90.0.10", "Office", 631, 0)), &net.UDPAddr{IP: net.ParseIP("10.90.0.10"), Port: 5353}, 10, false)
	if len(n.published()) != 0 || strings.Contains(fake.last(), "dnat") {
		t.Fatal("goodbye left a mapping behind:", fake.last())
	}
	withdrawn := false
	for _, m := range emitted {
		for _, rr := range m.Answer {
			if p, ok := rr.(*dns.PTR); ok && p.Hdr.Ttl == 0 && strings.Contains(p.Ptr, "Office") {
				withdrawn = true
			}
		}
	}
	if !withdrawn {
		t.Fatal("the LAN was not sent a TTL-0 withdrawal for the instance that left:", emitted)
	}
	// Stopping withdraws everything and removes the table.
	r.handle(pack(containerAnnouncement("printer", "10.90.0.10", "Office", 631, 120)), &net.UDPAddr{IP: net.ParseIP("10.90.0.10"), Port: 5353}, 10, false)
	r.stopNAT()
	if got := fake.last(); strings.Contains(got, "chain") {
		t.Fatal("the table survived a stop:", got)
	}
}

// A container may announce more than one address for its host (its bridge
// address and, say, its loopback). Only the one on its own network is
// translated: a LAN client must never be sent to the host's loopback, to the
// tailnet or to another LAN host because a container said so.
func TestNATMapsOnlyTheContainersOwnNetworkAddress(t *testing.T) {
	n := natRuleFor(t)
	two := containerAnnouncement("printer", "10.90.0.10", "Office", 631, 120)
	two.Extra = append(two.Extra, &dns.A{Hdr: dns.RR_Header{Name: "printer.local.", Rrtype: dns.TypeA, Class: dns.ClassINET | 0x8000, Ttl: 120}, A: net.ParseIP("127.0.0.1")})
	n.learn(two)
	if pub := n.published(); len(pub) != 1 || pub[0].ip.String() != "10.90.0.10" {
		t.Fatalf("mapped %+v instead of the address on the container's own network", pub)
	}
	// An address off the network, announced alone, is not a mapping at all.
	for _, off := range []string{"127.0.0.1", "100.64.0.9", "10.77.0.60"} {
		loop := natRuleFor(t)
		only := containerAnnouncement("printer", off, "Office", 631, 120)
		loop.learn(only)
		if pub := loop.published(); len(pub) != 0 || len(loop.mappings()) != 0 {
			t.Fatalf("%s became a LAN-reachable DNAT target: %+v", off, pub)
		}
	}
}

// The LAN sees the instance under the name the container advertised, unless
// ghostd advertises that name itself or it is not one plain .local label.
func TestNATKeepsTheContainersOwnName(t *testing.T) {
	rule := ReflectRule{LAN: "lab0", Network: "ctr0", Advertise: &NATConfig{Services: []string{"_ipp._tcp"}, Ports: "20000-20099"}}
	n, err := newNATRule(rule, 1, ctrSubnet, map[string]bool{"nas": true})
	if err != nil {
		t.Fatal(err)
	}
	label := func(instance string) string {
		t.Helper()
		for _, i := range n.published() {
			if i.instance == instance {
				return n.hostLabel(i)
			}
		}
		t.Fatalf("instance %s is not published: %+v", instance, n.published())
		return ""
	}
	n.learn(containerAnnouncement("printer", "10.90.0.10", "Office", 631, 120))
	if got := label("Office"); got != "printer" {
		t.Fatal("the container's own name must be the one the LAN sees:", got)
	}
	// A name ghostd advertises itself is never taken over by a container.
	n.learn(containerAnnouncement("nas", "10.90.0.11", "Backups", 631, 120))
	if got := label("Backups"); got != "ctr0" {
		t.Fatal("a container took over a name ghostd advertises itself:", got)
	}
	// A host that is not one plain .local label keeps the network's name.
	odd := containerAnnouncement("printer", "10.90.0.12", "Other", 631, 120)
	odd.Extra[0] = &dns.SRV{Hdr: dns.RR_Header{Name: "Other._ipp._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET | 0x8000, Ttl: 120}, Port: 631, Target: "printer.example.com."}
	odd.Extra[2] = &dns.A{Hdr: dns.RR_Header{Name: "printer.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET | 0x8000, Ttl: 120}, A: net.ParseIP("10.90.0.12")}
	n.learn(odd)
	if got := label("Other"); got != "ctr0" {
		t.Fatal("a host outside .local kept a name ghostd cannot serve:", got)
	}
}

func TestNATConfigValidationAndCoexistenceWithFilteredReflection(t *testing.T) {
	good := `{"reflect":[{"lan":"eth0","network":"p","advertise":{"services":["_ipp._tcp"],"ports":"20000-20099"}}]}`
	if c, err := ParseConfig([]byte(good)); err != nil || c.Reflect[0].Advertise == nil {
		t.Fatal("advertise-only rule (no allow_services):", err)
	}
	for name, doc := range map[string]string{
		"no services": `{"reflect":[{"lan":"eth0","network":"p","advertise":{"services":[],"ports":"20000-20099"}}]}`,
		"bad ports":   `{"reflect":[{"lan":"eth0","network":"p","advertise":{"services":["_ipp._tcp"],"ports":"80-90"}}]}`,
		"bad service": `{"reflect":[{"lan":"eth0","network":"p","advertise":{"services":["ipp"],"ports":"20000-20099"}}]}`,
		"neither":     `{"reflect":[{"lan":"eth0","network":"p"}]}`,
	} {
		if _, err := ParseConfig([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

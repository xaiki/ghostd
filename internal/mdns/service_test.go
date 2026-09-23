//go:build mdns

package mdns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// upIface is one usable mDNS interface for the resolution tests.
func upIface(index int, name string) net.Interface {
	return net.Interface{Index: index, Name: name, Flags: net.FlagUp | net.FlagMulticast}
}

// planAddrs is the interface-address lister planRules maps a source's announced
// addresses against.
func planAddrs(string) ([]netip.Prefix, error) { return ctrSubnet(), nil }

// An endpoint names one interface or a pattern that stands for several. The
// pattern is how the stack names the container bridges — Podman picks their
// names, so no inventory can hold them — and the same token its nft rule admits
// container mDNS with.
func TestRuleEndpointsResolveNamesAndPatterns(t *testing.T) {
	all := []net.Interface{
		upIface(1, "lo"), upIface(2, "end0"), upIface(3, "podman1"), upIface(4, "podman2"),
		upIface(5, "veth9"), {Index: 6, Name: "podman3"}, // podman3 exists but is down
	}
	got, err := endpoints("end0", all)
	if err != nil || len(got) != 1 || got[0].Name != "end0" {
		t.Fatalf("an exact name must resolve to that interface: %v, %v", got, err)
	}
	got, err = endpoints("podman*", all)
	if err != nil || len(got) != 2 || got[0].Name != "podman1" || got[1].Name != "podman2" {
		t.Fatalf("a pattern must stand for the interfaces that exist: %v, %v", got, err)
	}

	// Whatever names nothing usable refuses the apply: a pattern that quietly
	// relayed nowhere would read as converged while nothing is relayed, and the
	// watcher retries a failed apply until the bridge is there.
	for _, bad := range []string{"podman9", "podman9*", "nope*"} {
		if _, err := endpoints(bad, all); err == nil {
			t.Errorf("%s names no usable interface and was accepted", bad)
		}
	}
	// A pattern matching only an interface that cannot carry mDNS is refused the
	// same way, saying what it matched.
	if _, err := endpoints("podman3*", all); err == nil || !strings.Contains(err.Error(), "not up") {
		t.Fatalf("a match that cannot carry mDNS was accepted: %v", err)
	}
	// A pattern that matches the whole interface table would join the mDNS group
	// on every interface of a busy host: refused past the cap.
	many := make([]net.Interface, 0, endpointLimit+2)
	for i := 0; i <= endpointLimit; i++ {
		many = append(many, upIface(100+i, "veth"+strconv.Itoa(i)))
	}
	if _, err := endpoints("veth*", many); err == nil {
		t.Fatal("a pattern matching every interface was obeyed")
	}
	// A malformed pattern is refused, and an exact name that is not multicast
	// capable is refused as it always was.
	if _, err := endpoints("pod[man*", all); err == nil {
		t.Fatal("a malformed pattern was accepted")
	}
	if _, err := endpoints("sit0", []net.Interface{{Index: 7, Name: "sit0"}}); err == nil || !strings.Contains(err.Error(), "multicast") {
		t.Fatalf("a non-multicast interface was accepted: %v", err)
	}
}

// A rule naming a pattern becomes one rule per interface it matched, and the
// config is never rewritten: the read-back the stack diffs against has to carry
// the pattern as sent, or a converged host would read as permanent drift and
// every run would re-apply.
func TestAPatternRuleExpandsWithoutBeingRewritten(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"reflect":[{"from":"podman*","to":"end0","allow_services":["*"]},{"from":"end0","to":"podman*","allow_services":["*"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	all := []net.Interface{upIface(2, "end0"), upIface(3, "podman1"), upIface(4, "podman2")}
	pl, err := planRules(cfg, all, planAddrs, nil)
	if err != nil {
		t.Fatal(err)
	}
	pairs := map[string]bool{}
	for _, e := range pl.edges {
		pairs[fmt.Sprintf("%d>%d", e.from, e.to)] = true
	}
	for _, want := range []string{"3>2", "2>3", "4>2", "2>4"} {
		if !pairs[want] {
			t.Fatalf("missing %s: one rule per bridge in each direction, got %v", want, pairs)
		}
	}
	if len(pl.edges) != 4 {
		t.Fatalf("a pattern rule must expand to one edge per bridge, got %v", pairs)
	}
	// Every bridge a rule named is a domain the relay joins.
	for _, index := range []int{2, 3, 4} {
		if _, ok := pl.ifaces[index]; !ok {
			t.Fatalf("interface %d is not part of the plan", index)
		}
	}
	echo, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(echo), `"from":"podman*"`) || strings.Contains(string(echo), "podman1") {
		t.Fatalf("resolution rewrote the config: %s", echo)
	}
}

// A translated rule naming a pattern gives each bridge its own NAT rule: its own
// published host name and its own slot in the port namespace of the interface it
// publishes on.
func TestAPatternAdvertiseRuleGivesEachBridgeItsOwnRule(t *testing.T) {
	cfg, err := ParseConfig([]byte(`{"reflect":[{"from":"podman*","to":"end0","advertise":{"services":["_ipp._tcp"],"ports":"20000-20099"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	all := []net.Interface{upIface(2, "end0"), upIface(3, "podman1"), upIface(4, "podman2")}
	pl, err := planRules(cfg, all, planAddrs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.nats) != 2 {
		t.Fatalf("one NAT rule per bridge, got %d", len(pl.nats))
	}
	labels := map[string]bool{}
	for _, n := range pl.nats {
		labels[n.label] = true
		if n.from.Name == "" || n.to.Name != "end0" {
			t.Fatalf("a NAT rule must carry the interfaces it resolved to: %+v", n)
		}
	}
	if len(labels) != 2 {
		t.Fatalf("two bridges must not publish under one host name: %v", labels)
	}
	if pl.nats[0].pool != pl.nats[1].pool {
		t.Fatal("rules publishing on one interface must share its port namespace")
	}
	if len(pl.edges) != 0 {
		t.Fatal("a translated rule is not a relay edge:", pl.edges)
	}
}

func TestServiceApplyValidatesBeforeTouchingTheNetwork(t *testing.T) {
	s := NewService()
	defer s.Close()
	if !s.Config().Empty() {
		t.Fatal("a new service advertises nothing")
	}
	if err := s.Apply(Config{}); err != nil {
		t.Fatal("an empty target is valid and needs no socket:", err)
	}
	bad := Config{Interfaces: []string{"ghostd-none0"}, Host: "nas", Records: []Record{{Service: "_smb._tcp", Instance: "N", Port: 445}}}
	if err := s.Apply(bad); err == nil || !strings.Contains(err.Error(), "ghostd-none0") {
		t.Fatal("an unknown interface must fail with its name:", err)
	}
	if !s.Config().Empty() {
		t.Fatal("a failed apply must leave the previous (empty) set")
	}
	if err := s.Apply(Config{Interfaces: []string{"eth0"}, Host: "Bad.Host", Records: bad.Records}); err == nil {
		t.Fatal("an invalid config reached the sockets")
	}
	rule := Config{Reflect: []ReflectRule{{From: "ghostd-ctr0", To: "ghostd-lan0", AllowServices: []string{"_ipp._tcp"}}}}
	if err := s.Apply(rule); err == nil || !strings.Contains(err.Error(), "ghostd-ctr0") {
		t.Fatal("a reflect rule on a missing interface:", err)
	}
	s.Close()
	s.Close() // idempotent
}

func TestLANClientResolvesAndBrowsesThroughTheQuerier(t *testing.T) {
	hdr := func(name string, typ uint16) dns.RR_Header {
		return dns.RR_Header{Name: name, Rrtype: typ, Class: dns.ClassINET | 0x8000, Ttl: 120}
	}
	addr := responder(t, func(q dns.Question) []dns.RR {
		switch {
		case q.Name == "printer.local." && q.Qtype == dns.TypeA:
			return []dns.RR{&dns.A{Hdr: hdr("printer.local.", dns.TypeA), A: net.ParseIP("192.0.2.50")}}
		case q.Name == "printer.local." && q.Qtype == dns.TypeAAAA:
			return []dns.RR{&dns.AAAA{Hdr: hdr("printer.local.", dns.TypeAAAA), AAAA: net.ParseIP("fd00::50")}}
		case q.Name == "_ipp._tcp.local.":
			return []dns.RR{
				&dns.PTR{Hdr: hdr("_ipp._tcp.local.", dns.TypePTR), Ptr: "Office._ipp._tcp.local."},
				&dns.SRV{Hdr: hdr("Office._ipp._tcp.local.", dns.TypeSRV), Port: 631, Target: "printer.local."},
			}
		}
		return nil
	})
	lan := NewLAN(&Querier{targets: []*net.UDPAddr{addr}, Window: 250 * time.Millisecond})
	ips, err := lan.Lookup(context.Background(), "printer.local.")
	if err != nil || len(ips) != 2 {
		t.Fatal("a .local host has both address families:", ips, err)
	}
	if ips, err = lan.Lookup(context.Background(), "ghost.local."); err != nil || len(ips) != 0 {
		t.Fatal("silence is not an error:", ips, err)
	}
	ans, extra, err := lan.Browse(context.Background(), "_ipp._tcp.local.", dns.TypePTR)
	if err != nil || len(ans) != 1 || len(extra) != 1 {
		t.Fatal(ans, extra, err)
	}
	// With no interface able to send, the failure is reported so the resolver can fall back.
	dead := NewLAN(&Querier{Interfaces: []string{"ghostd-none0"}, Window: 50 * time.Millisecond})
	if _, err := dead.Lookup(context.Background(), "printer.local."); err == nil {
		t.Fatal("a querier with no usable interface must say so")
	}
	if _, _, err := dead.Browse(context.Background(), "_ipp._tcp.local.", dns.TypePTR); err == nil {
		t.Fatal("browse with no usable interface must say so")
	}
}

func TestNATHelpers(t *testing.T) {
	for in, want := range map[string]string{"podman-print": "podman-print", "My Net_1": "my-net-1", "--x--": "x", "": "container", "ünï": "n", strings.Repeat("a", 90): strings.Repeat("a", 63)} {
		if got := natLabel(in); got != want {
			t.Errorf("natLabel(%q) = %q, want %q", in, got, want)
		}
	}
	if protoOf("_ipp._tcp") != "tcp" || protoOf("_sip._udp") != "udp" {
		t.Fatal("protoOf")
	}
	if got := unescapeKeepCase(`Lobby\032Printer._ipp._tcp.local.`, "_ipp._tcp"); got != "Lobby Printer" {
		t.Fatal(got)
	}
	if got := unescapeKeepCase(`A\.B\\C._ipp._tcp.local.`, "_ipp._tcp"); got != `A.B\C` {
		t.Fatal(got)
	}
}

func TestNATSweeperWithdrawsExpiredInstances(t *testing.T) {
	saved := natSweep
	natSweep = 20 * time.Millisecond
	defer func() { natSweep = saved }()
	fake := &fakeNAT{}
	rule := ReflectRule{From: "ctr0", To: "lab0", Advertise: &NATConfig{Services: []string{"_ipp._tcp"}, Ports: "20000-20099"}}
	n, _ := newNATRule(rule, natIface(10, "ctr0"), natIface(1, "lab0"), newPorts(), ctrSubnet, nil)
	r := &running{
		a: answerer{addrs: func(string) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("10.77.0.1/24")}, nil
		}},
		ifaces: map[int]net.Interface{1: {Index: 1, Name: "lab0"}, 10: {Index: 10, Name: "ctr0"}}, advertise: map[int]bool{}, done: make(chan struct{}),
		nats: []*natRule{n}, natRunner: fake,
	}
	var goodbyes atomic.Int64
	r.testEmit = func(idx int, m *dns.Msg) {
		for _, rr := range m.Answer {
			if rr.Header().Ttl == 0 {
				goodbyes.Add(1)
			}
		}
	}
	n.learn(containerAnnouncement("printer", "10.90.0.10", "Office", 631, 1)) // a one-second record
	r.applyNAT()
	if !strings.Contains(fake.last(), "dnat") {
		t.Fatal("no mapping installed")
	}
	future := time.Now().Add(time.Minute)
	n.now = func() time.Time { return future }
	go r.runNAT()
	defer close(r.done)
	deadline := time.Now().Add(2 * time.Second)
	for strings.Contains(fake.last(), "dnat") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(fake.last(), "dnat") || len(n.published()) != 0 {
		t.Fatal("an expired instance was never swept")
	}
	if goodbyes.Load() == 0 {
		t.Fatal("the expiry must be withdrawn on the LAN with a goodbye")
	}
}

func TestQuerierInterfaceSelection(t *testing.T) {
	q := &Querier{Interfaces: []string{"ghostd-none0"}}
	if got, err := q.interfaces(); err != nil || len(got) != 0 {
		t.Fatal("an interface that does not exist selects nothing:", got, err)
	}
	all, err := (&Querier{}).interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range all {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagMulticast == 0 {
			t.Fatal("selected an interface that cannot carry mDNS:", i.Name)
		}
	}
	if (&Querier{}).window() != 700*time.Millisecond || (&Querier{Window: time.Second}).window() != time.Second {
		t.Fatal("window")
	}
}

func TestAnswersRelatedAndNormEdgeCases(t *testing.T) {
	rrs := []dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: "Host.local.", Rrtype: dns.TypeA, Class: dns.ClassINET | 0x8000, Ttl: 999}, A: net.ParseIP("192.0.2.1")},
		&dns.A{Hdr: dns.RR_Header{Name: "other.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 10}, A: net.ParseIP("192.0.2.2")},
	}
	got := Answers(rrs, "host.local.", dns.TypeA)
	if len(got) != 1 || got[0].Header().Ttl != 30 || got[0].Header().Class != dns.ClassINET {
		t.Fatal("answers are name-insensitive, TTL-capped and flush-bit-free:", got)
	}
	if len(Answers(rrs, "host.local.", dns.TypeAAAA)) != 0 || len(Answers(rrs, "host.local.", dns.TypeANY)) != 1 {
		t.Fatal("type matching")
	}
	if got := norm(`A\\B\`); got != `a\b` && got != `a\b\` {
		t.Fatal(got)
	}
	if norm(`x\999`) == "" {
		t.Fatal("an out-of-range escape must not be dropped")
	}
}

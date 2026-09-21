//go:build mdns

package mdns

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

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
	rule := Config{Reflect: []ReflectRule{{LAN: "ghostd-lan0", Network: "ghostd-ctr0", AllowServices: []string{"_ipp._tcp"}}}}
	if err := s.Apply(rule); err == nil || !strings.Contains(err.Error(), "ghostd-lan0") {
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
	rule := ReflectRule{LAN: "lab0", Network: "ctr0", Advertise: &NATConfig{Services: []string{"_ipp._tcp"}, Ports: "20000-20099"}}
	n, _ := newNATRule(rule, 1)
	r := &running{
		a:      answerer{addrs: func(string) ([]netip.Addr, error) { return []netip.Addr{netip.MustParseAddr("10.77.0.1")}, nil }},
		ifaces: map[int]net.Interface{1: {Index: 1, Name: "lab0"}, 10: {Index: 10, Name: "ctr0"}}, advertise: map[int]bool{}, done: make(chan struct{}),
		nats: []*natRule{n}, natRunner: fake, rules: []*reflectRule{{cfg: rule, f: newFilter(nil), lan: 1, net: 10}},
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

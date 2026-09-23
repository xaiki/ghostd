//go:build mdns

package mdns

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/xaiki/ghostd/internal/wellknown"
)

func hdr(name string, t uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: t, Class: dns.ClassINET | 0x8000, Ttl: 120}
}

// A LAN announcement carrying a printer and a speaker, hosted on two machines.
func lanAnnouncement() *dns.Msg {
	m := new(dns.Msg)
	m.Response = true
	m.Answer = []dns.RR{
		&dns.PTR{Hdr: hdr("_ipp._tcp.local.", dns.TypePTR), Ptr: `Lobby\032Printer._ipp._tcp.local.`},
		&dns.PTR{Hdr: hdr("_googlecast._tcp.local.", dns.TypePTR), Ptr: "Speaker._googlecast._tcp.local."},
		&dns.PTR{Hdr: hdr("_services._dns-sd._udp.local.", dns.TypePTR), Ptr: "_ipp._tcp.local."},
		&dns.PTR{Hdr: hdr("_services._dns-sd._udp.local.", dns.TypePTR), Ptr: "_googlecast._tcp.local."},
	}
	m.Extra = []dns.RR{
		&dns.SRV{Hdr: hdr(`Lobby\032Printer._ipp._tcp.local.`, dns.TypeSRV), Port: 631, Target: "printer.local."},
		&dns.TXT{Hdr: hdr(`Lobby\032Printer._ipp._tcp.local.`, dns.TypeTXT), Txt: []string{"rp=ipp/print"}},
		&dns.A{Hdr: hdr("printer.local.", dns.TypeA), A: net.ParseIP("192.0.2.60")},
		&dns.SRV{Hdr: hdr("Speaker._googlecast._tcp.local.", dns.TypeSRV), Port: 8009, Target: "speaker.local."},
		&dns.A{Hdr: hdr("speaker.local.", dns.TypeA), A: net.ParseIP("192.0.2.61")},
		&dns.A{Hdr: hdr("laptop.local.", dns.TypeA), A: net.ParseIP("192.0.2.62")},
	}
	return m
}

func names(rrs []dns.RR) string {
	var out []string
	for _, rr := range rrs {
		out = append(out, dns.TypeToString[rr.Header().Rrtype]+" "+norm(rr.Header().Name))
	}
	return strings.Join(out, "; ")
}

func TestReflectedResponsesCarryOnlyAllowedClassesAndTheirHosts(t *testing.T) {
	f := newFilter([]string{"_ipp._tcp"})
	got := f.Responses(lanAnnouncement())
	if got == nil {
		t.Fatal("nothing reflected")
	}
	all := names(got.Answer) + " | " + names(got.Extra)
	for _, want := range []string{`ptr _ipp._tcp.local.`, "srv lobby printer._ipp._tcp.local.", "txt lobby printer._ipp._tcp.local.", "a printer.local.", "ptr _services._dns-sd._udp.local."} {
		if !strings.Contains(strings.ToLower(all), want) {
			t.Fatalf("missing %q in %s", want, all)
		}
	}
	// The enumeration answer stands, but only for the classes it may see: the one
	// naming _googlecast is filtered out with the rest of that class's records.
	if len(got.Answer) != 2 || got.Answer[1].(*dns.PTR).Ptr != "_ipp._tcp.local." {
		t.Fatalf("enumeration was not trimmed to the allowed classes: %s | %s", names(got.Answer), names(got.Extra))
	}
	for _, leak := range []string{"googlecast", "speaker", "laptop"} {
		if strings.Contains(strings.ToLower(all), leak) {
			t.Fatalf("leaked %q into a network that may only see _ipp._tcp: %s", leak, all)
		}
	}
	// A record for a host no allowed service named is refused, even when it
	// arrives alone in a later packet.
	solo := new(dns.Msg)
	solo.Response = true
	solo.Answer = []dns.RR{&dns.A{Hdr: hdr("laptop.local.", dns.TypeA), A: net.ParseIP("192.0.2.62")}}
	if f.Responses(solo) != nil {
		t.Fatal("an address record for an unrelated host was reflected")
	}
	// A host an allowed service named stays resolvable for a while (separate packet).
	late := new(dns.Msg)
	late.Response = true
	late.Answer = []dns.RR{&dns.A{Hdr: hdr("printer.local.", dns.TypeA), A: net.ParseIP("192.0.2.60")}}
	if f.Responses(late) == nil {
		t.Fatal("the allowed service's host lost its address record")
	}
	now := time.Now().Add(5 * time.Minute)
	f.now = func() time.Time { return now }
	if f.Responses(late) != nil {
		t.Fatal("a host grant did not expire")
	}
}

func TestReflectedQueriesAreLimitedToWhatTheNetworkMayAsk(t *testing.T) {
	f := newFilter([]string{"_ipp._tcp"})
	ask := func(name string, typ uint16, known ...dns.RR) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(name, typ)
		q.Answer = known
		return f.Queries(q)
	}
	if ask("_ipp._tcp.local.", dns.TypePTR) == nil || ask("Lobby._ipp._tcp.local.", dns.TypeSRV) == nil || ask("_universal._sub._ipp._tcp.local.", dns.TypePTR) == nil {
		t.Fatal("allowed browse blocked")
	}
	// A browser that enumerates the types first sees the classes it may see: the
	// question names no class of its own, so its answers are what gets filtered.
	if ask("_services._dns-sd._udp.local.", dns.TypePTR) == nil {
		t.Fatal("the service-type enumeration must reach the LAN")
	}
	meta := ask("_services._dns-sd._udp.local.", dns.TypePTR,
		&dns.PTR{Hdr: hdr("_services._dns-sd._udp.local.", dns.TypePTR), Ptr: "_ipp._tcp.local."},
		&dns.PTR{Hdr: hdr("_services._dns-sd._udp.local.", dns.TypePTR), Ptr: "_googlecast._tcp.local."})
	if meta == nil || len(meta.Answer) != 1 || !strings.Contains(meta.Answer[0].String(), "_ipp._tcp") {
		t.Fatal("known enumeration answers must be trimmed to the allowed classes:", meta)
	}
	for _, name := range []string{"_googlecast._tcp.local.", "_smb._tcp.local.", "laptop.local.", "example.com."} {
		if ask(name, dns.TypePTR) != nil || ask(name, dns.TypeA) != nil {
			t.Fatalf("a query for %s left the container network", name)
		}
	}
	// A host is askable only after an allowed service named it.
	if ask("printer.local.", dns.TypeA) != nil {
		t.Fatal("host asked before any allowed browse named it")
	}
	f.Responses(lanAnnouncement())
	if ask("printer.local.", dns.TypeA) == nil {
		t.Fatal("host named by an allowed service cannot be asked")
	}
	// A mixed query is trimmed to its allowed questions; known answers likewise.
	mixed := new(dns.Msg)
	mixed.Question = []dns.Question{{Name: "_ipp._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}, {Name: "_googlecast._tcp.local.", Qtype: dns.TypePTR, Qclass: dns.ClassINET}}
	mixed.Answer = []dns.RR{&dns.PTR{Hdr: hdr("_googlecast._tcp.local.", dns.TypePTR), Ptr: "x._googlecast._tcp.local."}}
	out := f.Queries(mixed)
	if out == nil || len(out.Question) != 1 || len(out.Answer) != 0 {
		t.Fatal(out)
	}
}

// A wildcard rule carries every class, including the enumeration answer — but
// still only the hosts an allowed service named, exactly as a narrower rule does.
func TestWildcardCarriesEveryClass(t *testing.T) {
	f := newFilter([]string{"*"})
	if got := f.Responses(lanAnnouncement()); got == nil {
		t.Fatal("a wildcard rule reflected nothing")
	} else {
		all := strings.ToLower(names(got.Answer) + names(got.Extra))
		for _, want := range []string{"_ipp._tcp", "googlecast", "speaker", "printer"} {
			if !strings.Contains(all, want) {
				t.Fatalf("a wildcard rule dropped %q: %s", want, all)
			}
		}
		if strings.Contains(all, "laptop") {
			t.Fatalf("a wildcard rule carried a host no service named: %s", all)
		}
	}
	q := new(dns.Msg)
	q.SetQuestion("_smb._tcp.local.", dns.TypePTR)
	if f.Queries(q) == nil {
		t.Fatal("a wildcard rule blocked a class")
	}
	if !f.allowedName("x._anything._tcp.local.") {
		t.Fatal("a wildcard rule must allow a class it was never told about")
	}
}

// packedMsg and srcAt drive running.handle the way a socket would.
func packedMsg(t *testing.T, m *dns.Msg) []byte {
	t.Helper()
	b, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func srcAt(ip string) *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: wellknown.PortMDNS}
}

// fixtureRunning builds a running over named interfaces with the given relay
// rules already planned and indexed.
func fixtureRunning(t *testing.T, ifaces map[int]string, rules ...*relaying) *running {
	t.Helper()
	r := &running{a: testAnswerer(), ifaces: map[int]net.Interface{}, advertise: map[int]bool{}, done: make(chan struct{}),
		byFrom: map[int][]*relay{}, byTo: map[int][]*relay{}}
	for idx, name := range ifaces {
		r.ifaces[idx] = net.Interface{Index: idx, Name: name}
	}
	r.relays = planRelays(rules)
	for _, p := range r.relays {
		r.byFrom[p.from] = append(r.byFrom[p.from], p)
		r.byTo[p.to] = append(r.byTo[p.to], p)
	}
	return r
}

func forwarded(r *running) map[int][]*dns.Msg {
	sent := map[int][]*dns.Msg{}
	r.testForward = func(idx int, m *dns.Msg) { sent[idx] = append(sent[idx], m) }
	return sent
}

// A rule is one direction. Exporting a's services to b says nothing about b's to
// a: b's records stay where they are, and a's clients cannot ask for them.
func TestARuleExportsOneDirectionOnly(t *testing.T) {
	r := fixtureRunning(t, map[int]string{1: "vlan-a", 2: "vlan-b"},
		&relaying{cfg: ReflectRule{From: "vlan-a", To: "vlan-b", AllowServices: []string{"_ipp._tcp"}}, from: 1, to: 2})
	sent := forwarded(r)

	r.handle(packedMsg(t, lanAnnouncement()), srcAt("192.0.2.60"), 1, false)
	if len(sent[2]) != 1 || !strings.Contains(strings.ToLower(names(sent[2][0].Answer)), "_ipp._tcp") {
		t.Fatal("vlan-a's records were not exported to vlan-b:", sent)
	}
	if len(sent[1]) != 0 {
		t.Fatal("vlan-a's records were echoed back into vlan-a:", sent)
	}

	// vlan-b's records do not reach vlan-a.
	clear(sent)
	r.handle(packedMsg(t, lanAnnouncement()), srcAt("192.0.2.61"), 2, false)
	if len(sent) != 0 {
		t.Fatal("writing one direction opened the other:", sent)
	}

	// A question on vlan-b reaches vlan-a, whose services are the ones exported.
	q := new(dns.Msg)
	q.SetQuestion("_ipp._tcp.local.", dns.TypePTR)
	clear(sent)
	r.handle(packedMsg(t, q), srcAt("10.20.0.5"), 2, false)
	if len(sent[1]) != 1 || len(sent) != 1 {
		t.Fatal("a question on vlan-b did not reach vlan-a, or reached more:", sent)
	}

	// A question on vlan-a goes nowhere: nothing is exported into it.
	clear(sent)
	r.handle(packedMsg(t, q), srcAt("10.10.0.5"), 1, false)
	if len(sent) != 0 {
		t.Fatal("a question on vlan-a reached a domain that exports nothing:", sent)
	}
}

// planRelays is the reachability closure, with the classes of a path being the
// ones every rule on it allows.
func TestRelayPlanComposesWithTheNarrowerClassSet(t *testing.T) {
	plan := planRelays([]*relaying{
		{cfg: ReflectRule{From: "a", To: "b", AllowServices: []string{"_ipp._tcp"}}, from: 1, to: 2},
		{cfg: ReflectRule{From: "b", To: "c", AllowServices: []string{"_ipp._tcp", "_smb._tcp"}}, from: 2, to: 3},
		{cfg: ReflectRule{From: "c", To: "d", AllowServices: []string{"_smb._tcp"}}, from: 3, to: 4},
	})
	classes := func(f *filter) string {
		if f.all {
			return "*"
		}
		var out []string
		for k := range f.allow {
			out = append(out, k)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	got := map[string]string{}
	for _, p := range plan {
		got[fmt.Sprintf("%d>%d", p.from, p.to)] = classes(p.f)
	}
	want := map[string]string{
		"1>2": "_ipp._tcp",           // the rule itself
		"2>3": "_ipp._tcp,_smb._tcp", // the rule itself
		"3>4": "_smb._tcp",           // the rule itself
		"1>3": "_ipp._tcp",           // a->b->c: only what both allow
		"2>4": "_smb._tcp",           // b->c->d: only what both allow
	}
	for key, carry := range want {
		if got[key] != carry {
			t.Fatalf("%s carries %q, want %q (plan: %v)", key, got[key], carry, got)
		}
	}
	// a->b->c->d carries nothing: _ipp dies at c->d, _smb was never at a.
	if _, ok := got["1>4"]; ok {
		t.Fatalf("a path whose classes all die still carries a pair: %v", got)
	}
	// No direction was opened by composition, and no domain has a pair to itself.
	for _, absent := range []string{"2>1", "3>2", "4>3", "1>1", "2>2", "3>3", "4>4"} {
		if _, ok := got[absent]; ok {
			t.Fatalf("plan invented %s: %v", absent, got)
		}
	}
	if len(plan) != len(want) {
		t.Fatalf("plan has %d pairs, want %d: %v", len(plan), len(want), got)
	}
}

// Two domains exporting to each other are two rules, and the cycle must not
// become a pair that echoes a domain's own records back into it.
func TestAMutualPairDoesNotEchoADomainIntoItself(t *testing.T) {
	r := fixtureRunning(t, map[int]string{1: "a", 2: "b"},
		&relaying{cfg: ReflectRule{From: "a", To: "b", AllowServices: []string{"*"}}, from: 1, to: 2},
		&relaying{cfg: ReflectRule{From: "b", To: "a", AllowServices: []string{"*"}}, from: 2, to: 1})
	if len(r.relays) != 2 {
		t.Fatalf("a mutual pair must stay two pairs, not grow a self-pair: %+v", r.relays)
	}
	sent := forwarded(r)
	r.handle(packedMsg(t, lanAnnouncement()), srcAt("192.0.2.60"), 1, false)
	if len(sent[1]) != 0 {
		t.Fatal("a's own records were echoed back into a through the cycle:", sent)
	}
	if len(sent[2]) != 1 {
		t.Fatal("a's records did not reach b:", sent)
	}
}

// A record's source interface is the domain, not the packet: an interface that
// is only ever a destination reflects nothing.
func TestADestinationOnlyDomainReflectsNothing(t *testing.T) {
	r := fixtureRunning(t, map[int]string{1: "a", 2: "b"},
		&relaying{cfg: ReflectRule{From: "a", To: "b", AllowServices: []string{"*"}}, from: 1, to: 2})
	sent := forwarded(r)
	// A third interface that no rule names is not a domain at all.
	r.ifaces[3] = net.Interface{Index: 3, Name: "unrelated"}
	r.handle(packedMsg(t, lanAnnouncement()), srcAt("192.0.2.70"), 3, false)
	q := new(dns.Msg)
	q.SetQuestion("_ipp._tcp.local.", dns.TypePTR)
	r.handle(packedMsg(t, q), srcAt("192.0.2.71"), 3, false)
	if len(sent) != 0 {
		t.Fatal("an interface no rule names took part in the relay:", sent)
	}
}

func TestReflectConfigValidation(t *testing.T) {
	good := `{"reflect":[{"from":"eth0","to":"podman-print","allow_services":["_ipp._tcp"]},{"from":"podman-music","to":"eth0","allow_services":["_googlecast._tcp"]},{"from":"podman-print","to":"eth2","advertise":{"services":["_ipp._tcp"],"ports":"20000-20099"}}]}`
	c, err := ParseConfig([]byte(good))
	if err != nil || c.Empty() || len(c.Records) != 0 {
		t.Fatal("a pure relay needs no records, host or advertising interfaces:", err)
	}
	// A wildcard rule needs no class list, and both directions of a pair are two
	// independent rules.
	for _, doc := range []string{
		`{"reflect":[{"from":"a","to":"b","allow_services":["*"]}]}`,
		`{"reflect":[{"from":"a","to":"b","allow_services":["*"]},{"from":"b","to":"a","allow_services":["*"]}]}`,
	} {
		if _, err := ParseConfig([]byte(doc)); err != nil {
			t.Fatalf("%s rejected: %v", doc, err)
		}
	}
	for name, doc := range map[string]string{
		"neither":                 `{"reflect":[{"from":"eth0","to":"p"}]}`,
		"both":                    `{"reflect":[{"from":"eth0","to":"p","allow_services":["_ipp._tcp"],"advertise":{"services":["_ipp._tcp"],"ports":"20000-20099"}}]}`,
		"bad service":             `{"reflect":[{"from":"eth0","to":"p","allow_services":["ipp"]}]}`,
		"wildcard beside a class": `{"reflect":[{"from":"eth0","to":"p","allow_services":["*","_ipp._tcp"]}]}`,
		"same interface":          `{"reflect":[{"from":"eth0","to":"eth0","allow_services":["_ipp._tcp"]}]}`,
		"direction twice":         `{"reflect":[{"from":"eth0","to":"p","allow_services":["_ipp._tcp"]},{"from":"eth0","to":"p","allow_services":["_smb._tcp"]}]}`,
		"bad interface name":      `{"reflect":[{"from":"eth 0","to":"p","allow_services":["_ipp._tcp"]}]}`,
		"missing to":              `{"reflect":[{"from":"eth0","allow_services":["_ipp._tcp"]}]}`,
		"one pool disagrees":      `{"reflect":[{"from":"a","to":"eth0","advertise":{"services":["_ipp._tcp"],"ports":"20000-20099"}},{"from":"b","to":"eth0","advertise":{"services":["_ipp._tcp"],"ports":"20100-20199"}}]}`,
	} {
		if _, err := ParseConfig([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Advertising still validates as before when records are present.
	if _, err := ParseConfig([]byte(`{"host":"nas","records":[{"service":"_smb._tcp","instance":"N","port":445}],"reflect":[{"from":"eth0","to":"p","allow_services":["_ipp._tcp"]}]}`)); err == nil {
		t.Fatal("records without interfaces accepted")
	}
}

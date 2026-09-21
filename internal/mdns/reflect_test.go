//go:build mdns

package mdns

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
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

func TestRulesAreIndependentPerNetworkAndDirectional(t *testing.T) {
	r := &running{a: testAnswerer(), ifaces: map[int]net.Interface{}, advertise: map[int]bool{}, done: make(chan struct{})}
	r.rules = []*reflectRule{
		{cfg: ReflectRule{LAN: "lab0", Network: "ctr0"}, f: newFilter([]string{"_ipp._tcp"}), lan: 1, net: 10},
		{cfg: ReflectRule{LAN: "lab0", Network: "ctr1"}, f: newFilter([]string{"_googlecast._tcp"}), lan: 1, net: 11},
	}
	r.ifaces[1], r.ifaces[10], r.ifaces[11] = net.Interface{Index: 1, Name: "lab0"}, net.Interface{Index: 10, Name: "ctr0"}, net.Interface{Index: 11, Name: "ctr1"}
	sent := map[int][]*dns.Msg{}
	r.testForward = func(idx int, m *dns.Msg) { sent[idx] = append(sent[idx], m) }
	pack := func(m *dns.Msg) []byte { b, _ := m.Pack(); return b }
	// The LAN announces: each network receives only its own classes.
	r.handle(pack(lanAnnouncement()), &net.UDPAddr{IP: net.ParseIP("192.0.2.60"), Port: 5353}, 1, false)
	if len(sent[10]) != 1 || !strings.Contains(strings.ToLower(names(sent[10][0].Answer)), "_ipp._tcp") || strings.Contains(strings.ToLower(names(sent[10][0].Answer)+names(sent[10][0].Extra)), "googlecast") {
		t.Fatal("ctr0 saw the wrong records:", sent[10])
	}
	if len(sent[11]) != 1 || !strings.Contains(strings.ToLower(names(sent[11][0].Answer)), "googlecast") || strings.Contains(strings.ToLower(names(sent[11][0].Answer)+names(sent[11][0].Extra)), "ipp") {
		t.Fatal("ctr1 saw the wrong records:", sent[11])
	}
	if len(sent[1]) != 0 {
		t.Fatal("LAN traffic was echoed back to the LAN")
	}
	// A container asks: its query reaches the LAN, trimmed; the other network hears nothing.
	sent = map[int][]*dns.Msg{}
	q := new(dns.Msg)
	q.SetQuestion("_googlecast._tcp.local.", dns.TypePTR)
	r.handle(pack(q), &net.UDPAddr{IP: net.ParseIP("10.90.0.10"), Port: 5353}, 10, false)
	if len(sent) != 0 {
		t.Fatal("ctr0 may not browse googlecast, yet a query left:", sent)
	}
	q.SetQuestion("_ipp._tcp.local.", dns.TypePTR)
	r.handle(pack(q), &net.UDPAddr{IP: net.ParseIP("10.90.0.10"), Port: 5353}, 10, false)
	if len(sent[1]) != 1 || len(sent[11]) != 0 {
		t.Fatal("query not forwarded to the LAN only:", sent)
	}
	// A container's own response is never reflected outward.
	sent = map[int][]*dns.Msg{}
	r.handle(pack(lanAnnouncement()), &net.UDPAddr{IP: net.ParseIP("10.90.0.10"), Port: 5353}, 10, false)
	if len(sent) != 0 {
		t.Fatal("a container's advertisement leaked to the LAN:", sent)
	}
}

func TestReflectConfigValidation(t *testing.T) {
	good := `{"reflect":[{"lan":"eth0","network":"podman-print","allow_services":["_ipp._tcp"]},{"lan":"eth0","network":"podman-music","allow_services":["_googlecast._tcp"]}]}`
	c, err := ParseConfig([]byte(good))
	if err != nil || c.Empty() || len(c.Records) != 0 {
		t.Fatal("a pure reflector needs no records, host or advertising interfaces:", err)
	}
	for name, doc := range map[string]string{
		"no services":        `{"reflect":[{"lan":"eth0","network":"p","allow_services":[]}]}`,
		"bad service":        `{"reflect":[{"lan":"eth0","network":"p","allow_services":["ipp"]}]}`,
		"same interface":     `{"reflect":[{"lan":"eth0","network":"eth0","allow_services":["_ipp._tcp"]}]}`,
		"network twice":      `{"reflect":[{"lan":"eth0","network":"p","allow_services":["_ipp._tcp"]},{"lan":"eth0","network":"p","allow_services":["_smb._tcp"]}]}`,
		"lan is a network":   `{"reflect":[{"lan":"eth0","network":"p","allow_services":["_ipp._tcp"]},{"lan":"p","network":"q","allow_services":["_ipp._tcp"]}]}`,
		"bad interface name": `{"reflect":[{"lan":"eth 0","network":"p","allow_services":["_ipp._tcp"]}]}`,
	} {
		if _, err := ParseConfig([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Advertising still validates as before when records are present.
	if _, err := ParseConfig([]byte(`{"host":"nas","records":[{"service":"_smb._tcp","instance":"N","port":445}],"reflect":[{"lan":"eth0","network":"p","allow_services":["_ipp._tcp"]}]}`)); err == nil {
		t.Fatal("records without interfaces accepted")
	}
}

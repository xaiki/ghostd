package resolver

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestParseACLIsStrict(t *testing.T) {
	good := `{"identities":[{"name":"printing","listen":"100.64.0.20","allow_names":["printers.home.arpa"],"allow_services":["_ipp._tcp"]}]}`
	if _, err := ParseACL([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for name, doc := range map[string]string{
		"wildcard listener": `{"identities":[{"name":"a","listen":"0.0.0.0"}]}`,
		"duplicate name":    `{"identities":[{"name":"a","listen":"100.64.0.2"},{"name":"a","listen":"100.64.0.3"}]}`,
		"shared listener":   `{"identities":[{"name":"a","listen":"100.64.0.2"},{"name":"b","listen":"100.64.0.2"}]}`,
		"bad name":          `{"identities":[{"name":"A b","listen":"100.64.0.2"}]}`,
		"bad service":       `{"identities":[{"name":"a","listen":"100.64.0.2","allow_services":["ipp"]}]}`,
		"unknown field":     `{"identities":[],"default":"allow"}`,
		"trailing":          `{"identities":[]} {}`,
		"empty allow entry": `{"identities":[{"name":"a","listen":"100.64.0.2","allow_names":[""]}]}`,
		"leading dot allow": `{"identities":[{"name":"a","listen":"100.64.0.2","allow_names":[".arpa"]}]}`,
	} {
		if _, err := ParseACL([]byte(doc)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if a, err := ParseACL(nil); err != nil || len(a.Identities) != 0 {
		t.Fatal("an absent ACL means no identities:", a, err)
	}
}

func TestServiceClassExtraction(t *testing.T) {
	for name, want := range map[string]string{
		"_ipp._tcp.local.":                 "_ipp._tcp",
		"Office Printer._ipp._tcp.local.":  "_ipp._tcp",
		"_universal._sub._ipp._tcp.local.": "_ipp._tcp",
		"_services._dns-sd._udp.local.":    "_dns-sd._udp",
		"printer.local.":                   "",
		"_ipp._tcp.example.com.":           "",
	} {
		got, ok := serviceClass(name)
		if got != want || ok != (want != "") {
			t.Errorf("%s: got %q,%v want %q", name, got, ok, want)
		}
	}
}

func TestPolicyDecisions(t *testing.T) {
	now := time.Unix(2000000000, 0)
	p := newPolicy(Identity{Name: "printing", AllowNames: []string{"printers.home.arpa"}, AllowServices: []string{"_ipp._tcp"}})
	p.now = func() time.Time { return now }
	q := func(name string, typ uint16) dns.Question {
		return dns.Question{Name: name, Qtype: typ, Qclass: dns.ClassINET}
	}
	allowed := func(name string, typ uint16) bool { ok, _ := p.Decide(q(name, typ)); return ok }
	if !allowed("_ipp._tcp.local.", dns.TypePTR) || !allowed("Lobby._ipp._tcp.local.", dns.TypeSRV) || !allowed("_universal._sub._ipp._tcp.local.", dns.TypePTR) {
		t.Fatal("permitted service class refused")
	}
	if allowed("_googlecast._tcp.local.", dns.TypePTR) || allowed("_services._dns-sd._udp.local.", dns.TypePTR) {
		t.Fatal("other service classes, or the meta-query enumerating them, allowed")
	}
	if !allowed("q1.printers.home.arpa.", dns.TypeA) || !allowed("printers.home.arpa.", dns.TypeSOA) || allowed("home.arpa.", dns.TypeA) || allowed("example.com.", dns.TypeA) || allowed("evilprinters.home.arpa.", dns.TypeA) {
		t.Fatal("allow_names must match whole labels beneath the name only")
	}
	if allowed("printer.local.", dns.TypeA) {
		t.Fatal("raw .local host allowed without a browse that offered it")
	}
	p.GrantHost("Printer.local.")
	if !allowed("printer.local.", dns.TypeA) {
		t.Fatal("host from an allowed browse not resolvable")
	}
	now = now.Add(3 * time.Minute)
	if allowed("printer.local.", dns.TypeA) {
		t.Fatal("grant did not expire")
	}
	if ok, _ := p.Decide(dns.Question{Name: "printers.home.arpa.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}); ok {
		t.Fatal("non-IN class allowed")
	}
	all := newPolicy(Identity{Name: "open", AllowNames: []string{"*"}})
	if ok, _ := all.Decide(q("example.com.", dns.TypeA)); !ok {
		t.Fatal("* must allow ordinary names")
	}
	if ok, _ := all.Decide(q("printer.local.", dns.TypeA)); ok {
		t.Fatal("* must not open the LAN")
	}
	if ok, _ := newPolicy(Identity{Name: "none"}).Decide(q("example.com.", dns.TypeA)); ok {
		t.Fatal("an identity with no rules must resolve nothing")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Two containers, two resolver addresses, one shared upstream and one shared
// LAN: each may see only its own permissions, and neither can read the other's
// cached or granted answers.
func TestIdentityListenersEnforceAccessBeforeCacheAndLeases(t *testing.T) {
	for _, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		if l, err := net.ListenPacket("udp", ip+":0"); err != nil {
			t.Skipf("loopback alias %s unavailable: %v", ip, err)
		} else {
			l.Close()
		}
	}
	upstreamHits := 0
	packet, _ := net.ListenPacket("udp", "127.0.0.1:0")
	upstream := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		upstreamHits++
		a := new(dns.Msg)
		a.SetReply(r)
		a.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("203.0.113.5")}}
		w.WriteMsg(a)
	})}
	go upstream.ActivateAndServe()
	defer upstream.Shutdown()

	oldBrowse, oldLookup := browseFunc, lookupFunc
	defer func() { browseFunc, lookupFunc = oldBrowse, oldLookup }()
	lan := 0
	browseFunc = func(_ context.Context, name string, qtype uint16) ([]dns.RR, []dns.RR, error) {
		lan++
		hdr := func(n string, t uint16) dns.RR_Header {
			return dns.RR_Header{Name: n, Rrtype: t, Class: dns.ClassINET, Ttl: 30}
		}
		switch qtype {
		case dns.TypePTR:
			return []dns.RR{&dns.PTR{Hdr: hdr(name, dns.TypePTR), Ptr: "Lobby." + name}}, nil, nil
		case dns.TypeSRV:
			return []dns.RR{&dns.SRV{Hdr: hdr(name, dns.TypeSRV), Port: 631, Target: "printer.local."}}, nil, nil
		}
		return nil, nil, nil
	}
	lookupFunc = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("192.0.2.50")}, nil }

	port := freePort(t)
	acl := ACL{Identities: []Identity{
		{Name: "printing", Listen: "127.0.0.2", AllowNames: []string{"printers.example"}, AllowServices: []string{"_ipp._tcp"}},
		{Name: "music", Listen: "127.0.0.3", AllowNames: []string{"printers.example"}, AllowServices: []string{"_googlecast._tcp"}},
	}}
	dir := t.TempDir()
	stop, err := start("127.0.0.1", port, packet.LocalAddr().String(), dir, WithACL(acl))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	ask := func(server, name string, typ uint16, network string) *dns.Msg {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion(name, typ)
		r, _, err := (&dns.Client{Net: network, Timeout: 3 * time.Second}).Exchange(q, net.JoinHostPort(server, fmt.Sprint(port)))
		if err != nil {
			t.Fatalf("%s %s: %v", server, name, err)
		}
		return r
	}
	refused := func(server, name string, typ uint16) bool {
		return ask(server, name, typ, "udp").Rcode == dns.RcodeRefused
	}
	for _, network := range []string{"udp", "tcp"} {
		if ask("127.0.0.2", "_ipp._tcp.local.", dns.TypePTR, network).Rcode != dns.RcodeSuccess {
			t.Fatalf("permitted browse refused over %s", network)
		}
	}
	if !refused("127.0.0.2", "_googlecast._tcp.local.", dns.TypePTR) || !refused("127.0.0.3", "_ipp._tcp.local.", dns.TypePTR) {
		t.Fatal("a service class outside the identity's permission was answered")
	}
	// A host is resolvable only after that identity's own permitted browse named it.
	if !refused("127.0.0.2", "printer.local.", dns.TypeA) {
		t.Fatal("raw .local host resolvable before any browse")
	}
	if r := ask("127.0.0.2", "Lobby._ipp._tcp.local.", dns.TypeSRV, "udp"); len(r.Answer) != 1 {
		t.Fatal(r)
	}
	if r := ask("127.0.0.2", "printer.local.", dns.TypeA, "udp"); len(r.Answer) != 1 {
		t.Fatal("host from an allowed browse not resolvable:", r)
	}
	if !refused("127.0.0.3", "printer.local.", dns.TypeA) {
		t.Fatal("printing's grant leaked to music")
	}
	// Ordinary names: allowed ones forward, everything else is refused before
	// the upstream or any cache is consulted.
	before := upstreamHits
	if !refused("127.0.0.2", "example.com.", dns.TypeA) || !refused("127.0.0.3", "example.com.", dns.TypeA) || upstreamHits != before {
		t.Fatal("a disallowed name reached the upstream")
	}
	if r := ask("127.0.0.2", "x.printers.example.", dns.TypeA, "udp"); len(r.Answer) != 1 {
		t.Fatal(r)
	}
	// Same name asked by the other identity: its own cache, its own decision path.
	if r := ask("127.0.0.3", "x.printers.example.", dns.TypeA, "udp"); len(r.Answer) != 1 {
		t.Fatal(r)
	}
	// The base listener stays unrestricted, and per-identity files are published.
	if r := ask("127.0.0.1", "example.com.", dns.TypeA, "udp"); len(r.Answer) != 1 {
		t.Fatal("base listener restricted:", r)
	}
	for _, f := range []string{"dns-printing.env", "resolv-music.conf"} {
		if raw, err := osReadFile(dir, f); err != nil || !strings.Contains(raw, "127.0.0.") {
			t.Fatal(f, raw, err)
		}
	}
	stop()
	if policyFor("printing") != nil {
		t.Fatal("policies outlive the server")
	}
}

func osReadFile(dir, name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	return string(b), err
}

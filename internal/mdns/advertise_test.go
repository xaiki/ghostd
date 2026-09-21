//go:build mdns

package mdns

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func testAnswerer() answerer {
	cfg := Config{Interfaces: []string{"lab0"}, Host: "nas", Records: []Record{
		{Service: "_smb._tcp", Instance: "NAS", Port: 445},
		{Service: "_adisk._tcp", Instance: "NAS", TXT: []string{"dk0=adVN=Backups,adVF=0x82", "sys=adVF=0x100"}},
		{Service: "_ipp._tcp", Instance: "Office Printer", Port: 631, TXT: []string{"rp=ipp/print"}, Subtypes: []string{"_universal"}},
	}}
	return answerer{cfg: cfg, addrs: func(string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("fd00::10")}, nil
	}}
}

func ask(a answerer, name string, typ uint16, known ...dns.RR) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion(name, typ)
	q.Answer = known
	return a.Answer(q, "lab0")
}

func TestBrowseReturnsInstanceWithItsRecords(t *testing.T) {
	a := testAnswerer()
	r := ask(a, "_ipp._tcp.local.", dns.TypePTR)
	if r == nil || len(r.Answer) != 1 || r.Answer[0].(*dns.PTR).Ptr != "Office Printer._ipp._tcp.local." {
		t.Fatal(r)
	}
	kinds := map[uint16]int{}
	for _, rr := range r.Extra {
		kinds[rr.Header().Rrtype]++
	}
	if kinds[dns.TypeSRV] != 1 || kinds[dns.TypeTXT] != 1 || kinds[dns.TypeA] != 1 || kinds[dns.TypeAAAA] != 1 {
		t.Fatal("a browse answer must be self-contained:", kinds)
	}
	if r.Answer[0].Header().Class&0x8000 != 0 {
		t.Fatal("shared PTR must not carry the cache-flush bit")
	}
	if srv := r.Extra[0].(*dns.SRV); srv.Port != 631 || srv.Target != "nas.local." || srv.Hdr.Class&0x8000 == 0 {
		t.Fatal(srv)
	}
}

func TestSubtypeMetaQueryInstanceAndHost(t *testing.T) {
	a := testAnswerer()
	if r := ask(a, "_universal._sub._ipp._tcp.local.", dns.TypePTR); r == nil || len(r.Answer) != 1 {
		t.Fatal("subtype browse:", r)
	}
	if r := ask(a, "_smb._tcp.local.", dns.TypePTR); r == nil || ask(a, "_universal._sub._smb._tcp.local.", dns.TypePTR) != nil {
		t.Fatal("a subtype only its own service declares")
	}
	meta := ask(a, "_services._dns-sd._udp.local.", dns.TypePTR)
	if meta == nil || len(meta.Answer) != 3 {
		t.Fatal("service enumeration:", meta)
	}
	if r := ask(a, "Office Printer._ipp._tcp.local.", dns.TypeSRV); r == nil || len(r.Answer) != 1 {
		t.Fatal(r)
	}
	if r := ask(a, "office printer._ipp._tcp.local.", dns.TypeTXT); r == nil || r.Answer[0].(*dns.TXT).Txt[0] != "rp=ipp/print" {
		t.Fatal("instance names match case-insensitively:", r)
	}
	if r := ask(a, "nas.local.", dns.TypeA); r == nil || r.Answer[0].(*dns.A).A.String() != "192.0.2.10" {
		t.Fatal(r)
	}
	if r := ask(a, "NAS.local.", dns.TypeAAAA); r == nil || len(r.Answer) != 1 {
		t.Fatal(r)
	}
	if r := ask(a, "nas.local.", dns.TypeANY); r == nil || len(r.Answer) != 2 {
		t.Fatal("ANY for the host", r)
	}
}

func TestSilenceAboutStrangersAndKnownAnswerSuppression(t *testing.T) {
	a := testAnswerer()
	for _, name := range []string{"_googlecast._tcp.local.", "other.local.", "Office Printer._smb._tcp.local.", "example.com."} {
		if ask(a, name, dns.TypePTR) != nil || ask(a, name, dns.TypeA) != nil {
			t.Fatalf("answered for a name it does not own: %s", name)
		}
	}
	known := &dns.PTR{Hdr: dns.RR_Header{Name: "_ipp._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 4000}, Ptr: "Office Printer._ipp._tcp.local."}
	if ask(a, "_ipp._tcp.local.", dns.TypePTR, known) != nil {
		t.Fatal("re-sent a record the asker already holds with enough life left")
	}
	known.Hdr.Ttl = 100 // about to expire: worth refreshing
	if ask(a, "_ipp._tcp.local.", dns.TypePTR, known) == nil {
		t.Fatal("suppressed a nearly expired known answer")
	}
	resp := new(dns.Msg)
	resp.Response = true
	if a.Answer(resp, "lab0") != nil {
		t.Fatal("answered a response")
	}
}

func TestAnnouncementAndGoodbye(t *testing.T) {
	a := testAnswerer()
	all := a.all("lab0", ttlService)
	kinds := map[uint16]int{}
	for _, rr := range all {
		kinds[rr.Header().Rrtype]++
	}
	// 3 service PTR + 1 subtype PTR + 3 meta PTR; 3 SRV; 3 TXT; A and AAAA.
	if kinds[dns.TypePTR] != 7 || kinds[dns.TypeSRV] != 3 || kinds[dns.TypeTXT] != 3 || kinds[dns.TypeA] != 1 || kinds[dns.TypeAAAA] != 1 {
		t.Fatal(kinds)
	}
	for _, rr := range a.all("lab0", 0) {
		if rr.Header().Ttl != 0 {
			t.Fatal("goodbye records must have TTL 0:", rr)
		}
	}
}

func TestProbingDetectsAnotherHostOwningAName(t *testing.T) {
	a := testAnswerer()
	other := new(dns.Msg)
	other.Response = true
	other.Answer = []dns.RR{&dns.SRV{Hdr: dns.RR_Header{Name: "other._smb._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}}}
	if c := a.conflicts(other); c != "" {
		t.Fatal("unrelated instance flagged:", c)
	}
	other.Answer = []dns.RR{&dns.SRV{Hdr: dns.RR_Header{Name: "Office Printer._ipp._tcp.local.", Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}}}
	if c := a.conflicts(other); !strings.Contains(c, "Office Printer") {
		t.Fatal("conflicting instance missed:", c)
	}
	other.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "NAS.local.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 120}}}
	if a.conflicts(other) == "" {
		t.Fatal("host name conflict missed")
	}
	q := new(dns.Msg)
	q.SetQuestion("nas.local.", dns.TypeA)
	if a.conflicts(q) != "" {
		t.Fatal("a query is not a claim")
	}
}

func TestConfigValidation(t *testing.T) {
	good := `{"interfaces":["eth0"],"host":"nas","records":[{"service":"_smb._tcp","instance":"NAS","port":445}]}`
	if _, err := ParseConfig([]byte(good)); err != nil {
		t.Fatal(err)
	}
	if c, err := ParseConfig(nil); err != nil || !c.Empty() {
		t.Fatal("empty config is valid and advertises nothing", err)
	}
	for name, doc := range map[string]string{
		"no interfaces":   `{"host":"nas","records":[{"service":"_smb._tcp","instance":"N","port":445}]}`,
		"bad host":        `{"interfaces":["eth0"],"host":"Nas.local","records":[{"service":"_smb._tcp","instance":"N","port":445}]}`,
		"bad service":     `{"interfaces":["eth0"],"host":"nas","records":[{"service":"smb","instance":"N","port":445}]}`,
		"dotted instance": `{"interfaces":["eth0"],"host":"nas","records":[{"service":"_smb._tcp","instance":"a.b","port":445}]}`,
		"no port":         `{"interfaces":["eth0"],"host":"nas","records":[{"service":"_smb._tcp","instance":"N"}]}`,
		"duplicate":       `{"interfaces":["eth0"],"host":"nas","records":[{"service":"_smb._tcp","instance":"N","port":445},{"service":"_smb._tcp","instance":"n","port":445}]}`,
		"huge txt":        `{"interfaces":["eth0"],"host":"nas","records":[{"service":"_smb._tcp","instance":"N","port":445,"txt":["` + strings.Repeat("x", 300) + `"]}]}`,
		"bad subtype":     `{"interfaces":["eth0"],"host":"nas","records":[{"service":"_ipp._tcp","instance":"N","port":631,"subtypes":["universal"]}]}`,
		"unknown field":   `{"interfaces":["eth0"],"host":"nas","records":[],"extra":1}` + ` `,
	} {
		if _, err := ParseConfig([]byte(doc)); err == nil && name != "unknown field" {
			t.Errorf("%s accepted", name)
		} else if name == "unknown field" && err == nil {
			t.Error("unknown field accepted")
		}
	}
	// _adisk conventionally has port 0.
	if _, err := ParseConfig([]byte(`{"interfaces":["eth0"],"host":"nas","records":[{"service":"_adisk._tcp","instance":"N"}]}`)); err != nil {
		t.Fatal(err)
	}
}

// A plain resolver (dig, a stub) that asks from a port other than 5353 must get
// records it will accept: class IN, short TTL. handle() is the seam.
func TestLegacyUnicastAnswersDropCacheFlushAndCapTTL(t *testing.T) {
	a := testAnswerer()
	q := new(dns.Msg)
	q.SetQuestion("nas.local.", dns.TypeA)
	resp := a.Answer(q, "lab0")
	if resp.Answer[0].Header().Class&0x8000 == 0 {
		t.Fatal("multicast answers keep the cache-flush bit")
	}
	r := &running{a: a, ifaces: map[int]net.Interface{1: {Index: 1, Name: "lab0"}}, done: make(chan struct{})}
	var sent *dns.Msg
	r.testSend = func(m *dns.Msg) { sent = m }
	wire, _ := q.Pack()
	r.handle(wire, &net.UDPAddr{IP: net.ParseIP("192.0.2.77"), Port: 40000}, 1, false)
	if sent == nil || sent.Id != q.Id || len(sent.Question) != 1 {
		t.Fatal("reply must echo the question and id:", sent)
	}
	if h := sent.Answer[0].Header(); h.Class != dns.ClassINET || h.Ttl > 10 {
		t.Fatalf("legacy unicast answer not resolver-safe: %+v", h)
	}
}

// miekg presents a space in a label as \032; an instance name with a space must
// still match, be answered directly, and be recognised as a conflict.
func TestEscapedLabelsMatchRawInstanceNames(t *testing.T) {
	a := testAnswerer()
	if r := ask(a, `Office\032Printer._ipp._tcp.local.`, dns.TypeSRV); r == nil || len(r.Answer) != 1 {
		t.Fatal("direct SRV query with an escaped space:", r)
	}
	other := new(dns.Msg)
	other.Response = true
	other.Answer = []dns.RR{&dns.SRV{Hdr: dns.RR_Header{Name: `Office\032Printer._ipp._tcp.local.`, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 120}}}
	if a.conflicts(other) == "" {
		t.Fatal("conflict on an instance name with a space missed")
	}
	known := &dns.PTR{Hdr: dns.RR_Header{Name: "_ipp._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 4000}, Ptr: `Office\032Printer._ipp._tcp.local.`}
	if ask(a, "_ipp._tcp.local.", dns.TypePTR, known) != nil {
		t.Fatal("known-answer suppression missed an escaped name")
	}
	if norm(`a\.b\\c\065`) != `a.b\c`+"a" {
		t.Fatal(norm(`a\.b\\c\065`))
	}
}

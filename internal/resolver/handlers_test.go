//go:build coredns

package resolver

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func TestACLHandlerRefusesBeforeTheNextPluginAndTagsTheIdentity(t *testing.T) {
	setPolicies(ACL{Identities: []Identity{{Name: "printing", Listen: "100.64.0.21", AllowNames: []string{"printers.example"}, AllowServices: []string{"_ipp._tcp"}}}})
	defer clearPolicies()
	var sawIdentity *Policy
	reached := 0
	next := plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		reached++
		sawIdentity = identityOf(ctx)
		return dns.RcodeSuccess, nil
	})
	h := &aclHandler{name: "printing", next: next}
	ask := func(name string, typ uint16) (int, *dns.Msg) {
		q := new(dns.Msg)
		q.SetQuestion(name, typ)
		w := dnstest.NewRecorder(&test.ResponseWriter{})
		code, err := h.ServeDNS(context.Background(), w, q)
		if err != nil {
			t.Fatal(err)
		}
		return code, w.Msg
	}
	if code, msg := ask("x.printers.example.", dns.TypeA); code != dns.RcodeSuccess || reached != 1 || sawIdentity == nil || sawIdentity.id.Name != "printing" {
		t.Fatal("an allowed name must reach the next plugin carrying its identity:", code, reached, sawIdentity, msg)
	}
	if code, msg := ask("example.com.", dns.TypeA); code != dns.RcodeRefused || reached != 1 || msg == nil || msg.Rcode != dns.RcodeRefused {
		t.Fatal("a disallowed name must be refused, on the wire, before the next plugin:", code, reached, msg)
	}
	multi := new(dns.Msg)
	multi.Question = []dns.Question{{Name: "a.printers.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, {Name: "b.printers.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	if code, _ := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), multi); code != dns.RcodeRefused {
		t.Fatal("a multi-question query is refused, not partially served")
	}
	// A listener whose policy is gone refuses everything, never falling open.
	clearPolicies()
	if code, _ := ask("x.printers.example.", dns.TypeA); code != dns.RcodeRefused || reached != 1 {
		t.Fatal("a missing policy must refuse:", code, reached)
	}
	if identityOf(context.Background()) != nil || policyFor("nobody") != nil {
		t.Fatal("no identity without a listener")
	}
}

type fakeLAN struct {
	ips        []net.IP
	lookupErr  error
	answers    []dns.RR
	browseErr  error
	lookups    int
	browseSeen string
}

func (f *fakeLAN) Lookup(context.Context, string) ([]net.IP, error) {
	f.lookups++
	return f.ips, f.lookupErr
}
func (f *fakeLAN) Browse(_ context.Context, name string, _ uint16) ([]dns.RR, []dns.RR, error) {
	f.browseSeen = name
	return f.answers, nil, f.browseErr
}

func TestLANClientIsPreferredForLocalAndBrowseFailsCleanlyWithoutOne(t *testing.T) {
	saved := lanClient.Load()
	defer lanClient.Store(saved)
	lanClient.Store(nil)
	if _, _, err := browseLocal(context.Background(), "_ipp._tcp.local.", dns.TypePTR); !errors.Is(err, errNoLAN) {
		t.Fatal("browsing with no LAN client must say so:", err)
	}
	// Through the handler, that is NOTIMP, not a server failure or a hang.
	h := &localHandler{slots: make(chan struct{}, 1), lookup: lookupLocal, browse: browseLocal}
	q := new(dns.Msg)
	q.SetQuestion("_ipp._tcp.local.", dns.TypePTR)
	if code, _ := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), q); code != dns.RcodeNotImplemented {
		t.Fatal("DNS-SD without a LAN client is not implemented:", code)
	}
	fake := &fakeLAN{ips: []net.IP{net.ParseIP("192.0.2.9")}}
	lanClient.Store(&lanBox{fake})
	ips, err := lookupLocal(context.Background(), "printer.local")
	if err != nil || len(ips) != 1 || fake.lookups != 1 {
		t.Fatal("the LAN client answers .local lookups:", ips, err)
	}
	fake.answers = []dns.RR{&dns.PTR{Hdr: dns.RR_Header{Name: "_ipp._tcp.local.", Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: 30}, Ptr: "O._ipp._tcp.local."}}
	w := dnstest.NewRecorder(&test.ResponseWriter{})
	if code, err := h.ServeDNS(context.Background(), w, q); err != nil || code != dns.RcodeSuccess || len(w.Msg.Answer) != 1 || fake.browseSeen != "_ipp._tcp.local." {
		t.Fatal(code, err, w.Msg)
	}
	// A browse that finds nothing is an authoritative-looking NXDOMAIN, and a failing
	// client is a server failure.
	fake.answers = nil
	w = dnstest.NewRecorder(&test.ResponseWriter{})
	h.ServeDNS(context.Background(), w, q)
	if w.Msg == nil || w.Msg.Rcode != dns.RcodeNameError {
		t.Fatal("nothing found:", w.Msg)
	}
	fake.browseErr = errors.New("boom")
	if code, err := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), q); code != dns.RcodeServerFailure || err == nil {
		t.Fatal(code, err)
	}
}

func TestLocalHandlerRefusesMalformedAndNonINETQueries(t *testing.T) {
	h := &localHandler{slots: make(chan struct{}, 1), lookup: func(context.Context, string) ([]net.IP, error) { return nil, nil }}
	empty := new(dns.Msg)
	if code, _ := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), empty); code != dns.RcodeFormatError {
		t.Fatal(code)
	}
	q := &dns.Msg{Question: []dns.Question{{Name: "x.local.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}}}
	if code, _ := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), q); code != dns.RcodeRefused {
		t.Fatal(code)
	}
	q.Question[0].Qclass, q.Question[0].Qtype = dns.ClassINET, dns.TypeMX
	if code, _ := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), q); code != dns.RcodeNotImplemented {
		t.Fatal(code)
	}
	// Concurrency is bounded: with every slot taken, the answer is a failure, not a queue.
	h.slots <- struct{}{}
	q.Question[0].Qtype = dns.TypeA
	if code, _ := h.ServeDNS(context.Background(), dnstest.NewRecorder(&test.ResponseWriter{}), q); code != dns.RcodeServerFailure {
		t.Fatal("a saturated resolver must shed load:", code)
	}
}

func TestStartRejectsBadConfigurationBeforeBinding(t *testing.T) {
	dir := t.TempDir()
	if _, err := start("not-an-ip", 1, "127.0.0.1:1", dir); err == nil {
		t.Fatal("a bad bind address was accepted")
	}
	if _, err := start("127.0.0.1", 1, "127.0.0.1:1", dir, WithACL(ACL{Identities: []Identity{{Name: "a", Listen: "0.0.0.0"}}})); err == nil {
		t.Fatal("a wildcard identity listener was accepted")
	}
	if _, err := start("127.0.0.1", 1, "127.0.0.1:1", dir, WithACL(ACL{Identities: []Identity{{Name: "a", Listen: "127.0.0.1"}}})); err == nil {
		t.Fatal("an identity on the base resolver address was accepted")
	}
	if policyFor("a") != nil {
		t.Fatal("a rejected start left policies behind")
	}
}

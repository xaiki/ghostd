//go:build coredns

package resolver

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/xaiki/ghostd/internal/wellknown"
)

func TestPluginCorefileForwardsToThePublicFallbackWithFailover(t *testing.T) {
	text := pluginCorefile(53, "100.64.0.1", wellknown.Quad100)
	if !strings.Contains(text, "forward . 100.100.100.100 1.1.1.1 8.8.8.8 {") {
		t.Fatalf("primary and public fallbacks not all in one forward line: %s", text)
	}
	if !strings.Contains(text, "policy sequential") {
		t.Fatalf("missing policy sequential (quad-100 must stay authoritative first): %s", text)
	}
	if !strings.Contains(text, "failover SERVFAIL REFUSED") {
		t.Fatalf("missing failover — a SERVFAIL from the primary would never reach the fallback: %s", text)
	}
	if !strings.Contains(text, "servfail 5s") {
		t.Fatalf("missing explicit servfail cache window: %s", text)
	}
}

func TestPluginCorefileRepeatsTheForwardChainPerIdentity(t *testing.T) {
	text := pluginCorefile(53, "100.64.0.1", wellknown.Quad100, Identity{Name: "guest", Listen: "100.64.0.2"})
	if strings.Count(text, "failover SERVFAIL REFUSED") != 2 {
		t.Fatalf("every server block (base + each ACL identity) needs its own forward chain: %s", text)
	}
}

// fakeUpstream answers every query with `rcode`, unless answer is set, in which
// case it answers that instead — the SERVFAIL-then-success shape this fix exists for.
func fakeUpstream(t *testing.T, rcode int, answer net.IP) string {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		if answer != nil {
			reply.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   answer,
			}}
		} else {
			reply.Rcode = rcode
		}
		_ = w.WriteMsg(reply)
	})}
	go server.ActivateAndServe()
	t.Cleanup(func() { server.Shutdown() })
	return packet.LocalAddr().String()
}

func TestForwardFailsOverFromServfailToThePublicFallback(t *testing.T) {
	// The exact incident this fix is for: the primary (quad-100 in production)
	// answers every query, but SERVFAILs anything outside its own zone — which
	// a bare `forward . <upstream>` (the code before this change) never moved
	// past, because CoreDNS's forward plugin only tries the next upstream on
	// NO response by default, not on a definite SERVFAIL (confirmed against
	// its own source and docs). policy sequential + failover SERVFAIL is what
	// makes it actually retry the fallback instead of returning quad-100's own
	// answer to the client.
	primary := fakeUpstream(t, dns.RcodeServerFailure, nil)
	fallback := fakeUpstream(t, dns.RcodeSuccess, net.ParseIP("192.0.2.55"))

	restore := publicFallbackResolvers
	publicFallbackResolvers = []string{fallback}
	t.Cleanup(func() { publicFallbackResolvers = restore })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	directory := t.TempDir()
	stop, err := start("127.0.0.1", port, primary, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	client := &dns.Client{Net: "udp"}
	query := new(dns.Msg)
	query.SetQuestion("acme-v02.api.letsencrypt.org.", dns.TypeA)
	reply, _, err := client.Exchange(query, fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	if reply.Rcode != dns.RcodeSuccess {
		t.Fatalf("still SERVFAILing after the primary refused — fallback never reached: %v", reply)
	}
	if len(reply.Answer) != 1 || reply.Answer[0].(*dns.A).A.String() != "192.0.2.55" {
		t.Fatalf("answer did not come from the fallback resolver: %v", reply)
	}
}

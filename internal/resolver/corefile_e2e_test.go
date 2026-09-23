//go:build coredns

package resolver

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// corefile_e2e_test.go boots the generated Corefile through CoreDNS and asks it
// real questions in the two RCODE cases plugins_test.go's failover test does not
// cover: the other code in the failover list, and the negative that must survive
// it untouched.

// ask resolves one name against the base listener of a started resolver.
func ask(t *testing.T, port int, name string) *dns.Msg {
	t.Helper()
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)
	client := &dns.Client{Timeout: 5 * time.Second}
	reply, _, err := client.Exchange(msg, fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	return reply
}

// REFUSED is in the failover list too, and it is what a tailnet resolver gives
// when it declines a zone rather than failing to answer it.
func TestGeneratedCorefileFailsOverOnRefusedToo(t *testing.T) {
	refused := fakeUpstream(t, dns.RcodeRefused, nil)
	answering := fakeUpstream(t, dns.RcodeSuccess, net.ParseIP("192.0.2.55"))
	saved := publicFallbackResolvers
	publicFallbackResolvers = []string{answering}
	defer func() { publicFallbackResolvers = saved }()

	port := freePort(t)
	stop, err := start("127.0.0.1", port, refused, t.TempDir())
	if err != nil {
		t.Fatalf("the generated Corefile did not load: %v", err)
	}
	defer stop()

	reply := ask(t, port, "example.com.")
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) == 0 {
		t.Fatalf("a REFUSED from the primary upstream did not fail over: %v", reply)
	}
}

// A name the primary answers NXDOMAIN for is answered, not failed: failover
// must not hand a definite negative to a public resolver's opinion. This is the
// boundary of the fix — an upstream that denies a name rather than erroring
// keeps that answer, so a primary that NXDOMAINs public names is never escaped
// by failover at all.
func TestGeneratedCorefileKeepsADefiniteNegative(t *testing.T) {
	nxdomain := fakeUpstream(t, dns.RcodeNameError, nil)
	answering := fakeUpstream(t, dns.RcodeSuccess, net.ParseIP("192.0.2.55"))
	saved := publicFallbackResolvers
	publicFallbackResolvers = []string{answering}
	defer func() { publicFallbackResolvers = saved }()

	port := freePort(t)
	stop, err := start("127.0.0.1", port, nxdomain, t.TempDir())
	if err != nil {
		t.Fatalf("the generated Corefile did not load: %v", err)
	}
	defer stop()

	reply := ask(t, port, "does-not-exist.example.com.")
	if reply.Rcode != dns.RcodeNameError {
		t.Fatalf("a NXDOMAIN from the primary upstream was replaced by the fallback: %v", reply)
	}
}

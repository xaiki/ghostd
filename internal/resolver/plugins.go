//go:build coredns

package resolver

import (
	"fmt"
	"strings"

	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/forward"

	"github.com/xaiki/ghostd/internal/wellknown"
)

func init() {
	// Build-time plugin assembly, like CoreDNS's generated plugin list. Add
	// imports and directives here, then configure them in the generated Corefile.
	// Never import coremain: ghostd owns process flags, signals and listeners.
	// Lease answers precede cache so release/expiry is visible immediately.
	// Future access-control plugins must also precede cache and ghostleases.
	dnsserver.Directives = []string{"bind", "ghostacl", "cache", "ghostlocal", "forward"}
}

// pluginCorefile is the configuration counterpart to the compiled plugin list.
// The base listener is unrestricted; every ACL identity gets its own server
// block, hence its own cache, behind an access check that precedes both lease
// answers and cache.
// leaseDirective is " ghostleases\n" when the dhcp feature is built in (it also
// inserts the plugin into dnsserver.Directives), and empty otherwise.
var leaseDirective string

// publicFallbackResolvers sit behind upstream (Quad100, tailscaled's own
// resolver, in production) in the forward chain — see pluginCorefile for why a
// bare `forward . <upstream>` was not enough. Package vars, not a Start/Option
// parameter: nothing about them is per-deployment, unlike the ACL identities or
// the bind address.
var publicFallbackResolvers = []string{wellknown.CloudflareResolver, wellknown.GoogleResolver}

func pluginCorefile(port int, address, upstream string, identities ...Identity) string {
	// A tailnet serving MagicDNS only (accept-dns off, or no global nameserver
	// configured) answers SERVFAIL for everything outside its own zone, and a
	// bare `forward . %s` has no fallback of its own for that: CoreDNS's forward
	// plugin advances to the next target only when an upstream gives no response
	// at all, never when it answers with a definite error. Nor does a public
	// resolver listed after ghostd at the container's own --dns= help, because
	// aardvark-dns, too, advances only past silence and never past a SERVFAIL
	// (confirmed against its forwarding source). This hop is the one built to
	// retry a definite error: `policy sequential` keeps Quad100 authoritative
	// for MagicDNS first, and `failover` is what CoreDNS's own forward plugin
	// calls "try the next upstream on this RCODE, not just on a timeout" — the
	// retry a plain multi-target forward line does not do by default.
	targets := strings.Join(append([]string{upstream}, publicFallbackResolvers...), " ")
	block := func(bind, acl string) string {
		return fmt.Sprintf(".:%d {\n bind %s\n%s%s cache 30 {\n servfail 5s\n }\n ghostlocal\n forward . %s {\n max_concurrent 128\n policy sequential\n failover SERVFAIL REFUSED\n }\n}\n",
			port, bind, acl, leaseDirective, targets)
	}
	out := block(address, "")
	for _, id := range identities {
		out += block(id.Listen, " ghostacl "+id.Name+"\n")
	}
	return out
}

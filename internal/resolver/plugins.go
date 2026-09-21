package resolver

import (
	"fmt"
	"github.com/coredns/coredns/core/dnsserver"
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/forward"
)

func init() {
	// Build-time plugin assembly, like CoreDNS's generated plugin list. Add
	// imports and directives here, then configure them in the generated Corefile.
	// Never import coremain: ghostd owns process flags, signals and listeners.
	// Lease answers precede cache so release/expiry is visible immediately.
	// Future access-control plugins must also precede cache and ghostleases.
	dnsserver.Directives = []string{"bind", "ghostacl", "ghostleases", "cache", "ghostlocal", "forward"}
}

// pluginCorefile is the configuration counterpart to the compiled plugin list.
// The base listener is unrestricted; every ACL identity gets its own server
// block, hence its own cache, behind an access check that precedes both lease
// answers and cache.
func pluginCorefile(port int, address, upstream string, identities ...Identity) string {
	block := func(bind, acl string) string {
		return fmt.Sprintf(".:%d {\n bind %s\n%s ghostleases\n cache 30\n ghostlocal\n forward . %s {\n max_concurrent 128\n }\n}\n", port, bind, acl, upstream)
	}
	out := block(address, "")
	for _, id := range identities {
		out += block(id.Listen, " ghostacl "+id.Name+"\n")
	}
	return out
}

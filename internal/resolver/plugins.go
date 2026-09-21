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
	dnsserver.Directives = []string{"bind", "ghostleases", "cache", "ghostlocal", "forward"}
}

// pluginCorefile is the configuration counterpart to the compiled plugin list.
func pluginCorefile(port int, address, upstream string) string {
	return fmt.Sprintf(".:%d {\n bind %s\n ghostleases\n cache 30\n ghostlocal\n forward . %s {\n max_concurrent 128\n }\n}\n", port, address, upstream)
}

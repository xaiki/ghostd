//go:build coredns && mdns

package main

import (
	"github.com/xaiki/ghostd/internal/mdns"
	"github.com/xaiki/ghostd/internal/resolver"
)

// With both features, the container resolver answers .local and DNS-SD from the
// LAN natively, with no mDNS daemon on the host.
func init() {
	resolverOptions = append(resolverOptions, func() resolver.Option {
		return resolver.WithLAN(mdns.NewLAN(&mdns.Querier{Interfaces: mdnsIfaces}))
	})
}

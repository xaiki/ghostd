//go:build coredns

package main

import (
	"fmt"
	"log"

	"github.com/xaiki/ghostd/internal/resolver"
)

// resolverOptions lets other features (mdns) add to the container resolver.
var resolverOptions []func() resolver.Option

func init() {
	register(feature{
		name: "coredns",
		// The container resolver needs the tailnet address, so it starts once
		// the RPC listener's address is known. It never binds a wildcard.
		serve: func(env *featureEnv) (func(), error) {
			aclRaw, err := env.store.Load(resolver.ACLFile)
			if err != nil {
				return nil, err
			}
			acl, err := resolver.ParseACL(aclRaw)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", resolver.ACLFile, err)
			}
			opts := []resolver.Option{resolver.WithACL(acl)}
			for _, o := range resolverOptions {
				opts = append(opts, o())
			}
			stop, err := resolver.Start(env.dnsAddress, runtimeDirectory, opts...)
			if err != nil {
				return nil, fmt.Errorf("start container DNS: %w", err)
			}
			if len(acl.Identities) > 0 {
				log.Printf("ghostd: DNS ACL: %d identities, each on its own listener", len(acl.Identities))
			}
			log.Printf("ghostd: container DNS listening on %s:53 (tailnet-only)", env.dnsAddress)
			return stop, nil
		},
	})
}

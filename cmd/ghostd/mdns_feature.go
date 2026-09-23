//go:build mdns

package main

import (
	"context"
	"flag"
	"log"
	"reflect"
	"strings"
	"time"

	"github.com/xaiki/ghostd/internal/mdns"
	"github.com/xaiki/ghostd/internal/state"
)

// mdnsIfaces is set from --mdns-interfaces before the daemon starts.
var mdnsIfaces []string

var mdnsInterfacesFlag *string

func init() {
	registerDomainHook(domainHook{name: "mdns-v2", key: mdns.ConfigFile, restore: restoreMDNSConfig})
	register(feature{
		name: "mdns",
		flags: func() {
			mdnsInterfacesFlag = flag.String("mdns-interfaces", "", "comma-separated LAN interfaces the native mDNS client queries and the mdns-v2 advertisement uses (default: every up multicast interface for queries)")
		},
		cli: func() bool {
			for _, name := range strings.Split(*mdnsInterfacesFlag, ",") {
				if name = strings.TrimSpace(name); name != "" {
					mdnsIfaces = append(mdnsIfaces, name)
				}
			}
			return false
		},
		attach: func(env *featureEnv) (func(), error) {
			if env.observeOnly {
				return nil, nil
			}
			advertiser := mdns.NewService()
			env.server.MDNS = advertiser
			go watchMDNS(env.ctx, env.store, advertiser)
			return advertiser.Close, nil
		},
	})
}

// restoreMDNSConfig makes the persisted advertisement match a confirmed or
// snapshot state; the watcher below brings the running service to it.
func restoreMDNSConfig(store *state.Store, raw []byte) error {
	if _, err := mdns.ParseConfig(raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	return store.Save(mdns.ConfigFile, raw)
}

// watchMDNS converges the running advertisement on the persisted one: at boot,
// after a rollback, and after a failed start (a port that was busy, an
// interface that was not up yet). A start that fails is retried, never fatal.
func watchMDNS(ctx context.Context, store *state.Store, svc *mdns.Service) {
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()
	for {
		if unlock, err := store.Lock(); err == nil {
			raw, lerr := store.Load(mdns.ConfigFile)
			if lerr == nil {
				if want, perr := mdns.ParseConfig(raw); perr != nil {
					log.Printf("ghostd: %s: %v", mdns.ConfigFile, perr)
				} else if !reflect.DeepEqual(want, svc.Config()) {
					if err := svc.Apply(want); err != nil {
						log.Printf("ghostd: mDNS advertisement not running: %v", err)
					}
				}
			}
			unlock()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

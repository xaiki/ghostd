//go:build dhcp

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/xaiki/ghostd/internal/overlay"
	"github.com/xaiki/ghostd/internal/replica"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/resolver"
	"github.com/xaiki/ghostd/internal/state"
)

func restoreDHCPConfig(store *state.Store, raw []byte) error {
	if _, err := addressbook.ParseConfig(raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		raw = []byte(`{"scopes":[]}`)
	}
	return store.Save(addressbook.ConfigFile, raw)
}

// standbyMode is set from --follow before the daemon starts.
var standbyMode bool

// handoverRecovery rolls back an interrupted, or (force) any unconfirmed,
// takeover from a legacy allocator; it is set by the dnsmasq feature and nil
// otherwise. rolledBack reports that the journal ended in "rolled-back". The
// caller holds the store lock.
var handoverRecovery func(store *state.Store, manager *addressbook.Manager, force bool) (rolledBack bool, err error)

func recoverHandover(store *state.Store, manager *addressbook.Manager, force bool) (bool, error) {
	if handoverRecovery == nil {
		return false, nil
	}
	return handoverRecovery(store, manager, force)
}

func startAddressbook(store *state.Store, observeOnly bool) (*addressbook.Manager, func(), error) {
	db, err := addressbook.Open(filepath.Join(store.Dir(), "addressbook.db"))
	if err != nil {
		return nil, nil, err
	}
	manager := addressbook.NewManager(db)
	manager.Forward = resolver.Forward
	raw, err := store.Load(addressbook.ConfigFile)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	config, err := addressbook.ParseConfig(raw)
	if err != nil {
		db.Close()
		return nil, nil, err
	}
	if observeOnly {
		config = addressbook.Config{}
	}
	if standbyMode {
		// A warm standby keeps its configuration but serves nothing until promoted.
		manager.SetStandby(true)
		config = addressbook.Disabled(config)
	}
	// An interrupted or expired takeover is rolled back before anything binds,
	// and a pending one whose target cannot start is rolled back rather than
	// stranding the host with neither allocator running. Both paths only need
	// the disabled configuration, so they work when the target cannot bind.
	if !observeOnly {
		unlock, lockErr := store.Lock()
		if lockErr != nil {
			db.Close()
			return nil, nil, lockErr
		}
		// A failing rollback stays journaled and is retried by the watcher below;
		// it must not keep the RPC surface (the operator's repair path) down.
		if _, recoverErr := recoverHandover(store, manager, false); recoverErr != nil {
			log.Printf("ghostd: handover recovery pending: %v", recoverErr)
		}
		raw, err = store.Load(addressbook.ConfigFile)
		if err == nil {
			config, err = addressbook.ParseConfig(raw)
		}
		if err == nil {
			if err = manager.Apply(config, func() error { return nil }); err != nil {
				log.Printf("ghostd: DHCP configuration cannot start (%v); rolling back any pending takeover", err)
				if rolledBack, recoverErr := recoverHandover(store, manager, true); recoverErr != nil {
					err = fmt.Errorf("%w; handover rollback: %v", err, recoverErr)
				} else if rolledBack {
					if raw, err = store.Load(addressbook.ConfigFile); err == nil {
						if config, err = addressbook.ParseConfig(raw); err == nil {
							err = manager.Apply(config, func() error { return nil })
						}
					}
				}
			}
		}
		unlock()
		if err != nil {
			db.Close()
			return nil, nil, err
		}
	} else if err = manager.Apply(config, func() error { return nil }); err != nil {
		db.Close()
		return nil, nil, err
	}
	resolver.SetRegistry(manager)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		nextExpiry := time.Time{}
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if observeOnly {
					continue
				}
				unlock, err := store.Lock()
				if err != nil {
					log.Printf("ghostd DHCP reload lock: %v", err)
					continue
				}
				_, recoveryErr := recoverHandover(store, manager, false)
				if recoveryErr != nil {
					log.Printf("ghostd handover recovery pending: %v", recoveryErr)
				}
				latest, err := store.Load(addressbook.ConfigFile)
				if err == nil && !bytes.Equal(latest, raw) {
					desired, e := addressbook.ParseConfig(latest)
					if e == nil {
						e = manager.Apply(desired, func() error { return nil })
					}
					if e == nil {
						raw = latest
					} else {
						err = e
					}
				}
				unlock()
				if err != nil {
					log.Printf("ghostd DHCP config reload: %v", err)
				}
				if time.Now().After(nextExpiry) {
					if err := db.Expire(); err != nil {
						log.Printf("ghostd lease expiry: %v", err)
					}
					if err := manager.CollectNeighbors(ctx); err != nil {
						log.Printf("ghostd neighbor observation: %v", err)
					}
					if err := manager.ReconcileRoutes(ctx); err != nil {
						log.Printf("ghostd delegated-prefix routes: %v", err)
					}
					if err := manager.CollectPeers(ctx); err != nil {
						log.Printf("ghostd peer inventory: %v", err)
					}
					nextExpiry = time.Now().Add(30 * time.Second)
				}
			}
		}
	}()
	return manager, func() { cancel(); <-done; resolver.SetRegistry(nil); manager.Close(); db.Close() }, nil
}

var (
	reportTo   *string
	followFlag *string
)

func init() {
	registerDomainHook(domainHook{name: "dhcp-v1", key: addressbook.ConfigFile, restore: restoreDHCPConfig})
	register(feature{
		name: "dhcp",
		flags: func() {
			reportTo = flag.String("report-to", "", "report this host interfaces once to a tailnet DHCP authority and exit")
			followFlag = flag.String("follow", "", "run as a warm standby of the ghostd authority at this tailnet host:port: mirror its ledger, serve nothing until promoted (DHCPHandover action \"promote\")")
		},
		cli: func() bool {
			if *followFlag != "" {
				standbyMode, followAddr = true, *followFlag
			}
			if *reportTo == "" {
				return false
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			reply, err := reportHost(ctx, *reportTo)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(reply)
			return true
		},
		// DHCP and authoritative LAN DNS stay available even if tailscaled is
		// unavailable at boot, so the registry starts before the tailnet wait.
		boot: func(env *featureEnv) (func(), error) {
			manager, stop, err := startAddressbook(env.store, env.observeOnly)
			if err != nil {
				return nil, fmt.Errorf("start address registry: %w", err)
			}
			env.shared["dhcp.manager"] = manager
			go func() {
				select {
				case e := <-manager.Errors:
					env.fatal <- fmt.Errorf("DHCP/DNS listener failed: %w", e)
				case <-env.ctx.Done():
				}
			}()
			return stop, nil
		},
		attach: func(env *featureEnv) (func(), error) {
			manager := env.shared["dhcp.manager"].(*addressbook.Manager)
			env.server.DHCP = manager
			manager.SetPeerSource(func(ctx context.Context) ([]addressbook.Peer, error) { return overlayPeers(ctx, env.overlay) })
			if authority := os.Getenv("GHOSTD_IDENTITY_AUTHORITY"); authority != "" && !env.observeOnly {
				go runReports(env.ctx, authority)
			}
			if standbyMode && !env.observeOnly {
				follower := &replica.Follower{Store: env.store, Manager: manager, Leader: followAddr}
				env.server.Standby = follower
				go follower.Run(env.ctx)
				log.Printf("ghostd: warm standby of %s; serving nothing until promoted", followAddr)
			}
			return nil, nil
		},
	})
}

// followAddr is the leader a warm standby mirrors (--follow).
var followAddr string

// overlayPeers reads the peer inventory from the overlay provider. LAN endpoints
// are the private paths its client itself learned, not what a peer claims.
func overlayPeers(ctx context.Context, p overlay.Provider) ([]addressbook.Peer, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	list, err := p.Peers(ctx)
	if err != nil {
		return nil, err
	}
	var peers []addressbook.Peer
	for _, q := range list {
		peers = append(peers, addressbook.Peer{ID: q.ID, DNSName: q.DNSName, HostName: q.HostName, Online: q.Online,
			Addresses: q.Addresses, LANAddrs: addressbook.PrivateEndpoints(q.Endpoints...)})
	}
	return peers, nil
}

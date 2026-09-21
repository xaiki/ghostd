package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
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

// newLegacy builds the legacy authority; tests replace it to avoid systemd.
var newLegacy = func(spec addressbook.LegacySpec) addressbook.LegacyAuthority {
	return addressbook.SystemDNSmasq{Spec: spec}
}

// recoverHandover rolls back an interrupted, or (with force) any unconfirmed,
// dnsmasq takeover. The caller holds the store lock.
func recoverHandover(store *state.Store, manager *addressbook.Manager, force bool) error {
	journal, err := manager.Store.HandoverJournal()
	if err != nil || journal.Phase == "" {
		return err
	}
	handover := addressbook.Handover{Manager: manager, Legacy: newLegacy(journal.Legacy), SaveConfig: func(c addressbook.Config) error {
		data, e := json.Marshal(c)
		if e != nil {
			return e
		}
		return store.SaveExternallyManagedConfig("dhcp-v1", addressbook.ConfigFile, data)
	}}
	if force && journal.Phase == "pending" {
		return handover.Rollback()
	}
	return handover.Recover()
}

// standbyMode is set from --follow before the daemon starts.
var standbyMode bool

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
		if recoverErr := recoverHandover(store, manager, false); recoverErr != nil {
			log.Printf("ghostd: handover recovery pending: %v", recoverErr)
		}
		raw, err = store.Load(addressbook.ConfigFile)
		if err == nil {
			config, err = addressbook.ParseConfig(raw)
		}
		if err == nil {
			if err = manager.Apply(config, func() error { return nil }); err != nil {
				log.Printf("ghostd: DHCP configuration cannot start (%v); rolling back any pending takeover", err)
				if recoverErr := recoverHandover(store, manager, true); recoverErr != nil {
					err = fmt.Errorf("%w; handover rollback: %v", err, recoverErr)
				} else if journal, jerr := db.HandoverJournal(); jerr == nil && journal.Phase == "rolled-back" {
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
				recoveryErr := recoverHandover(store, manager, false)
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

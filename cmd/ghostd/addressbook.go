package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"path/filepath"
	"time"

	"smarthome/ghostd/internal/addressbook"
	"smarthome/ghostd/internal/resolver"
	"smarthome/ghostd/internal/state"
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
	if err = manager.Apply(config, func() error { return nil }); err != nil {
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
				journal, recoveryErr := db.HandoverJournal()
				if recoveryErr == nil && journal.Phase != "" {
					handover := addressbook.Handover{Manager: manager, Legacy: addressbook.SystemDNSmasq{Spec: journal.Legacy}, SaveConfig: func(c addressbook.Config) error {
						data, e := json.Marshal(c)
						if e != nil {
							return e
						}
						return store.SaveExternallyManagedConfig("dhcp-v1", addressbook.ConfigFile, data)
					}}
					recoveryErr = handover.Recover()
				}
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
					nextExpiry = time.Now().Add(30 * time.Second)
				}
			}
		}
	}()
	return manager, func() { cancel(); <-done; resolver.SetRegistry(nil); manager.Close(); db.Close() }, nil
}

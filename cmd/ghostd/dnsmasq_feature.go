//go:build dhcp && dnsmasq

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/state"
)

var (
	convertDNSmasq *string
	legacyUnit     *string
)

func init() {
	handoverRecovery = recoverLegacyHandover
	register(feature{
		name: "dnsmasq",
		flags: func() {
			convertDNSmasq = flag.String("convert-dnsmasq", "", "preview: convert this dnsmasq config (following includes) to a dhcp-v1 handover plan and exit; touches nothing")
			legacyUnit = flag.String("legacy-unit", "dnsmasq.service", "the dnsmasq unit --convert-dnsmasq records in the plan")
		},
		cli: func() bool {
			if *convertDNSmasq == "" {
				return false
			}
			plan, err := addressbook.ConvertDNSmasq(*convertDNSmasq, addressbook.ConvertOptions{Files: addressbook.OSFiles, Unit: *legacyUnit, Addrs: addressbook.InterfaceAddrs})
			if err != nil {
				log.Fatalf("ghostd: cannot convert %s: %v", *convertDNSmasq, err)
			}
			out, _ := json.MarshalIndent(plan, "", "  ")
			fmt.Println(string(out))
			return true
		},
	})
}

// newLegacy builds the legacy authority; tests replace it to avoid systemd.
var newLegacy = func(spec addressbook.LegacySpec) addressbook.LegacyAuthority {
	return addressbook.SystemDNSmasq{Spec: spec}
}

// recoverHandover rolls back an interrupted, or (with force) any unconfirmed,
// dnsmasq takeover. The caller holds the store lock.
func recoverLegacyHandover(store *state.Store, manager *addressbook.Manager, force bool) (bool, error) {
	journal, err := manager.Store.HandoverJournal()
	if err != nil || journal.Phase == "" {
		return false, err
	}
	handover := addressbook.Handover{Manager: manager, Legacy: newLegacy(journal.Legacy), SaveConfig: func(c addressbook.Config) error {
		data, e := json.Marshal(c)
		if e != nil {
			return e
		}
		return store.SaveExternallyManagedConfig("dhcp-v1", addressbook.ConfigFile, data)
	}}
	if force && journal.Phase == "pending" {
		err = handover.Rollback()
	} else {
		err = handover.Recover()
	}
	if err != nil {
		return false, err
	}
	after, jerr := manager.Store.HandoverJournal()
	return jerr == nil && after.Phase == "rolled-back", nil
}

//go:build dhcp

package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/state"
)

func TestDeadmanDHCPRevertsConfigWithoutRewindingLeases(t *testing.T) {
	dir := t.TempDir()
	configStore, e := state.NewStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	ledger, e := addressbook.Open(filepath.Join(dir, "addressbook.db"))
	if e != nil {
		t.Fatal(e)
	}
	defer ledger.Close()
	c := addressbook.Config{Scopes: []addressbook.Scope{{ID: "lan", Interface: "eth0", Subnet: "10.0.0.0/24", Server: "10.0.0.1", Router: "10.0.0.1", Start: "10.0.0.6", End: "10.0.0.8", Zone: "home.arpa", LeaseSeconds: 600, Enabled: true}}}
	if _, e = ledger.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true); e != nil {
		t.Fatal(e)
	}
	before := []byte(`{"scopes":[]}`)
	if e = configStore.SaveDomain("dhcp-v1", state.DomainState{Confirmed: before, Pending: &state.Pending{ID: "dhcp-test", Snapshot: before, Deadline: time.Now().Add(-time.Second)}}); e != nil {
		t.Fatal(e)
	}
	if e = runRevert(configStore, "dhcp-test", "dhcp-v1"); e != nil {
		t.Fatal(e)
	}
	raw, e := configStore.Load(addressbook.ConfigFile)
	if e != nil || string(raw) != string(before) {
		t.Fatal(string(raw), e)
	}
	snapshot, e := ledger.Snapshot("lan", "10.0.0.6", 0)
	if e != nil || len(snapshot.Bindings) != 1 || snapshot.Bindings[0].State != "active" {
		t.Fatal(snapshot, e)
	}
}

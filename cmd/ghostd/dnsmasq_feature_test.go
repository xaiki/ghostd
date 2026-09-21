//go:build dhcp && dnsmasq

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/state"
)

type fakeLegacy struct {
	running bool
	leases  string
}

func (l *fakeLegacy) Stop() error                       { l.running = false; return nil }
func (l *fakeLegacy) Start() error                      { l.running = true; return nil }
func (l *fakeLegacy) ReadLeases() (string, error)       { return l.leases, nil }
func (l *fakeLegacy) WriteLeases(s string) error        { l.leases = s; return nil }
func (l *fakeLegacy) Validate(addressbook.Config) error { return nil }

// The confirmed target cannot start (its server address is not on this host),
// yet a pending takeover must still roll back at boot and keep the ledger.
func TestBootRollsBackPendingHandoverWhoseTargetCannotStart(t *testing.T) {
	dir := t.TempDir()
	store, e := state.NewStore(dir)
	if e != nil {
		t.Fatal(e)
	}
	legacy := &fakeLegacy{}
	newLegacy = func(addressbook.LegacySpec) addressbook.LegacyAuthority { return legacy }
	t.Cleanup(func() {
		newLegacy = func(s addressbook.LegacySpec) addressbook.LegacyAuthority { return addressbook.SystemDNSmasq{Spec: s} }
	})

	target := addressbook.Config{Scopes: []addressbook.Scope{{ID: "lan", Interface: "nonexist0", Subnet: "10.0.0.0/24", Server: "10.0.0.1", Router: "10.0.0.1", Start: "10.0.0.6", End: "10.0.0.8", Zone: "home.arpa", LeaseSeconds: 600, Enabled: true}}}
	disabled := target
	disabled.Scopes = append([]addressbook.Scope(nil), target.Scopes...)
	disabled.Scopes[0].Enabled = false

	db, e := addressbook.Open(filepath.Join(dir, "addressbook.db"))
	if e != nil {
		t.Fatal(e)
	}
	m := addressbook.NewManager(db)
	h := addressbook.Handover{Manager: m, Legacy: legacy, SaveConfig: func(c addressbook.Config) error {
		raw, _ := json.Marshal(c)
		return store.SaveExternallyManagedConfig("dhcp-v1", addressbook.ConfigFile, raw)
	}}
	if e = h.Begin(disabled, addressbook.LegacySpec{}, time.Minute); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Allocate(target, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true); e != nil {
		t.Fatal(e)
	}
	// Simulate the daemon dying with the enabled target durably confirmed.
	raw, _ := json.Marshal(target)
	if e = store.SaveExternallyManagedConfig("dhcp-v1", addressbook.ConfigFile, raw); e != nil {
		t.Fatal(e)
	}
	m.Close()
	db.Close()

	_, stop, e := startAddressbook(store, false)
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	if !legacy.running || !strings.Contains(legacy.leases, "10.0.0.7") {
		t.Fatalf("legacy not restored with new grant: running=%v %q", legacy.running, legacy.leases)
	}
	cfg, _ := store.Load(addressbook.ConfigFile)
	if strings.Contains(string(cfg), `"enabled":true`) {
		t.Fatalf("boot configuration still enables the target: %s", cfg)
	}
}

// An interrupted (never confirmed) takeover is recovered before anything binds.
func TestBootRecoversInterruptedHandover(t *testing.T) {
	dir := t.TempDir()
	store, _ := state.NewStore(dir)
	legacy := &fakeLegacy{leases: "0 00:11:22:33:44:55 10.0.0.6 old *\n"}
	newLegacy = func(addressbook.LegacySpec) addressbook.LegacyAuthority { return legacy }
	t.Cleanup(func() {
		newLegacy = func(s addressbook.LegacySpec) addressbook.LegacyAuthority { return addressbook.SystemDNSmasq{Spec: s} }
	})
	db, e := addressbook.Open(filepath.Join(dir, "addressbook.db"))
	if e != nil {
		t.Fatal(e)
	}
	if e = db.SaveHandoverForTest(addressbook.HandoverJournal{Phase: "stopping", Deadline: time.Now().Add(time.Hour).Unix()}); e != nil {
		t.Fatal(e)
	}
	db.Close()
	_, stop, e := startAddressbook(store, false)
	if e != nil {
		t.Fatal(e)
	}
	defer stop()
	if !legacy.running {
		t.Fatal("interrupted takeover was not rolled back at boot")
	}
}

func TestConvertDNSmasqFlagIsPreviewOnly(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "dnsmasq.conf")
	os.WriteFile(conf, []byte("interface=lo\ndomain=home.arpa\ndhcp-leasefile=/var/lib/misc/x.leases\ndhcp-range=127.0.0.10,127.0.0.20,255.0.0.0,1h\nunknown-thing=1\n"), 0600)
	out, err := exec.Command("go", "run", "-tags", "dhcp dnsmasq coredns", ".", "--convert-dnsmasq="+conf).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "needs explicit conversion") {
		t.Fatalf("unsupported semantics must be refused with an explanation: %v\n%s", err, out)
	}
}

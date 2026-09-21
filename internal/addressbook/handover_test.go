package addressbook

import (
	"errors"
	"strings"
	"testing"
	"time"
)

type memoryLegacy struct {
	running   bool
	leases    string
	failStart bool
}

func (l *memoryLegacy) Stop() error { l.running = false; return nil }
func (l *memoryLegacy) Start() error {
	if l.failStart {
		return errors.New("injected start failure")
	}
	l.running = true
	return nil
}
func (l *memoryLegacy) ReadLeases() (string, error) { return l.leases, nil }
func (l *memoryLegacy) WriteLeases(s string) error  { l.leases = s; return nil }
func (l *memoryLegacy) Validate(Config) error       { return nil }
func TestHandoverRollbackPreservesNewGrantsAndRetries(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	c := disabled(testConfig())
	l := &memoryLegacy{running: true, leases: "0 00:11:22:33:44:55 10.0.0.6 old *\n"}
	h := Handover{Manager: m, Legacy: l, SaveConfig: func(Config) error { return nil }}
	if e := h.Begin(c, LegacySpec{}, time.Minute); e != nil {
		t.Fatal(e)
	}
	b, e := s.Allocate(testConfig(), "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true)
	if e != nil {
		t.Fatal(e)
	}
	j, _ := s.HandoverJournal()
	j.Deadline = time.Now().Unix() - 1
	if e = s.saveHandover(j); e != nil {
		t.Fatal(e)
	}
	l.failStart = true
	if e = h.Recover(); e == nil {
		t.Fatal("injected rollback failure ignored")
	}
	if l.running {
		t.Fatal("legacy started before successful recovery")
	}
	l.failStart = false
	if e = h.Recover(); e != nil {
		t.Fatal(e)
	}
	if !l.running || !strings.Contains(l.leases, b.Address) {
		t.Fatal("new grant lost on rollback", l.leases)
	}
	j, _ = s.HandoverJournal()
	if j.Phase != "rolled-back" {
		t.Fatal(j)
	}
	snap, _ := s.Snapshot("", "", 0)
	if len(snap.Bindings) != 2 {
		t.Fatal(snap)
	}
}
func TestHandoverConfigFailureRestoresLegacy(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	l := &memoryLegacy{running: true, leases: "0 00:11:22:33:44:55 10.0.0.6 old *\n"}
	calls := 0
	h := Handover{Manager: m, Legacy: l, SaveConfig: func(Config) error {
		calls++
		if calls == 1 {
			return errors.New("injected write failure")
		}
		return nil
	}}
	if e := h.Begin(disabled(testConfig()), LegacySpec{}, time.Minute); e == nil {
		t.Fatal("failure not reported")
	}
	if !l.running || !strings.Contains(l.leases, "10.0.0.6") {
		t.Fatal(l)
	}
	j, _ := s.HandoverJournal()
	if j.Phase != "rolled-back" || j.Error == "" {
		t.Fatal(j)
	}
}

func TestReimportAfterLegacyRenewal(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	b, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	// After rollback dnsmasq can legitimately renew a lease originally granted
	// by ghostd. A subsequent takeover must preserve that newer expiry.
	l := ImportedLease{Scope: b.Scope, Address: b.Address, MAC: b.MAC, Expiry: b.End + 600}
	if e = s.Import(disabled(c), []ImportedLease{l}); e != nil {
		t.Fatal(e)
	}
	snap, _ := s.Snapshot("", "", 0)
	if snap.Bindings[0].End != l.Expiry {
		t.Fatal(snap)
	}
}

func TestRollbackRefusesChangedConfiguration(t *testing.T) {
	m := NewManager(openTest(t))
	defer m.Close()
	legacy := &memoryLegacy{running: true}
	h := Handover{Manager: m, Legacy: legacy, SaveConfig: func(Config) error { return nil }}
	if e := h.Begin(disabled(testConfig()), LegacySpec{}, time.Minute); e != nil {
		t.Fatal(e)
	}
	if e := h.Confirm(); e != nil {
		t.Fatal(e)
	}
	changed := disabled(testConfig())
	changed.Scopes[0].End = "10.0.0.20"
	if e := m.Apply(changed, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e := h.Rollback(); e == nil || legacy.running {
		t.Fatal("restarted legacy after incompatible configuration change", e)
	}
}

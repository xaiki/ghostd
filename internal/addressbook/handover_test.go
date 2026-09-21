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

// An empty legacy pool must not skip the rollback export: grants made after
// takeover would otherwise vanish when dnsmasq is restarted.
func TestHandoverRollbackFromEmptyPoolExportsNewGrants(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	l := &memoryLegacy{running: true}
	h := Handover{Manager: m, Legacy: l, SaveConfig: func(Config) error { return nil }}
	if e := h.Begin(disabled(testConfig()), LegacySpec{}, time.Minute); e != nil {
		t.Fatal(e)
	}
	b, e := s.Allocate(testConfig(), "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true)
	if e != nil {
		t.Fatal(e)
	}
	if e = h.Rollback(); e != nil {
		t.Fatal(e)
	}
	if !l.running || !strings.Contains(l.leases, b.Address) || !strings.Contains(l.leases, "00:11:22:33:44:66") {
		t.Fatalf("new grant lost with empty original snapshot: running=%v %q", l.running, l.leases)
	}
}

// A snapshot that cannot be imported never activated ghostd, so rolling back
// must restore the untouched legacy authority without parsing it again.
func TestHandoverRollbackAfterUnimportableSnapshot(t *testing.T) {
	for name, snapshot := range map[string]string{
		"malformed":         "0 00:11:22:33:44:55 10.0.0.6\n",
		"undeclared scope":  "0 00:11:22:33:44:55 192.0.2.9 old *\n",
		"temporary IA (v6)": "0 T1 fd00::6 old 00:01:00:01:aa\n",
	} {
		t.Run(name, func(t *testing.T) {
			s := openTest(t)
			m := NewManager(s)
			defer m.Close()
			c := disabled(testConfig())
			if name == "temporary IA (v6)" {
				c = disabled(config6())
			}
			l := &memoryLegacy{running: true, leases: snapshot}
			h := Handover{Manager: m, Legacy: l, SaveConfig: func(Config) error { return nil }}
			if e := h.Begin(c, LegacySpec{}, time.Minute); e == nil {
				t.Fatal("unimportable snapshot accepted")
			}
			if !l.running || l.leases != snapshot {
				t.Fatalf("legacy authority not restored untouched: running=%v %q", l.running, l.leases)
			}
			j, _ := s.HandoverJournal()
			if j.Phase != "rolled-back" || j.Activated {
				t.Fatal(j)
			}
		})
	}
}

type crash struct{ point string }

// crashingLegacy panics at a named boundary, standing in for a killed process.
type crashingLegacy struct {
	memoryLegacy
	at string
}

func (l *crashingLegacy) hit(p string) {
	if l.at == p {
		l.at = ""
		panic(crash{p})
	}
}
func (l *crashingLegacy) Stop() error {
	l.hit("before-stop")
	e := l.memoryLegacy.Stop()
	l.hit("after-stop")
	return e
}
func (l *crashingLegacy) ReadLeases() (string, error) {
	l.hit("before-read")
	return l.memoryLegacy.ReadLeases()
}
func (l *crashingLegacy) WriteLeases(s string) error {
	l.hit("before-export")
	e := l.memoryLegacy.WriteLeases(s)
	l.hit("after-export")
	return e
}
func (l *crashingLegacy) Start() error { l.hit("before-start"); return l.memoryLegacy.Start() }

func runToCrash(f func() error) (crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(crash); !ok {
				panic(r)
			}
			crashed = true
		}
	}()
	_ = f()
	return false
}

// A kill at any boundary of takeover or rollback, followed by a restart and
// recovery, ends with the legacy authority running exactly once and every
// grant (original or new) present in its lease file.
func TestHandoverSurvivesKillAtEveryBoundary(t *testing.T) {
	for _, point := range []string{"before-stop", "after-stop", "before-read", "before-export", "after-export", "before-start"} {
		t.Run(point, func(t *testing.T) {
			s := openTest(t)
			l := &crashingLegacy{memoryLegacy: memoryLegacy{running: true, leases: "0 00:11:22:33:44:55 10.0.0.6 old *\n"}}
			save := func(Config) error { return nil }
			m := NewManager(s)
			h := Handover{Manager: m, Legacy: l, SaveConfig: save}
			takeoverPoint := point == "before-stop" || point == "after-stop" || point == "before-read"
			var newGrant Binding
			if takeoverPoint {
				l.at = point
				if !runToCrash(func() error { return h.Begin(disabled(testConfig()), LegacySpec{}, time.Minute) }) {
					t.Fatal("no crash at", point)
				}
			} else {
				if e := h.Begin(disabled(testConfig()), LegacySpec{}, time.Minute); e != nil {
					t.Fatal(e)
				}
				var e error
				newGrant, e = s.Allocate(testConfig(), "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true)
				if e != nil {
					t.Fatal(e)
				}
				l.at = point
				if !runToCrash(h.Rollback) {
					t.Fatal("no crash at", point)
				}
			}
			m.Close()
			// Restart: a fresh manager on the same durable ledger, and the deadline
			// long gone (the machine was down).
			j, _ := s.HandoverJournal()
			if j.Phase == "pending" {
				j.Deadline = time.Now().Unix() - 1
				if e := s.saveHandover(j); e != nil {
					t.Fatal(e)
				}
			}
			m2 := NewManager(s)
			defer m2.Close()
			h2 := Handover{Manager: m2, Legacy: l, SaveConfig: save}
			for i := 0; i < 2; i++ { // recovery is idempotent
				if e := h2.Recover(); e != nil {
					t.Fatal(e)
				}
			}
			if !l.running || !strings.Contains(l.leases, "10.0.0.6") {
				t.Fatalf("legacy not restored with original lease: running=%v %q", l.running, l.leases)
			}
			if newGrant.Address != "" && !strings.Contains(l.leases, newGrant.Address) {
				t.Fatalf("new grant lost at %s: %q", point, l.leases)
			}
			if j, _ = s.HandoverJournal(); j.Phase != "rolled-back" {
				t.Fatal(j)
			}
		})
	}
}

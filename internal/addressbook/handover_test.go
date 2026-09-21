package addressbook

import (
	"errors"
	"fmt"
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

func TestHandoverStatusReportsClientEvidence(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	c := testConfig()
	// Journal an enabled target directly: binding a real interface is the lab's job.
	j := HandoverJournal{Phase: "pending", Deadline: time.Now().Add(time.Minute).Unix(), Target: c, Revision: s.Revision(), ImportedLeases: map[string]int{"lan": 1}, RequireEvidence: true}
	if e := s.saveHandover(j); e != nil {
		t.Fatal(e)
	}
	h := Handover{Manager: m}
	st, e := h.Status()
	if e != nil || len(st.Missing) != 2 || st.RemainingSeconds <= 0 || st.Retryable {
		t.Fatal("nothing verified yet:", st, e)
	}
	// The inherited client renews (an import made it live first), then a stranger is allocated.
	if e = s.Import(disabled(c), []ImportedLease{{Scope: "lan", Address: "10.0.0.6", MAC: "00:11:22:33:44:55", Expiry: time.Now().Add(time.Hour).Unix()}}); e != nil {
		t.Fatal(e)
	}
	j.Revision = s.Revision() // evidence counts only what happens after activation
	if e = s.saveHandover(j); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true); e != nil {
		t.Fatal(e)
	}
	st, _ = h.Status()
	if len(st.Missing) != 1 || !strings.Contains(st.Missing[0], "no new client") || st.Evidence["lan"].Renewals != 1 {
		t.Fatal("renewal not credited, or fresh grant not demanded:", st)
	}
	if _, e = s.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true); e != nil {
		t.Fatal(e)
	}
	if st, _ = h.Status(); len(st.Missing) != 0 || st.Evidence["lan"].Grants != 1 {
		t.Fatal(st)
	}
	// An expired takeover is retryable.
	j.Deadline = time.Now().Unix() - 5
	s.saveHandover(j)
	if st, _ = h.Status(); !st.Retryable || st.RemainingSeconds != 0 {
		t.Fatal(st)
	}
}

func TestConfirmWaitsForClientEvidenceAndHistoryIsArchived(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	l := &memoryLegacy{running: true, leases: "0 00:11:22:33:44:55 10.0.0.6 old *\n"}
	h := Handover{Manager: m, Legacy: l, SaveConfig: func(Config) error { return nil }}
	if e := h.Begin(disabled(testConfig()), LegacySpec{}, time.Minute); e != nil {
		t.Fatal(e)
	}
	// Require evidence for an enabled scope the way the daemon would; confirmation
	// must then refuse until real clients have exercised it.
	j, _ := s.HandoverJournal()
	if j.ImportedLeases["lan"] != 1 || j.Started == 0 {
		t.Fatal("journal lost the import count", j)
	}
	j.RequireEvidence = true
	j.Target = testConfig()
	s.saveHandover(j)
	if e := h.Confirm(); e == nil || !strings.Contains(e.Error(), "client verification incomplete") {
		t.Fatal("confirmed without client evidence:", e)
	}
	j.Target = disabled(testConfig())
	j.RequireEvidence = false
	s.saveHandover(j)
	if e := h.Confirm(); e != nil {
		t.Fatal(e)
	}
	if e := h.Rollback(); e != nil {
		t.Fatal(e)
	}
	hist, e := s.HandoverHistory()
	if e != nil || len(hist) != 2 || hist[0].Phase != "confirmed" || hist[1].Phase != "rolled-back" || hist[0].Snapshot != "" || hist[0].Finished == 0 {
		t.Fatal("finished takeovers not archived:", hist, e)
	}
}

// A second takeover imports the lease file the first rollback exported. Its
// quarantine markers and offers must not collide with the ledger's own holds.
func TestReimportOfOwnExportKeepsQuarantineAndOffers(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	c := testConfig()
	l := &memoryLegacy{running: true}
	h := Handover{Manager: m, Legacy: l, SaveConfig: func(Config) error { return nil }}
	if e := h.Begin(disabled(c), LegacySpec{}, time.Minute); e != nil {
		t.Fatal(e)
	}
	// One offer outstanding, one address declined (quarantined), one active lease.
	if _, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", false); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true); e != nil {
		t.Fatal(e)
	}
	if e := s.Release("lan", "mac:00:11:22:33:44:66", "10.0.0.7", true); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:77", "00:11:22:33:44:77", "", "10.0.0.8", true); e != nil {
		t.Fatal(e)
	}
	if e := h.Rollback(); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(l.leases, "02:ff:ff:ff:ff:fe 10.0.0.7") {
		t.Fatal("quarantine marker not exported:", l.leases)
	}
	// The legacy allocator runs, then a second takeover starts from what it holds.
	if e := h.Begin(disabled(c), LegacySpec{}, time.Minute); e != nil {
		t.Fatal("second takeover collided with the ledger's own export:", e)
	}
	snap, _ := s.Snapshot("lan", "10.0.0.7", 0)
	if snap.Bindings[0].State != "declined" {
		t.Fatal("quarantine was turned into something else:", snap.Bindings[0])
	}
	// A hold the ledger no longer has is restored as a quarantine, not as a lease.
	s2 := openTest(t)
	m2 := NewManager(s2)
	defer m2.Close()
	l2 := &memoryLegacy{running: true, leases: fmt.Sprintf("%d 02:ff:ff:ff:ff:fe 10.0.0.7 * ff:31\n", time.Now().Add(5*time.Minute).Unix())}
	h2 := Handover{Manager: m2, Legacy: l2, SaveConfig: func(Config) error { return nil }}
	if e := h2.Begin(disabled(c), LegacySpec{}, time.Minute); e != nil {
		t.Fatal(e)
	}
	got, _ := s2.Snapshot("lan", "10.0.0.7", 0)
	if len(got.Bindings) != 1 || got.Bindings[0].State != "declined" {
		t.Fatal(got.Bindings)
	}
	if _, e := s2.Allocate(c, "lan", "mac:02:ff:ff:ff:ff:fe", "02:ff:ff:ff:ff:fe", "", "10.0.0.7", true); e == nil {
		t.Fatal("the quarantine identity could take the address")
	}
}

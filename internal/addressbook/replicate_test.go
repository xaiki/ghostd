//go:build dhcp

package addressbook

import (
	"reflect"
	"testing"
	"time"
)

func TestStandbyMirrorsLeaderAndContinuesAfterPromotion(t *testing.T) {
	leader, standby := openTest(t), openTest(t)
	c := testConfig()
	now := int64(2000000000)
	leader.now = func() time.Time { return time.Unix(now, 0) }
	standby.now = leader.now

	a, _ := leader.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "kitchen", "10.0.0.6", true)
	leader.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true)
	leader.Release("lan", "mac:00:11:22:33:44:66", "10.0.0.7", true) // declined: a quarantine to carry over
	leader.Observe(c, []Observation{{Scope: "lan", Address: "10.0.0.77", MAC: "00:11:22:33:44:99"}})
	if e := leader.Repair(c, []IdentityRepair{{Scope: "lan", Address: a.Address, Client: a.Client, ExpectedDevice: a.Device, Device: "kitchen", Name: "kitchen", NodeID: "n1", Reason: "verified", Persist: true}}); e != nil {
		t.Fatal(e)
	}
	leaderSID, _ := leader.ServerDUID()

	sync := func() uint64 {
		t.Helper()
		events, e := leader.Events(standby.ReplicaCursor(), 1000)
		if e != nil {
			t.Fatal(e)
		}
		snap, _ := leader.Snapshot("", "", 0)
		cur, e := standby.ApplyReplicated(events, &snap)
		if e != nil {
			t.Fatal(e)
		}
		return cur
	}
	first := sync()
	if first == 0 {
		t.Fatal("cursor did not advance")
	}
	// Idempotent: a repeated sync changes nothing and keeps the cursor.
	if again := sync(); again != first {
		t.Fatal("cursor moved without new events", first, again)
	}
	ls, _ := leader.Snapshot("", "", 0)
	ss, _ := standby.Snapshot("", "", 0)
	if !reflect.DeepEqual(ls.Bindings, ss.Bindings) {
		t.Fatalf("bindings differ:\nleader  %+v\nstandby %+v", ls.Bindings, ss.Bindings)
	}
	if len(ss.Associations) != 1 || ss.Associations[0].Device != "kitchen" || len(ss.Observations) != 1 {
		t.Fatal("associations or observations not mirrored:", ss.Associations, ss.Observations)
	}
	if sid, _ := standby.ServerDUID(); !sid.Equal(leaderSID) {
		t.Fatal("the server DUID must be the leader's, or every IPv6 client rebinds after failover")
	}

	// The leader keeps working; the standby follows.
	now += 100
	leader.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", a.Address, true) // renew
	sync()
	ls, _ = leader.Snapshot("", "", 0)
	ss, _ = standby.Snapshot("", "", 0)
	if !reflect.DeepEqual(ls.Bindings, ss.Bindings) {
		t.Fatal("renewal not mirrored")
	}

	// Promotion: the standby answers exactly as the leader would have. The
	// existing client renews the same address; a newcomer cannot take an
	// address the leader granted or the quarantined one.
	if b, e := standby.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", a.Address, true); e != nil || b.Address != a.Address || b.Device != "kitchen" || b.NodeID != "n1" {
		t.Fatal("promoted standby lost the client's lease or identity:", b, e)
	}
	if _, e := standby.Allocate(c, "lan", "mac:00:11:22:33:44:AA", "00:11:22:33:44:aa", "", "10.0.0.7", true); e == nil {
		t.Fatal("promoted standby forgot the quarantine")
	}
	if got, _ := standby.Allocate(c, "lan", "mac:00:11:22:33:44:BB", "00:11:22:33:44:bb", "", "", false); got.Address == a.Address || got.Address == "10.0.0.7" {
		t.Fatal("promoted standby reissued a live address", got)
	}
}

func TestStandbyRefusesToServe(t *testing.T) {
	m := NewManager(openTest(t))
	defer m.Close()
	m.SetStandby(true)
	if e := m.Apply(testConfig(), func() error { t.Fatal("saved"); return nil }); e == nil {
		t.Fatal("a standby enabled a scope")
	}
	if e := m.Apply(disabled(testConfig()), func() error { return nil }); e != nil {
		t.Fatal("a standby must still hold disabled configuration:", e)
	}
	m.SetStandby(false)
	if !m.Standby() == false {
		t.Fatal("promotion flag")
	}
}

func TestReplicationSurvivesInterruptedSync(t *testing.T) {
	leader, standby := openTest(t), openTest(t)
	c := testConfig()
	leader.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	events, _ := leader.Events(0, 100)
	bad := Snapshot{ServerDUID: "not-hex"}
	if _, e := standby.ApplyReplicated(events, &bad); e == nil {
		t.Fatal("a corrupt snapshot was applied")
	}
	if standby.ReplicaCursor() != 0 {
		t.Fatal("a failed sync advanced the cursor")
	}
	if snap, _ := standby.Snapshot("", "", 0); len(snap.Bindings) != 0 {
		t.Fatal("a failed sync left partial state", snap.Bindings)
	}
	if _, e := standby.ApplyReplicated(events, nil); e != nil {
		t.Fatal(e)
	}
	if snap, _ := standby.Snapshot("", "", 0); len(snap.Bindings) != 1 {
		t.Fatal(snap.Bindings)
	}
}

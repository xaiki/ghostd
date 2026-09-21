package addressbook

import (
	bolt "go.etcd.io/bbolt"
	"testing"
	"time"
)

func TestNeighborReportAndIdentityRepair(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	o := Observation{Scope: "lan", Address: "10.0.0.77", MAC: "00:11:22:33:44:55"}
	if e := s.Observe(c, []Observation{o}); e != nil {
		t.Fatal(e)
	}
	snap, _ := s.Snapshot("", "", 0)
	if len(snap.Bindings) != 0 || len(snap.Observations) != 1 {
		t.Fatal("observation became grant", snap)
	}
	node := Node{ID: "n1", DNSName: "node-a.tailnet.example", Interfaces: []InterfaceReport{{MAC: o.MAC, Addresses: []string{o.Address}}}}
	joined, e := s.Report(c, node)
	if e != nil || len(joined) != 1 || joined[0].Origin != "neighbor-report" {
		t.Fatal(joined, e)
	}
	old := joined[0]
	now++
	change := IdentityRepair{Scope: old.Scope, Address: old.Address, Client: old.Client, ExpectedDevice: old.Device, Device: "repaired", Name: "correct-host", NodeID: "n2", Reason: "verified separate device"}
	if e = s.Repair(c, []IdentityRepair{change}); e != nil {
		t.Fatal(e)
	}
	if e = s.Repair(c, []IdentityRepair{change}); e == nil {
		t.Fatal("stale repair applied")
	}
	past, _ := s.Snapshot("", old.Address, now-1)
	current, _ := s.Snapshot("", old.Address, 0)
	if past.Bindings[0].Device != old.Device || current.Bindings[0].Device != "repaired" {
		t.Fatal(past, current)
	}
	if _, e = s.Report(c, node); e == nil {
		t.Fatal("self-report overrode explicit repair")
	}
	events, _ := s.Events(0, 100)
	if events[len(events)-1].Kind != "identity-conflict" {
		t.Fatal(events)
	}
	now += 121
	fresh, _ := s.Snapshot("", old.Address, 0)
	if fresh.Bindings[0].State != "expired" {
		t.Fatal(fresh)
	}
}

func TestObservationHistoryIsSeparateFromCurrentSightings(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	a := Observation{Scope: "lan", Address: "10.0.0.77", MAC: "00:11:22:33:44:55"}
	b := Observation{Scope: "lan", Address: "10.0.0.77", MAC: "00:11:22:33:44:66"}
	if e := s.Observe(c, []Observation{a}); e != nil {
		t.Fatal(e)
	}
	t0 := now
	now += 30 // refresh of an unchanged sighting must not flood the log
	if e := s.Observe(c, []Observation{a}); e != nil {
		t.Fatal(e)
	}
	now += 500 // first sighting long expired, address now seen on another MAC
	if e := s.Observe(c, []Observation{b}); e != nil {
		t.Fatal(e)
	}
	events, _ := s.Events(0, 100)
	kinds := []string{}
	for _, e := range events {
		kinds = append(kinds, e.Kind)
	}
	if len(kinds) != 3 || kinds[0] != "observation" || kinds[1] != "observation-end" || kinds[2] != "observation" {
		t.Fatal("unexpected observation history", kinds)
	}
	cur, _ := s.Snapshot("", "10.0.0.77", 0)
	if len(cur.Observations) != 1 || cur.Observations[0].MAC != b.MAC || cur.Observations[0].Historical {
		t.Fatal(cur.Observations)
	}
	past, _ := s.Snapshot("", "10.0.0.77", t0+10)
	if len(past.Observations) != 1 || past.Observations[0].MAC != a.MAC || !past.Observations[0].Historical {
		t.Fatal("history lost the contemporaneous sighting", past.Observations)
	}
	gap, _ := s.Snapshot("", "10.0.0.77", t0+300) // after expiry, before the next sighting
	if len(gap.Observations) != 0 {
		t.Fatal("expired sighting presented as evidence", gap.Observations)
	}
}

func TestRepairPolicyMatchesReports(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	c.Devices = []DeviceConfig{{ID: "d1", Name: "printer", NodeID: "n1", NodeIDs: []string{"n2"}}}
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	b, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	c2 := c
	c2.Devices = append(append([]DeviceConfig(nil), c.Devices...), DeviceConfig{ID: "d2", Name: "other"})
	repair := func(dev, name, node string) error {
		return s.Repair(c, []IdentityRepair{{Scope: b.Scope, Address: b.Address, Client: b.Client, ExpectedDevice: b.Device, Device: dev, Name: name, NodeID: node, Reason: "test"}})
	}
	if e = repair("d1", "printer", "n3"); e == nil {
		t.Fatal("repair linked a node the device does not declare")
	}
	if e = repair("d1", "printer", "n2"); e != nil {
		t.Fatal("additional declared tailnet_node_ids rejected:", e)
	}
	// A different, undeclared live device already holds the name.
	if _, e = s.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true); e != nil {
		t.Fatal(e)
	}
	held, _ := s.Snapshot("lan", "10.0.0.7", 0)
	other := held.Bindings[0]
	other.Name = "holder"
	if e = s.db.Update(func(tx *bolt.Tx) error { return s.save(tx, other, "test") }); e != nil {
		t.Fatal(e)
	}
	cur, _ := s.Snapshot("lan", "10.0.0.6", 0)
	err := s.Repair(c, []IdentityRepair{{Scope: "lan", Address: "10.0.0.6", Client: cur.Bindings[0].Client, ExpectedDevice: cur.Bindings[0].Device, Device: "newdev", Name: "holder", Reason: "test"}})
	if err == nil {
		t.Fatal("repair took a name held by another live undeclared device")
	}
}

func TestPersistentAssociationSurvivesExpiryAndReallocation(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	client, mac := "mac:00:11:22:33:44:55", "00:11:22:33:44:55"
	b, e := s.Allocate(c, "lan", client, mac, "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	fix := func(dev, name, node string, persist, forget bool) IdentityRepair {
		cur, _ := s.Snapshot("lan", "", 0)
		var live Binding
		for _, x := range cur.Bindings {
			if x.Client == client && x.State == "active" {
				live = x
			}
		}
		return IdentityRepair{Scope: live.Scope, Address: live.Address, Client: client, ExpectedDevice: live.Device, Device: dev, Name: name, NodeID: node, Reason: "verified", Persist: persist, Forget: forget}
	}
	if e = s.Repair(c, []IdentityRepair{fix("kitchen", "kitchen", "n1", true, false)}); e != nil {
		t.Fatal(e)
	}
	// Let the lease expire, and have a different client take the address.
	now += 601
	if e = s.Expire(); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Allocate(c, "lan", "mac:00:11:22:33:44:99", "00:11:22:33:44:99", "", "10.0.0.6", true); e != nil {
		t.Fatal(e)
	}
	again, e := s.Allocate(c, "lan", client, mac, "", "10.0.0.7", true)
	if e != nil {
		t.Fatal(e)
	}
	if again.Address == b.Address || again.Device != "kitchen" || again.Name != "kitchen" || again.NodeID != "n1" {
		t.Fatal("association lost across expiry/reallocation", again)
	}
	// Changing the association keeps the old mapping and the old bindings' history.
	now++
	if e = s.Repair(c, []IdentityRepair{fix("den", "den", "n2", true, false)}); e != nil {
		t.Fatal(e)
	}
	snap, _ := s.Snapshot("", "", 0)
	if len(snap.Associations) != 1 || snap.Associations[0].Device != "den" || len(snap.Associations[0].History) != 1 || snap.Associations[0].History[0].Device != "kitchen" {
		t.Fatal(snap.Associations)
	}
	old, _ := s.Snapshot("lan", "10.0.0.7", now-1)
	if old.Bindings[0].Device != "kitchen" {
		t.Fatal("past ownership rewritten", old.Bindings)
	}
	if e = s.Repair(c, []IdentityRepair{fix("den", "den", "n2", false, true)}); e != nil {
		t.Fatal(e)
	}
	snap, _ = s.Snapshot("", "", 0)
	if len(snap.Associations) != 0 {
		t.Fatal("forgotten association still present", snap.Associations)
	}
}

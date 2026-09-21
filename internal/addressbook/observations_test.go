package addressbook

import (
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

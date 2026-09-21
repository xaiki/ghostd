//go:build dhcp

package addressbook

import (
	"testing"
	"time"
)

func TestPeerSuggestionsAreEvidenceBasedAndNeverSelfApplying(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	direct, _ := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "kitchen", "10.0.0.6", true)
	named, _ := s.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "den", "10.0.0.7", true)
	if e := s.SightPeers([]Peer{
		{ID: "n-direct", DNSName: "laptop.example.ts.net.", LANAddrs: PrivateEndpoints("10.0.0.6:41641", "203.0.113.9:41641", "[2001:db8::1]:1")},
		{ID: "n-name", DNSName: "Den.example.ts.net.", Online: true},
		{ID: "n-other", DNSName: "unrelated.example.ts.net."},
	}); e != nil {
		t.Fatal(e)
	}
	got, e := s.Suggest(c)
	if e != nil || len(got) != 2 {
		t.Fatal(got, e)
	}
	byAddr := map[string]Suggestion{got[0].Address: got[0], got[1].Address: got[1]}
	if sg := byAddr[direct.Address]; sg.Strength != "endpoint" || sg.PeerID != "n-direct" || sg.Ambiguous || sg.Repair.NodeID != "n-direct" || !sg.Repair.Persist {
		t.Fatal(sg)
	}
	if sg := byAddr[named.Address]; sg.Strength != "hostname" || sg.PeerID != "n-name" {
		t.Fatal("hostname match should be offered, marked weak:", sg)
	}
	// Nothing was merged: suggestions do not touch bindings.
	snap, _ := s.Snapshot("", "", 0)
	for _, b := range snap.Bindings {
		if b.NodeID != "" {
			t.Fatal("a suggestion linked a binding by itself", b)
		}
	}
	// Applying one through the explicit repair path removes it from the list.
	if e = s.Repair(c, []IdentityRepair{byAddr[direct.Address].Repair}); e != nil {
		t.Fatal(e)
	}
	got, _ = s.Suggest(c)
	if len(got) != 1 || got[0].Address != named.Address {
		t.Fatal("applied suggestion still offered:", got)
	}
	// A peer already linked elsewhere is flagged, and ambiguity is reported.
	if e = s.SightPeers([]Peer{{ID: "n-direct", DNSName: "laptop.example.ts.net.", LANAddrs: []string{"10.0.0.7"}}, {ID: "n-name", DNSName: "den.example.ts.net."}}); e != nil {
		t.Fatal(e)
	}
	got, _ = s.Suggest(c)
	if len(got) != 2 || !got[0].Ambiguous || (got[0].Conflict == "" && got[1].Conflict == "") {
		t.Fatal("ambiguity/conflict not reported:", got)
	}
	// Peers that disappear stop being suggested.
	s.SightPeers(nil)
	if got, _ = s.Suggest(c); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestSwitchEvidenceIsAObservationNotAGrant(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	o := Observation{Scope: "lan", Address: "10.0.0.50", MAC: "00:11:22:33:44:77", Detail: "sw1 Gi1/0/7"}
	if e := s.ObserveSwitch(c, []Observation{o}, 5); e == nil {
		t.Fatal("ttl below the floor accepted")
	}
	if e := s.ObserveSwitch(c, []Observation{o}, 600); e != nil {
		t.Fatal(e)
	}
	snap, _ := s.Snapshot("", "", 0)
	if len(snap.Bindings) != 0 || len(snap.Observations) != 1 || snap.Observations[0].Origin != "switch-snooping" || snap.Observations[0].Detail != "sw1 Gi1/0/7" || snap.Observations[0].Until != now+600 {
		t.Fatal(snap)
	}
	// It corroborates an authenticated self-report exactly like a neighbour entry.
	joined, e := s.Report(c, Node{ID: "n1", DNSName: "node-a.example.ts.net", Interfaces: []InterfaceReport{{MAC: o.MAC, Addresses: []string{o.Address}}}})
	if e != nil || len(joined) != 1 || joined[0].Origin != "neighbor-report" || joined[0].Evidence == "" {
		t.Fatal(joined, e)
	}
	if want := "switch-snooping"; !contains(joined[0].Evidence, want) {
		t.Fatal("evidence does not say where the sighting came from:", joined[0].Evidence)
	}
	events, _ := s.Events(0, 100)
	found := false
	for _, ev := range events {
		if ev.Kind == "observation" && ev.Observation.Origin == "switch-snooping" {
			found = true
		}
	}
	if !found {
		t.Fatal("switch sighting missing from history")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

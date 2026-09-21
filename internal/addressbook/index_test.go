//go:build dhcp

package addressbook

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	bolt "go.etcd.io/bbolt"
)

// seedHistory writes n expired/released bindings straight through save(), the way
// years of churn would, so the indexes see them exactly as production would.
func seedHistory(t *testing.T, s *Store, n int) {
	t.Helper()
	err := s.db.Update(func(tx *bolt.Tx) error {
		for i := 0; i < n; i++ {
			b := Binding{Scope: "lan", Address: fmt.Sprintf("10.9.%d.%d", i/250, i%250+1), Client: fmt.Sprintf("mac:02:00:%02x:%02x:%02x:%02x", i>>24, i>>16, i>>8, i), MAC: "02:00:00:00:00:01",
				State: "expired", Origin: "dhcpv4", Start: 1, End: 2, Device: "old", Name: fmt.Sprintf("old-%d", i)}
			if i%2 == 0 {
				b.State = "released"
			}
			if err := s.save(tx, b, "expire"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Work on the hot paths follows what is live and what is asked about, not how much
// history the ledger has accumulated.
func TestHotPathsDoNotScanHistory(t *testing.T) {
	s := openTest(t)
	c := configPD()
	c.Scopes = append(c.Scopes, testConfig().Scopes[0])
	c.Scopes[0].ID = "v6"
	c.Devices = []DeviceConfig{{ID: "d1", Name: "printer", NodeID: "n1"}}
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	seedHistory(t, s, 20000)
	scansBefore, decodesBefore := bindingScans.Load(), bindingDecodes.Load()

	// IPv4: discover, request, renew, rebind path, release.
	lan := c.Scopes[1]
	if _, e := s.Allocate(c, lan.ID, "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "kitchen", "", false); e != nil {
		t.Fatal(e)
	}
	b, e := s.Allocate(c, lan.ID, "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "kitchen", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Allocate(c, lan.ID, "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "kitchen", "", false); e != nil {
		t.Fatal(e)
	}
	// IPv6 NA and PD for one DUID.
	sid, _ := s.ServerDUID()
	cid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}
	msg := func(kind dhcpv6.MessageType, pd bool) {
		t.Helper()
		r := &dhcpv6.Message{MessageType: kind}
		r.AddOption(dhcpv6.OptClientID(cid))
		if kind != dhcpv6.MessageTypeSolicit {
			r.AddOption(dhcpv6.OptServerID(sid))
		}
		if pd {
			r.AddOption(&dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 1}})
		} else {
			ia := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
			r.AddOption(ia)
		}
		if _, e := s.Handle6Via(c, c.Scopes[0], r, net.ParseIP("fe80::5")); e != nil {
			t.Fatal(e)
		}
	}
	for _, kind := range []dhcpv6.MessageType{dhcpv6.MessageTypeSolicit, dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew} {
		msg(kind, false)
		msg(kind, true)
	}
	// A report, a repair and expiry.
	if _, e = s.Report(c, Node{ID: "n1", DNSName: "kitchen.example.ts.net", Interfaces: []InterfaceReport{{MAC: "00:11:22:33:44:55", Addresses: []string{b.Address}}}}); e != nil {
		t.Fatal(e)
	}
	if e = s.Repair(c, []IdentityRepair{{Scope: lan.ID, Address: b.Address, Client: b.Client, ExpectedDevice: "d1", Device: "d1", Name: "printer", NodeID: "n1", Reason: "test"}}); e != nil {
		t.Fatal(e)
	}
	now += 100000
	if e = s.Expire(); e != nil {
		t.Fatal(e)
	}
	if scans := bindingScans.Load() - scansBefore; scans != 0 {
		t.Fatalf("%d full-ledger scans on the hot paths", scans)
	}
	if d := bindingDecodes.Load() - decodesBefore; d > 400 {
		t.Fatalf("%d bindings decoded for a handful of operations against 20000 historical ones: work follows history", d)
	}
}

// The indexes are candidates only: they must agree with the ledger through every
// transition, and be rebuilt for a ledger written before they existed.
func TestIndexesTrackTransitionsAndBackfill(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	b, _ := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	check := func(client string, want int) {
		t.Helper()
		var got []Binding
		s.db.View(func(tx *bolt.Tx) error { got, _ = liveByClient(tx, "lan", client); return nil })
		if len(got) != want {
			t.Fatalf("client index for %s: %d live, want %d", client, len(got), want)
		}
	}
	check(b.Client, 1)
	s.Release("lan", b.Client, b.Address, false)
	check(b.Client, 0) // released: history, no longer indexed
	b2, _ := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	check(b2.Client, 1)
	var byName, byAddr, byMAC []Binding
	s.db.View(func(tx *bolt.Tx) error {
		byName, _ = activeByName(tx, b2.Name)
		byAddr, _ = liveByAddress(tx, b2.Address)
		byMAC, _ = liveByMAC(tx, b2.MAC)
		return nil
	})
	if len(byName) != 1 || len(byAddr) != 1 || len(byMAC) != 1 {
		t.Fatal("name/address/MAC indexes:", len(byName), len(byAddr), len(byMAC))
	}
	// Drop every index, as in a ledger from before they existed, and reopen.
	path := s.db.Path()
	s.db.Update(func(tx *bolt.Tx) error {
		for _, name := range indexBuckets {
			if e := tx.DeleteBucket(name); e != nil {
				return e
			}
		}
		return nil
	})
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.db.View(func(tx *bolt.Tx) error {
		got, _ := liveByClient(tx, "lan", b2.Client)
		if len(got) != 1 || got[0].Address != b2.Address {
			t.Fatal("indexes were not rebuilt on open:", got)
		}
		return nil
	})
	// A lookup never returns a binding that lapsed into history under a stale entry.
	s2.now = func() time.Time { return time.Unix(now+100000, 0) }
	s2.Expire()
	s2.db.View(func(tx *bolt.Tx) error {
		if got, _ := liveByClient(tx, "lan", b2.Client); len(got) != 0 {
			t.Fatal("expired binding still indexed:", got)
		}
		return nil
	})
}

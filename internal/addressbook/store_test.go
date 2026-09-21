package addressbook

import (
	bolt "go.etcd.io/bbolt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{Scopes: []Scope{{ID: "lan", Interface: "eth0", Subnet: "10.0.0.0/24", Server: "10.0.0.1", Router: "10.0.0.1", Start: "10.0.0.6", End: "10.0.0.8", Zone: "home.arpa", LeaseSeconds: 600, Enabled: true}}}
}
func openTest(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "registry.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestHistoryAndReuse(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(1000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	a, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "node-a", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	now = 1700
	b, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "node-a", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	if a.Device == b.Device {
		t.Fatal("hostname merged unrelated clients")
	}
	past, e := s.Snapshot("lan", "10.0.0.6", 1100)
	if e != nil || past.Bindings[0].Device != a.Device {
		t.Fatal(past, e)
	}
	current, e := s.Snapshot("lan", "10.0.0.6", 0)
	if e != nil || current.Bindings[0].Device != b.Device {
		t.Fatal(current, e)
	}
}
func TestOfferDoesNotShortenActiveLease(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	client := "mac:00:11:22:33:44:55"
	a, e := s.Allocate(c, "lan", client, client[4:], "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	b, e := s.Allocate(c, "lan", client, client[4:], "", "", false)
	if e != nil || b.End != a.End || b.State != "active" {
		t.Fatal(b, e)
	}
}
func TestDurabilityAndConcurrentAllocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	c := testConfig()
	var wg sync.WaitGroup
	addresses := make(chan string, 2)
	for _, mac := range []string{"00:11:22:33:44:55", "00:11:22:33:44:66"} {
		wg.Add(1)
		go func(mac string) {
			defer wg.Done()
			b, e := s.Allocate(c, "lan", "mac:"+mac, mac, "", "", false)
			if e != nil {
				t.Error(e)
			}
			addresses <- b.Address
		}(mac)
	}
	wg.Wait()
	a, b := <-addresses, <-addresses
	if a == b {
		t.Fatal("double allocation")
	}
	s.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	snapshot, e := s.Snapshot("", "", 0)
	if e != nil || len(snapshot.Bindings) != 2 {
		t.Fatal(snapshot, e)
	}
}
func TestAuthenticatedJoinAndConflict(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	mac := "00:11:22:33:44:55"
	_, e := s.Allocate(c, "lan", "mac:"+mac, mac, "node-a", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	n := Node{ID: "node1", DNSName: "node-a.mesh.ts.net.", Addresses: []string{"100.64.0.2"}, Interfaces: []InterfaceReport{{MAC: mac, Addresses: []string{"10.0.0.6"}}}}
	joined, e := s.Report(c, n)
	if e != nil || len(joined) != 1 || joined[0].Name != "node-a" {
		t.Fatal(joined, e)
	}
	n.ID = "attacker"
	if _, e = s.Report(c, n); e == nil {
		t.Fatal("conflicting node accepted")
	}
}

func TestDNSIndexTracksIdentityAndExpiry(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(1000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	b, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	if rows, e := s.DNSBindings("lan", b.Name, ""); e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	joined, e := s.Report(c, Node{ID: "node-a", DNSName: "node-a.example.ts.net.", Interfaces: []InterfaceReport{{MAC: b.MAC, Addresses: []string{b.Address}}}})
	if e != nil || len(joined) != 1 {
		t.Fatal(joined, e)
	}
	if rows, e := s.DNSBindings("lan", b.Name, ""); e != nil || len(rows) != 0 {
		t.Fatal("old name remains indexed", rows, e)
	}
	if rows, e := s.DNSBindings("lan", "node-a", ""); e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	now = b.End
	if rows, e := s.DNSBindings("lan", "node-a", ""); e != nil || len(rows) != 0 {
		t.Fatal("expired name answered before sweep", rows, e)
	}
	if e = s.Expire(); e != nil {
		t.Fatal(e)
	}
	if rows, e := s.DNSBindings("lan", "", b.Address); e != nil || len(rows) != 0 {
		t.Fatal("expired PTR answered", rows, e)
	}
}

func TestSOASerialFollowsDNSConfiguration(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	c := disabled(testConfig())
	apply := func(c Config) uint32 {
		t.Helper()
		if e := m.Apply(c, func() error { return nil }); e != nil {
			t.Fatal(e)
		}
		return s.Revision()
	}
	r1 := apply(c)
	if r1 == 0 {
		t.Fatal("configuration did not advance the serial")
	}
	if r2 := apply(c); r2 != r1 {
		t.Fatal("re-applying identical configuration moved the serial", r1, r2)
	}
	c.Scopes[0].Zone = "lan.example"
	r3 := apply(c)
	if r3 <= r1 {
		t.Fatal("zone change did not advance the serial", r1, r3)
	}
	c.Devices = []DeviceConfig{{ID: "d1", Name: "printer", Aliases: []string{"lp"}}}
	if r4 := apply(c); r4 <= r3 {
		t.Fatal("alias change did not advance the serial", r3, r4)
	}
	// A rollback to older configuration still moves forward.
	old := disabled(testConfig())
	if r5 := apply(old); r5 <= r3 {
		t.Fatal("rollback did not advance the serial")
	}
}

func TestExpiryIndexBoundsWorkAndMigrates(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(1000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	a, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	now += 300
	if _, e = s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", a.Address, true); e != nil { // renew moves the end
		t.Fatal(e)
	}
	now = a.End + 1 // past the original end, before the renewed one
	if e = s.Expire(); e != nil {
		t.Fatal(e)
	}
	cur, _ := s.Snapshot("", "", 0)
	if cur.Bindings[0].State != "active" {
		t.Fatal("stale index entry expired a renewed lease", cur.Bindings[0])
	}
	now += 1000
	if e = s.Expire(); e != nil {
		t.Fatal(e)
	}
	cur, _ = s.Snapshot("", "", 0)
	if cur.Bindings[0].State != "expired" {
		t.Fatal(cur.Bindings[0])
	}
	// A ledger written before the index existed is backfilled on open.
	path := s.db.Path()
	if e = s.db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(expiryBucket) }); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s2, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	s2.now = s.now
	now = 5000
	if _, e = s2.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.7", true); e != nil {
		t.Fatal(e)
	}
	if e = s2.db.Update(func(tx *bolt.Tx) error { return tx.DeleteBucket(expiryBucket) }); e != nil {
		t.Fatal(e)
	}
	s2.Close()
	s3, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s3.Close()
	s3.now = s.now
	now = 9000
	if e = s3.Expire(); e != nil {
		t.Fatal(e)
	}
	got, _ := s3.Snapshot("lan", "10.0.0.7", 0)
	if got.Bindings[0].State != "expired" {
		t.Fatal("index not rebuilt on upgrade", got.Bindings[0])
	}
}

package addressbook

import (
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

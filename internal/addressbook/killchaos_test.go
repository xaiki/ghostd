//go:build dhcp

package addressbook

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// TestLedgerChaosChild hammers a ledger until it is killed.
func TestLedgerChaosChild(t *testing.T) {
	path := os.Getenv("GHOSTD_CHAOS_LEDGER")
	if path == "" {
		t.Skip("child only")
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig()
	c.Scopes[0].Start, c.Scopes[0].End = "10.0.0.2", "10.0.0.200"
	seed := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; ; i++ {
		n := seed.Intn(60)
		mac := fmt.Sprintf("02:00:00:00:00:%02x", n)
		client := "mac:" + mac
		switch seed.Intn(6) {
		case 0, 1, 2:
			if b, e := s.Allocate(c, "lan", client, mac, "h", "", false); e == nil {
				s.Allocate(c, "lan", client, mac, "h", b.Address, true)
			}
		case 3:
			snap, _ := s.Snapshot("lan", "", 0)
			for _, b := range snap.Bindings {
				if b.Client == client && b.State == "active" {
					s.Release("lan", client, b.Address, seed.Intn(3) == 0)
				}
			}
		case 4:
			s.Expire()
		case 5:
			s.Report(c, Node{ID: fmt.Sprint("n", n), DNSName: "h.example.ts.net", Interfaces: []InterfaceReport{{MAC: mac, Addresses: []string{"10.0.0.9"}}}})
		}
	}
}

// verifyLedger checks the invariants a killed process must not have broken.
func verifyLedger(t *testing.T, path string) (bindings int) {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("a ledger killed mid-write no longer opens: %v", err)
	}
	defer s.Close()
	err = s.db.View(func(tx *bolt.Tx) error {
		live := map[string]Binding{}
		if e := tx.Bucket(leaseBucket).ForEach(func(k, raw []byte) error {
			var b Binding
			if e := json.Unmarshal(raw, &b); e != nil {
				return fmt.Errorf("undecodable binding %q: %w", k, e)
			}
			bindings++
			if string(k) != b.Scope+"/"+b.Address {
				return fmt.Errorf("binding filed under the wrong key: %q vs %s/%s", k, b.Scope, b.Address)
			}
			if liveState(b.State) {
				live[string(k)] = b
				for _, e := range indexEntries(b) {
					if tx.Bucket(e.bucket).Get(e.key) == nil {
						return fmt.Errorf("live binding %s is missing from index %s", k, e.bucket)
					}
				}
				if tx.Bucket(expiryBucket).Get(expiryKey(b)) == nil {
					return fmt.Errorf("live binding %s is missing from the expiry index", k)
				}
				if b.State == "active" && b.Origin != originPD && tx.Bucket(dnsBucket).Get(dnsKey(b)) == nil {
					return fmt.Errorf("active binding %s is missing from the DNS index", k)
				}
			}
			return nil
		}); e != nil {
			return e
		}
		// No index entry may point at a binding that is not live (a torn transaction).
		for _, name := range indexBuckets {
			if e := tx.Bucket(name).ForEach(func(k, _ []byte) error {
				parts := bytes.Split(k, []byte{0})
				var key string
				if bytes.Equal(name, addrIdxBucket) {
					key = string(parts[1]) + "/" + string(parts[0])
				} else {
					key = string(parts[1]) + "/" + string(parts[2])
				}
				if _, ok := live[key]; !ok {
					return fmt.Errorf("index %s holds %q for a binding that is not live", name, k)
				}
				return nil
			}); e != nil {
				return e
			}
		}
		if e := tx.Bucket(expiryBucket).ForEach(func(k, _ []byte) error {
			if _, ok := live[string(k[8:])]; !ok {
				return fmt.Errorf("expiry index holds %q for a binding that is not live", k[8:])
			}
			return nil
		}); e != nil {
			return e
		}
		// Events: strictly increasing ids, no gaps (one transaction writes a binding
		// and its event together, so a kill cannot separate them).
		var last uint64
		return tx.Bucket(eventBucket).ForEach(func(k, _ []byte) error {
			id := binary.BigEndian.Uint64(k)
			if id != last+1 {
				return fmt.Errorf("event ids skip from %d to %d", last, id)
			}
			last = id
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	// Every live binding still answers a lookup the way the ledger says.
	snap, _ := s.Snapshot("lan", "", 0)
	seen := map[string]string{}
	for _, b := range snap.Bindings {
		if b.State == "active" && b.End > time.Now().Unix() {
			if other, dup := seen[b.Address]; dup {
				t.Fatalf("address %s is held by %s and %s", b.Address, other, b.Client)
			}
			seen[b.Address] = b.Client
		}
	}
	return bindings
}

// Kill -9 the process hammering the ledger, at random moments, many times: after
// every kill the ledger opens and is fully consistent — bindings, indexes and event
// log agree — because each change is one bolt transaction.
func TestLedgerSurvivesRepeatedKills(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chaos.db")
	rng := rand.New(rand.NewSource(1))
	total := 0
	for round := 0; round < 15; round++ {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerChaosChild$")
		cmd.Env = append(os.Environ(), "GHOSTD_CHAOS_LEDGER="+path)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Duration(80+rng.Intn(220)) * time.Millisecond)
		cmd.Process.Signal(syscall.SIGKILL)
		cmd.Wait()
		total = verifyLedger(t, path)
	}
	if total < 5 {
		t.Fatalf("the children did almost no work (%d bindings): the test proved nothing", total)
	}
	t.Logf("%d bindings survived 15 kills", total)
}

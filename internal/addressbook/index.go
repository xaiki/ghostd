//go:build dhcp

package addressbook

import (
	"bytes"
	"encoding/json"
	"sync/atomic"

	bolt "go.etcd.io/bbolt"
)

// Secondary indexes over *live* bindings (active, offered, declined), so the hot
// paths — allocation, renewal, reports, repair, delegation — read what they need
// instead of the whole ledger. History (released, expired) is never indexed and
// never scanned on these paths; it can grow without slowing them. Each index is
// maintained in save() with the binding, backfilled on open for a ledger without
// it, and its entries are only ever candidates: readers re-read the binding and
// re-check its state and end time.
var (
	clientIdxBucket = []byte("idx-client-v1") // client \0 scope \0 address
	macIdxBucket    = []byte("idx-mac-v1")    // mac    \0 scope \0 address
	nameIdxBucket   = []byte("idx-name-v1")   // name   \0 scope \0 address   (active, named)
	addrIdxBucket   = []byte("idx-addr-v1")   // address \0 scope
)

var indexBuckets = [][]byte{clientIdxBucket, macIdxBucket, nameIdxBucket, addrIdxBucket}

// bindingScans counts full-ledger scans, so tests can prove hot paths avoid them.
var bindingScans atomic.Int64

// bindingDecodes counts every binding decoded on the indexed paths (point reads
// and counted scans), so tests can prove work does not grow with history.
var bindingDecodes atomic.Int64

func indexEntries(b Binding) (entries []struct{ bucket, key []byte }) {
	if !liveState(b.State) {
		return nil
	}
	add := func(bucket []byte, parts ...string) {
		var k []byte
		for i, p := range parts {
			if i > 0 {
				k = append(k, 0)
			}
			k = append(k, p...)
		}
		entries = append(entries, struct{ bucket, key []byte }{bucket, k})
	}
	add(clientIdxBucket, b.Client, b.Scope, b.Address)
	if b.MAC != "" {
		add(macIdxBucket, b.MAC, b.Scope, b.Address)
	}
	if b.State == "active" && b.Name != "" {
		add(nameIdxBucket, b.Name, b.Scope, b.Address)
	}
	add(addrIdxBucket, b.Address, b.Scope)
	return entries
}

// reindex moves a binding's index entries from its old value to its new one.
func reindex(tx *bolt.Tx, old, b Binding) error {
	for _, e := range indexEntries(old) {
		if err := tx.Bucket(e.bucket).Delete(e.key); err != nil {
			return err
		}
	}
	for _, e := range indexEntries(b) {
		if err := tx.Bucket(e.bucket).Put(e.key, []byte{1}); err != nil {
			return err
		}
	}
	return nil
}

// backfillIndexes builds the indexes from the ledger, once, on upgrade.
func backfillIndexes(tx *bolt.Tx) error {
	return tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
		var b Binding
		if e := json.Unmarshal(raw, &b); e != nil {
			return e
		}
		return reindex(tx, Binding{}, b)
	})
}

// liveFromIndex returns the live bindings whose index key starts with prefix,
// re-reading each and dropping any that is no longer live. Keys are
// "x\0scope\0address" except the address index, "address\0scope".
func liveFromIndex(tx *bolt.Tx, bucket, prefix []byte) ([]Binding, error) {
	var out []Binding
	c := tx.Bucket(bucket).Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		parts := bytes.Split(k, []byte{0})
		var scope, address string
		switch {
		case bytes.Equal(bucket, addrIdxBucket) && len(parts) == 2:
			address, scope = string(parts[0]), string(parts[1])
		case len(parts) == 3:
			scope, address = string(parts[1]), string(parts[2])
		default:
			continue
		}
		b, err := readBinding(tx, scope, address)
		if err != nil {
			return nil, err
		}
		if b.Scope == "" || !liveState(b.State) {
			continue
		}
		out = append(out, b)
	}
	return out, nil
}

func idxPrefix(parts ...string) []byte {
	var k []byte
	for _, p := range parts {
		k = append(k, p...)
		k = append(k, 0)
	}
	return k
}

// liveByClient: a client's live bindings in one scope.
func liveByClient(tx *bolt.Tx, scope, client string) ([]Binding, error) {
	return liveFromIndex(tx, clientIdxBucket, idxPrefix(client, scope))
}

// liveByClientPrefix: live bindings of every client whose identity starts with
// prefix (for example every IAID of one DUID), in any scope.
func liveByClientPrefix(tx *bolt.Tx, prefix string) ([]Binding, error) {
	var out []Binding
	c := tx.Bucket(clientIdxBucket).Cursor()
	p := []byte(prefix)
	for k, _ := c.Seek(p); k != nil && bytes.HasPrefix(k, p); k, _ = c.Next() {
		parts := bytes.Split(k, []byte{0})
		if len(parts) != 3 {
			continue
		}
		b, err := readBinding(tx, string(parts[1]), string(parts[2]))
		if err != nil {
			return nil, err
		}
		if b.Scope != "" && liveState(b.State) {
			out = append(out, b)
		}
	}
	return out, nil
}

// liveByAddress: the live bindings at an address, across scopes.
func liveByAddress(tx *bolt.Tx, address string) ([]Binding, error) {
	return liveFromIndex(tx, addrIdxBucket, idxPrefix(address))
}

// liveByMAC: a hardware address's live bindings.
func liveByMAC(tx *bolt.Tx, mac string) ([]Binding, error) {
	return liveFromIndex(tx, macIdxBucket, idxPrefix(mac))
}

// activeByName: the active bindings carrying a DNS name, across scopes.
func activeByName(tx *bolt.Tx, name string) ([]Binding, error) {
	all, err := liveFromIndex(tx, nameIdxBucket, idxPrefix(name))
	var out []Binding
	for _, b := range all {
		if b.State == "active" && b.Name == name {
			out = append(out, b)
		}
	}
	return out, err
}

// forEachBinding is the counted full-ledger scan, for the paths that really need
// history (Snapshot at a past instant, adoption checks).
func forEachBinding(tx *bolt.Tx, fn func(Binding) error) error {
	bindingScans.Add(1)
	return tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
		var b Binding
		if e := json.Unmarshal(raw, &b); e != nil {
			return e
		}
		bindingDecodes.Add(1)
		return fn(b)
	})
}

// forEachLive iterates only the live bindings, through the expiry index (which
// holds exactly the live set), never history.
func forEachLive(tx *bolt.Tx, fn func(Binding) error) error {
	c := tx.Bucket(expiryBucket).Cursor()
	for k, _ := c.First(); k != nil; k, _ = c.Next() {
		raw := tx.Bucket(leaseBucket).Get(k[8:])
		if raw == nil {
			continue
		}
		var b Binding
		if e := json.Unmarshal(raw, &b); e != nil {
			return e
		}
		bindingDecodes.Add(1)
		if liveState(b.State) {
			if e := fn(b); e != nil {
				return e
			}
		}
	}
	return nil
}

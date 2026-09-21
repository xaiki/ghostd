//go:build dhcp

package addressbook

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// Warm-standby replication. One authority serves; a standby mirrors its ledger
// so that, if the authority is lost, promoting the standby continues every
// lease, identity association, server DUID and delegation instead of starting
// from nothing. This is active/passive with a manual, fenced promotion, not
// multi-master: two authorities allocating from one pool would hand out the
// same address twice, and deciding by itself that its peer is dead is exactly
// the split-brain a DHCP server must not risk.

var replicaCursorKey = []byte("replica-cursor")

// ReplicaCursor is the last leader event the ledger has applied.
func (s *Store) ReplicaCursor() uint64 {
	var c uint64
	_ = s.db.View(func(tx *bolt.Tx) error {
		if m := tx.Bucket(metaBucket); m != nil {
			if v := m.Get(replicaCursorKey); len(v) == 8 {
				c = binary.BigEndian.Uint64(v)
			}
		}
		return nil
	})
	return c
}

// ApplyReplicated applies the leader's events in order, then (when given) its
// snapshot for the state events do not carry: the server DUID, tailnet nodes and
// durable associations. Everything happens in one transaction, and the cursor
// advances with it, so an interrupted sync repeats rather than skips.
func (s *Store) ApplyReplicated(events []Event, snap *Snapshot) (uint64, error) {
	cursor := s.ReplicaCursor()
	err := s.db.Update(func(tx *bolt.Tx) error {
		for _, ev := range events {
			if ev.ID <= cursor {
				continue
			}
			switch {
			case ev.Observation != nil:
				o := *ev.Observation
				if ev.Kind == "observation" {
					raw, e := json.Marshal(o)
					if e != nil {
						return e
					}
					if e = tx.Bucket(observationBucket).Put(bindingKey(o.Scope, o.Address), raw); e != nil {
						return e
					}
				}
				if e := appendEvent(tx, Event{Time: ev.Time, Kind: ev.Kind, Observation: &o}); e != nil {
					return e
				}
			case ev.Binding.Scope != "":
				if e := s.save(tx, ev.Binding, ev.Kind); e != nil {
					return e
				}
			}
			cursor = ev.ID
		}
		if snap != nil {
			meta, e := tx.CreateBucketIfNotExists(metaBucket)
			if e != nil {
				return e
			}
			if snap.ServerDUID != "" {
				raw, e := hex.DecodeString(strings.ReplaceAll(snap.ServerDUID, ":", ""))
				if e != nil {
					return fmt.Errorf("replicated server DUID: %w", e)
				}
				if e = meta.Put([]byte("duid"), raw); e != nil {
					return e
				}
			}
			for _, bucket := range [][]byte{nodeBucket, associationBucket} {
				var stale [][]byte
				_ = tx.Bucket(bucket).ForEach(func(k, _ []byte) error { stale = append(stale, append([]byte(nil), k...)); return nil })
				for _, k := range stale {
					if e = tx.Bucket(bucket).Delete(k); e != nil {
						return e
					}
				}
			}
			for _, n := range snap.Nodes {
				raw, e := json.Marshal(n)
				if e != nil {
					return e
				}
				if e = tx.Bucket(nodeBucket).Put([]byte(n.ID), raw); e != nil {
					return e
				}
			}
			for _, a := range snap.Associations {
				raw, e := json.Marshal(a)
				if e != nil {
					return e
				}
				if e = tx.Bucket(associationBucket).Put([]byte(a.Client), raw); e != nil {
					return e
				}
			}
		}
		meta, e := tx.CreateBucketIfNotExists(metaBucket)
		if e != nil {
			return e
		}
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], cursor)
		return meta.Put(replicaCursorKey, buf[:])
	})
	return cursor, err
}

// SetStandby marks the manager a warm standby: it will not enable any scope, so
// no listener can compete with the authority it mirrors, until it is promoted.
func (m *Manager) SetStandby(on bool) {
	m.mu.Lock()
	m.standby = on
	m.mu.Unlock()
}
func (m *Manager) Standby() bool { m.mu.RLock(); defer m.mu.RUnlock(); return m.standby }

// Disabled returns the configuration with every scope switched off.
func Disabled(c Config) Config { return disabled(c) }

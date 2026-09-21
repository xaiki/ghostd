package addressbook

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"
)

var leaseBucket = []byte("bindings-v1")
var eventBucket = []byte("events-v1")
var nodeBucket = []byte("nodes-v1")
var dnsBucket = []byte("dns-v1")

type Store struct {
	db  *bolt.DB
	now func() time.Time
}
type Binding struct {
	DUID         string `json:"duid,omitempty"`
	IAID         string `json:"iaid,omitempty"`
	PreferredEnd int64  `json:"preferred_end,omitempty"`
	Scope        string `json:"scope"`
	Address      string `json:"address"`
	Client       string `json:"client"`
	MAC          string `json:"mac"`
	Device       string `json:"device"`
	Name         string `json:"name"`
	ClaimedName  string `json:"claimed_name,omitempty"`
	State        string `json:"state"`
	Origin       string `json:"origin"`
	Start        int64  `json:"start"` // imported start is observation time, not invented grant time
	End          int64  `json:"end"`
	NodeID       string `json:"tailnet_node_id,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
}
type Event struct {
	Message string  `json:"message,omitempty"`
	ID      uint64  `json:"id"`
	Time    int64   `json:"time"`
	Kind    string  `json:"kind"`
	Binding Binding `json:"binding"`
}
type Node struct {
	ID         string            `json:"id"`
	DNSName    string            `json:"dns_name"`
	Addresses  []string          `json:"addresses"`
	Interfaces []InterfaceReport `json:"interfaces"`
	Seen       int64             `json:"seen"`
}
type InterfaceReport struct {
	MAC       string   `json:"mac"`
	Addresses []string `json:"addresses"`
}
type Snapshot struct {
	Observations []Observation `json:"observations"`
	ServerDUID   string        `json:"server_duid,omitempty"`
	Bindings     []Binding     `json:"bindings"`
	Nodes        []Node        `json:"nodes"`
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, now: time.Now}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{leaseBucket, eventBucket, nodeBucket, observationBucket} {
			if _, e := tx.CreateBucketIfNotExists(name); e != nil {
				return e
			}
		}
		// Reconstruct the index once when upgrading a ledger without it.
		if tx.Bucket(dnsBucket) == nil {
			index, e := tx.CreateBucket(dnsBucket)
			if e != nil {
				return e
			}
			return tx.Bucket(leaseBucket).ForEach(func(k, raw []byte) error {
				var b Binding
				if e := json.Unmarshal(raw, &b); e != nil {
					return e
				}
				if b.State == "active" {
					return index.Put(dnsKey(b), k)
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error                 { return s.db.Close() }
func bindingKey(scope, address string) []byte { return []byte(scope + "/" + address) }
func readBinding(tx *bolt.Tx, scope, address string) (Binding, error) {
	var b Binding
	raw := tx.Bucket(leaseBucket).Get(bindingKey(scope, address))
	if raw == nil {
		return b, nil
	}
	err := json.Unmarshal(raw, &b)
	return b, err
}
func dnsKey(b Binding) []byte { return []byte(b.Scope + "/" + b.Name + "/" + b.Address) }
func (s *Store) save(tx *bolt.Tx, b Binding, kind string) error {
	old, err := readBinding(tx, b.Scope, b.Address)
	if err != nil {
		return err
	}
	if old.Name != "" {
		if err := tx.Bucket(dnsBucket).Delete(dnsKey(old)); err != nil {
			return err
		}
	}
	if b.State == "active" {
		if err := tx.Bucket(dnsBucket).Put(dnsKey(b), bindingKey(b.Scope, b.Address)); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if err = tx.Bucket(leaseBucket).Put(bindingKey(b.Scope, b.Address), raw); err != nil {
		return err
	}
	events := tx.Bucket(eventBucket)
	id, err := events.NextSequence()
	if err != nil {
		return err
	}
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], id)
	raw, err = json.Marshal(Event{ID: id, Time: s.now().Unix(), Kind: kind, Binding: b})
	if err != nil {
		return err
	}
	return events.Put(key[:], raw)
}
func (s *Store) Snapshot(scope, ip string, at int64) (Snapshot, error) {
	result := Snapshot{Bindings: []Binding{}, Nodes: []Node{}}
	now := s.now().Unix()
	if at == 0 {
		at = now
	}
	if at < 0 {
		return result, fmt.Errorf("at must be a nonnegative Unix timestamp")
	}
	if at > now {
		return result, fmt.Errorf("future attribution is not available")
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		if meta := tx.Bucket(metaBucket); meta != nil {
			result.ServerDUID = fmt.Sprintf("%x", meta.Get([]byte("duid")))
		}
		states := map[string]Binding{}
		collect := func(b Binding) {
			if (scope == "" || b.Scope == scope) && (ip == "" || b.Address == ip) {
				states[string(bindingKey(b.Scope, b.Address))] = b
			}
		}
		if at == now {
			if e := tx.Bucket(leaseBucket).ForEach(func(_, v []byte) error {
				var b Binding
				if e := json.Unmarshal(v, &b); e != nil {
					return e
				}
				collect(b)
				return nil
			}); e != nil {
				return e
			}
		} else {
			if e := tx.Bucket(eventBucket).ForEach(func(_, v []byte) error {
				var event Event
				if e := json.Unmarshal(v, &event); e != nil {
					return e
				}
				if event.Time <= at {
					if event.Binding.Scope != "" {
						collect(event.Binding)
					}
				}
				return nil
			}); e != nil {
				return e
			}
		}
		for _, b := range states {
			if b.End <= at && (b.State == "active" || b.State == "offered" || b.State == "declined") {
				b.State = "expired"
			}
			result.Bindings = append(result.Bindings, b)
		}
		if e := tx.Bucket(observationBucket).ForEach(func(_, v []byte) error {
			var o Observation
			if e := json.Unmarshal(v, &o); e != nil {
				return e
			}
			if (scope == "" || o.Scope == scope) && (ip == "" || o.Address == ip) {
				result.Observations = append(result.Observations, o)
			}
			return nil
		}); e != nil {
			return e
		}
		// Current node sightings are labelled with Seen; history lives on binding events.
		return tx.Bucket(nodeBucket).ForEach(func(_, v []byte) error {
			var n Node
			if e := json.Unmarshal(v, &n); e != nil {
				return e
			}
			result.Nodes = append(result.Nodes, n)
			return nil
		})
	})
	sort.Slice(result.Bindings, func(i, j int) bool {
		a, b := result.Bindings[i], result.Bindings[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return a.Address < b.Address
	})
	return result, err
}
func (s *Store) Events(after uint64, limit int) ([]Event, error) {
	if limit < 1 || limit > 1000 {
		return nil, fmt.Errorf("limit must be 1..1000")
	}
	out := []Event{}
	err := s.db.View(func(tx *bolt.Tx) error {
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], after)
		c := tx.Bucket(eventBucket).Cursor()
		for k, v := c.Seek(key[:]); k != nil && len(out) < limit; k, v = c.Next() {
			if binary.BigEndian.Uint64(k) <= after {
				continue
			}
			var e Event
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}

// DNSBindings uses the materialized name index or the exact scoped IP key.
// It never scans lease history or node reports on the request path.
func (s *Store) DNSBindings(scope, name, address string) ([]Binding, error) {
	result := []Binding{}
	err := s.db.View(func(tx *bolt.Tx) error {
		appendBinding := func(raw []byte) error {
			if raw == nil {
				return nil
			}
			var b Binding
			if e := json.Unmarshal(raw, &b); e != nil {
				return e
			}
			if b.State == "active" && b.End > s.now().Unix() {
				result = append(result, b)
			}
			return nil
		}
		if address != "" {
			return appendBinding(tx.Bucket(leaseBucket).Get(bindingKey(scope, address)))
		}
		prefix := []byte(scope + "/" + name + "/")
		cursor := tx.Bucket(dnsBucket).Cursor()
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			if e := appendBinding(tx.Bucket(leaseBucket).Get(v)); e != nil {
				return e
			}
		}
		return nil
	})
	return result, err
}

func (s *Store) Revision() uint32 {
	var revision uint64
	_ = s.db.View(func(tx *bolt.Tx) error { revision = tx.Bucket(eventBucket).Sequence(); return nil })
	return uint32(revision)
}

func (s *Store) audit(kind, message string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(eventBucket)
		id, e := bucket.NextSequence()
		if e != nil {
			return e
		}
		var key [8]byte
		binary.BigEndian.PutUint64(key[:], id)
		raw, e := json.Marshal(Event{ID: id, Time: s.now().Unix(), Kind: kind, Message: message})
		if e != nil {
			return e
		}
		return bucket.Put(key[:], raw)
	})
}

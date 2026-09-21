package addressbook

import (
	"bytes"
	"crypto/sha256"
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
var expiryBucket = []byte("expiry-v1")
var associationBucket = []byte("associations-v1")

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
	// Observation is set on kernel-sighting events. It keeps evidence history
	// apart from DHCP grants: the sighting's own Seen/Until bound its validity,
	// not the event's Time.
	Observation *Observation `json:"observation,omitempty"`
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
	// Associations are current only; a past instant is answered from binding events.
	Associations []Association `json:"associations,omitempty"`
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
		backfill := tx.Bucket(expiryBucket) == nil
		for _, name := range [][]byte{leaseBucket, eventBucket, nodeBucket, observationBucket, associationBucket, expiryBucket} {
			if _, e := tx.CreateBucketIfNotExists(name); e != nil {
				return e
			}
		}
		if backfill {
			if e := tx.Bucket(leaseBucket).ForEach(func(k, raw []byte) error {
				var b Binding
				if e := json.Unmarshal(raw, &b); e != nil {
					return e
				}
				if liveState(b.State) {
					return tx.Bucket(expiryBucket).Put(expiryKey(b), []byte{1})
				}
				return nil
			}); e != nil {
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
func liveState(state string) bool {
	return state == "active" || state == "offered" || state == "declined"
}

// expiryKey orders live bindings by end time so expiry reads only what is due.
func expiryKey(b Binding) []byte {
	key := make([]byte, 8, 8+len(b.Scope)+len(b.Address)+1)
	binary.BigEndian.PutUint64(key, uint64(b.End))
	return append(key, bindingKey(b.Scope, b.Address)...)
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
	if liveState(old.State) {
		if err := tx.Bucket(expiryBucket).Delete(expiryKey(old)); err != nil {
			return err
		}
	}
	if liveState(b.State) {
		if err := tx.Bucket(expiryBucket).Put(expiryKey(b), []byte{1}); err != nil {
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
		sightings := map[string]Observation{}
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
					if o := event.Observation; o != nil && (scope == "" || o.Scope == scope) && (ip == "" || o.Address == ip) {
						sightings[string(bindingKey(o.Scope, o.Address))] = *o
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
		if at == now {
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
		} else {
			// Only sightings whose own validity window covered the instant are
			// evidence for it; a later sighting of the address is not.
			for _, o := range sightings {
				if o.Seen <= at && at < o.Until {
					o.Historical = true
					result.Observations = append(result.Observations, o)
				}
			}
			sort.Slice(result.Observations, func(i, j int) bool {
				a, b := result.Observations[i], result.Observations[j]
				return a.Scope+"/"+a.Address < b.Scope+"/"+b.Address
			})
		}
		if at == now {
			if e := tx.Bucket(associationBucket).ForEach(func(_, v []byte) error {
				var a Association
				if e := json.Unmarshal(v, &a); e != nil {
					return e
				}
				result.Associations = append(result.Associations, a)
				return nil
			}); e != nil {
				return e
			}
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

// appendEvent appends within an open transaction.
func appendEvent(tx *bolt.Tx, e Event) error {
	bucket := tx.Bucket(eventBucket)
	id, err := bucket.NextSequence()
	if err != nil {
		return err
	}
	e.ID = id
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], id)
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return bucket.Put(key[:], raw)
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

// NoteDNSConfig appends a "dns-config" event, and so advances the SOA serial,
// when the DNS-visible part of the configuration differs from the last one
// noted. The fingerprint is durable, so a restart with unchanged configuration
// keeps the serial, while a rollback to older configuration still moves it
// forward.
func (s *Store) NoteDNSConfig(c Config) error {
	type view struct {
		Scopes  []Scope        `json:"scopes"`
		Devices []DeviceConfig `json:"devices"`
	}
	raw, err := json.Marshal(view{c.Scopes, c.Devices})
	if err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	return s.db.Update(func(tx *bolt.Tx) error {
		meta, e := tx.CreateBucketIfNotExists(metaBucket)
		if e != nil {
			return e
		}
		if bytes.Equal(meta.Get([]byte("dns-config")), sum[:]) {
			return nil
		}
		if e = meta.Put([]byte("dns-config"), sum[:]); e != nil {
			return e
		}
		return appendEvent(tx, Event{Time: s.now().Unix(), Kind: "dns-config", Message: fmt.Sprintf("%x", sum[:8])})
	})
}

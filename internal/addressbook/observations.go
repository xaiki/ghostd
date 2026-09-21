//go:build dhcp

package addressbook

import (
	"context"
	"encoding/json"
	"fmt"
	bolt "go.etcd.io/bbolt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

var observationBucket = []byte("observations-v1")

type Observation struct {
	Scope   string `json:"scope"`
	Address string `json:"address"`
	MAC     string `json:"mac"`
	Origin  string `json:"origin"`
	// Detail names where the sighting came from, for example a switch port.
	Detail string `json:"detail,omitempty"`
	Seen   int64  `json:"seen"`
	Until  int64  `json:"until"`
	// Historical marks evidence reconstructed from the event log for a past
	// instant, as opposed to a current sighting.
	Historical bool `json:"historical,omitempty"`
}

// Observe records kernel neighbor evidence separately from DHCP allocations.
// It neither claims a grant nor publishes an uncorroborated name in DNS.
func (s *Store) Observe(c Config, observations []Observation) error {
	for i := range observations {
		observations[i].Origin = "kernel-neighbor"
	}
	return s.observe(c, observations, 120)
}

// ObserveSwitch records DHCP-snooping / MAC-table evidence exported by a
// switch. It is stored and aged exactly like a kernel sighting and is equally
// never a grant; ttl bounds how long the switch's word is trusted.
func (s *Store) ObserveSwitch(c Config, observations []Observation, ttl int64) error {
	if ttl < 10 || ttl > 3600 {
		return fmt.Errorf("ttl must be 10..3600 seconds")
	}
	for i := range observations {
		observations[i].Origin = "switch-snooping"
		if len(observations[i].Detail) > 128 {
			return fmt.Errorf("observation detail too long")
		}
	}
	return s.observe(c, observations, ttl)
}

func (s *Store) observe(c Config, observations []Observation, ttl int64) error {
	if len(observations) > 10000 {
		return fmt.Errorf("too many observations")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, o := range observations {
			scope, ok := c.Scope(o.Scope)
			if !ok {
				return fmt.Errorf("unknown observation scope")
			}
			ip, e := netip.ParseAddr(o.Address)
			if e != nil || !netip.MustParsePrefix(scope.Subnet).Contains(ip) {
				return fmt.Errorf("observation outside scope")
			}
			mac, e := net.ParseMAC(o.MAC)
			if e != nil || len(mac) != 6 {
				return fmt.Errorf("invalid observation MAC")
			}
			o.Address = ip.String()
			o.MAC = mac.String()
			o.Seen = s.now().Unix()
			o.Until = o.Seen + ttl
			raw, e := json.Marshal(o)
			if e != nil {
				return e
			}
			key := bindingKey(o.Scope, o.Address)
			// Refreshing an unchanged, still-valid sighting only extends the
			// latest bucket; a first sighting, a changed MAC or a sighting after
			// the previous one expired is history worth keeping.
			var prev Observation
			old := tx.Bucket(observationBucket).Get(key)
			fresh := old == nil || json.Unmarshal(old, &prev) != nil || prev.MAC != o.MAC || prev.Until <= o.Seen
			if e = tx.Bucket(observationBucket).Put(key, raw); e != nil {
				return e
			}
			if fresh {
				if old != nil && prev.Until > 0 && (prev.MAC != o.MAC || prev.Until <= o.Seen) {
					// Close out the earlier sighting at its own expiry, or now if
					// a different MAC superseded it while still valid.
					if prev.Until > o.Seen {
						prev.Until = o.Seen
					}
					if e = appendEvent(tx, Event{Time: s.now().Unix(), Kind: "observation-end", Observation: &prev}); e != nil {
						return e
					}
				}
				oc := o
				if e = appendEvent(tx, Event{Time: s.now().Unix(), Kind: "observation", Observation: &oc}); e != nil {
					return e
				}
			}
		}
		return nil
	})
}

// CollectNeighbors uses only fresh reachable/permanent kernel entries. STALE
// entries can be arbitrarily old and must not refresh identity corroboration.
func (m *Manager) CollectNeighbors(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	raw, e := exec.CommandContext(ctx, "ip", "-j", "neigh", "show").Output()
	if e != nil {
		return e
	}
	if len(raw) > 4<<20 {
		return fmt.Errorf("neighbor table exceeds limit")
	}
	var rows []struct {
		Address   string   `json:"dst"`
		MAC       string   `json:"lladdr"`
		Interface string   `json:"dev"`
		State     []string `json:"state"`
	}
	if e = json.Unmarshal(raw, &rows); e != nil {
		return e
	}
	c := m.Config()
	var observations []Observation
	for _, r := range rows {
		if !strings.Contains(" "+strings.Join(r.State, " ")+" ", " REACHABLE ") && !strings.Contains(" "+strings.Join(r.State, " ")+" ", " PERMANENT ") {
			continue
		}
		ip, e := netip.ParseAddr(r.Address)
		if e != nil {
			continue
		}
		for _, scope := range c.Scopes {
			if scope.Interface == r.Interface && scope.Relay == nil && netip.MustParsePrefix(scope.Subnet).Contains(ip) {
				observations = append(observations, Observation{Scope: scope.ID, Address: ip.String(), MAC: r.MAC})
			}
		}
	}
	return m.Store.Observe(c, observations)
}

type IdentityRepair struct {
	Scope          string `json:"scope"`
	Address        string `json:"address"`
	Client         string `json:"client"`
	ExpectedDevice string `json:"expected_device"`
	Device         string `json:"device"`
	Name           string `json:"name"`
	NodeID         string `json:"tailnet_node_id"`
	Reason         string `json:"reason"`
	// Persist records the edit as a durable client association, so the identity
	// follows the client across expiry, reallocation and address changes.
	Persist bool `json:"persist,omitempty"`
	// Forget removes the client's association (the binding edit still applies).
	Forget bool `json:"forget,omitempty"`
}

// Association is an operator-asserted, durable client → device mapping. It is
// consulted by allocation, is never rewritten by lease expiry, and keeps every
// replaced mapping in History so historical ownership stays answerable.
type Association struct {
	Client  string               `json:"client"`
	Device  string               `json:"device"`
	Name    string               `json:"name"`
	NodeID  string               `json:"tailnet_node_id,omitempty"`
	Reason  string               `json:"reason"`
	Updated int64                `json:"updated"`
	History []AssociationVersion `json:"history,omitempty"`
}
type AssociationVersion struct {
	Device  string `json:"device"`
	Name    string `json:"name"`
	NodeID  string `json:"tailnet_node_id,omitempty"`
	Reason  string `json:"reason"`
	Updated int64  `json:"updated"`
	Ended   int64  `json:"ended"`
}

func readAssociation(tx *bolt.Tx, client string) (Association, bool, error) {
	raw := tx.Bucket(associationBucket).Get([]byte(client))
	if raw == nil {
		return Association{}, false, nil
	}
	var a Association
	return a, true, json.Unmarshal(raw, &a)
}

func (s *Store) putAssociation(tx *bolt.Tx, r IdentityRepair) error {
	if r.Forget {
		if _, ok, e := readAssociation(tx, r.Client); e != nil || !ok {
			return e
		}
		return tx.Bucket(associationBucket).Delete([]byte(r.Client))
	}
	if !r.Persist {
		return nil
	}
	now := s.now().Unix()
	a, ok, e := readAssociation(tx, r.Client)
	if e != nil {
		return e
	}
	if ok && (a.Device != r.Device || a.Name != r.Name || a.NodeID != r.NodeID) {
		a.History = append(a.History, AssociationVersion{Device: a.Device, Name: a.Name, NodeID: a.NodeID, Reason: a.Reason, Updated: a.Updated, Ended: now})
	}
	a.Client, a.Device, a.Name, a.NodeID, a.Reason, a.Updated = r.Client, r.Device, r.Name, r.NodeID, r.Reason, now
	raw, e := json.Marshal(a)
	if e != nil {
		return e
	}
	return tx.Bucket(associationBucket).Put([]byte(r.Client), raw)
}

// Repair supports explicit merge/split/unlink by assigning selected bindings in
// one transaction. Compare-and-swap prevents a stale repair affecting IP reuse.
func (s *Store) Repair(c Config, changes []IdentityRepair) error {
	if len(changes) == 0 || len(changes) > 256 {
		return fmt.Errorf("repair needs 1..256 bindings")
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, r := range changes {
			if !labelPattern.MatchString(r.Device) || !labelPattern.MatchString(r.Name) || r.Name == "ns" || strings.TrimSpace(r.Reason) == "" || len(r.Reason) > 512 {
				return fmt.Errorf("repair requires valid device/name and reason")
			}
			for _, d := range c.Devices {
				// Declared node identity may be several ids; a repair must name
				// one of them, exactly as automatic reports are judged.
				if ((d.Name == r.Name || d.HasAlias(r.Name)) && d.ID != r.Device) || (d.ID == r.Device && (d.Name != r.Name || (d.DeclaresNodes() && !d.HasNode(r.NodeID)))) {
					return fmt.Errorf("repair conflicts with inventory")
				}
			}
			// The name must also not belong to another live, undeclared device.
			now := s.now().Unix()
			holders, e := activeByName(tx, r.Name)
			if e != nil {
				return e
			}
			for _, other := range holders {
				if other.Device != r.Device && other.End > now && !(other.Scope == r.Scope && other.Address == r.Address) {
					return fmt.Errorf("name %q is already held by live device %s", r.Name, other.Device)
				}
			}
			b, e := readBinding(tx, r.Scope, r.Address)
			if e != nil {
				return e
			}
			if b.Client != r.Client || b.Device != r.ExpectedDevice || b.State != "active" || b.End <= s.now().Unix() {
				return fmt.Errorf("binding changed; refresh before repairing")
			}
			if scope, ok := c.Scope(b.Scope); ok {
				if reserved, ok := reservation(scope, b.Client, b.MAC); ok && reserved.Device != r.Device {
					return fmt.Errorf("change inventory reservation before repairing this binding")
				}
			}
			b.Device = r.Device
			b.Name = r.Name
			b.NodeID = r.NodeID
			b.Evidence = "operator repair: " + r.Reason
			if e = s.save(tx, b, "identity-repair"); e != nil {
				return e
			}
			if e = s.putAssociation(tx, r); e != nil {
				return e
			}
		}
		return nil
	})
}

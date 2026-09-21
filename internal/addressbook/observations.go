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
	Seen    int64  `json:"seen"`
	Until   int64  `json:"until"`
}

// Observe records kernel neighbor evidence separately from DHCP allocations.
// It neither claims a grant nor publishes an uncorroborated name in DNS.
func (s *Store) Observe(c Config, observations []Observation) error {
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
			o.Origin = "kernel-neighbor"
			o.Seen = s.now().Unix()
			o.Until = o.Seen + 120
			raw, e := json.Marshal(o)
			if e != nil {
				return e
			}
			if e = tx.Bucket(observationBucket).Put(bindingKey(o.Scope, o.Address), raw); e != nil {
				return e
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
				if ((d.Name == r.Name || d.HasAlias(r.Name)) && d.ID != r.Device) || (d.ID == r.Device && (d.Name != r.Name || (d.NodeID != "" && d.NodeID != r.NodeID))) {
					return fmt.Errorf("repair conflicts with inventory")
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
		}
		return nil
	})
}

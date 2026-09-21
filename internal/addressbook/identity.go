//go:build dhcp

package addressbook

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// Report joins only authenticated self-identity with matching live lease evidence.
// It is attribution, never permission to assume the client's network privileges.
func (s *Store) Report(c Config, node Node) ([]Binding, error) {
	if node.ID == "" || len(node.Interfaces) > 64 {
		return nil, fmt.Errorf("invalid host report")
	}
	for _, iface := range node.Interfaces {
		mac, err := net.ParseMAC(iface.MAC)
		if err != nil || len(mac) != 6 || len(iface.Addresses) > 128 {
			return nil, fmt.Errorf("invalid reported interface")
		}
		for _, address := range iface.Addresses {
			if _, err := netip.ParseAddr(address); err != nil {
				return nil, fmt.Errorf("invalid reported address")
			}
		}
	}
	now := s.now().Unix()
	node.Seen = now
	joined := []Binding{}
	err := s.db.Update(func(tx *bolt.Tx) error {
		var matches []Binding
		if err := tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
			var b Binding
			if err := json.Unmarshal(raw, &b); err != nil {
				return err
			}
			if b.State != "active" || b.End <= now {
				return nil
			}
			for _, iface := range node.Interfaces {
				mac, _ := net.ParseMAC(iface.MAC)
				if b.MAC != mac.String() {
					var observation Observation
					raw := tx.Bucket(observationBucket).Get(bindingKey(b.Scope, b.Address))
					if raw == nil || json.Unmarshal(raw, &observation) != nil || observation.Until <= now || observation.MAC != mac.String() {
						continue
					}
				}
				for _, ip := range iface.Addresses {
					if ip == b.Address {
						matches = append(matches, b)
						return nil
					}
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if e := tx.Bucket(observationBucket).ForEach(func(_, raw []byte) error {
			var o Observation
			if e := json.Unmarshal(raw, &o); e != nil {
				return e
			}
			if o.Until <= now {
				return nil
			}
			old, e := readBinding(tx, o.Scope, o.Address)
			if e != nil {
				return e
			}
			if old.End > now && (old.State == "active" || old.State == "offered" || old.State == "declined") {
				return nil
			}
			for _, iface := range node.Interfaces {
				mac, _ := net.ParseMAC(iface.MAC)
				if mac.String() != o.MAC {
					continue
				}
				for _, ip := range iface.Addresses {
					if ip == o.Address {
						matches = append(matches, Binding{Scope: o.Scope, Address: o.Address, MAC: o.MAC, Client: "neighbor:" + o.MAC, Device: deviceID(o.Scope, o.MAC), Origin: "neighbor-report", State: "active", Start: now, End: o.Until})
						return nil
					}
				}
			}
			return nil
		}); e != nil {
			return e
		}
		// Existing declarations and associations win over a new assertion. Reject
		// the entire report's joins on conflict, rather than partially merging it.
		device, name := "", ""
		for _, d := range c.Devices {
			if d.HasNode(node.ID) {
				device, name = d.ID, d.Name
			}
		}
		for _, b := range matches {
			if b.NodeID != "" && b.NodeID != node.ID {
				if d, ok := c.Device(b.Device); !ok || !d.HasNode(b.NodeID) || !d.HasNode(node.ID) {
					return fmt.Errorf("identity conflict for %s/%s", b.Scope, b.Address)
				}
			}
			if d, declared := c.Device(b.Device); declared {
				if d.DeclaresNodes() && !d.HasNode(node.ID) {
					return fmt.Errorf("inventory identity conflict")
				}
				if device != "" && device != d.ID {
					return fmt.Errorf("report spans distinct declared devices")
				}
				device, name = d.ID, d.Name
			}
		}
		if device == "" {
			device = deviceID("tailnet", node.ID)
			name = strings.Split(node.DNSName, ".")[0]
			if !labelPattern.MatchString(name) || name == "ns" {
				name = device
			}
			for _, d := range c.Devices {
				if d.Name == name || d.HasAlias(name) {
					name = device
				}
			}
			// Tailnet names need not be unique across sightings/re-enrollment.
			if err := tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
				var b Binding
				if err := json.Unmarshal(raw, &b); err != nil {
					return err
				}
				if b.Name == name && b.Device != device && b.NodeID != "" && b.NodeID != node.ID && b.State == "active" && b.End > now {
					name = device
				}
				return nil
			}); err != nil {
				return err
			}
		}
		for _, b := range matches {
			if strings.HasPrefix(b.Evidence, "operator repair:") && b.NodeID != node.ID {
				return fmt.Errorf("operator association requires explicit repair")
			}
			changed := b.Device != device || b.NodeID != node.ID || b.Name != name
			b.Device = device
			b.Name = name
			b.NodeID = node.ID
			b.Evidence = "authenticated self-report + active DHCP MAC/address"
			if b.Origin == "neighbor-report" {
				var o Observation
				source := "kernel-neighbor"
				if raw := tx.Bucket(observationBucket).Get(bindingKey(b.Scope, b.Address)); raw != nil && json.Unmarshal(raw, &o) == nil && o.MAC == b.MAC && o.Until > now {
					changed = changed || b.End != o.Until
					b.End = o.Until
					source = o.Origin
				}
				b.Evidence = "authenticated self-report + fresh " + source + " sighting (not a DHCP grant)"
			}
			if changed {
				if err := s.save(tx, b, "associate"); err != nil {
					return err
				}
			}
			joined = append(joined, b)
		}
		raw, err := json.Marshal(node)
		if err != nil {
			return err
		}
		return tx.Bucket(nodeBucket).Put([]byte(node.ID), raw)
	})
	if err != nil {
		if auditErr := s.audit("identity-conflict", node.ID+": "+err.Error()); auditErr != nil {
			return nil, auditErr
		}
	}
	return joined, err
}

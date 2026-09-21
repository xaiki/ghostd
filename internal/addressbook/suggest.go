package addressbook

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	bolt "go.etcd.io/bbolt"
)

var peerBucket = []byte("peers-v1")

// Peer is a tailnet peer as seen by the authority's own tailscaled. It is
// evidence about who a LAN address might belong to, never an assertion.
type Peer struct {
	ID        string   `json:"id"`
	DNSName   string   `json:"dns_name"`
	HostName  string   `json:"host_name,omitempty"`
	Addresses []string `json:"addresses,omitempty"` // tailnet addresses
	// LANAddrs are private-range endpoints the peer is currently reachable at:
	// what tailscaled learned from a direct connection, not what the peer says.
	LANAddrs []string `json:"lan_addrs,omitempty"`
	Online   bool     `json:"online"`
	Seen     int64    `json:"seen"`
}

// PrivateEndpoints keeps only RFC 1918 / ULA / link-local endpoint hosts from
// tailscaled's "ip:port" list.
func PrivateEndpoints(endpoints ...string) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range endpoints {
		host := e
		if ap, err := netip.ParseAddrPort(e); err == nil {
			host = ap.Addr().String()
		}
		a, err := netip.ParseAddr(host)
		if err != nil || !(a.IsPrivate() || a.IsLinkLocalUnicast()) || seen[a.String()] {
			continue
		}
		seen[a.String()] = true
		out = append(out, a.String())
	}
	sort.Strings(out)
	return out
}

// SightPeers replaces the current peer inventory with what tailscaled reports.
// Peers that disappear are dropped: an inventory that only grew would suggest
// associations for nodes that no longer exist.
func (s *Store) SightPeers(peers []Peer) error {
	if len(peers) > 10000 {
		return fmt.Errorf("too many peers")
	}
	now := s.now().Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(peerBucket)
		if e != nil {
			return e
		}
		var stale [][]byte
		_ = b.ForEach(func(k, _ []byte) error { stale = append(stale, append([]byte(nil), k...)); return nil })
		for _, k := range stale {
			if e = b.Delete(k); e != nil {
				return e
			}
		}
		for _, p := range peers {
			if p.ID == "" {
				continue
			}
			p.Seen = now
			raw, e := json.Marshal(p)
			if e != nil {
				return e
			}
			if e = b.Put([]byte(p.ID), raw); e != nil {
				return e
			}
		}
		return nil
	})
}

// Suggestion is a reviewable, never self-applying proposal to link a live LAN
// binding to a tailnet node.
type Suggestion struct {
	Scope    string `json:"scope"`
	Address  string `json:"address"`
	Device   string `json:"current_device"`
	PeerID   string `json:"peer_id"`
	PeerName string `json:"peer_name"`
	// Strength is "endpoint" when tailscaled reaches the peer at this very LAN
	// address, or "hostname" when only a name matches. A hostname alone is a
	// weak hint: it is offered for review, and never applied or merged.
	Strength  string         `json:"strength"`
	Evidence  string         `json:"evidence"`
	Ambiguous bool           `json:"ambiguous,omitempty"`
	Conflict  string         `json:"conflict,omitempty"`
	Repair    IdentityRepair `json:"repair"`
}

func firstLabel(dnsName string) string {
	return strings.ToLower(strings.Split(strings.TrimSuffix(dnsName, "."), ".")[0])
}

// Suggest compares live, unassociated bindings with the peer inventory.
func (s *Store) Suggest(c Config) ([]Suggestion, error) {
	now := s.now().Unix()
	var peers []Peer
	var bindings []Binding
	linked := map[string]string{} // peer id -> device already carrying it
	err := s.db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(peerBucket); b != nil {
			if e := b.ForEach(func(_, v []byte) error {
				var p Peer
				if e := json.Unmarshal(v, &p); e != nil {
					return e
				}
				peers = append(peers, p)
				return nil
			}); e != nil {
				return e
			}
		}
		return tx.Bucket(leaseBucket).ForEach(func(_, v []byte) error {
			var b Binding
			if e := json.Unmarshal(v, &b); e != nil {
				return e
			}
			if b.State == "active" && b.End > now {
				bindings = append(bindings, b)
				if b.NodeID != "" {
					linked[b.NodeID] = b.Device
				}
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].Scope+bindings[i].Address < bindings[j].Scope+bindings[j].Address
	})
	out := []Suggestion{}
	for _, b := range bindings {
		if b.NodeID != "" || strings.HasPrefix(b.Evidence, "operator repair:") {
			continue
		}
		if d, ok := c.Device(b.Device); ok && d.DeclaresNodes() {
			continue // the inventory already speaks for this device
		}
		var mine []Suggestion
		for _, p := range peers {
			strength, evidence := "", ""
			for _, a := range p.LANAddrs {
				if a == b.Address {
					strength, evidence = "endpoint", "tailscaled reaches this peer directly at the leased LAN address"
				}
			}
			if strength == "" {
				name := firstLabel(p.DNSName)
				if name != "" && (name == strings.ToLower(b.ClaimedName) || (b.Name != b.Device && name == b.Name)) {
					strength, evidence = "hostname", "only the host name matches; weak, confirm out of band before applying"
				}
			}
			if strength == "" {
				continue
			}
			name := firstLabel(p.DNSName)
			if !labelPattern.MatchString(name) || name == "ns" {
				name = deviceID("tailnet", p.ID)
			}
			sg := Suggestion{Scope: b.Scope, Address: b.Address, Device: b.Device, PeerID: p.ID, PeerName: p.DNSName, Strength: strength, Evidence: evidence,
				Repair: IdentityRepair{Scope: b.Scope, Address: b.Address, Client: b.Client, ExpectedDevice: b.Device, Device: deviceID("tailnet", p.ID), Name: name, NodeID: p.ID, Reason: "suggested from peer inventory (" + strength + ")", Persist: true}}
			if dev, ok := linked[p.ID]; ok && dev != b.Device {
				sg.Conflict = "peer is already linked to device " + dev
			}
			mine = append(mine, sg)
		}
		// One address, several plausible peers: none is more right than another.
		for i := range mine {
			mine[i].Ambiguous = len(mine) > 1
		}
		out = append(out, mine...)
	}
	return out, nil
}

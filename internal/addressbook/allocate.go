//go:build dhcp

package addressbook

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"encoding/json"
	bolt "go.etcd.io/bbolt"
)

func deviceID(scope, client string) string {
	return fmt.Sprintf("device-%x", sha256.Sum256([]byte(scope+"/"+client)))[:23]
}
func reservation(s Scope, client, mac string) (Reservation, bool) {
	for _, r := range s.Reservations {
		if r.Client == client || r.Client == "mac:"+mac {
			return r, true
		}
	}
	return Reservation{}, false
}
func allowed(s Scope, client, mac, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.Is6() != s.Is6() || ip == s.Server || ip == s.Router {
		return false
	}
	if r, ok := reservation(s, client, mac); ok {
		return r.Address == ip
	}
	for _, r := range s.Reservations {
		if r.Address == ip {
			return false
		}
	}
	return a.Compare(netip.MustParseAddr(s.Start)) >= 0 && a.Compare(netip.MustParseAddr(s.End)) <= 0
}
func (s *Store) Allocate(c Config, scopeID, client, mac, claimed, requested string, commit bool) (Binding, error) {
	scope, ok := c.Scope(scopeID)
	if !ok || !scope.Enabled {
		return Binding{}, fmt.Errorf("scope is not enabled")
	}
	if !validClient(client) {
		return Binding{}, fmt.Errorf("invalid client identifier")
	}
	var err error
	if mac != "" || !scope.Is6() {
		hw, e := net.ParseMAC(mac)
		if e != nil || len(hw) != 6 {
			return Binding{}, fmt.Errorf("invalid hardware address")
		}
		mac = hw.String()
	}
	if scope.Is6() != strings.HasPrefix(client, "duid:") {
		return Binding{}, fmt.Errorf("client family does not match scope")
	}
	var result Binding
	now := s.now().Unix()
	err = s.db.Update(func(tx *bolt.Tx) error {
		candidate := requested
		if commit && candidate == "" {
			return fmt.Errorf("%w: request must identify its address", ErrUnavailable)
		}
		if !commit {
			// Preserve the current address on rediscovery, before considering hints.
			mine, err := liveByClient(tx, scopeID, client)
			if err != nil {
				return err
			}
			for _, b := range mine {
				if b.Origin != originPD && b.End > now && (b.State == "active" || b.State == "offered") && allowed(scope, client, mac, b.Address) {
					candidate = b.Address
				}
			}
			if r, ok := reservation(scope, client, mac); ok {
				candidate = r.Address
			}
		}
		available := func(ip string) (bool, error) {
			if !allowed(scope, client, mac, ip) {
				return false, nil
			}
			b, err := readBinding(tx, scopeID, ip)
			if err != nil {
				return false, err
			}
			busy := b.End > now && (b.State == "active" || b.State == "offered" || b.State == "declined")
			return !busy || (b.Client == client && b.State != "declined"), nil
		}
		usable, err := available(candidate)
		if err != nil {
			return err
		}
		if !usable && commit {
			return fmt.Errorf("%w: requested address is outside client policy or occupied", ErrUnavailable)
		}
		if !usable {
			if _, reserved := reservation(scope, client, mac); reserved {
				return fmt.Errorf("%w: reserved address is occupied", ErrUnavailable)
			}
			for a, end := netip.MustParseAddr(scope.Start), netip.MustParseAddr(scope.End); a.Compare(end) <= 0; a = a.Next() {
				usable, err = available(a.String())
				if err != nil {
					return err
				}
				if usable {
					candidate = a.String()
					break
				}
			}
			if !usable {
				return fmt.Errorf("%w: address pool exhausted", ErrUnavailable)
			}
		}
		old, err := readBinding(tx, scopeID, candidate)
		if err != nil {
			return err
		}
		if !commit && old.Client == client && old.State == "active" && old.End > now {
			result = old
			return nil
		}
		result = Binding{Scope: scopeID, Address: candidate, Client: client, MAC: mac, ClaimedName: strings.ToValidUTF8(claimed, ""), State: "offered", Origin: "dhcpv4", Start: now, End: now + 30}
		if scope.Is6() {
			result.Origin = "dhcpv6"
			parts := strings.Split(strings.TrimPrefix(client, "duid:"), "/iaid:")
			result.DUID = parts[0]
			result.IAID = parts[1]
		}
		result.Device = deviceID(scopeID, client)
		result.Name = result.Device
		if old.Client == client && old.End > now && old.State != "declined" {
			result.Device = old.Device
			result.Name = old.Name
			result.Start = old.Start
			result.NodeID = old.NodeID
			result.Evidence = old.Evidence
		}
		// A durable operator association outranks what the last lease carried, but
		// never the inventory: a reservation below still wins.
		if a, ok, e := readAssociation(tx, client); e != nil {
			return e
		} else if ok {
			result.Device, result.Name, result.NodeID = a.Device, a.Name, a.NodeID
			result.Evidence = "operator repair: " + a.Reason
		}
		if r, ok := reservation(scope, client, mac); ok {
			d, _ := c.Device(r.Device)
			result.Device = d.ID
			result.Name = d.Name
			result.NodeID = d.NodeID
			result.Evidence = "inventory reservation"
		}
		kind := "offer"
		if commit {
			result.State = "active"
			result.End = now + int64(scope.LeaseSeconds)
			if scope.Is6() {
				result.PreferredEnd = now + int64(scope.PreferredSeconds)
			}
			kind = "grant"
			if old.Client == client && old.State == "active" && old.End > now {
				kind = "renew"
			}
		}
		return s.save(tx, result, kind)
	})
	return result, err
}
func (s *Store) Release(scope, client, ip string, decline bool) error {
	now := s.now().Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := readBinding(tx, scope, ip)
		if err != nil {
			return err
		}
		if b.Client != client || b.End <= now || (b.State != "active" && b.State != "offered") {
			return fmt.Errorf("no live binding owned by client")
		}
		b.State = "released"
		b.End = now
		kind := "release"
		if decline {
			b.State = "declined"
			b.End = now + 600
			kind = "decline"
		}
		return s.save(tx, b, kind)
	})
}

// Expire reads only the expiry index up to now, and at most 1000 entries per
// call, so its work is bounded by what is due rather than by ledger size.
func (s *Store) Expire() error {
	now := s.now().Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		var due [][]byte
		cursor := tx.Bucket(expiryBucket).Cursor()
		for k, _ := cursor.First(); k != nil && len(due) < 1000 && int64(binary.BigEndian.Uint64(k)) <= now; k, _ = cursor.Next() {
			due = append(due, append([]byte(nil), k...))
		}
		for _, k := range due {
			raw := tx.Bucket(leaseBucket).Get(k[8:])
			var b Binding
			if raw == nil || json.Unmarshal(raw, &b) != nil || !liveState(b.State) || b.End != int64(binary.BigEndian.Uint64(k)) {
				// A stale index entry (the binding moved on) is simply dropped.
				if err := tx.Bucket(expiryBucket).Delete(k); err != nil {
					return err
				}
				continue
			}
			b.State = "expired"
			if err := s.save(tx, b, "expire"); err != nil {
				return err
			}
		}
		return nil
	})
}

type ImportedLease struct {
	DUID     string `json:"duid,omitempty"`
	IAID     string `json:"iaid,omitempty"`
	Scope    string `json:"scope"`
	Address  string `json:"address"`
	MAC      string `json:"mac"`
	ClientID string `json:"client_id,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Expiry   int64  `json:"expiry"`
}

func (s *Store) Import(c Config, leases []ImportedLease) error {
	if len(leases) > 10000 {
		return fmt.Errorf("import limited to 10000 leases per request")
	}
	return s.ImportDocument(c, ImportDocument{Leases: leases})
}

type ImportDocument struct {
	Leases     []ImportedLease `json:"leases"`
	ServerDUID string          `json:"server_duid,omitempty"`
}

func (s *Store) ImportDocument(c Config, doc ImportDocument) error {
	if len(doc.Leases) > 10000 {
		return fmt.Errorf("too many leases")
	}
	now := s.now().Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		if doc.ServerDUID != "" {
			if err := adoptDUID(tx, c, doc.ServerDUID); err != nil {
				return err
			}
		}
		for _, l := range doc.Leases {
			if l.Expiry < 0 {
				return fmt.Errorf("negative imported lease expiry")
			}
			if l.DUID != "" && doc.ServerDUID == "" {
				meta := tx.Bucket(metaBucket)
				if meta == nil || len(meta.Get([]byte("duid"))) == 0 {
					return fmt.Errorf("IPv6 adoption requires the legacy server DUID")
				}
			}

			scope, ok := c.Scope(l.Scope)
			if !ok {
				return fmt.Errorf("unknown import scope %s", l.Scope)
			}
			if scope.Enabled {
				return fmt.Errorf("disable scope %s before importing leases", scope.ID)
			}
			p := netip.MustParsePrefix(scope.Subnet)
			ip, err := netip.ParseAddr(l.Address)
			if err != nil || !p.Contains(ip) || ip == p.Addr() || (!p.Addr().Is6() && ip == lastAddr(p)) || l.Address == scope.Server || l.Address == scope.Router {
				return fmt.Errorf("invalid imported address")
			}
			mac, err := net.ParseMAC(l.MAC)
			if !scope.Is6() && (err != nil || len(mac) != 6) {
				return fmt.Errorf("invalid imported MAC")
			}
			client := "mac:" + mac.String()
			if l.ClientID != "" && l.ClientID != "*" {
				client = "id:" + strings.ToLower(strings.ReplaceAll(l.ClientID, ":", ""))
			}
			if scope.Is6() {
				client = "duid:" + strings.ToLower(strings.ReplaceAll(l.DUID, ":", "")) + "/iaid:" + strings.ToLower(l.IAID)
			}
			if !validClient(client) {
				return fmt.Errorf("invalid imported client ID")
			}
			end := l.Expiry
			if end == 0 {
				end = 253402300799
			}
			if end <= now {
				continue
			}
			old, err := readBinding(tx, l.Scope, l.Address)
			if err != nil {
				return err
			}
			// Our own quarantine marker, written by ExportDNSmasq, coming back on a
			// later takeover: the ledger's quarantine is authoritative, and a hold the
			// ledger no longer has is restored as a quarantine, never as a lease
			// anybody owns.
			if isQuarantineMarker(scope, l, mac) {
				if old.End > now && old.State == "declined" {
					continue
				}
				b := Binding{Scope: l.Scope, Address: l.Address, Client: client, MAC: mac.String(), State: "declined", Origin: "dnsmasq-import", Start: now, End: end, Device: deviceID(l.Scope, client), Evidence: "quarantine restored from exported lease file"}
				if scope.Is6() {
					b.DUID = strings.TrimPrefix(strings.Split(client, "/iaid:")[0], "duid:")
					b.IAID = l.IAID
				}
				b.Name = b.Device
				if old.End > now && (old.State == "active" || old.State == "offered") {
					return fmt.Errorf("import conflicts with live binding %s/%s", l.Scope, l.Address)
				}
				if err := s.save(tx, b, "import"); err != nil {
					return err
				}
				continue
			}
			if old.End > now && (old.State == "active" || old.State == "offered" || old.State == "declined") {
				if old.Client == client && old.State == "active" && old.End >= end {
					continue
				}
				if old.Client != client || old.State == "declined" {
					return fmt.Errorf("import conflicts with live binding %s/%s", l.Scope, l.Address)
				}
			}
			b := Binding{Scope: l.Scope, Address: l.Address, Client: client, MAC: mac.String(), ClaimedName: l.Hostname, State: "active", Origin: "dnsmasq-import", Start: now, End: end, Device: deviceID(l.Scope, client)}
			if scope.Is6() {
				b.DUID = strings.TrimPrefix(strings.Split(client, "/iaid:")[0], "duid:")
				b.IAID = l.IAID
				b.PreferredEnd = end
			}
			b.Name = b.Device
			if old.Client == client && old.State == "active" && old.End > now {
				b.Device, b.Name, b.NodeID, b.Evidence, b.Start = old.Device, old.Name, old.NodeID, old.Evidence, old.Start
			}
			if r, ok := reservation(scope, client, b.MAC); ok {
				d, _ := c.Device(r.Device)
				b.Device = d.ID
				b.Name = d.Name
				b.NodeID = d.NodeID
				b.Evidence = "inventory reservation"
			}
			if err := s.save(tx, b, "import"); err != nil {
				return err
			}
		}
		return nil
	})
}

// isQuarantineMarker recognises the synthetic identity ExportDNSmasq gives a
// declined address, so a later import can tell its own hold from a real client.
func isQuarantineMarker(scope Scope, l ImportedLease, mac net.HardwareAddr) bool {
	if scope.Is6() {
		sum := sha256.Sum256([]byte(scope.ID + "/" + l.Address))
		return strings.EqualFold(strings.ReplaceAll(l.DUID, ":", ""), "0004"+hex.EncodeToString(sum[:16]))
	}
	return mac.String() == "02:ff:ff:ff:ff:fe"
}

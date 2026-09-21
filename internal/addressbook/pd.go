package addressbook

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	bolt "go.etcd.io/bbolt"
)

// prefixAt returns the i-th delegable prefix of a pool: the pool's network
// with i written into the bits between the pool length and the delegated length.
func prefixAt(pool netip.Prefix, length, i int) netip.Prefix {
	raw := pool.Addr().As16()
	shift := 128 - length
	// Add i << shift to the 128-bit address.
	carry := uint64(i)
	byteIdx, bitOff := 15-shift/8, uint(shift%8)
	carry <<= bitOff
	for k := byteIdx; k >= 0 && carry != 0; k-- {
		sum := uint64(raw[k]) + (carry & 0xff)
		raw[k] = byte(sum)
		carry = carry>>8 + sum>>8
	}
	return netip.PrefixFrom(netip.AddrFrom16(raw), length)
}

func poolSize(pool netip.Prefix, length int) int { return 1 << (length - pool.Bits()) }

// inPool reports whether p is one of the pool's delegable prefixes.
func inPool(pool netip.Prefix, length int, p netip.Prefix) bool {
	return p.Bits() == length && p == p.Masked() && pool.Contains(p.Addr())
}

// pdClient is the ledger identity of one IA_PD: the DUID and IAID, as for IA_NA.
func pdClient(cid dhcpv6.DUID, iaid [4]byte) string {
	return fmt.Sprintf("duid:%s/iaid:%x", hex.EncodeToString(cid.ToBytes()), iaid)
}

// AllocatePrefix offers (commit=false) or grants (commit=true) one delegated
// prefix to a client. A client keeps the prefix it already holds; otherwise the
// hint is honoured when free and in the pool, and the lowest free prefix is
// used. A delegation, like a lease, is owned until it ends or expires.
func (s *Store) AllocatePrefix(scope Scope, client, duidHex, hint string, via net.IP, commit bool) (Binding, error) {
	pool := netip.MustParsePrefix(scope.PD.Prefix)
	length := scope.PD.Length
	now := s.now().Unix()
	var result Binding
	err := s.db.Update(func(tx *bolt.Tx) error {
		free := func(p netip.Prefix) (bool, Binding, error) {
			b, e := readBinding(tx, scope.ID, p.String())
			if e != nil {
				return false, b, e
			}
			busy := b.End > now && (b.State == "active" || b.State == "offered")
			return !busy || b.Client == client, b, nil
		}
		// What this client already has.
		var mine Binding
		if e := tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
			var b Binding
			if e := json.Unmarshal(raw, &b); e != nil {
				return e
			}
			if b.Scope == scope.ID && b.Origin == originPD && b.Client == client && b.End > now && (b.State == "active" || b.State == "offered") {
				mine = b
			}
			return nil
		}); e != nil {
			return e
		}
		var chosen netip.Prefix
		if mine.Address != "" {
			chosen = netip.MustParsePrefix(mine.Address)
		} else {
			if hint != "" {
				if hp, e := netip.ParsePrefix(hint); e == nil && inPool(pool, length, hp) {
					if ok, _, e := free(hp); e != nil {
						return e
					} else if ok {
						chosen = hp
					}
				}
			}
			if !chosen.IsValid() {
				// A Request that names no usable prefix is treated like a Solicit that
				// commits: the lowest free prefix, as for an IA_NA without a hint.
				for i, n := 0, poolSize(pool, length); i < n; i++ {
					p := prefixAt(pool, length, i)
					ok, _, e := free(p)
					if e != nil {
						return e
					}
					if ok {
						chosen = p
						break
					}
				}
				if !chosen.IsValid() {
					return fmt.Errorf("%w: prefix pool exhausted", ErrUnavailable)
				}
			}
		}
		old, e := readBinding(tx, scope.ID, chosen.String())
		if e != nil {
			return e
		}
		b := Binding{Scope: scope.ID, Address: chosen.String(), Client: client, DUID: duidHex, Origin: originPD, State: "offered", Start: now, End: now + 30,
			Evidence: "delegated prefix", Via: ""}
		if via != nil {
			b.Via = via.String()
		}
		b.Device = deviceID(scope.ID, client)
		b.Name = b.Device
		// Attribute the delegated range to the device that already holds this
		// DUID's address in the scope, so the router and its prefix are one device.
		var same Binding
		_ = tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
			var x Binding
			if json.Unmarshal(raw, &x) == nil && x.Scope == scope.ID && x.Origin == "dhcpv6" && x.DUID == duidHex && x.State == "active" && x.End > now {
				same = x
			}
			return nil
		})
		if same.Device != "" {
			b.Device, b.Name, b.NodeID = same.Device, same.Name, same.NodeID
			b.Evidence = "delegated prefix; same DUID as " + same.Address
		} else if old.Client == client && old.Device != "" && old.End > now {
			b.Device, b.Name, b.NodeID = old.Device, old.Name, old.NodeID
		}
		if old.Client == client && old.End > now {
			b.Start = old.Start
		}
		kind := "offer"
		if commit {
			b.State, b.End = "active", now+int64(scope.LeaseSeconds)
			b.PreferredEnd = now + int64(scope.PreferredSeconds)
			kind = "grant"
			if old.Client == client && old.State == "active" && old.End > now {
				kind = "renew"
			}
		} else if mine.State == "active" {
			result = mine // an active delegation is simply offered again, unchanged
			return nil
		}
		result = b
		return s.save(tx, b, kind)
	})
	return result, err
}

func (s *Store) releasePrefix(scope Scope, client string) error {
	now := s.now().Unix()
	return s.db.Update(func(tx *bolt.Tx) error {
		var held []Binding
		if e := tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
			var b Binding
			if e := json.Unmarshal(raw, &b); e != nil {
				return e
			}
			if b.Scope == scope.ID && b.Origin == originPD && b.Client == client && b.End > now && (b.State == "active" || b.State == "offered") {
				held = append(held, b)
			}
			return nil
		}); e != nil {
			return e
		}
		for _, b := range held {
			b.State, b.End = "released", now
			if e := s.save(tx, b, "release"); e != nil {
				return e
			}
		}
		if len(held) == 0 {
			return fmt.Errorf("no live delegation owned by client")
		}
		return nil
	})
}

// handlePD answers one IA_PD.
func (s *Store) handlePD(scope Scope, kind dhcpv6.MessageType, cid dhcpv6.DUID, ia *dhcpv6.OptIAPD, via net.IP) (*dhcpv6.OptIAPD, error) {
	out := &dhcpv6.OptIAPD{IaId: ia.IaId}
	if scope.PD == nil {
		out.Options.Add(status6(iana.StatusNoPrefixAvail, "prefix delegation not configured"))
		return out, nil
	}
	client := pdClient(cid, ia.IaId)
	if !validClient(client) {
		out.Options.Add(status6(iana.StatusNoPrefixAvail, "invalid client"))
		return out, nil
	}
	now := s.now().Unix()
	current := func() (Binding, bool) {
		var found Binding
		_ = s.db.View(func(tx *bolt.Tx) error {
			return tx.Bucket(leaseBucket).ForEach(func(_, raw []byte) error {
				var b Binding
				if json.Unmarshal(raw, &b) == nil && b.Scope == scope.ID && b.Origin == originPD && b.Client == client && b.State == "active" && b.End > now {
					found = b
				}
				return nil
			})
		})
		return found, found.Client != ""
	}
	switch kind {
	case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
		if _, ok := current(); !ok {
			out.Options.Add(status6(iana.StatusNoBinding, "no delegation"))
			return out, nil
		}
		if e := s.releasePrefix(scope, client); e != nil {
			return nil, e
		}
		out.Options.Add(status6(iana.StatusSuccess, "delegation released"))
		return out, nil
	case dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
		if _, ok := current(); !ok {
			out.Options.Add(status6(iana.StatusNoBinding, "no active delegation"))
			return out, nil
		}
	case dhcpv6.MessageTypeConfirm:
		return out, nil
	}
	hint := ""
	for _, p := range ia.Options.Prefixes() {
		if p.Prefix != nil {
			hint = p.Prefix.String()
		}
	}
	b, e := s.AllocatePrefix(scope, client, hex.EncodeToString(cid.ToBytes()), hint, via, kind != dhcpv6.MessageTypeSolicit)
	if e != nil {
		if errors.Is(e, ErrUnavailable) {
			out.Options.Add(status6(iana.StatusNoPrefixAvail, "no prefix available"))
			return out, nil
		}
		return nil, e
	}
	_, network, _ := net.ParseCIDR(b.Address)
	out.T1 = time.Duration(scope.LeaseSeconds/2) * time.Second
	out.T2 = time.Duration(scope.LeaseSeconds*4/5) * time.Second
	out.Options.Add(&dhcpv6.OptIAPrefix{PreferredLifetime: time.Duration(scope.PreferredSeconds) * time.Second, ValidLifetime: time.Duration(scope.LeaseSeconds) * time.Second, Prefix: network})
	return out, nil
}

// RouteRunner runs the routing tool; tests substitute a fake.
type RouteRunner interface {
	Run(ctx context.Context, args ...string) ([]byte, error)
}
type ipRunner struct{}

func (ipRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// routeProto marks the routes ghostd installed, so reconciliation touches only
// its own and never another daemon's.
const routeProto = "250"

// ReconcileRoutes makes the kernel's delegated-prefix routes match the ledger:
// every live delegation in a routing pool is routed via its router's
// link-local address, and a route whose delegation ended or expired is removed.
// Running it periodically also restores the routes after a reboot.
func (m *Manager) ReconcileRoutes(ctx context.Context) error {
	m.routeMu.Lock()
	defer m.routeMu.Unlock()
	m.mu.RLock()
	c := cloneConfig(m.config)
	runner := m.routes
	m.mu.RUnlock()
	if runner == nil {
		runner = ipRunner{}
	}
	type route struct{ via, dev string }
	want := map[string]route{}
	snap, err := m.Store.Snapshot("", "", 0)
	if err != nil {
		return err
	}
	for _, b := range snap.Bindings {
		if b.Origin != originPD || b.State != "active" || b.Via == "" {
			continue
		}
		if sc, ok := c.Scope(b.Scope); ok && sc.Enabled && sc.PD != nil && sc.PD.Route {
			want[b.Address] = route{b.Via, sc.Interface}
		}
	}
	raw, err := runner.Run(ctx, "-6", "-j", "route", "show", "proto", routeProto)
	if err != nil {
		return err
	}
	var have []struct {
		Dst     string `json:"dst"`
		Gateway string `json:"gateway"`
		Dev     string `json:"dev"`
	}
	if len(strings.TrimSpace(string(raw))) > 0 {
		if err = json.Unmarshal(raw, &have); err != nil {
			return err
		}
	}
	current := map[string]route{}
	for _, r := range have {
		current[r.Dst] = route{r.Gateway, r.Dev}
	}
	var errs []string
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, prefix := range keys {
		r := want[prefix]
		if cur, ok := current[prefix]; ok && cur == r {
			continue
		}
		if _, err := runner.Run(ctx, "-6", "route", "replace", prefix, "via", r.via, "dev", r.dev, "proto", routeProto); err != nil {
			errs = append(errs, err.Error())
		}
	}
	for prefix, r := range current {
		if _, ok := want[prefix]; ok {
			continue
		}
		if _, err := runner.Run(ctx, "-6", "route", "del", prefix, "dev", r.dev, "proto", routeProto); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

//go:build dhcp

package addressbook

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	bolt "go.etcd.io/bbolt"
)

var metaBucket = []byte("metadata-v1")

func (s *Store) ServerDUID() (dhcpv6.DUID, error) {
	var data []byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, e := tx.CreateBucketIfNotExists(metaBucket)
		if e != nil {
			return e
		}
		data = append([]byte(nil), b.Get([]byte("duid"))...)
		if len(data) == 0 {
			d := &dhcpv6.DUIDUUID{}
			if _, e := rand.Read(d.UUID[:]); e != nil {
				return e
			}
			data = d.ToBytes()
			return b.Put([]byte("duid"), data)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return dhcpv6.DUIDFromBytes(data)
}
func duidMAC(d dhcpv6.DUID) string {
	switch d := d.(type) {
	case *dhcpv6.DUIDLL:
		if len(d.LinkLayerAddr) == 6 {
			return d.LinkLayerAddr.String()
		}
	case *dhcpv6.DUIDLLT:
		if len(d.LinkLayerAddr) == 6 {
			return d.LinkLayerAddr.String()
		}
	}
	return ""
}
func (s *Store) currentClient(scope, client string) (Binding, bool, error) {
	var found Binding
	now := s.now().Unix()
	err := s.db.View(func(tx *bolt.Tx) error {
		bindings, e := liveByClient(tx, scope, client)
		for _, b := range bindings {
			if b.Origin != originPD && b.State == "active" && b.End > now {
				found = b
			}
		}
		return e
	})
	return found, found.Client != "", err
}
func status6(code iana.StatusCode, message string) *dhcpv6.OptStatusCode {
	return &dhcpv6.OptStatusCode{StatusCode: code, StatusMessage: message}
}
func (s *Store) Handle6(c Config, scope Scope, packet dhcpv6.DHCPv6) (dhcpv6.DHCPv6, error) {
	return s.Handle6Via(c, scope, packet, nil)
}

// Handle6Via is Handle6 with the requester's link-local address, which a
// delegation is routed to. It is nil for callers that cannot know it.
func (s *Store) Handle6Via(c Config, scope Scope, packet dhcpv6.DHCPv6, via net.IP) (dhcpv6.DHCPv6, error) {
	r, e := packet.GetInnerMessage()
	if e != nil {
		return nil, nil
	}
	if !scope.Is6() || !scope.Enabled {
		return nil, nil
	}
	kind := r.MessageType
	switch kind {
	case dhcpv6.MessageTypeSolicit, dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind, dhcpv6.MessageTypeConfirm, dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline, dhcpv6.MessageTypeInformationRequest:
	default:
		return nil, nil
	}
	cid := r.Options.ClientID()
	if cid == nil && kind != dhcpv6.MessageTypeInformationRequest {
		return nil, nil
	}
	if len(r.Options.Get(dhcpv6.OptionClientID)) > 1 || len(r.Options.Get(dhcpv6.OptionServerID)) > 1 {
		return nil, nil
	}
	server, e := s.ServerDUID()
	if e != nil {
		return nil, e
	}
	sid := r.Options.ServerID()
	requiresID := kind == dhcpv6.MessageTypeRequest || kind == dhcpv6.MessageTypeRenew || kind == dhcpv6.MessageTypeRelease || kind == dhcpv6.MessageTypeDecline
	if (requiresID && sid == nil) || (sid != nil && !sid.Equal(server)) {
		return nil, nil
	}
	if (kind == dhcpv6.MessageTypeSolicit || kind == dhcpv6.MessageTypeConfirm || kind == dhcpv6.MessageTypeRebind) && sid != nil {
		return nil, nil
	}
	reply := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeReply, TransactionID: r.TransactionID}
	if cid != nil {
		reply.AddOption(dhcpv6.OptClientID(cid))
	}
	reply.AddOption(dhcpv6.OptServerID(server))
	if kind == dhcpv6.MessageTypeSolicit {
		reply.MessageType = dhcpv6.MessageTypeAdvertise
	} // explicit Request commits, no rapid-commit promise
	dhcpv6.WithDNS(net.ParseIP(scope.Server))(reply)
	dhcpv6.WithDomainSearchList(scope.Zone)(reply)
	if kind == dhcpv6.MessageTypeInformationRequest {
		return reply, nil
	}
	ias := r.Options.IANA()
	if len(ias) > 16 {
		return nil, nil
	}
	seen := map[[4]byte]bool{}
	for _, ia := range ias {
		if seen[ia.IaId] || len(ia.Options.Addresses()) > 16 {
			return nil, nil
		}
		seen[ia.IaId] = true
	}
	if kind == dhcpv6.MessageTypeConfirm {
		code := iana.StatusSuccess
		for _, ia := range ias {
			for _, a := range ia.Options.Addresses() {
				ip, ok := netip.AddrFromSlice(a.IPv6Addr)
				if !ok || !netip.MustParsePrefix(scope.Subnet).Contains(ip) {
					code = iana.StatusNotOnLink
				}
			}
		}
		reply.AddOption(status6(code, "link check"))
		return reply, nil
	}
	for _, ia := range ias {
		out := &dhcpv6.OptIANA{IaId: ia.IaId}
		reply.AddOption(out)
		client := fmt.Sprintf("duid:%s/iaid:%x", hex.EncodeToString(cid.ToBytes()), ia.IaId)
		if !validClient(client) {
			return nil, nil
		}
		current, exists, e := s.currentClient(scope.ID, client)
		if e != nil {
			return nil, e
		}
		switch kind {
		case dhcpv6.MessageTypeRelease, dhcpv6.MessageTypeDecline:
			code := iana.StatusSuccess
			if !exists {
				code = iana.StatusNoBinding
			} else {
				addresses := ia.Options.Addresses()
				if len(addresses) == 0 {
					code = iana.StatusNoBinding
				}
				for _, a := range addresses {
					if a.IPv6Addr.String() != current.Address {
						code = iana.StatusNoBinding
						continue
					}
					if e = s.Release(scope.ID, client, current.Address, kind == dhcpv6.MessageTypeDecline); e != nil {
						return nil, e
					}
				}
			}
			out.Options.Add(status6(code, "binding release"))
			continue
		case dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind:
			if !exists {
				out.Options.Add(status6(iana.StatusNoBinding, "no active binding"))
				continue
			}
		}
		requested := ""
		if exists {
			requested = current.Address
		} else if a := ia.Options.OneAddress(); a != nil {
			requested = a.IPv6Addr.String()
		}
		commit := kind != dhcpv6.MessageTypeSolicit
		if requested == "" || !allowed(scope, client, duidMAC(cid), requested) {
			offer, e := s.Allocate(c, scope.ID, client, duidMAC(cid), "", "", false)
			if e != nil {
				if errors.Is(e, ErrUnavailable) {
					out.Options.Add(status6(iana.StatusNoAddrsAvail, "pool unavailable"))
					continue
				}
				return nil, e
			}
			requested = offer.Address
		}
		b, e := s.Allocate(c, scope.ID, client, duidMAC(cid), "", requested, commit)
		if e != nil {
			if errors.Is(e, ErrUnavailable) {
				out.Options.Add(status6(iana.StatusNoAddrsAvail, "address unavailable"))
				continue
			}
			return nil, e
		}
		out.T1 = time.Duration(scope.LeaseSeconds/2) * time.Second
		out.T2 = time.Duration(scope.LeaseSeconds*4/5) * time.Second
		out.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP(b.Address), PreferredLifetime: time.Duration(scope.PreferredSeconds) * time.Second, ValidLifetime: time.Duration(scope.LeaseSeconds) * time.Second})
	}
	pds := r.Options.IAPD()
	if len(pds) > 16 {
		return nil, nil
	}
	for _, pd := range pds {
		out, e := s.handlePD(scope, kind, cid, pd, via)
		if e != nil {
			return nil, e
		}
		reply.AddOption(out)
	}
	return reply, nil
}

// A legacy server identity is adopted atomically with imported leases. A changed
// identity while any v6 grants exist is refused, even when listeners are stopped.
func adoptDUID(tx *bolt.Tx, c Config, value string) error {
	raw, err := hex.DecodeString(strings.ReplaceAll(value, ":", ""))
	if err != nil {
		return err
	}
	if _, err = dhcpv6.DUIDFromBytes(raw); err != nil {
		return err
	}
	for _, scope := range c.Scopes {
		if scope.Is6() && scope.Enabled {
			return fmt.Errorf("disable IPv6 scopes before adopting DUID")
		}
	}
	meta, err := tx.CreateBucketIfNotExists(metaBucket)
	if err != nil {
		return err
	}
	old := meta.Get([]byte("duid"))
	if len(old) > 0 && !bytes.Equal(old, raw) {
		if err = tx.Bucket(leaseBucket).ForEach(func(_, v []byte) error {
			var b Binding
			if e := json.Unmarshal(v, &b); e != nil {
				return e
			}
			if b.DUID != "" {
				return fmt.Errorf("server DUID differs from existing IPv6 ledger")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return meta.Put([]byte("duid"), raw)
}

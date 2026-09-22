//go:build dhcp

package addressbook

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"

	"github.com/xaiki/ghostd/internal/wellknown"
)

func TestReverseNames(t *testing.T) {
	for name, want := range map[string]string{
		"6.0.0.10.in-addr.arpa.": "10.0.0.6",
		"6.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.": "fd00::6",
	} {
		if got, ok := reverseIP(name); !ok || got.String() != want {
			t.Errorf("%s -> %v %v, want %s", name, got, ok, want)
		}
	}
	for _, bad := range []string{"1.2.3.in-addr.arpa.", "a.b.c.d.in-addr.arpa.", "example.com.", "1.0.ip6.arpa.", strings.Repeat("zz.", 16) + "ip6.arpa.", strings.Repeat("g.", 32) + "ip6.arpa."} {
		if _, ok := reverseIP(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestDUIDMACOnlyForSixByteLinkLayerIdentities(t *testing.T) {
	mac := net.HardwareAddr{0, 1, 2, 3, 4, 5}
	if got := duidMAC(&dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: mac}); got != mac.String() {
		t.Fatal(got)
	}
	if got := duidMAC(&dhcpv6.DUIDLLT{HWType: iana.HWTypeEthernet, LinkLayerAddr: mac}); got != mac.String() {
		t.Fatal(got)
	}
	if got := duidMAC(&dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{1, 2, 3}}); got != "" {
		t.Fatal("a short link-layer address is not a MAC:", got)
	}
	if got := duidMAC(&dhcpv6.DUIDUUID{}); got != "" {
		t.Fatal(got)
	}
}

func TestRelayAdmissionMatchesOnlyTheDeclaredPeerAndLink(t *testing.T) {
	direct4 := Scope{ID: "d", Subnet: "10.0.0.0/24"}
	relay4 := Scope{ID: "r", Subnet: "10.8.0.0/24", Relay: &RelayConfig{Peer: "10.0.0.100", Link: "10.8.0.1"}}
	v6 := Scope{ID: "v6", Subnet: "fd00::/64"}
	req := func(gw string, hops uint8) *dhcpv4.DHCPv4 {
		r, _ := dhcpv4.NewDiscovery(net.HardwareAddr{2, 0, 0, 0, 0, 1})
		if gw != "" {
			r.GatewayIPAddr = net.ParseIP(gw)
		}
		r.HopCount = hops
		return r
	}
	relayPeer := &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: wellknown.PortDHCPv4Server}
	for name, tc := range map[string]struct {
		s    Scope
		r    *dhcpv4.DHCPv4
		peer net.Addr
		want bool
	}{
		"direct, no gateway":          {direct4, req("", 0), nil, true},
		"direct refuses relayed":      {direct4, req("10.8.0.1", 0), relayPeer, false},
		"relay ok":                    {relay4, req("10.8.0.1", 1), relayPeer, true},
		"wrong link":                  {relay4, req("10.9.0.1", 1), relayPeer, false},
		"wrong peer":                  {relay4, req("10.8.0.1", 1), &net.UDPAddr{IP: net.ParseIP("10.0.0.101"), Port: wellknown.PortDHCPv4Server}, false},
		"wrong source port":           {relay4, req("10.8.0.1", 1), &net.UDPAddr{IP: net.ParseIP("10.0.0.100"), Port: wellknown.PortDHCPv4Client}, false},
		"too many hops":               {relay4, req("10.8.0.1", 17), relayPeer, false},
		"non-UDP peer":                {relay4, req("10.8.0.1", 1), &net.TCPAddr{IP: net.ParseIP("10.0.0.100"), Port: wellknown.PortDHCPv4Server}, false},
		"an IPv6 scope never matches": {v6, req("", 0), nil, false},
	} {
		if got := matches4(tc.s, tc.r, tc.peer); got != tc.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
	// IPv6.
	inner := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeSolicit}
	relay6 := Scope{ID: "r6", Subnet: "fd88::/64", Relay: &RelayConfig{Peer: "fd77::100", Link: "fd88::1"}}
	fwd := func(link string) dhcpv6.DHCPv6 {
		m, _ := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.ParseIP(link), net.ParseIP("fe80::2"))
		return m
	}
	peer6 := &net.UDPAddr{IP: net.ParseIP("fd77::100"), Port: wellknown.PortDHCPv6Server}
	if !matches6(v6, inner, nil) || matches6(v6, fwd("fd88::1"), peer6) || matches6(direct4, inner, nil) {
		t.Fatal("direct IPv6 matching")
	}
	if !matches6(relay6, fwd("fd88::1"), peer6) {
		t.Fatal("the declared relay and link must match")
	}
	if matches6(relay6, fwd("fd89::1"), peer6) || matches6(relay6, fwd("fd88::1"), &net.UDPAddr{IP: net.ParseIP("fd77::101"), Port: wellknown.PortDHCPv6Server}) || matches6(relay6, inner, peer6) || matches6(relay6, fwd("fd88::1"), &net.UDPAddr{IP: net.ParseIP("fd77::100"), Port: wellknown.PortDHCPv6Client}) {
		t.Fatal("a wrong link, peer, port, or an un-relayed message was admitted")
	}
	// Nested relays are unwrapped to the innermost link.
	nested, _ := dhcpv6.EncapsulateRelay(fwd("fd88::1"), dhcpv6.MessageTypeRelayForward, net.ParseIP("fd99::1"), net.ParseIP("fe80::3"))
	if !matches6(relay6, nested, peer6) {
		t.Fatal("a nested relay chain is judged by its innermost link")
	}
	if got := relayLink(fwd("fd88::1")); got.String() != "fd88::1" {
		t.Fatal(got)
	}
	if relayLink(inner) != nil {
		t.Fatal("no relay, no link")
	}
}

func TestSmallHelpers(t *testing.T) {
	d := DeviceConfig{Aliases: []string{"lp", "printer2"}}
	if !d.HasAlias("lp") || d.HasAlias("nope") {
		t.Fatal("HasAlias")
	}
	all := &TFTPConfig{Root: "/srv"}
	limited := &TFTPConfig{Root: "/srv", Interfaces: []string{"eth1"}}
	if !tftpServes(all, Scope{Interface: "eth0"}) || tftpServes(limited, Scope{Interface: "eth0"}) || !tftpServes(limited, Scope{Interface: "eth1"}) {
		t.Fatal("tftpServes")
	}
	c := Config{Scopes: []Scope{{ID: "lan", Enabled: true}, {ID: "off"}}}
	if dc := Disabled(c); dc.Scopes[0].Enabled || !c.Scopes[0].Enabled {
		t.Fatal("Disabled must copy, not mutate")
	}
}

func TestPeerInventoryFlowsFromTheSourceIntoSuggestions(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	if err := m.CollectPeers(context.Background()); err != nil {
		t.Fatal("no source means nothing to do, not an error:", err)
	}
	c := testConfig()
	b, _ := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "kitchen", "10.0.0.6", true)
	m.SetPeerSource(func(context.Context) ([]Peer, error) {
		return []Peer{{ID: "n1", DNSName: "kitchen.example.ts.net.", LANAddrs: []string{b.Address}}}, nil
	})
	if err := m.CollectPeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Suggest(c)
	if len(got) != 1 || got[0].Strength != "endpoint" {
		t.Fatal(got)
	}
	m.SetPeerSource(func(context.Context) ([]Peer, error) { return nil, context.DeadlineExceeded })
	if err := m.CollectPeers(context.Background()); err == nil {
		t.Fatal("a failing source must surface")
	}
	// A failed poll must not wipe the inventory it had.
	if got, _ = s.Suggest(c); len(got) != 1 {
		t.Fatal("inventory lost on a failed poll")
	}
}

func TestManagerApplyRefusalsAreAtomic(t *testing.T) {
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	c := testConfig()
	if _, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true); e != nil {
		t.Fatal(e)
	}
	// A scope with a new ID over addresses another still leases is refused, and
	// nothing is saved.
	moved := disabled(c)
	moved.Scopes[0].ID = "other"
	saved := false
	if e := m.Apply(moved, func() error { saved = true; return nil }); e == nil || !strings.Contains(e.Error(), "overlaps outstanding binding") || saved {
		t.Fatal("a scope rename over live leases was accepted:", e, saved)
	}
	// An enabled scope whose interface does not carry its address cannot start.
	if e := m.Apply(c, func() error { saved = true; return nil }); e == nil || saved {
		t.Fatal("an enabled scope on an interface that does not exist started:", e)
	}
	if !reflectEqualConfig(m.Config(), Config{}) {
		t.Fatal("a refused apply must leave the previous (empty) configuration:", m.Config())
	}
	// A save that fails after the listeners came up must roll everything back.
	failed := disabled(c)
	if e := m.Apply(failed, func() error { return context.Canceled }); e == nil {
		t.Fatal("a failing save was ignored")
	}
	if !reflectEqualConfig(m.Config(), Config{}) {
		t.Fatal("the configuration changed although its save failed")
	}
	if e := m.Apply(failed, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	// Invalid configuration never reaches the sockets.
	bad := cloneConfig(failed)
	bad.Scopes[0].LeaseSeconds = 1
	if e := m.Apply(bad, func() error { t.Fatal("saved an invalid config"); return nil }); e == nil {
		t.Fatal("invalid config accepted")
	}
}

func reflectEqualConfig(a, b Config) bool {
	return len(a.Scopes) == len(b.Scopes) && len(a.Devices) == len(b.Devices)
}

package addressbook

import (
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"net"
	"testing"
	"time"
)

func config6() Config {
	return Config{Scopes: []Scope{{ID: "v6", Interface: "eth0", Subnet: "fd00::/64", Server: "fd00::1", Start: "fd00::6", End: "fd00::6", Zone: "home.arpa", LeaseSeconds: 600, PreferredSeconds: 300, Enabled: true}}}
}
func TestDHCP6Lifecycle(t *testing.T) {
	s := openTest(t)
	c := config6()
	scope := c.Scopes[0]
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	sid, e := s.ServerDUID()
	if e != nil {
		t.Fatal(e)
	}
	cid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 5}}
	send := func(kind dhcpv6.MessageType, client dhcpv6.DUID, address string) *dhcpv6.Message {
		t.Helper()
		r := &dhcpv6.Message{MessageType: kind}
		r.AddOption(dhcpv6.OptClientID(client))
		if kind == dhcpv6.MessageTypeRequest || kind == dhcpv6.MessageTypeRenew || kind == dhcpv6.MessageTypeRelease || kind == dhcpv6.MessageTypeDecline {
			r.AddOption(dhcpv6.OptServerID(sid))
		}
		ia := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
		if address != "" {
			ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP(address)})
		}
		r.AddOption(ia)
		raw, e := s.Handle6(c, scope, r)
		if e != nil || raw == nil {
			t.Fatalf("%s: %v", kind, e)
		}
		return raw.(*dhcpv6.Message)
	}
	if r := send(dhcpv6.MessageTypeSolicit, cid, ""); r.Type() != dhcpv6.MessageTypeAdvertise {
		t.Fatal(r)
	}
	for _, kind := range []dhcpv6.MessageType{dhcpv6.MessageTypeRequest, dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind} {
		now += 10
		r := send(kind, cid, "fd00::6")
		a := r.Options.IANA()[0].Options.OneAddress()
		if a == nil || a.IPv6Addr.String() != "fd00::6" || a.ValidLifetime != 600*time.Second {
			t.Fatal(r)
		}
		snap, _ := s.Snapshot("", "", 0)
		if snap.Bindings[0].End != now+600 {
			t.Fatal(snap)
		}
	}
	other := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 6}}
	r := send(dhcpv6.MessageTypeSolicit, other, "")
	if r.Options.IANA()[0].Options.OneAddress() != nil {
		t.Fatal("double allocation")
	}
	send(dhcpv6.MessageTypeDecline, cid, "fd00::6")
	if r = send(dhcpv6.MessageTypeSolicit, other, ""); r.Options.IANA()[0].Options.OneAddress() != nil {
		t.Fatal("decline quarantine lost")
	}
	now += 601
	if r = send(dhcpv6.MessageTypeSolicit, other, ""); r.Options.IANA()[0].Options.OneAddress() == nil {
		t.Fatal("expired quarantine not reclaimed")
	}
	send(dhcpv6.MessageTypeRequest, other, "fd00::6")
	send(dhcpv6.MessageTypeRelease, other, "fd00::6")
	snap, _ := s.Snapshot("", "", 0)
	if snap.Bindings[0].State != "released" {
		t.Fatal(snap)
	}
}
func TestV6DNSmasqImportIdentityAndRollback(t *testing.T) {
	s := openTest(t)
	c := disabled(config6())
	text := "duid 00:03:00:01:00:11:22:33:44:55\n0 4294967295 fd00::6 host 00:03:00:01:00:11:22:33:44:66\n"
	doc, e := ParseDNSmasq(c, text)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ImportDocument(c, doc); e != nil {
		t.Fatal(e)
	}
	snap, _ := s.Snapshot("", "", 0)
	if snap.Bindings[0].IAID != "ffffffff" || snap.Bindings[0].End != 253402300799 {
		t.Fatal(snap)
	}
	exported, e := ExportDNSmasq(snap)
	if e != nil {
		t.Fatal(e)
	}
	round, e := ParseDNSmasq(c, exported)
	if e != nil || round.ServerDUID != doc.ServerDUID || round.Leases[0].DUID != doc.Leases[0].DUID {
		t.Fatal(round, e)
	}
	doc.ServerDUID = "00030001001122334477"
	if e = s.ImportDocument(c, doc); e == nil {
		t.Fatal("server identity changed under existing grants")
	}
}

//go:build dhcp

package addressbook

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/miekg/dns"
)

func TestDORAAndDNSLifecycle(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(1000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	discover, e := dhcpv4.NewDiscovery(mac)
	if e != nil {
		t.Fatal(e)
	}
	offer, e := s.Handle4(c, c.Scopes[0], discover)
	if e != nil || offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatal(offer, e)
	}
	request, e := dhcpv4.NewRequestFromOffer(offer)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := s.Handle4(c, c.Scopes[0], request)
	if e != nil || ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatal(ack, e)
	}
	snapshot, e := s.Snapshot("lan", ack.YourIPAddr.String(), 0)
	if e != nil || len(snapshot.Bindings) != 1 || snapshot.Bindings[0].State != "active" {
		t.Fatal(snapshot, e)
	}
	b := snapshot.Bindings[0]
	// Real UDP DNS exchanges exercise serialization and authoritative responses.
	conn, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	handler := &DNS{Store: s, Config: func() Config { return c }, Next: plugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
		t.Error("private query escaped authoritative zone")
		return 2, nil
	})}
	ready := make(chan struct{})
	server := &dns.Server{PacketConn: conn, NotifyStartedFunc: func() { close(ready) }, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_, err := handler.ServeDNS(context.Background(), w, r)
		if err != nil {
			t.Error(err)
		}
	})}
	go server.ActivateAndServe()
	<-ready
	defer server.Shutdown()
	query := func(name string, typ uint16) *dns.Msg {
		t.Helper()
		q := new(dns.Msg)
		q.SetQuestion(name, typ)
		r, _, err := new(dns.Client).Exchange(q, conn.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	r := query(b.Name+".home.arpa.", dns.TypeA)
	if !r.Authoritative || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != b.Address {
		t.Fatal(r)
	}
	reverse, _ := dns.ReverseAddr(b.Address)
	r = query(reverse, dns.TypePTR)
	if len(r.Answer) != 1 || r.Answer[0].(*dns.PTR).Ptr != b.Name+".home.arpa." {
		t.Fatal(r)
	}
	r = query(b.Name+".home.arpa.", dns.TypeAAAA)
	if r.Rcode != 0 || len(r.Answer) != 0 || len(r.Ns) != 1 {
		t.Fatal(r)
	}
	r = query("unknown.home.arpa.", dns.TypeA)
	if r.Rcode != dns.RcodeNameError {
		t.Fatal(r)
	}
	if e := s.Release("lan", b.Client, b.Address, false); e != nil {
		t.Fatal(e)
	}
	r = query(b.Name+".home.arpa.", dns.TypeA)
	if r.Rcode != dns.RcodeNameError {
		t.Fatal("released lease still published", r)
	}
}

func TestRequestsIgnoreOtherServersAndRelaysAndDiskFailure(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	r, _ := dhcpv4.NewDiscovery(mac, dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("10.0.0.2"))))
	if reply, e := s.Handle4(c, c.Scopes[0], r); reply != nil || e != nil {
		t.Fatal(reply, e)
	}
	r, _ = dhcpv4.NewDiscovery(mac)
	r.GatewayIPAddr = net.ParseIP("10.0.0.2")
	if reply, e := s.Handle4(c, c.Scopes[0], r); reply != nil || e != nil {
		t.Fatal(reply, e)
	}
	r.GatewayIPAddr = net.IPv4zero
	r.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeRequest))
	r.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("10.0.0.6")))
	s.Close()
	if reply, e := s.Handle4(c, c.Scopes[0], r); reply != nil || e == nil {
		t.Fatal("must not ACK/NAK database failure", reply, e)
	}
}

func TestDeclineAndImportHandover(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	now := int64(1000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	importLease := ImportedLease{Scope: "lan", Address: "10.0.0.6", MAC: "00:11:22:33:44:55", ClientID: "01:00:11:22:33:44:55", Expiry: 2000}
	if s.Import(c, []ImportedLease{importLease}) == nil {
		t.Fatal("import while serving accepted")
	}
	c.Scopes[0].Enabled = false
	if e := s.Import(c, []ImportedLease{importLease}); e != nil {
		t.Fatal(e)
	}
	c.Scopes[0].Enabled = true
	b, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "", false)
	if e != nil || b.Address == importLease.Address {
		t.Fatal(b, e)
	}
	if e = s.Release("lan", b.Client, b.Address, true); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Allocate(c, "lan", b.Client, b.MAC, "", b.Address, true); !errors.Is(e, ErrUnavailable) {
		t.Fatal("declined address reissued", e)
	}
	now += 601
	if _, e = s.Allocate(c, "lan", b.Client, b.MAC, "", b.Address, true); e != nil {
		t.Fatal(e)
	}
}

func TestConfigRollbackRetainsIssuedAddresses(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	b, e := s.Allocate(c, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	m := NewManager(s)
	defer m.Close()
	disabled := testConfig()
	disabled.Scopes[0].Enabled = false
	if e = m.Apply(disabled, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	changed := testConfig()
	changed.Scopes[0].Enabled = false
	changed.Scopes[0].Zone = "other.home.arpa"
	if e = m.Apply(changed, func() error { return errors.New("disk failure") }); e == nil {
		t.Fatal("ignored config save failure")
	}
	if m.Config().Scopes[0].Zone != "home.arpa" {
		t.Fatal("changed config despite failed persistence")
	}
	if e = m.Apply(Config{}, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", b.Address, true); !errors.Is(e, ErrUnavailable) {
		t.Fatal("rollback erased live grant", e)
	}
}

func TestConfigRejectsOverlappingScopesAndReservedDNSName(t *testing.T) {
	c := testConfig()
	other := c.Scopes[0]
	other.ID = "other"
	other.Interface = "eth1"
	other.Zone = "other.home.arpa"
	c.Scopes = append(c.Scopes, other)
	if c.Validate() == nil {
		t.Fatal("overlapping authorities accepted")
	}
	c = testConfig()
	c.Devices = []DeviceConfig{{ID: "nameserver", Name: "ns"}}
	if c.Validate() == nil {
		t.Fatal("reserved DNS label accepted")
	}
	if _, e := ParseConfig([]byte(`{"scopes":[],"typo":true}`)); e == nil {
		t.Fatal("unknown config field ignored")
	}
}

func TestDeclaredDNSAliasAndMultipleNodeMembership(t *testing.T) {
	s := openTest(t)
	c := testConfig()
	c.Devices = []DeviceConfig{{ID: "node-a", Name: "node-a", Aliases: []string{"server"}, NodeIDs: []string{"node1", "node2"}}}
	c.Scopes[0].Reservations = []Reservation{{Client: "mac:00:11:22:33:44:55", Address: "10.0.0.6", Device: "node-a"}}
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	_, e := s.Allocate(c, "lan", c.Scopes[0].Reservations[0].Client, "00:11:22:33:44:55", "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	for _, node := range []string{"node1", "node2"} {
		_, e = s.Report(c, Node{ID: node, DNSName: "other.example", Interfaces: []InterfaceReport{{MAC: "00:11:22:33:44:55", Addresses: []string{"10.0.0.6"}}}})
		if e != nil {
			t.Fatal(e)
		}
	}
	handler := &DNS{Store: s, Config: func() Config { return c }}
	query := new(dns.Msg)
	query.SetQuestion("server.home.arpa.", dns.TypeA)
	recorder := dnstest.NewRecorder(&test.ResponseWriter{})
	if _, e = handler.ServeDNS(context.Background(), recorder, query); e != nil || len(recorder.Msg.Answer) != 1 {
		t.Fatal(recorder.Msg, e)
	}
	if recorder.Msg.Answer[0].(*dns.A).A.String() != "10.0.0.6" {
		t.Fatal(recorder.Msg)
	}
	c.Devices = append(c.Devices, DeviceConfig{ID: "other", Name: "server"})
	if e = c.Validate(); e == nil {
		t.Fatal("alias collision accepted")
	}
}

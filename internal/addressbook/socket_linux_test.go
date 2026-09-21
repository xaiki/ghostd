//go:build linux

package addressbook

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/miekg/dns"
)

// Run only inside an isolated network namespace: this binds real DHCP/DNS
// ports on loopback, with no LAN broadcasts or host interface changes.
func TestLinuxListenerAndPortOwnership(t *testing.T) {
	if os.Getenv("GHOSTD_DHCP_INTEGRATION") != "1" {
		t.Skip("requires isolated Linux network namespace")
	}
	s := openTest(t)
	m := NewManager(s)
	defer m.Close()
	c := Config{Scopes: []Scope{{ID: "isolated", Interface: "lo", Subnet: "127.0.0.0/8", Server: "127.0.0.1", Router: "127.0.0.1", Start: "127.0.0.2", End: "127.0.0.4", Zone: "test.home.arpa", LeaseSeconds: 600, Enabled: true}}}
	if e := m.Apply(c, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	other := NewManager(s)
	defer other.Close()
	if e := other.Apply(c, func() error { t.Fatal("saved despite occupied DHCP port"); return nil }); e == nil {
		t.Fatal("two authorities bound same interface")
	}
	client, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2"), Port: 68})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	mac, _ := net.ParseMAC("02:00:00:00:00:01")
	request, e := dhcpv4.New(dhcpv4.WithHwAddr(mac), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithClientIP(net.ParseIP("127.0.0.2")))
	if e != nil {
		t.Fatal(e)
	}
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = client.WriteToUDP(request.ToBytes(), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 67}); e != nil {
		t.Fatal(e)
	}
	buffer := make([]byte, 4096)
	n, _, e := client.ReadFromUDP(buffer)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := dhcpv4.FromBytes(buffer[:n])
	if e != nil || reply.MessageType() != dhcpv4.MessageTypeAck || reply.YourIPAddr.String() != "127.0.0.2" {
		t.Fatal(reply, e)
	}
	snapshot, e := s.Snapshot("isolated", "127.0.0.2", 0)
	if e != nil || len(snapshot.Bindings) != 1 {
		t.Fatal(snapshot, e)
	}
	for _, transport := range []string{"udp", "tcp"} {
		q := new(dns.Msg)
		q.SetQuestion(snapshot.Bindings[0].Name+".test.home.arpa.", dns.TypeA)
		reply, _, e := (&dns.Client{Net: transport, Timeout: time.Second}).Exchange(q, "127.0.0.1:53")
		if e != nil || len(reply.Answer) != 1 {
			t.Fatal(transport, reply, e)
		}
	}
	c.Scopes[0].Enabled = false
	if e = m.Apply(c, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	snapshot, e = s.Snapshot("isolated", "127.0.0.2", 0)
	if e != nil || snapshot.Bindings[0].State != "active" {
		t.Fatal("disabling erased lease", snapshot, e)
	}
}

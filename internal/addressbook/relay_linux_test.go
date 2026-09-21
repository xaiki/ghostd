//go:build dhcp && linux

package addressbook

import (
	"fmt"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
	"net"
	"os"
	"testing"
	"time"
)

// Child helper runs inside the isolated relay namespace and exercises the real
// server socket's peer admission, including rejection before allocation.
func TestRelayClient(t *testing.T) {
	if os.Getenv("GHOSTD_RELAY_CLIENT") != "1" {
		t.Skip("lab child only")
	}
	send, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.77.0.100"), Port: 67})
	if e != nil {
		t.Fatal(e)
	}
	defer send.Close()
	receive, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("10.88.0.1"), Port: 67})
	if e != nil {
		t.Fatal(e)
	}
	defer receive.Close()
	mac, _ := net.ParseMAC("00:aa:bb:cc:dd:ee")
	r, e := dhcpv4.NewDiscovery(mac)
	if e != nil {
		t.Fatal(e)
	}
	r.GatewayIPAddr = net.ParseIP("10.88.0.1")
	r.HopCount = 1
	if _, e = send.WriteToUDP(r.ToBytes(), &net.UDPAddr{IP: net.ParseIP("10.77.0.1"), Port: 67}); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 4096)
	receive.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, e := receive.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	offer, e := dhcpv4.FromBytes(b[:n])
	if e != nil || offer.YourIPAddr.String() != "10.88.0.10" {
		t.Fatal(offer, e)
	}
	request, e := dhcpv4.NewRequestFromOffer(offer)
	if e != nil {
		t.Fatal(e)
	}
	request.GatewayIPAddr = r.GatewayIPAddr
	send.WriteToUDP(request.ToBytes(), &net.UDPAddr{IP: net.ParseIP("10.77.0.1"), Port: 67})
	receive.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, e = receive.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	ack, e := dhcpv4.FromBytes(b[:n])
	if e != nil || ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatal(ack, e)
	}
	// Same approved peer but wrong relay link: no response is allowed.
	request.GatewayIPAddr = net.ParseIP("10.89.0.1")
	send.WriteToUDP(request.ToBytes(), &net.UDPAddr{IP: net.ParseIP("10.77.0.1"), Port: 67})
	receive.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, e = receive.ReadFromUDP(b); e == nil {
		t.Fatal("wrong relay link accepted")
	}
	conn, e := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP("fd77::100"), Port: 547})
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	inner := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeInformationRequest}
	relay, e := dhcpv6.EncapsulateRelay(inner, dhcpv6.MessageTypeRelayForward, net.ParseIP("fd88::1"), net.ParseIP("fe80::2"))
	if e != nil {
		t.Fatal(e)
	}
	conn.WriteToUDP(relay.ToBytes(), &net.UDPAddr{IP: net.ParseIP("fd77::1"), Port: 547})
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, e = conn.ReadFromUDP(b)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := dhcpv6.FromBytes(b[:n])
	if e != nil || reply.Type() != dhcpv6.MessageTypeRelayReply {
		t.Fatal(reply, e)
	}
	relay.LinkAddr = net.ParseIP("fd89::1")
	conn.WriteToUDP(relay.ToBytes(), &net.UDPAddr{IP: net.ParseIP("fd77::1"), Port: 547})
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, e = conn.ReadFromUDP(b); e == nil {
		t.Fatal("wrong IPv6 relay link accepted")
	}
	// Prefix delegation through the relay: Solicit -> Advertise carries a prefix and
	// the server DUID; Request commits it. Both arrive as Relay-Reply.
	pdCID := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 0x77, 1, 2, 3, 4}}
	relayed := func(m *dhcpv6.Message) *dhcpv6.Message {
		t.Helper()
		fwd, e := dhcpv6.EncapsulateRelay(m, dhcpv6.MessageTypeRelayForward, net.ParseIP("fd88::1"), net.ParseIP("fe80::77"))
		if e != nil {
			t.Fatal(e)
		}
		conn.WriteToUDP(fwd.ToBytes(), &net.UDPAddr{IP: net.ParseIP("fd77::1"), Port: 547})
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, e := conn.ReadFromUDP(b)
		if e != nil {
			t.Fatal("no relayed reply:", e)
		}
		out, e := dhcpv6.FromBytes(b[:n])
		if e != nil {
			t.Fatal(e)
		}
		inner, e := out.(*dhcpv6.RelayMessage).GetInnerMessage()
		if e != nil {
			t.Fatal(e)
		}
		return inner
	}
	solicit := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeSolicit}
	solicit.AddOption(dhcpv6.OptClientID(pdCID))
	solicit.AddOption(&dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 9}})
	adv := relayed(solicit)
	pds := adv.Options.IAPD()
	if len(pds) != 1 || len(pds[0].Options.Prefixes()) != 1 {
		t.Fatal("no prefix offered through the relay:", adv)
	}
	reqPD := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeRequest}
	reqPD.AddOption(dhcpv6.OptClientID(pdCID))
	reqPD.AddOption(dhcpv6.OptServerID(adv.Options.ServerID()))
	ia := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, 9}}
	ia.Options.Add(pds[0].Options.Prefixes()[0])
	reqPD.AddOption(ia)
	rep := relayed(reqPD)
	if got := rep.Options.IAPD(); len(got) != 1 || len(got[0].Options.Prefixes()) != 1 {
		t.Fatal("prefix not delegated through the relay:", rep)
	} else {
		fmt.Printf("RELAYPD prefix=%s\n", got[0].Options.Prefixes()[0].Prefix)
	}

}

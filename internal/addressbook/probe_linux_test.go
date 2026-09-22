//go:build dnsmasq && dhcp && linux

package addressbook

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"

	"github.com/xaiki/ghostd/internal/wellknown"
)

// TestDHCPProbeClient is a lab child, run inside a client namespace, that
// speaks just enough raw DHCPv4 to leave an unrequested OFFER outstanding or to
// DECLINE a leased address — states the ISC client never produces.
func TestDHCPProbeClient(t *testing.T) {
	mode := os.Getenv("GHOSTD_PROBE")
	if mode == "" {
		t.Skip("lab child only")
	}
	mac, e := net.ParseMAC(os.Getenv("GHOSTD_PROBE_MAC"))
	if e != nil {
		t.Fatal(e)
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var err error
		c.Control(func(fd uintptr) {
			if err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); err != nil {
				return
			}
			err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, os.Getenv("GHOSTD_PROBE_IFACE"))
		})
		return err
	}}
	pc, e := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:68")
	if e != nil {
		t.Fatal(e)
	}
	defer pc.Close()
	broadcast := &net.UDPAddr{IP: net.IPv4bcast, Port: wellknown.PortDHCPv4Server}
	exchange := func(m *dhcpv4.DHCPv4, want dhcpv4.MessageType) *dhcpv4.DHCPv4 {
		t.Helper()
		if _, e := pc.WriteTo(m.ToBytes(), broadcast); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 4096)
		pc.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			n, _, e := pc.ReadFrom(buf)
			if e != nil {
				t.Fatal("no reply:", e)
			}
			r, e := dhcpv4.FromBytes(buf[:n])
			if e == nil && r.TransactionID == m.TransactionID && r.MessageType() == want {
				return r
			}
		}
	}
	discover, e := dhcpv4.NewDiscovery(mac, dhcpv4.WithBroadcast(true))
	if e != nil {
		t.Fatal(e)
	}
	offer := exchange(discover, dhcpv4.MessageTypeOffer)
	if mode == "decline" {
		request, e := dhcpv4.NewRequestFromOffer(offer, dhcpv4.WithBroadcast(true))
		if e != nil {
			t.Fatal(e)
		}
		ack := exchange(request, dhcpv4.MessageTypeAck)
		decline, e := dhcpv4.New(dhcpv4.WithHwAddr(mac), dhcpv4.WithMessageType(dhcpv4.MessageTypeDecline),
			dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(ack.YourIPAddr)), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ack.ServerIdentifier())))
		if e != nil {
			t.Fatal(e)
		}
		pc.WriteTo(decline.ToBytes(), broadcast)
		time.Sleep(300 * time.Millisecond)
	}
	fmt.Printf("PROBE ip=%s\n", offer.YourIPAddr)
}

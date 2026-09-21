//go:build dhcp

package addressbook

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

func v6Request(t *testing.T, s *Store, sid dhcpv6.DUID, kind dhcpv6.MessageType, ll byte) (dhcpv6.DHCPv6, error) {
	t.Helper()
	cid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, ll}}
	r := &dhcpv6.Message{MessageType: kind}
	r.AddOption(dhcpv6.OptClientID(cid))
	r.AddOption(dhcpv6.OptServerID(sid))
	ia := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("fd00::6")})
	r.AddOption(ia)
	c := config6()
	return s.Handle6(c, c.Scopes[0], r)
}

// The DHCPv6 twin of TestCrashAfterACK: a process killed right after it sent a
// Reply must leave the address durably granted, and never hand it out again.
func TestCrashAfterV6Reply(t *testing.T) {
	if path := os.Getenv("GHOSTD_CRASH_LEDGER6"); path != "" {
		s, e := Open(path)
		if e != nil {
			t.Fatal(e)
		}
		sid, e := s.ServerDUID()
		if e != nil {
			t.Fatal(e)
		}
		reply, e := v6Request(t, s, sid, dhcpv6.MessageTypeRequest, 5)
		if e != nil || reply == nil || reply.Type() != dhcpv6.MessageTypeReply {
			t.Fatal(reply, e)
		}
		os.Exit(0) // no Close, no cleanup: the Reply was "sent"
	}
	path := filepath.Join(t.TempDir(), "crash6.db")
	child := exec.Command(os.Args[0], "-test.run=^TestCrashAfterV6Reply$")
	child.Env = append(os.Environ(), "GHOSTD_CRASH_LEDGER6="+path)
	if raw, e := child.CombinedOutput(); e != nil {
		t.Fatalf("child: %v %s", e, raw)
	}
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	snap, e := s.Snapshot("v6", "fd00::6", 0)
	if e != nil || len(snap.Bindings) != 1 || snap.Bindings[0].State != "active" {
		t.Fatal("acknowledged v6 grant not durable:", snap, e)
	}
	sid, _ := s.ServerDUID()
	// A different client asking for the same single-address pool gets nothing.
	other, e := v6Request(t, s, sid, dhcpv6.MessageTypeRequest, 6)
	if e == nil && other != nil {
		if a := other.(*dhcpv6.Message).Options.IANA(); len(a) > 0 && a[0].Options.OneAddress() != nil {
			t.Fatal("reissued an acknowledged v6 address after a crash")
		}
	}
}

// If the durable write fails, no Reply may grant an address that was not recorded.
func TestNoReplyWithoutDurableRecord(t *testing.T) {
	s := openTest(t)
	sid, e := s.ServerDUID()
	if e != nil {
		t.Fatal(e)
	}
	c := testConfig()
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	req4, _ := dhcpv4.New(dhcpv4.WithHwAddr(mac), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithClientIP(net.ParseIP("10.0.0.6")))
	s.db.Close() // every later write fails, as a full or failing disk would
	if reply, e := s.Handle4(c, c.Scopes[0], req4); e == nil && reply != nil && reply.MessageType() == dhcpv4.MessageTypeAck {
		t.Fatal("v4 ACK sent although the grant could not be recorded")
	}
	reply, e := v6Request(t, s, sid, dhcpv6.MessageTypeRequest, 5)
	if e == nil && reply != nil {
		if a := reply.(*dhcpv6.Message).Options.IANA(); len(a) > 0 && a[0].Options.OneAddress() != nil {
			t.Fatal("v6 Reply carried an address that was not recorded")
		}
	}
}

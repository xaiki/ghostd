package addressbook

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestCrashAfterACK(t *testing.T) {
	if path := os.Getenv("GHOSTD_CRASH_LEDGER"); path != "" {
		s, e := Open(path)
		if e != nil {
			t.Fatal(e)
		}
		c := testConfig()
		mac, _ := net.ParseMAC("00:11:22:33:44:55")
		request, _ := dhcpv4.New(dhcpv4.WithHwAddr(mac), dhcpv4.WithMessageType(dhcpv4.MessageTypeRequest), dhcpv4.WithClientIP(net.ParseIP("10.0.0.6")))
		reply, e := s.Handle4(c, c.Scopes[0], request)
		if e != nil || reply.MessageType() != dhcpv4.MessageTypeAck {
			t.Fatal(reply, e)
		}
		os.Exit(0) // Intentionally skip Close and all cleanup after the acknowledged grant.
	}
	path := filepath.Join(t.TempDir(), "crash.db")
	child := exec.Command(os.Args[0], "-test.run=^TestCrashAfterACK$")
	child.Env = append(os.Environ(), "GHOSTD_CRASH_LEDGER="+path)
	if raw, e := child.CombinedOutput(); e != nil {
		t.Fatalf("child: %v %s", e, raw)
	}
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	snapshot, e := s.Snapshot("lan", "10.0.0.6", 0)
	if e != nil || len(snapshot.Bindings) != 1 || snapshot.Bindings[0].State != "active" {
		t.Fatal(snapshot, e)
	}
	c := testConfig()
	if _, e = s.Allocate(c, "lan", "mac:00:11:22:33:44:66", "00:11:22:33:44:66", "", "10.0.0.6", true); e == nil {
		t.Fatal("reissued acknowledged address after crash")
	}
}

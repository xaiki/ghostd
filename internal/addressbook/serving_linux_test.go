//go:build linux

package addressbook

import (
	"net"
	"os"
	"testing"
)

func TestProcessOwnsUDPPort(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port
	if ok, err := processOwnsUDPPort(os.Getpid(), port); err != nil || !ok {
		t.Fatal("own socket not found:", ok, err)
	}
	if ok, _ := processOwnsUDPPort(os.Getpid(), port+1); ok {
		t.Fatal("reported a port nobody bound")
	}
	// Another process (init) does not own our socket.
	if ok, _ := processOwnsUDPPort(1, port); ok {
		t.Fatal("attributed our socket to pid 1")
	}
	if _, err := processOwnsUDPPort(0, port); err == nil {
		t.Fatal("no process must be an error, not a pass")
	}
}

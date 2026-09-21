//go:build dhcp && !linux

package addressbook

import (
	"fmt"
	"net"
)

func listenDHCP(iface string) (net.PacketConn, error) {
	return nil, fmt.Errorf("DHCP listeners require Linux")
}

func listenDHCP6(iface string) (net.PacketConn, error) {
	return nil, fmt.Errorf("DHCP listeners require Linux")
}

//go:build !linux

package coredhcpserver

import (
	"fmt"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"net"
)

func sendEthernet(net.Interface, *dhcpv4.DHCPv4) error {
	return fmt.Errorf("raw Ethernet DHCP replies require Linux")
}

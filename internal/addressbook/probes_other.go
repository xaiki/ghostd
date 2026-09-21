//go:build dhcp && dnsmasq && !linux

package addressbook

import (
	"context"
	"fmt"
)

func probeDHCP(context.Context, Probe, Config) (string, error) {
	return "", fmt.Errorf("the dhcp probe needs Linux raw sockets")
}

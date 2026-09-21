//go:build dhcp && !dnsmasq

package addressbook

import "testing"

func checkNoDelegationExport(*testing.T, Snapshot) {}

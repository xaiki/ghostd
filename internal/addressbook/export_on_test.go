//go:build dhcp && dnsmasq

package addressbook

import (
	"strings"
	"testing"
)

func checkNoDelegationExport(t *testing.T, snap Snapshot) {
	t.Helper()
	text, err := ExportDNSmasq(snap)
	if err != nil || strings.Contains(text, "fd78") {
		t.Fatalf("delegation exported to a dnsmasq lease file: %v\n%s", err, text)
	}
}

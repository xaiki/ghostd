package nft

import (
	"strings"
	"testing"
)

func TestRedirectOnlyPreservesFiltering(t *testing.T) {
	ds := DesiredState{RedirectOnly: true, Zones: map[string]Zone{"services": {Interfaces: []string{"eth0"}, Redirects: []RedirectRule{{Port: 514, ToPort: 15514, Proto: "udp"}}}}}
	script, err := Render(ds, ReachabilityGuard{TailscaleInterface: "tailscale0", Port: 7443})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "udp dport 514 redirect to :15514") || strings.Contains(script, "type filter") || strings.Contains(script, "postrouting") {
		t.Fatal(script)
	}
	ds.Zones["services"] = Zone{Interfaces: []string{"eth0"}, SSH: &SSHRule{Port: 22}}
	if _, err := Render(ds, ReachabilityGuard{TailscaleInterface: "tailscale0", Port: 7443}); err == nil {
		t.Fatal("silently discarded filter policy")
	}
}

func TestRedirectOnlyCannotEraseOwnedFiltering(t *testing.T) {
	for _, table := range []string{"stack_ghostd", "filter"} {
		raw := []byte(`{"nftables":[{"chain":{"family":"inet","table":"` + table + `","type":"filter"}}]}`)
		err := ValidateRedirectCoexistence(raw)
		if (err != nil) != (table == "stack_ghostd") {
			t.Fatalf("%s: %v", table, err)
		}
	}
	if err := ValidateRedirectCoexistence([]byte(`{"nftables":[{"chain":{"family":"inet","table":"stack_ghostd","type":"nat"}}]}`)); err != nil {
		t.Fatal(err)
	}
}

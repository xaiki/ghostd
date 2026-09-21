package nft

import (
	"strings"
	"testing"
)

func guard() ReachabilityGuard {
	return ReachabilityGuard{TailscaleInterface: "tailscale0", Port: 7443}
}

func minimalDesiredState() DesiredState {
	return DesiredState{
		Zones: map[string]Zone{
			"mgmt": {Interfaces: []string{"end0.10"}, SSH: &SSHRule{Port: 22}},
		},
	}
}

func TestRenderRejectsNoZones(t *testing.T) {
	_, err := Render(DesiredState{}, guard())
	if err == nil {
		t.Fatal("expected an error for an empty DesiredState")
	}
}

func TestRenderPreservesIPv6ControlTrafficWithoutOpeningApplicationPorts(t *testing.T) {
	script, err := Render(minimalDesiredState(), guard())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(script, "nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept") ||
		!strings.Contains(script, "packet-too-big") {
		t.Fatal("IPv6 NDP/PMTU blocked by default drop")
	}
}

func TestRenderRejectsNoReachableZone(t *testing.T) {
	ds := DesiredState{Zones: map[string]Zone{
		"iot": {Interfaces: []string{"end0.50"}},
	}}
	_, err := Render(ds, guard())
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("expected an unreachable-host error, got %v", err)
	}
}

func TestRenderAcceptsTrustedZoneAsReachable(t *testing.T) {
	ds := DesiredState{Zones: map[string]Zone{
		"trusted": {Interfaces: []string{"tailscale0"}},
	}}
	if _, err := Render(ds, guard()); err != nil {
		t.Fatalf("a trusted zone alone should satisfy reachability: %v", err)
	}
}

func TestRenderRejectsForwardToUndeclaredZone(t *testing.T) {
	ds := DesiredState{Zones: map[string]Zone{
		"mgmt": {Interfaces: []string{"end0.10"}, SSH: &SSHRule{Port: 22}, Forward: []string{"wan"}},
	}}
	_, err := Render(ds, guard())
	if err == nil || !strings.Contains(err.Error(), "wan") {
		t.Fatalf("expected an undeclared-forward-zone error naming wan, got %v", err)
	}
}

func TestRenderRejectsUnrecognizedService(t *testing.T) {
	ds := minimalDesiredState()
	zone := ds.Zones["mgmt"]
	zone.Services = []string{"carrier-pigeon"}
	ds.Zones["mgmt"] = zone
	_, err := Render(ds, guard())
	if err == nil || !strings.Contains(err.Error(), "carrier-pigeon") {
		t.Fatalf("expected an unrecognized-service error, got %v", err)
	}
}

func TestReachabilityGuardAlwaysPresentEvenWhenNoZoneMentionsTailscale(t *testing.T) {
	script, err := Render(minimalDesiredState(), guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(script, `iifname "tailscale0" tcp dport 7443 accept`) {
		t.Fatalf("expected the hardcoded reachability guard in:\n%s", script)
	}
}

func TestRenderIsDeterministicAcrossMapIterationOrder(t *testing.T) {
	ds := DesiredState{Zones: map[string]Zone{
		"mgmt":  {Interfaces: []string{"end0.10"}, SSH: &SSHRule{Port: 22}},
		"iot":   {Interfaces: []string{"end0.50"}},
		"guest": {Interfaces: []string{"end0.70"}, Services: []string{"mdns"}},
	}}
	first, err := Render(ds, guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	for i := 0; i < 10; i++ {
		again, err := Render(ds, guard())
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if again != first {
			t.Fatalf("Render is not deterministic across repeated calls (Go map iteration order):\n%s\n---\n%s", first, again)
		}
	}
}

func TestRenderSSHZoneProducesExpectedShape(t *testing.T) {
	script, err := Render(minimalDesiredState(), guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := []string{
		"table inet stack_ghostd {",
		`iifname { "end0.10" } jump zone_mgmt`,
		"chain zone_mgmt {",
		"tcp dport 22 accept",
	}
	for _, w := range want {
		if !strings.Contains(script, w) {
			t.Fatalf("expected %q in:\n%s", w, script)
		}
	}
}

func TestRenderNFSZoneRestrictsBySourceCIDR(t *testing.T) {
	ds := minimalDesiredState()
	zone := ds.Zones["mgmt"]
	zone.NFS = &NFSRule{Exports: []string{"10.0.10.0/24"}}
	ds.Zones["mgmt"] = zone
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(script, `ip saddr 10.0.10.0/24 tcp dport { 111, 2049, 20048 } accept`) {
		t.Fatalf("expected a source-restricted NFS rule in:\n%s", script)
	}
}

func TestRenderTrustedZoneIsFullAccept(t *testing.T) {
	ds := DesiredState{Zones: map[string]Zone{
		"trusted": {Interfaces: []string{"tailscale0"}},
	}}
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(script, "chain zone_trusted {\n    accept\n  }") {
		t.Fatalf("expected a bare-accept trusted zone chain in:\n%s", script)
	}
}

func TestRenderForwardBetweenZones(t *testing.T) {
	ds := DesiredState{Zones: map[string]Zone{
		"lan": {Interfaces: []string{"end0"}, SSH: &SSHRule{Port: 22}, Forward: []string{"wan"}},
		"wan": {Interfaces: []string{"eth1"}},
	}}
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(script, `iifname { "end0" } oifname { "eth1" } accept`) {
		t.Fatalf("expected a forward rule between lan and wan in:\n%s", script)
	}
}

func TestRenderMasqueradeOnEgressInterface(t *testing.T) {
	ds := DesiredState{Zones: map[string]Zone{
		"lan": {Interfaces: []string{"end0"}, SSH: &SSHRule{Port: 22}},
		"wan": {Interfaces: []string{"eth1"}, Masquerade: true},
	}}
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(script, `oifname "eth1" masquerade`) {
		t.Fatalf("expected a masquerade rule in:\n%s", script)
	}
}

func TestRenderIngressDNATAndAccept(t *testing.T) {
	ds := minimalDesiredState()
	ds.Ingress = &Ingress{Interfaces: []string{"end0"}, HTTPPort: 18080}
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(script, `iifname "end0" fib daddr type local tcp dport 80 dnat to :18080`) {
		t.Fatalf("expected an 80->http_port DNAT rule in:\n%s", script)
	}
	if !strings.Contains(script, `iifname "end0" fib daddr type local tcp dport 443 dnat to :8443`) {
		t.Fatalf("expected a 443->8443 DNAT rule in:\n%s", script)
	}
	if !strings.Contains(script, `iifname { "end0" } tcp dport { 18080, 8443 } accept`) {
		t.Fatalf("expected an input-chain accept for the DNAT'd ports in:\n%s", script)
	}
}

func TestRenderTargetAcceptAddsCatchAll(t *testing.T) {
	ds := minimalDesiredState()
	zone := ds.Zones["mgmt"]
	zone.Target = "ACCEPT"
	ds.Zones["mgmt"] = zone
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(script, "chain zone_mgmt {\n    tcp dport 22 accept\n    accept\n  }") {
		t.Fatalf("expected a trailing catch-all accept in:\n%s", script)
	}
}

func TestParseDesiredStateRoundTrips(t *testing.T) {
	raw := `{"zones":{"mgmt":{"interfaces":["end0.10"],"ssh":{"port":22}}}}`
	ds, err := ParseDesiredState(raw)
	if err != nil {
		t.Fatalf("ParseDesiredState: %v", err)
	}
	if ds.Zones["mgmt"].SSH.Port != 22 {
		t.Fatalf("got %+v", ds)
	}
}

func TestRenderRejectsUnsafeOrAmbiguousFields(t *testing.T) {
	cases := map[string]func(*DesiredState){
		"zone syntax": func(ds *DesiredState) { ds.Zones["x { accept; }"] = ds.Zones["mgmt"] },
		"protocol syntax": func(ds *DesiredState) {
			z := ds.Zones["mgmt"]
			z.Ports = []PortRule{{Port: 22, Proto: "tcp; flush ruleset;"}}
			ds.Zones["mgmt"] = z
		},
		"source syntax": func(ds *DesiredState) {
			z := ds.Zones["mgmt"]
			z.NFS = &NFSRule{Exports: []string{"0.0.0.0/0 accept; drop"}}
			ds.Zones["mgmt"] = z
		},
		"SSH port": func(ds *DesiredState) { ds.Zones["mgmt"].SSH.Port = 0 },
		"port overflow": func(ds *DesiredState) {
			z := ds.Zones["mgmt"]
			z.Ports = []PortRule{{Port: 65536, Proto: "tcp"}}
			ds.Zones["mgmt"] = z
		},
		"shared interface":   func(ds *DesiredState) { ds.Zones["other"] = Zone{Interfaces: []string{"end0.10"}} },
		"wildcard interface": func(ds *DesiredState) { z := ds.Zones["mgmt"]; z.Interfaces = []string{"end*"}; ds.Zones["mgmt"] = z },
		"unknown target":     func(ds *DesiredState) { z := ds.Zones["mgmt"]; z.Target = "ACCEPP"; ds.Zones["mgmt"] = z },
		"ingress port":       func(ds *DesiredState) { ds.Ingress = &Ingress{Interfaces: []string{"end0"}, HTTPPort: -1} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			ds := minimalDesiredState()
			mutate(&ds)
			if _, err := Render(ds, guard()); err == nil {
				t.Fatal("invalid policy accepted")
			}
		})
	}
}

func TestRenderRejectsMissingReachabilityGuard(t *testing.T) {
	if _, err := Render(minimalDesiredState(), ReachabilityGuard{}); err == nil {
		t.Fatal("guard omitted")
	}
}

func TestRootlessRedirectIsLocalScopedAndWithdrawn(t *testing.T) {
	ds := minimalDesiredState()
	zone := ds.Zones["mgmt"]
	zone.Redirects = []RedirectRule{{Port: 514, ToPort: 15514, Proto: "udp"}}
	ds.Zones["mgmt"] = zone
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`iifname "end0.10" fib daddr type local udp dport 514 redirect to :15514`,
		`ct status dnat meta l4proto udp ct original proto-dst 514 udp dport 15514 accept`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s in %s", want, script)
		}
	}
	if strings.Contains(script, "    udp dport 15514 accept") {
		t.Fatal("backend opened directly")
	}
	zone.Redirects = nil
	ds.Zones["mgmt"] = zone
	script, err = Render(ds, guard())
	if err != nil || strings.Contains(script, "15514") {
		t.Fatal("redirect was not withdrawn", err, script)
	}
}

func TestRejectInvalidRedirects(t *testing.T) {
	for _, rules := range [][]RedirectRule{
		{{Port: 514, ToPort: 0, Proto: "udp"}},
		{{Port: 514, ToPort: 15514, Proto: "udp;accept"}},
		{{Port: 514, ToPort: 514, Proto: "udp"}},
		{{Port: 514, ToPort: 15514, Proto: "udp"}, {Port: 514, ToPort: 15515, Proto: "udp"}},
	} {
		ds := minimalDesiredState()
		zone := ds.Zones["mgmt"]
		zone.Redirects = rules
		ds.Zones["mgmt"] = zone
		if _, err := Render(ds, guard()); err == nil {
			t.Fatalf("accepted %+v", rules)
		}
	}
}

func TestMDNSServiceAlsoAdmitsUnicastReplies(t *testing.T) {
	desired, err := ParseDesiredState(`{"zones":{"trusted":{"interfaces":["tailscale0"]},"lan":{"interfaces":["eth0"],"services":["mdns"]}}}`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(desired, ReachabilityGuard{TailscaleInterface: "tailscale0", Port: 7443})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"udp dport 5353 accept", "udp sport 5353 udp dport 1024-65535 accept"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	// Zones without the service admit neither.
	plain, _ := ParseDesiredState(`{"zones":{"trusted":{"interfaces":["tailscale0"]},"lan":{"interfaces":["eth0"],"services":["dns"]}}}`)
	if out, _ = Render(plain, ReachabilityGuard{TailscaleInterface: "tailscale0", Port: 7443}); strings.Contains(out, "5353") {
		t.Fatal("mDNS admitted without the service")
	}
}

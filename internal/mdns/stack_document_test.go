//go:build mdns

package mdns

import (
	"encoding/json"
	"testing"
)

// The document the stack's mdns layer emits has to parse here, and the echo the
// daemon hands back has to be the shape that layer diffs against.
//
// The fixtures mirror what the stack's own emitter produces
// (<code>/packages/machines/machines/host_mdns_advertise.py's
// desired_document, whose output its tests/test_host_mdns_advertise.py asserts
// literally) — a mirror, not a live read, so a change to that emitter has to
// change these with it. It is worth pinning because a field or domain mismatch
// is silent on both sides: the stack sends, the daemon refuses, and nothing in
// the relay is reached.
func TestTheStacksMDNSDocumentParses(t *testing.T) {
	const (
		// desired_document() for a machine that only advertises — the stack's own
		// DESIRED literal: _adisk/_device-info carry port 0 by convention.
		advertising = `{"interfaces": ["eth0"], "host": "nas", "records": [
			{"service": "_smb._tcp", "instance": "nas", "port": 445},
			{"service": "_device-info._tcp", "instance": "nas", "port": 0},
			{"service": "_adisk._tcp", "instance": "nas", "port": 0}]}`

		// A pure reflector: every class on every flow, and records/host still
		// spelled out empty because the emitter always writes those keys.
		pureReflector = `{"interfaces": ["end0.70", "podman1"], "host": "", "records": [],
			"reflect": [
			{"from": "podman1", "to": "end0.70", "allow_services": ["*"]},
			{"from": "end0.70", "to": "podman1", "allow_services": ["*"]},
			{"from": "end0.70", "to": "tailscale0", "allow_services": ["*"]},
			{"from": "podman1", "to": "tailscale0", "allow_services": ["*"]}]}`

		// Both halves, the four flows of a machine that reflects and advertises:
		// media (70), guest (50), the container bridge, and the overlay each
		// domain reaches.
		bothHalves = `{"interfaces": ["end0", "end0.70", "end0.50", "podman1"], "host": "nas",
			"records": [{"service": "_smb._tcp", "instance": "nas", "port": 445}],
			"reflect": [
			{"from": "podman1", "to": "end0.70", "allow_services": ["*"]},
			{"from": "podman1", "to": "end0.50", "allow_services": ["*"]},
			{"from": "end0.70", "to": "podman1", "allow_services": ["*"]},
			{"from": "end0", "to": "tailscale0", "allow_services": ["*"]},
			{"from": "end0.70", "to": "tailscale0", "allow_services": ["*"]},
			{"from": "end0.50", "to": "tailscale0", "allow_services": ["*"]},
			{"from": "podman1", "to": "tailscale0", "allow_services": ["*"]}]}`
	)
	for name, doc := range map[string]string{"advertising": advertising, "pure reflector": pureReflector, "both halves": bothHalves} {
		if _, err := ParseConfig([]byte(doc)); err != nil {
			t.Errorf("%s: the daemon refuses the stack's own document: %v", name, err)
		}
	}

	// What the daemon echoes back (GetState's mdns_config_json) is what the stack
	// diffs a desired document against, reading per rule the names `from`, `to`,
	// `allow_services` (host_mdns_advertise._reflect_key). A rename on either side
	// would read as permanent drift on a host that is in fact converged, so the
	// echo is checked against the stack's names, not just re-parsed here.
	c, err := ParseConfig([]byte(bothHalves))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var echo map[string]any
	if err := json.Unmarshal(raw, &echo); err != nil {
		t.Fatalf("the echo is not JSON: %v", err)
	}
	rules, ok := echo["reflect"].([]any)
	if !ok || len(rules) != 7 {
		t.Fatalf("the echo carries %d reflect rules, want 7: %s", len(rules), raw)
	}
	got := map[string]bool{}
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			t.Fatalf("a rule is not an object: %v", r)
		}
		from, fromOK := rule["from"].(string)
		to, toOK := rule["to"].(string)
		classes, classesOK := rule["allow_services"].([]any)
		if !fromOK || !toOK || !classesOK {
			t.Fatalf("the echo's field names are not the ones the stack reads: %v", rule)
		}
		if len(classes) != 1 || classes[0] != "*" {
			t.Fatalf("the echo does not carry the wildcard the stack sent: %v", rule)
		}
		got[from+" > "+to] = true
	}
	for _, want := range []string{
		"podman1 > end0.70", "podman1 > end0.50", "end0.70 > podman1",
		"end0 > tailscale0", "end0.70 > tailscale0", "end0.50 > tailscale0", "podman1 > tailscale0",
	} {
		if !got[want] {
			t.Errorf("the echo dropped %s: %v", want, got)
		}
	}
}

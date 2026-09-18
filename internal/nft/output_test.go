package nft

import (
	"strings"
	"testing"
)

func TestOutputOptInAndRestrictions(t *testing.T) {
	ds := minimalDesiredState()
	before, err := Render(ds, guard())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(before, "hook output") {
		t.Fatal("changed legacy output behavior")
	}
	ds.Output = &OutputPolicy{Policy: "DROP", EstablishedRelated: true, Loopback: true, Rules: []OutputRule{
		{Proto: "tcp", Port: 443}, {Proto: "udp", Port: 53, Family: "ip", Interface: "eth0", Destination: "192.0.2.0/24"},
	}}
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"hook output priority 0; policy drop;", "oifname \"lo\" accept", "meta nfproto ipv4 oifname \"eth0\" ip daddr 192.0.2.0/24 udp dport 53 accept", "tcp dport 443 accept"} {
		if !strings.Contains(script, want) {
			t.Fatalf("missing %s", want)
		}
	}
	output := strings.Split(strings.Split(script, "chain output {")[1], "  }\n")[0]
	if strings.Contains(output, "tcp dport 22") {
		t.Fatal("inbound SSH leaked into output")
	}
}

func TestOutputRejectsInvalidAndUnknownFields(t *testing.T) {
	for _, output := range []OutputPolicy{
		{Policy: "invalid"}, {Policy: "DROP", Rules: []OutputRule{{Proto: "tcp", Port: 0}}},
		{Policy: "DROP", Rules: []OutputRule{{Proto: "tcp", Port: 443, Interface: "eth0; accept"}}},
		{Policy: "DROP", Rules: []OutputRule{{Proto: "tcp", Port: 443, Family: "ip", Destination: "::1"}}},
	} {
		ds := minimalDesiredState()
		ds.Output = &output
		if _, err := Render(ds, guard()); err == nil {
			t.Fatalf("accepted %+v", output)
		}
	}
	if _, err := ParseDesiredState(`{"zones":{},"output":{"policy":"DROP","typo":true}}`); err == nil {
		t.Fatal("ignored unknown policy field")
	}
}

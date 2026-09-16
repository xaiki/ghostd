package nft

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestOwnedRulesetExcludesOtherWriters(t *testing.T) {
	raw := []byte(`{"nftables":[{"metainfo":{"json_schema_version":1}},{"table":{"family":"inet","name":"safety_net"}},{"table":{"family":"inet","name":"stack_ghostd"}},{"chain":{"family":"inet","table":"stack_ghostd","name":"input"}},{"rule":{"family":"inet","table":"safety_net","chain":"input"}}]}`)
	out, err := OwnedRuleset(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "safety_net") || strings.Contains(string(out), "metainfo") {
		t.Fatalf("foreign table leaked: %s", out)
	}
	if !strings.Contains(string(out), `"chain"`) {
		t.Fatal("lost owned chain")
	}
}

// Run only in a disposable Linux network namespace with CAP_NET_ADMIN.
func TestIntegrationReplaceAndRollback(t *testing.T) {
	if os.Getenv("GHOSTD_NFT_INTEGRATION") != "1" {
		t.Skip("requires isolated Linux nftables")
	}
	ctx := context.Background()
	r := ExecRunner{}
	if _, err := r.RunStdin(ctx, "nft", "table inet safety_net {\n chain untouched {\n }\n}\n", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		raw, err := ReadRulesetJSON(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	absent, err := OwnedRuleset([]byte(read()))
	if err != nil {
		t.Fatal(err)
	}
	ds := minimalDesiredState()
	ds.Ingress = &Ingress{Interfaces: []string{"end0.10"}, HTTPPort: 18080}
	zone := ds.Zones["mgmt"]
	zone.Ports = []PortRule{{Port: 12345, Proto: "tcp"}}
	ds.Zones["mgmt"] = zone
	script, err := Render(ds, guard())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSyntax(ctx, r, script); err != nil {
		t.Fatal(err)
	}
	if err := Commit(ctx, r, script); err != nil {
		t.Fatal(err)
	}
	before, err := OwnedRuleset([]byte(read()))
	if err != nil {
		t.Fatal(err)
	}
	count := func(raw string) int {
		var d struct {
			Nftables []map[string]any `json:"nftables"`
		}
		json.Unmarshal([]byte(raw), &d)
		n := 0
		for _, entry := range d.Nftables {
			if _, ok := entry["rule"]; ok {
				n++
			}
		}
		return n
	}
	if err := Commit(ctx, r, script); err != nil {
		t.Fatal(err)
	}
	if count(read()) != count(string(before)) {
		t.Fatal("repeat apply duplicated rules")
	}
	zone.Ports = nil
	ds.Zones["mgmt"] = zone
	script, err = Render(ds, guard())
	if err != nil {
		t.Fatal(err)
	}
	if err := Commit(ctx, r, script); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(read(), "12345") {
		t.Fatal("withdrawn port still allowed")
	}
	if err := Restore(ctx, r, before); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(), "12345") {
		t.Fatal("snapshot not restored")
	}
	if err := Restore(ctx, r, absent); err != nil {
		t.Fatal(err)
	}
	raw := read()
	if strings.Contains(raw, "stack_ghostd") || !strings.Contains(raw, "safety_net") {
		t.Fatalf("first-apply rollback damaged other tables: %s", raw)
	}
}

package nft

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type restoreCapture struct{ script string }

func (r *restoreCapture) Output(context.Context, string, ...string) ([]byte, error) {
	panic("restore must not split its atomic transaction with a read")
}
func (r *restoreCapture) RunStdin(_ context.Context, _ string, script string, _ ...string) ([]byte, error) {
	r.script = script
	return nil, nil
}

func TestRestoreDropsKernelHandlesButPreservesRuleOrder(t *testing.T) {
	raw := []byte(`{"nftables":[
	 {"table":{"family":"inet","name":"stack_ghostd","handle":51}},
	 {"chain":{"family":"inet","table":"stack_ghostd","name":"input","handle":52}},
	 {"rule":{"family":"inet","table":"stack_ghostd","chain":"input","handle":53,"expr":[{"accept":null}]}},
	 {"rule":{"family":"inet","table":"stack_ghostd","chain":"input","handle":54,"expr":[{"drop":null}]}}
	]}`)
	r := &restoreCapture{}
	if err := Restore(context.Background(), r, raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.script, `"handle"`) {
		t.Fatalf("stale kernel handles replayed: %s", r.script)
	}
	if !strings.Contains(string(raw), `"handle":53`) {
		t.Fatal("saved snapshot mutated")
	}
	if strings.Index(r.script, `"accept"`) >= strings.Index(r.script, `"drop"`) {
		t.Fatal("rule order changed")
	}
}

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
	ds.Ingress = &Ingress{Interfaces: []string{"end0.10"}, Redirects: []RedirectRule{
		{Port: 80, ToPort: 18080, Proto: "tcp"}, {Port: 443, ToPort: 8443, Proto: "tcp"}}}
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
	// Boot recovery must also work with no live owned table at all.
	if _, err := r.RunStdin(ctx, "nft", "delete table inet stack_ghostd\n", "-f", "-"); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, r, before); err != nil {
		t.Fatal(err)
	}
	if count(read()) != count(string(before)) {
		t.Fatal("boot restore lost or duplicated rules")
	}
	if err := Restore(ctx, r, absent); err != nil {
		t.Fatal(err)
	}
	raw := read()
	if strings.Contains(raw, "stack_ghostd") || !strings.Contains(raw, "safety_net") {
		t.Fatalf("first-apply rollback damaged other tables: %s", raw)
	}
}

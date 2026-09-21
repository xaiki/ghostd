package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xaiki/ghostd/internal/nft"
	"github.com/xaiki/ghostd/internal/rpc"
	"github.com/xaiki/ghostd/internal/state"
)

func TestIntegrationRevertUsesSnapshotAndLateTimerCannotUndoConfirm(t *testing.T) {
	if os.Getenv("GHOSTD_NFT_INTEGRATION") != "1" {
		t.Skip("requires isolated Linux nftables")
	}
	ctx := context.Background()
	store, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	runner := nft.ExecRunner{}
	script := "table inet stack_ghostd {\n chain allowed { tcp dport 54321 accept\n }\n}\n"
	if err := nft.Commit(ctx, runner, script); err != nil {
		t.Fatal(err)
	}
	d := state.DomainState{Pending: &state.Pending{ID: "first", Snapshot: []byte(`{"nftables":[]}`), Deadline: time.Now().Add(time.Minute)}}
	if err := store.SaveDomain("firewall", d); err != nil {
		t.Fatal(err)
	}
	if err := runRevert(store, "first", "firewall"); err != nil {
		t.Fatal(err)
	}
	raw, err := nft.ReadRulesetJSON(ctx, runner)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "stack_ghostd") {
		t.Fatal("first apply not rolled back")
	}
	if err := nft.Commit(ctx, runner, script); err != nil {
		t.Fatal(err)
	}
	d = state.DomainState{Confirmed: []byte(`{"nftables":[]}`)}
	if err := store.SaveDomain("firewall", d); err != nil {
		t.Fatal(err)
	}
	if err := runRevert(store, "first", "firewall"); err != nil {
		t.Fatal(err)
	}
	raw, err = nft.ReadRulesetJSON(ctx, runner)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(raw, "54321") {
		t.Fatal("late timer undid confirmed transaction")
	}
	// Boot restore uses the committed record, not stale legacy snapshot files.
	if err := store.Save(rpc.NftRuleset, []byte(`bad legacy bytes`)); err != nil {
		t.Fatal(err)
	}
	if err := recoverDomain(store, "firewall", ""); err != nil {
		t.Fatal(err)
	}
	raw, err = nft.ReadRulesetJSON(ctx, runner)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, "stack_ghostd") {
		t.Fatal("boot did not restore confirmed absence")
	}
}

func TestObservationBootDoesNotRestoreOrAbandonManagedState(t *testing.T) {
	store, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, domain := range []string{"firewall", "netconfig"} {
		if err := prepareDomain(store, domain, true); err != nil {
			t.Fatal(err)
		}
		original := state.DomainState{Confirmed: []byte(`{"proof":"must not execute"}`)}
		if err := store.SaveDomain(domain, original); err != nil {
			t.Fatal(err)
		}
		if err := prepareDomain(store, domain, true); err == nil {
			t.Fatal("managed state accepted in observation mode")
		}
		original = state.DomainState{Pending: &state.Pending{ID: "pending", Deadline: time.Now().Add(time.Minute)}}
		if err := store.SaveDomain(domain, original); err != nil {
			t.Fatal(err)
		}
		if err := prepareDomain(store, domain, true); err == nil {
			t.Fatal("pending rollback accepted in observation mode")
		}
	}
}

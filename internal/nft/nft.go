// Package nft owns the firewall domain's read and write side: rendering
// firewall.base.zones/firewall.ingress into an actual nft ruleset
// (render.go), and validating+applying one (this file, `nft -c`, atomic
// replace).
package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Runner is the seam tests fake — real callers use ExecRunner.
type Runner interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
	// RunStdin runs name with stdin piped from script — nft(8)'s own `-f -`
	// convention. A full ruleset travels this way, never as an argv
	// argument: it can be arbitrarily large and its own syntax includes
	// characters a shell would need escaping for no benefit.
	RunStdin(ctx context.Context, name string, script string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func (ExecRunner) RunStdin(ctx context.Context, name string, script string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = bytes.NewBufferString(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return out, nil
}

// ReadRulesetJSON is GetState's firewall half, and what Confirm persists as
// last-confirmed state: the live kernel ruleset, structured (nft -j), not
// a text scrape — the same "diffable, not a blob" requirement FIREWALL.md
// put on GetState generally. Restore replays the owned objects after removing
// kernel handles, which have positioning semantics in explicit add commands.
func ReadRulesetJSON(ctx context.Context, runner Runner) (string, error) {
	out, err := runner.Output(ctx, "nft", "-j", "list", "ruleset")
	if err != nil {
		return "", fmt.Errorf("nft: list ruleset: %w", err)
	}
	return string(out), nil
}

// ValidateSyntax runs `nft -c -f -` against a rendered script (Render's
// output — plain nft(8) syntax, not JSON) without touching the kernel.
// Every Apply call runs this before Commit — see internal/rpc.Server.Apply.
func ValidateSyntax(ctx context.Context, runner Runner, script string) error {
	if _, err := runner.RunStdin(ctx, "nft", script, "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft: ruleset failed validation: %w", err)
	}
	return nil
}

// Commit loads the rendered add/delete/recreate script in one transaction.
// Callers must already have run ValidateSyntax.
func Commit(ctx context.Context, runner Runner, script string) error {
	if _, err := runner.RunStdin(ctx, "nft", script, "-f", "-"); err != nil {
		return fmt.Errorf("nft: commit failed: %w", err)
	}
	return nil
}

// OwnedRuleset keeps only ghostd's table. Never persist/replay other writers'
// tables (tailscaled, podman, or the operator's migration safety net).
func OwnedRuleset(raw []byte) ([]byte, error) {
	var dump struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &dump); err != nil {
		return nil, err
	}
	entries := []map[string]json.RawMessage{}
	for _, entry := range dump.Nftables {
		for kind, body := range entry {
			var obj struct {
				Family string `json:"family"`
				Table  string `json:"table"`
				Name   string `json:"name"`
			}
			if err := json.Unmarshal(body, &obj); err != nil {
				return nil, err
			}
			if obj.Family == "inet" && (obj.Table == tableName || (kind == "table" && obj.Name == tableName)) {
				entries = append(entries, entry)
			}
		}
	}
	return json.Marshal(map[string]any{"nftables": entries})
}

// Restore atomically replaces our table, including restoring its absence on a
// first-apply rollback. A nil blob means no boot baseline, not an empty table.
func Restore(ctx context.Context, runner Runner, rulesetJSON []byte) error {
	if len(rulesetJSON) == 0 {
		return nil
	}
	owned, err := OwnedRuleset(rulesetJSON)
	if err != nil {
		return fmt.Errorf("nft: invalid snapshot: %w", err)
	}
	var dump struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(owned, &dump); err != nil {
		return err
	}
	table := map[string]any{"table": map[string]string{"family": "inet", "name": tableName}}
	commands := []any{map[string]any{"add": table}, map[string]any{"delete": table}}
	for _, entry := range dump.Nftables {
		// A list-output handle identifies the old kernel object. In an
		// explicit add-rule command it instead means "append after this
		// handle", which no longer exists after deleting our table.
		clean := make(map[string]any, len(entry))
		for kind, body := range entry {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(body, &obj); err != nil {
				return fmt.Errorf("nft: invalid snapshot %s: %w", kind, err)
			}
			delete(obj, "handle")
			clean[kind] = obj
		}
		commands = append(commands, map[string]any{"add": clean})
	}
	script, err := json.Marshal(map[string]any{"nftables": commands})
	if err != nil {
		return err
	}
	if _, err := runner.RunStdin(ctx, "nft", string(script), "-j", "-f", "-"); err != nil {
		return fmt.Errorf("nft: restore failed: %w", err)
	}
	return nil
}

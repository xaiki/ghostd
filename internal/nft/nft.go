// Package nft owns the firewall domain's read and write side: rendering
// firewall.base.zones/firewall.ingress into an actual nft ruleset
// (render.go), and validating+applying one (this file, `nft -c`, atomic
// replace).
package nft

import (
	"bytes"
	"context"
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
// put on GetState generally. It is also what Restore below replays,
// unchanged — nft's own JSON format round-trips through `-j -f -`.
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

// Commit loads a validated script into the kernel — one atomic transaction
// (see Render's own doc on why a same-named `table inet` block replaces
// the old one without a gap). Callers must have already run ValidateSyntax;
// this does not re-validate.
func Commit(ctx context.Context, runner Runner, script string) error {
	if _, err := runner.RunStdin(ctx, "nft", script, "-f", "-"); err != nil {
		return fmt.Errorf("nft: commit failed: %w", err)
	}
	return nil
}

// Restore is the boot-time and dead-man's-switch-revert path: replay the
// last-confirmed ruleset — nft's own JSON dump (ReadRulesetJSON's output,
// exactly as Confirm persisted it), fed back through nft's JSON *input*
// mode (`-j -f -`), not re-rendered from a DesiredState. This is
// deliberate: what gets restored is provably what was live and reachable
// when it was confirmed, not a fresh re-render that could differ if
// Render's own logic changes between the confirm and the restore.
//
// A nil/empty rulesetJSON (nothing ever confirmed yet — a fresh install)
// is always a no-op — there is nothing to restore to, and refusing to boot
// because of that would be exactly the kind of failure this design exists
// to avoid.
func Restore(ctx context.Context, runner Runner, rulesetJSON []byte) error {
	if len(rulesetJSON) == 0 {
		return nil
	}
	if _, err := runner.RunStdin(ctx, "nft", string(rulesetJSON), "-j", "-f", "-"); err != nil {
		return fmt.Errorf("nft: restore failed: %w", err)
	}
	return nil
}

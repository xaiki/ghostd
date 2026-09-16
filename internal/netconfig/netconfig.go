// Package netconfig owns the netconfig domain's read and execute side
// (FIREWALL.md Phase 5). The pure planning — which files a machine's
// projection wants, which `ip`/`sysctl` steps live state still needs — stays
// entirely in machines.net_ifaces (plan_network/desired_files/live_actions,
// reused unchanged per FIREWALL.md); this package is only the executor,
// the same relationship internal/nft has with machines.firewall_schema.
//
// Every action this package recognizes is additive by construction — no
// action kind here ever removes an address or brings an interface down.
// That is FIREWALL.md's own stated invariant for this domain ("Netconfig
// keeps net_ifaces.py's existing invariants... Additive only"), and Apply
// enforces it as a hard refusal (see Validate) rather than trusting the
// caller, since Apply is the one place a malformed desired_state_json from
// anywhere could otherwise slip an unrecognized, non-additive action past
// every other layer of review.
package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// InterfacesDir is the one directory this package ever writes to or reads
// from — the same path machines.net_ifaces.py has always written
// `/etc/network/interfaces.d/stack-*.conf` into. Validate refuses any
// desired-state file path outside it.
const InterfacesDir = "/etc/network/interfaces.d"

// Runner runs one command to completion and returns its combined output —
// the seam tests fake. Real callers use ExecRunner.
type Runner interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// DesiredState is the JSON shape Nornir sends in ApplyRequest.desired_state_json
// for domain="netconfig" — the *complete* file set
// (machines.net_ifaces.desired_files) plus the live actions still needed
// (machines.net_ifaces.live_actions), rendered straight from the
// NetworkPlan Nornir's own plan_network already computed. Each action is
// `[kind, ...args]`, matching that Python action tuple's own shape
// one-for-one — see machines.net_ifaces.ghostd_desired_state_json.
type DesiredState struct {
	Files   map[string]string `json:"files"`
	Actions [][]string        `json:"actions"`
}

func ParseDesiredState(raw string) (DesiredState, error) {
	var ds DesiredState
	if err := json.Unmarshal([]byte(raw), &ds); err != nil {
		return DesiredState{}, err
	}
	return ds, nil
}

// knownActions maps each recognized action kind to how many arguments (after
// the kind itself) it takes — the complete, closed set of additive
// operations this package will ever run. See the package doc.
var knownActions = map[string]int{
	"vlan":    3, // base, dev, vlan_id
	"addr":    2, // dev, ip
	"sysctl":  1, // keyval
	"forward": 1, // the forwarding script's path
	"up":      1, // dev
}

// Validate rejects anything Apply must never be allowed to act on: a file
// path outside InterfacesDir, or an action this package does not
// recognize as additive. Called both by internal/rpc.Server before arming
// a lease (so a malformed push never arms one at all — the same ordering
// internal/nft.Render's own validation gets before ValidateSyntax) and
// internally by Apply itself, defensively.
func Validate(ds DesiredState) error {
	for path := range ds.Files {
		clean := filepath.Clean(path)
		if clean != path || !strings.HasPrefix(clean, InterfacesDir+string(filepath.Separator)) {
			return fmt.Errorf("netconfig: refusing to write %q: not inside %s", path, InterfacesDir)
		}
	}
	for _, action := range ds.Actions {
		if len(action) == 0 {
			return fmt.Errorf("netconfig: empty action")
		}
		want, ok := knownActions[action[0]]
		if !ok {
			return fmt.Errorf("netconfig: unrecognized action kind %q — only additive actions "+
				"(vlan/addr/sysctl/forward/up) are accepted", action[0])
		}
		if got := len(action) - 1; got != want {
			return fmt.Errorf("netconfig: action %q wants %d argument(s), got %d", action[0], want, got)
		}
	}
	return validateNoConflictingAddresses(ds.Actions)
}

// validateNoConflictingAddresses refuses a desired state where two "addr"
// actions claim the same bare address — e.g. 10.0.0.1/24 on one device and
// 10.0.0.1/32 on another. This is the wire-side twin of
// machines.net_ifaces._check_no_conflicting_addresses: Nornir's own
// planning already refuses this before it ever renders a desired_state_json
// (see that function's doc), but Apply is the one point any malformed
// desired_state_json — from a bug, not just this codebase's own client —
// would otherwise slip past. Same discipline as everywhere else in this
// package: refuse outright rather than pick a winner between the
// conflicting declarations.
func validateNoConflictingAddresses(actions [][]string) error {
	claims := map[string]map[string]bool{} // bare ip -> set of "dev ip" pairs
	for _, action := range actions {
		if action[0] != "addr" {
			continue
		}
		dev, ip := action[1], action[2]
		bare := strings.SplitN(ip, "/", 2)[0]
		pairs, ok := claims[bare]
		if !ok {
			pairs = map[string]bool{}
			claims[bare] = pairs
		}
		pairs[dev+" ("+ip+")"] = true
	}
	for _, bare := range sortedStringKeys(claims) {
		pairs := claims[bare]
		if len(pairs) <= 1 {
			continue
		}
		details := make([]string, 0, len(pairs))
		for pair := range pairs {
			details = append(details, pair)
		}
		sort.Strings(details)
		return fmt.Errorf("netconfig: %s is declared more than once with conflicting "+
			"assignments — %s", bare, strings.Join(details, ", "))
	}
	return nil
}

func sortedStringKeys(m map[string]map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("netconfig: create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("netconfig: write %s: %w", path, err)
	}
	return nil
}

// Apply writes every declared file, then executes every action, in order.
// It is idempotent by construction: `ds` is the *complete* target, not a
// pre-vetted diff (this daemon does not decide policy, see FIREWALL.md),
// and a boot-time or dead-man's-switch Restore replays exactly this
// function against whatever is already live — so each action tolerates
// "already applied" itself, the same fallback-on-failure idiom
// machines.net_ifaces.render_converge_script's bash already used (`ip link
// add ... || ip link show ...`), just as Go exec calls instead of shell
// operators.
func Apply(ctx context.Context, runner Runner, ds DesiredState) error {
	if err := Validate(ds); err != nil {
		return err
	}
	for _, path := range sortedKeys(ds.Files) {
		if err := writeFile(path, ds.Files[path]); err != nil {
			return err
		}
	}
	for _, action := range ds.Actions {
		if err := applyAction(ctx, runner, action); err != nil {
			return err
		}
	}
	return nil
}

func applyAction(ctx context.Context, runner Runner, action []string) error {
	switch action[0] {
	case "vlan":
		base, dev, vlanID := action[1], action[2], action[3]
		if _, err := runner.Output(ctx, "ip", "link", "add", "link", base, "name", dev,
			"type", "vlan", "id", vlanID); err != nil {
			if _, chkErr := runner.Output(ctx, "ip", "link", "show", dev); chkErr != nil {
				return fmt.Errorf("netconfig: create vlan %s on %s: %w", dev, base, err)
			}
		}
		return nil
	case "addr":
		dev, ip := action[1], action[2]
		if _, err := runner.Output(ctx, "ip", "addr", "add", ip, "dev", dev); err != nil {
			out, chkErr := runner.Output(ctx, "ip", "-o", "addr", "show", "dev", dev)
			bare := strings.SplitN(ip, "/", 2)[0]
			if chkErr != nil || !strings.Contains(string(out), bare) {
				return fmt.Errorf("netconfig: add %s to %s: %w", ip, dev, err)
			}
		}
		return nil
	case "sysctl":
		if _, err := runner.Output(ctx, "sysctl", "-q", "-w", action[1]); err != nil {
			return fmt.Errorf("netconfig: sysctl -w %s: %w", action[1], err)
		}
		return nil
	case "forward":
		if _, err := runner.Output(ctx, "sh", action[1]); err != nil {
			return fmt.Errorf("netconfig: apply forwarding script %s: %w", action[1], err)
		}
		if _, err := runner.Output(ctx, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1"); err != nil {
			return fmt.Errorf("netconfig: sysctl -w net.ipv4.ip_forward=1: %w", err)
		}
		return nil
	case "up":
		if _, err := runner.Output(ctx, "ip", "link", "set", action[1], "up"); err != nil {
			return fmt.Errorf("netconfig: bring %s up: %w", action[1], err)
		}
		return nil
	default:
		return fmt.Errorf("netconfig: unrecognized action kind %q", action[0]) // unreachable after Validate
	}
}

// LiveState is GetState's netconfig half: the persisted interfaces.d file
// bytes plus live addressing/forwarding, structured — the same facts
// machines.net_ifaces._live_state/parse_network_live already read over SSH,
// now read directly by the daemon and returned over RPC. Diffable, because
// Nornir still does the diffing (machines.net_ifaces.plan_network, reused
// unchanged).
type LiveState struct {
	Files     map[string]string   `json:"files"`
	Addrs     map[string][]string `json:"addrs"`
	IPForward string              `json:"ip_forward"`
}

func readInterfacesFiles() (map[string]string, error) {
	files := map[string]string{}
	entries, err := os.ReadDir(InterfacesDir)
	if os.IsNotExist(err) {
		return files, nil
	}
	if err != nil {
		return nil, fmt.Errorf("netconfig: read %s: %w", InterfacesDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(InterfacesDir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("netconfig: read %s: %w", path, err)
		}
		files[path] = string(content)
	}
	return files, nil
}

type ipAddrInfo struct {
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}

type ipIface struct {
	IfName   string       `json:"ifname"`
	AddrInfo []ipAddrInfo `json:"addr_info"`
}

func readAddrs(ctx context.Context, runner Runner) (map[string][]string, error) {
	out, err := runner.Output(ctx, "ip", "-j", "addr", "show")
	if err != nil {
		return nil, fmt.Errorf("netconfig: ip -j addr show: %w", err)
	}
	var ifaces []ipIface
	if err := json.Unmarshal(out, &ifaces); err != nil {
		return nil, fmt.Errorf("netconfig: parse 'ip -j addr show': %w", err)
	}
	addrs := map[string][]string{}
	for _, iface := range ifaces {
		if iface.IfName == "" {
			continue
		}
		list := addrs[iface.IfName]
		for _, info := range iface.AddrInfo {
			if info.Local == "" {
				continue
			}
			list = append(list, fmt.Sprintf("%s/%d", info.Local, info.PrefixLen))
		}
		addrs[iface.IfName] = list
	}
	return addrs, nil
}

// ReadLive is GetState's netconfig half and Confirm's proof that live
// addressing is at least readable — see ReadLiveJSON.
func ReadLive(ctx context.Context, runner Runner) (LiveState, error) {
	files, err := readInterfacesFiles()
	if err != nil {
		return LiveState{}, err
	}
	addrs, err := readAddrs(ctx, runner)
	if err != nil {
		return LiveState{}, err
	}
	ipForward := ""
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		ipForward = strings.TrimSpace(string(b))
	}
	return LiveState{Files: files, Addrs: addrs, IPForward: ipForward}, nil
}

// ReadLiveJSON is ReadLive, marshalled — what GetState actually returns in
// State.netconfig_json.
func ReadLiveJSON(ctx context.Context, runner Runner) (string, error) {
	live, err := ReadLive(ctx, runner)
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(live)
	if err != nil {
		return "", fmt.Errorf("netconfig: encode live state: %w", err)
	}
	return string(b), nil
}

// Restore replays the last-confirmed desired state — the same
// DesiredState bytes Apply already validated and applied once, not a
// fresh derivation from a live read.
//
// This is a deliberate asymmetry from internal/nft.Restore, which replays
// a literal kernel dump: nft's `-j` format is a complete, lossless,
// single-shot target, so replaying exactly what was live is both correct
// and trivial. There is no equivalent for interface configuration —
// re-deriving the actions needed to reach an observed `ip -j addr show`
// snapshot is exactly the diffing machines.net_ifaces.live_actions already
// owns, and duplicating that logic here would be a second, driftable copy
// of it. Replaying the already-decided, already-applied DesiredState
// instead is simpler and just as safe: every action Apply runs is
// additive and idempotent by construction (see applyAction's own
// fallback-on-failure checks), so replaying them against whatever is live
// now can only add what is still missing, never break what already works.
//
// A nil/empty blob (nothing ever confirmed yet — a fresh install) is
// always a no-op, for the same reason internal/nft.Restore treats an empty
// ruleset as a no-op: refusing to boot because there is nothing to
// restore to would be exactly the kind of failure this design exists to
// avoid.
func Restore(ctx context.Context, runner Runner, blob []byte) error {
	if len(blob) == 0 {
		return nil
	}
	ds, err := ParseDesiredState(string(blob))
	if err != nil {
		return fmt.Errorf("netconfig: restore: %w", err)
	}
	return Apply(ctx, runner, ds)
}

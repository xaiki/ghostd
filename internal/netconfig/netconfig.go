// Package netconfig owns the netconfig domain's read and execute side. The
// pure planning — which files a machine wants, which `ip`/`sysctl` steps live
// state still needs — stays entirely with the client; this package is only
// the executor, the same relationship internal/nft has with the client's
// firewall schema.
//
// Every action this package recognizes is additive by construction — no
// action kind here ever removes an address or brings an interface down. That
// invariant is enforced as a hard refusal (see Validate) rather than trusted
// from the caller, since Apply is the one place a malformed
// desired_state_json from anywhere could otherwise slip an unrecognized,
// non-additive action past every other layer of review.
package netconfig

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// InterfacesDir is the one directory this package ever writes to or reads
// from. Validate refuses any desired-state file path outside it, and the
// conventional file naming inside it is `stack-*.conf`.
const InterfacesDir = "/etc/network/interfaces.d"

var forwardingFiles = map[string]bool{
	"/etc/sysctl.d/99-stack-forward.conf":    true,
	"/etc/sysctl.d/99-stack-no-forward.conf": true,
}

// Runner runs one command to completion and returns its combined output —
// the seam tests fake. Real callers use ExecRunner.
type Runner interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// DesiredState is the JSON shape a client sends in
// ApplyRequest.desired_state_json for domain="netconfig": the *complete* file
// set the host should have, plus the live actions still needed to reach it,
// rendered from the plan the client already computed. Each action is
// `[kind, ...args]`. See docs/netconfig.md.
type DesiredState struct {
	ExpectedFilesSHA256 map[string]string `json:"expected_files_sha256,omitempty"`
	Files               map[string]string `json:"files"`
	Actions             [][]string        `json:"actions"`
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
	"default-route": 3, // dev, gateway, onlink|offlink
	"vlan":          3, // base, dev, vlan_id
	"addr":          2, // dev, ip
	"sysctl":        1, // keyval
	"forward":       1, // the forwarding script's path
	"up":            1, // dev
}

// Validate rejects anything Apply must never be allowed to act on: a file
// path outside InterfacesDir, or an action this package does not
// recognize as additive. Called both by internal/rpc.Server before arming
// a lease (so a malformed push never arms one at all — the same ordering
// internal/nft.Render's own validation gets before ValidateSyntax) and
// internally by Apply itself, defensively.
func Validate(ds DesiredState) error {
	for path, digest := range ds.ExpectedFilesSHA256 {
		if path != "/etc/network/interfaces" || len(digest) != 64 {
			return fmt.Errorf("invalid network file precondition")
		}
		for _, ch := range digest {
			if !strings.ContainsRune("0123456789abcdef", ch) {
				return fmt.Errorf("invalid network file digest")
			}
		}
		if _, ok := ds.Files[path]; !ok {
			return fmt.Errorf("precondition without desired file")
		}
	}
	for path, content := range ds.Files {
		if path == "/etc/network/interfaces" {
			if ds.ExpectedFilesSHA256[path] == "" {
				return fmt.Errorf("main ifupdown file requires explicit adoption precondition")
			}
			continue
		}
		if forwardingFiles[path] {
			if content != "" && content != "net.ipv4.ip_forward=0\n" && content != "net.ipv4.ip_forward=1\n" {
				return fmt.Errorf("netconfig: invalid forwarding file %s", path)
			}
			continue
		}
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
		if action[0] == "default-route" {
			if err := validateDefaultRoute(action); err != nil {
				return err
			}
		}
		if action[0] == "sysctl" && action[1] != "net.ipv4.ip_forward=0" && action[1] != "net.ipv4.ip_forward=1" {
			return fmt.Errorf("netconfig: only IPv4 forwarding sysctl is supported")
		}
		if action[0] == "forward" && action[1] != "/etc/stack-forward.sh" {
			return fmt.Errorf("netconfig: unknown forwarding script")
		}
	}
	return validateNoConflictingAddresses(ds.Actions)
}

// validateNoConflictingAddresses refuses a desired state where two "addr"
// actions claim the same bare address — e.g. 10.0.0.1/24 on one device and
// 10.0.0.1/32 on another. The client's own planning is expected to have
// refused this before it ever rendered a desired_state_json, but Apply is the
// one point any malformed desired_state_json — from a bug, not just this
// codebase's own client — would otherwise slip past. Same discipline as
// everywhere else in this package: refuse outright rather than pick a winner
// between the conflicting declarations.
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
	// A crash must not leave the boot-time fallback truncated. Stage on the
	// same filesystem, sync the complete file, then atomically replace it.
	f, err := os.CreateTemp(filepath.Dir(path), ".stack-network-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Apply writes every declared file, then executes every action, in order.
// It is idempotent by construction: `ds` is the *complete* target, not a
// pre-vetted diff (this daemon does not decide policy, see docs/netconfig.md),
// and a boot-time or dead-man's-switch Restore replays exactly this function
// against whatever is already live — so each action tolerates "already
// applied" itself, the same fallback-on-failure idiom of
// `ip link add ... || ip link show ...`, as Go exec calls instead of shell
// operators.
func Apply(ctx context.Context, runner Runner, ds DesiredState) error {
	if err := Validate(ds); err != nil {
		return err
	}
	if err := checkFilePreconditions(ds); err != nil {
		return err
	}
	if err := checkIfupdown(ds); err != nil {
		return err
	}
	// Refuse conflicting routes before any persistent configuration changes.
	for _, action := range ds.Actions {
		if action[0] == "default-route" {
			if _, _, err := routeState(ctx, runner, action); err != nil {
				return err
			}
		}
	}
	for _, path := range sortedKeys(ds.Files) {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeFile(path, ds.Files[path]); err != nil {
			return err
		}
	}
	for _, action := range ds.Actions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := applyAction(ctx, runner, action); err != nil {
			return err
		}
	}
	return nil
}

// A colliding name is not proof that an existing link is the requested VLAN.
func checkVLAN(ctx context.Context, runner Runner, base, dev, vlanID string) error {
	out, err := runner.Output(ctx, "ip", "-j", "-d", "link", "show")
	if err != nil {
		return err
	}
	var links []struct {
		Name   string `json:"ifname"`
		Index  int    `json:"ifindex"`
		Parent int    `json:"link_index"`
		Link   string `json:"link"`
		Info   struct {
			Kind string `json:"info_kind"`
			Data struct {
				ID int `json:"id"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if err := json.Unmarshal(out, &links); err != nil {
		return err
	}
	id, err := strconv.Atoi(vlanID)
	if err != nil {
		return err
	}
	parent := 0
	for _, link := range links {
		if link.Name == base {
			parent = link.Index
		}
	}
	for _, link := range links {
		if link.Name == dev && parent != 0 && (link.Parent == parent || (link.Parent == 0 && link.Link == base)) && link.Info.Kind == "vlan" && link.Info.Data.ID == id {
			return nil
		}
	}
	return fmt.Errorf("existing %s does not match VLAN %s on %s", dev, vlanID, base)
}

func applyAction(ctx context.Context, runner Runner, action []string) error {
	switch action[0] {
	case "default-route":
		return ensureDefaultRoute(ctx, runner, action)
	case "vlan":
		base, dev, vlanID := action[1], action[2], action[3]
		if _, err := runner.Output(ctx, "ip", "link", "add", "link", base, "name", dev,
			"type", "vlan", "id", vlanID); err != nil {
			if chkErr := checkVLAN(ctx, runner, base, dev, vlanID); chkErr != nil {
				return fmt.Errorf("netconfig: create vlan %s on %s: %w", dev, base, err)
			}
		}
		return nil
	case "addr":
		dev, ip := action[1], action[2]
		if _, err := runner.Output(ctx, "ip", "addr", "add", ip, "dev", dev); err != nil {
			addrs, chkErr := readAddrs(ctx, runner)
			wanted, parseErr := netip.ParsePrefix(ip)
			found := false
			for _, address := range addrs[dev] {
				actual, err := netip.ParsePrefix(address)
				if err == nil && parseErr == nil && actual == wanted {
					found = true
				}
			}
			if chkErr != nil || !found {
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
// bytes plus live addressing/forwarding, structured. Diffable, because the
// diffing itself still belongs to the client: the daemon reports facts and
// executes a decided target, and never computes the target itself.
type LiveState struct {
	Observation       map[string]json.RawMessage `json:"observation,omitempty"`
	ObservationErrors map[string]string          `json:"observation_errors,omitempty"`
	Files             map[string]string          `json:"files"`
	Addrs             map[string][]string        `json:"addrs"`
	IPForward         string                     `json:"ip_forward"`
}

func readInterfacesFiles() (map[string]string, error) {
	files := map[string]string{}
	for path := range forwardingFiles {
		content, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		files[path] = string(content)
	}
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
	observation := map[string]json.RawMessage{}
	errors := map[string]string{}
	commands := map[string][]string{
		"links":     {"-d", "-j", "link", "show"},
		"addresses": {"-j", "addr", "show"},
		"routes4":   {"-j", "-4", "route", "show", "table", "all"},
		"routes6":   {"-j", "-6", "route", "show", "table", "all"},
		"rules4":    {"-j", "-4", "rule", "show"},
		"rules6":    {"-j", "-6", "rule", "show"},
	}
	for name, args := range commands {
		raw, err := runner.Output(ctx, "ip", args...)
		if err != nil {
			errors[name] = err.Error()
			continue
		}
		if !json.Valid(raw) {
			errors[name] = "invalid JSON"
			continue
		}
		observation[name] = json.RawMessage(raw)
	}
	if raw, err := os.ReadFile("/etc/network/interfaces"); err == nil {
		files["/etc/network/interfaces"] = string(raw)
	} else if !os.IsNotExist(err) {
		errors["interfaces"] = err.Error()
	}
	return LiveState{Files: files, Addrs: addrs, IPForward: ipForward,
		Observation: observation, ObservationErrors: errors}, nil
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
// snapshot is exactly the diffing the client already owns, and duplicating
// that logic here would be a second, driftable copy of it. Replaying the already-decided, already-applied DesiredState
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

func checkFilePreconditions(ds DesiredState) error {
	for path, digest := range ds.ExpectedFilesSHA256 {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("cannot read adoption precondition: %w", err)
		}
		if string(raw) == ds.Files[path] {
			continue
		}
		if fmt.Sprintf("%x", sha256.Sum256(raw)) != digest {
			return fmt.Errorf("%s changed since observation; refusing adoption", path)
		}
	}
	return nil
}

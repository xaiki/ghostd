package netconfig

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeRunner struct {
	calls    [][]string
	fail     map[string]bool // command name -> fail its next call
	addrJSON string
}

func (f *fakeRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if f.fail[name] {
		return nil, errFake
	}
	if name == "ip" && len(args) > 0 && args[0] == "-j" {
		return []byte(f.addrJSON), nil
	}
	return nil, nil
}

var errFake = &fakeError{"fake failure"}

type fakeError struct{ msg string }

func (e *fakeError) Error() string { return e.msg }

func TestParseDesiredStateRoundTrips(t *testing.T) {
	raw := `{"files":{"/etc/network/interfaces.d/stack-eth0.conf":"auto eth0\n"},"actions":[["up","eth0"]]}`
	ds, err := ParseDesiredState(raw)
	if err != nil {
		t.Fatalf("ParseDesiredState: %v", err)
	}
	if ds.Files["/etc/network/interfaces.d/stack-eth0.conf"] != "auto eth0\n" {
		t.Fatalf("unexpected files: %v", ds.Files)
	}
	if len(ds.Actions) != 1 || ds.Actions[0][0] != "up" {
		t.Fatalf("unexpected actions: %v", ds.Actions)
	}
}

func TestValidateRejectsAFileOutsideInterfacesDir(t *testing.T) {
	ds := DesiredState{Files: map[string]string{"/etc/passwd": "pwned"}}
	if err := Validate(ds); err == nil {
		t.Fatal("expected a refusal for a file outside /etc/network/interfaces.d")
	}
}

func TestValidateRejectsPathTraversal(t *testing.T) {
	ds := DesiredState{Files: map[string]string{
		"/etc/network/interfaces.d/../../../etc/passwd": "pwned"}}
	if err := Validate(ds); err == nil {
		t.Fatal("expected a refusal for a traversal path")
	}
}

func TestValidateRejectsAnUnrecognizedActionKind(t *testing.T) {
	ds := DesiredState{Actions: [][]string{{"delete", "eth0"}}}
	if err := Validate(ds); err == nil {
		t.Fatal("expected a refusal for a non-additive action kind")
	}
}

func TestValidateRejectsWrongArgCount(t *testing.T) {
	ds := DesiredState{Actions: [][]string{{"addr", "eth0"}}} // addr wants 2 args
	if err := Validate(ds); err == nil {
		t.Fatal("expected a refusal for a malformed action")
	}
}

func TestValidateAcceptsEveryKnownActionKind(t *testing.T) {
	ds := DesiredState{Actions: [][]string{
		{"vlan", "eth0", "eth0.10", "10"},
		{"addr", "eth0.10", "10.0.0.5/24"},
		{"sysctl", "net.ipv4.ip_forward=1"},
		{"forward", "/etc/stack-forward.sh"},
		{"up", "eth0.10"},
	}}
	if err := Validate(ds); err != nil {
		t.Fatalf("expected every known action kind to validate, got %v", err)
	}
}

func TestValidateRejectsTheSameAddressOnTwoDevices(t *testing.T) {
	ds := DesiredState{Actions: [][]string{
		{"addr", "eth0", "10.0.0.1/24"},
		{"addr", "eth0.10", "10.0.0.1/32"},
	}}
	err := Validate(ds)
	if err == nil {
		t.Fatal("expected a refusal for the same bare address on two devices")
	}
	if !strings.Contains(err.Error(), "10.0.0.1") {
		t.Fatalf("expected the conflicting address in the error, got %v", err)
	}
}

func TestValidateRejectsTheSameDeviceClaimingAnAddressTwiceWithDifferentPrefixes(t *testing.T) {
	ds := DesiredState{Actions: [][]string{
		{"addr", "eth0", "10.0.0.1/24"},
		{"addr", "eth0", "10.0.0.1/32"},
	}}
	if err := Validate(ds); err == nil {
		t.Fatal("expected a refusal for the same device claiming an address twice with different prefixes")
	}
}

func TestValidateAllowsAnExactDuplicateAddrAction(t *testing.T) {
	ds := DesiredState{Actions: [][]string{
		{"addr", "eth0", "10.0.0.1/24"},
		{"addr", "eth0", "10.0.0.1/24"},
	}}
	if err := Validate(ds); err != nil {
		t.Fatalf("expected an exact duplicate to be harmless, got %v", err)
	}
}

func TestValidateAllowsDistinctAddressesOnDistinctDevices(t *testing.T) {
	ds := DesiredState{Actions: [][]string{
		{"addr", "eth0", "10.0.0.1/24"},
		{"addr", "eth0.10", "10.0.0.2/24"},
	}}
	if err := Validate(ds); err != nil {
		t.Fatalf("expected non-conflicting addresses to validate, got %v", err)
	}
}

func TestApplyWritesFilesUnderInterfacesDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stack-eth0.conf")
	ds := DesiredState{Files: map[string]string{path: "auto eth0\n"}}
	// Validate would refuse this path (not under the real InterfacesDir) —
	// exercise writeFile directly via a DesiredState with no actions and a
	// path that happens to already look absolute-and-clean, bypassing the
	// real constant so the test does not need root to write under /etc.
	if err := writeFile(path, ds.Files[path]); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "auto eth0\n" {
		t.Fatalf("got %q", got)
	}
}

func TestApplyRunsActionsInOrder(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{}}
	ds := DesiredState{Actions: [][]string{
		{"sysctl", "net.ipv4.ip_forward=1"},
		{"up", "eth0.10"},
	}}
	if err := Apply(context.Background(), runner, ds); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("expected 2 calls, got %v", runner.calls)
	}
	if runner.calls[0][0] != "sysctl" || runner.calls[1][0] != "ip" {
		t.Fatalf("expected sysctl then ip, got %v", runner.calls)
	}
}

func TestApplyVlanToleratesAnAlreadyExistingLink(t *testing.T) {
	// First call (link add) fails, second (link show) succeeds -- the same
	// fallback-on-failure idiom render_converge_script's bash already used.
	calls := 0
	wrapped := &sequencedRunner{onCall: func(name string, args []string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errFake // link add fails: already exists
		}
		return nil, nil // link show succeeds: it really is there
	}}
	ds := DesiredState{Actions: [][]string{{"vlan", "eth0", "eth0.10", "10"}}}
	if err := Apply(context.Background(), wrapped, ds); err != nil {
		t.Fatalf("expected the existence-check fallback to make this a no-op success, got %v", err)
	}
}

func TestApplyVlanFailsWhenNeitherAddNorShowSucceed(t *testing.T) {
	wrapped := &sequencedRunner{onCall: func(name string, args []string) ([]byte, error) {
		return nil, errFake
	}}
	ds := DesiredState{Actions: [][]string{{"vlan", "eth0", "eth0.10", "10"}}}
	if err := Apply(context.Background(), wrapped, ds); err == nil {
		t.Fatal("expected a failure when both the create and the fallback existence check fail")
	}
}

func TestApplyRejectsNonAdditiveActionsBeforeRunningAnything(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{}}
	ds := DesiredState{Actions: [][]string{{"down", "eth0"}}}
	if err := Apply(context.Background(), runner, ds); err == nil {
		t.Fatal("expected Apply to refuse a non-additive action")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no commands to run once validation refuses the whole state, got %v", runner.calls)
	}
}

type sequencedRunner struct {
	onCall func(name string, args []string) ([]byte, error)
}

func (s *sequencedRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return s.onCall(name, args)
}

func TestReadLiveReportsAddressesAndForwarding(t *testing.T) {
	runner := &fakeRunner{
		fail:     map[string]bool{},
		addrJSON: `[{"ifname":"eth0","addr_info":[{"local":"10.0.0.5","prefixlen":24}]}]`,
	}
	live, err := ReadLive(context.Background(), runner)
	if err != nil {
		t.Fatalf("ReadLive: %v", err)
	}
	if len(live.Addrs["eth0"]) != 1 || live.Addrs["eth0"][0] != "10.0.0.5/24" {
		t.Fatalf("unexpected addrs: %v", live.Addrs)
	}
}

func TestReadLiveJSONMarshalsCleanly(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{}, addrJSON: `[]`}
	raw, err := ReadLiveJSON(context.Background(), runner)
	if err != nil {
		t.Fatalf("ReadLiveJSON: %v", err)
	}
	var decoded LiveState
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func TestReadLiveSurfacesAnAddrReadFailure(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{"ip": true}}
	if _, err := ReadLive(context.Background(), runner); err == nil {
		t.Fatal("expected a failure when 'ip -j addr show' fails")
	}
}

func TestRestoreOfAnEmptyBlobIsANoOp(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{}}
	if err := Restore(context.Background(), runner, nil); err != nil {
		t.Fatalf("expected a nil blob to be a no-op, got %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected no commands for an empty restore, got %v", runner.calls)
	}
}

func TestRestoreReplaysTheDesiredState(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{}}
	blob := []byte(`{"actions":[["sysctl","net.ipv4.ip_forward=1"]]}`)
	if err := Restore(context.Background(), runner, blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if len(runner.calls) != 1 || runner.calls[0][0] != "sysctl" {
		t.Fatalf("expected the persisted action to be replayed, got %v", runner.calls)
	}
}

func TestRestoreOfMalformedJSONFails(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{}}
	if err := Restore(context.Background(), runner, []byte("not json")); err == nil {
		t.Fatal("expected a restore of malformed persisted state to fail loudly, not silently no-op")
	}
}

func TestValidateRejectsAnEmptyAction(t *testing.T) {
	ds := DesiredState{Actions: [][]string{{}}}
	if err := Validate(ds); err == nil {
		t.Fatal("expected a refusal for an empty action")
	}
}

func TestReadInterfacesFilesIsANoOpWhenTheDirIsMissing(t *testing.T) {
	// InterfacesDir is a package constant, not overridable — this exercises
	// the not-exist branch indirectly by trusting the real filesystem check;
	// on the dev machine /etc/network/interfaces.d does not exist (macOS),
	// which is exactly the "fresh install" case this must not error on.
	files, err := readInterfacesFiles()
	if err != nil {
		t.Fatalf("expected a missing directory to read as empty, not fail: %v", err)
	}
	if files == nil {
		t.Fatal("expected a non-nil empty map")
	}
}

func TestApplyIdempotentAddrToleratesAnAlreadyPresentAddress(t *testing.T) {
	calls := 0
	wrapped := &sequencedRunner{onCall: func(name string, args []string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errFake // addr add fails: already assigned
		}
		return []byte("inet 10.0.0.5/24 scope global eth0.10"), nil // show confirms it
	}}
	ds := DesiredState{Actions: [][]string{{"addr", "eth0.10", "10.0.0.5/24"}}}
	if err := Apply(context.Background(), wrapped, ds); err != nil {
		t.Fatalf("expected the existence-check fallback to make this a no-op success, got %v", err)
	}
}

func TestApplyForwardRunsScriptThenSysctl(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{}}
	ds := DesiredState{Actions: [][]string{{"forward", "/etc/stack-forward.sh"}}}
	if err := Apply(context.Background(), runner, ds); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(runner.calls) != 2 || runner.calls[0][0] != "sh" || runner.calls[1][0] != "sysctl" {
		t.Fatalf("expected sh then sysctl, got %v", runner.calls)
	}
}

func TestValidateRejectsAnAbsoluteButUncleanPath(t *testing.T) {
	ds := DesiredState{Files: map[string]string{
		"/etc/network/interfaces.d//stack-eth0.conf": "x"}}
	if err := Validate(ds); err == nil {
		t.Fatal("expected a refusal for a non-canonical path")
	}
}

func TestValidateAcceptsAWellFormedInterfacesPath(t *testing.T) {
	ds := DesiredState{Files: map[string]string{
		"/etc/network/interfaces.d/stack-eth0.conf": "auto eth0\n"}}
	if err := Validate(ds); err != nil {
		t.Fatalf("expected a well-formed path to validate, got %v", err)
	}
}

func TestApplySysctlFailureIsReported(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{"sysctl": true}}
	ds := DesiredState{Actions: [][]string{{"sysctl", "net.ipv4.ip_forward=1"}}}
	if err := Apply(context.Background(), runner, ds); err == nil {
		t.Fatal("expected a sysctl failure to be reported, not swallowed")
	}
}

func TestApplyUpFailureIsReported(t *testing.T) {
	runner := &fakeRunner{fail: map[string]bool{"ip": true}}
	ds := DesiredState{Actions: [][]string{{"up", "eth0.10"}}}
	if err := Apply(context.Background(), runner, ds); err == nil {
		t.Fatal("expected an 'ip link set up' failure to be reported")
	}
}

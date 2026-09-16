package rpc

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"smarthome/ghostd/internal/auth"
	"smarthome/ghostd/internal/netconfig"
	"smarthome/ghostd/internal/nft"
	"smarthome/ghostd/internal/state"
	pb "smarthome/ghostd/proto"
)

// validDesiredStateJSON is the smallest DesiredState that passes
// nft.Render's own validation (a "trusted" zone is reachable on its own —
// see internal/nft/render_test.go) — every Apply test below needs a
// desired_state_json that gets *past* validation to exercise the RPC's
// own behavior, not nft.Render's (already covered in internal/nft).
const validDesiredStateJSON = `{"zones":{"trusted":{"interfaces":["tailscale0"]}}}`

type fakeWhoIs struct {
	tags []string
}

func (f fakeWhoIs) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Tags: f.tags},
		UserProfile: &tailcfg.UserProfile{LoginName: "test@example.com"},
	}, nil
}

type fakeNftRunner struct {
	output       []byte
	err          error
	outputCalls  int
	validateErr  error
	commitErr    error
	validateArgs []string
	commitArgs   []string
	stdinCalls   int
}

func (f *fakeNftRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.outputCalls++
	return f.output, f.err
}

func (f *fakeNftRunner) RunStdin(ctx context.Context, name string, script string, args ...string) ([]byte, error) {
	f.stdinCalls++
	// nft.ValidateSyntax calls with -c -f -; nft.Commit calls with -f -.
	isValidate := len(args) > 0 && args[0] == "-c"
	if isValidate {
		f.validateArgs = args
		return nil, f.validateErr
	}
	f.commitArgs = args
	return nil, f.commitErr
}

type fakeLeaseRunner struct {
	calls [][]string
}

func (f *fakeLeaseRunner) Run(name string, args ...string) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	return nil
}

type fakeNetconfigRunner struct {
	err        error
	outputJSON string
}

func (f *fakeNetconfigRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	if name == "ip" {
		return []byte(f.outputJSON), nil
	}
	return nil, nil
}

func withPeer(ctx context.Context) context.Context {
	return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("100.64.0.9"), Port: 1234}})
}

func testGuard() nft.ReachabilityGuard {
	return nft.ReachabilityGuard{TailscaleInterface: "tailscale0", Port: 7443}
}

func newTestServer(t *testing.T, tags []string) (*Server, *fakeNftRunner, *fakeNetconfigRunner, *fakeLeaseRunner) {
	t.Helper()
	store, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	leaseRunner := &fakeLeaseRunner{}
	leases := state.NewLeases("/opt/ghostd/ghostd", leaseRunner)
	authenticator := auth.NewAuthenticator(fakeWhoIs{tags: tags}, "tag:stack-deployer")
	nftRunner := &fakeNftRunner{output: []byte(`{"nftables":[]}`)}
	netconfigRunner := &fakeNetconfigRunner{outputJSON: "[]"}
	return NewServer(authenticator, store, leases, nftRunner, netconfigRunner, testGuard()),
		nftRunner, netconfigRunner, leaseRunner
}

const validNetconfigDesiredStateJSON = `{"actions":[["sysctl","net.ipv4.ip_forward=1"]]}`

func TestGetStateRequiresNoTagJustTailnetIdentity(t *testing.T) {
	server, _, _, _ := newTestServer(t, nil) // no tags at all
	resp, err := server.GetState(withPeer(context.Background()), &pb.GetStateRequest{})
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if resp.GetNftRulesetJson() != `{"nftables":[]}` {
		t.Fatalf("got %q", resp.GetNftRulesetJson())
	}
}

func TestGetStateAlsoReturnsNetconfigJSON(t *testing.T) {
	server, _, _, _ := newTestServer(t, nil)
	resp, err := server.GetState(withPeer(context.Background()), &pb.GetStateRequest{})
	if err != nil {
		t.Fatalf("GetState: %v", err)
	}
	if resp.GetNetconfigJson() == "" {
		t.Fatalf("expected a non-empty netconfig_json envelope")
	}
}

func TestGetStateRefusesACallerWithNoPeerInfo(t *testing.T) {
	server, _, _, _ := newTestServer(t, nil)
	_, err := server.GetState(context.Background(), &pb.GetStateRequest{}) // no peer attached
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expected Unauthenticated, got %v", err)
	}
}

func TestApplyRefusesAnUntaggedCaller(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:something-else"})
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestApplyRequiresAPositiveDeadManSwitch(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 0})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for a zero dead-man's-switch, got %v", err)
	}
}

func TestApplyRejectsAnUnrecognizedDomain(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "ingress", DesiredStateJson: "{}", DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for an unrecognized domain, got %v", err)
	}
}

func TestApplyRejectsAnEmptyDomain(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for a missing domain (never auto-detected), got %v", err)
	}
}

func TestApplyRejectsMalformedJSON(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: "not json", DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for malformed JSON, got %v", err)
	}
}

func TestApplyRejectsADesiredStateThatWouldStrandTheHost(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	unreachable := `{"zones":{"iot":{"interfaces":["end0.50"]}}}` // no ssh, not "trusted"
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: unreachable, DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("expected the render-time reachability rejection, got %v", err)
	}
}

func TestApplyNeverArmsALeaseWhenValidationFails(t *testing.T) {
	server, nftRunner, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	nftRunner.validateErr = errors.New("syntax error at line 3")
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for a failed nft -c, got %v", err)
	}
	// Confirming a lease id that was never returned must fail -- proving
	// no lease was armed for this rejected Apply.
	if _, err := server.Confirm(withPeer(context.Background()),
		&pb.ConfirmRequest{LeaseId: "anything"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected no lease to have been armed, got Confirm error %v", err)
	}
}

func TestApplyValidatesBeforeCommitting(t *testing.T) {
	server, nftRunner, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(nftRunner.validateArgs) == 0 || nftRunner.validateArgs[0] != "-c" {
		t.Fatalf("expected a -c validate call, got %v", nftRunner.validateArgs)
	}
	if len(nftRunner.commitArgs) == 0 || nftRunner.commitArgs[0] == "-c" {
		t.Fatalf("expected a plain (non -c) commit call, got %v", nftRunner.commitArgs)
	}
}

func TestApplyArmsALeaseAndReturnsItsID(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	resp, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if resp.GetLeaseId() == "" {
		t.Fatalf("expected a non-empty lease id")
	}
}

func TestApplyArmsTheLeaseWithItsOwnDomain(t *testing.T) {
	server, _, _, leaseRunner := newTestServer(t, []string{"tag:stack-deployer"})
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(leaseRunner.calls) == 0 {
		t.Fatalf("expected a systemd-run call")
	}
	joined := strings.Join(leaseRunner.calls[0], " ")
	if !strings.Contains(joined, "--revert-domain=firewall") {
		t.Fatalf("expected the revert command to carry its own domain, got %v", leaseRunner.calls[0])
	}
}

func TestApplyLeaseStaysArmedWhenCommitFails(t *testing.T) {
	server, nftRunner, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	nftRunner.commitErr = errors.New("device or resource busy")
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "stays armed") {
		t.Fatalf("expected an Internal error noting the lease stays armed, got %v", err)
	}
}

func TestConfirmRefusesAnUntaggedCaller(t *testing.T) {
	server, _, _, _ := newTestServer(t, nil)
	_, err := server.Confirm(withPeer(context.Background()), &pb.ConfirmRequest{LeaseId: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", err)
	}
}

func TestConfirmOfAnUnknownLeaseFails(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	_, err := server.Confirm(withPeer(context.Background()), &pb.ConfirmRequest{LeaseId: "never-armed"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition for an unarmed lease, got %v", err)
	}
}

func TestConfirmCancelsTheLeaseAndPersistsLiveStateAsLastGood(t *testing.T) {
	server, nftRunner, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	ctx := withPeer(context.Background())

	applied, err := server.Apply(ctx, &pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	confirmed, err := server.Confirm(ctx, &pb.ConfirmRequest{LeaseId: applied.GetLeaseId()})
	if err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	if !confirmed.GetOk() {
		t.Fatalf("expected Confirm to report ok")
	}
	saved, err := server.store.Load(NftRuleset)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(saved) != `{"nftables":[]}` {
		t.Fatalf("expected the live ruleset to be persisted as last-good, got %q", saved)
	}
	if nftRunner.outputCalls != 1 { // only Confirm's persist step reads live state
		t.Fatalf("expected exactly one nft read from Confirm, got %d calls", nftRunner.outputCalls)
	}
	if nftRunner.stdinCalls != 2 { // Apply's validate + commit
		t.Fatalf("expected exactly two nft -f calls from Apply (validate, commit), got %d", nftRunner.stdinCalls)
	}
}

func TestConfirmOfAnAlreadyConfirmedLeaseFails(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	ctx := withPeer(context.Background())
	applied, err := server.Apply(ctx, &pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := server.Confirm(ctx, &pb.ConfirmRequest{LeaseId: applied.GetLeaseId()}); err != nil {
		t.Fatalf("first Confirm: %v", err)
	}
	if _, err := server.Confirm(ctx, &pb.ConfirmRequest{LeaseId: applied.GetLeaseId()}); err == nil {
		t.Fatalf("a second Confirm on the same lease must not silently succeed")
	}
}

func TestConfirmOfARestartedDaemonFailsButDoesNotCorrupt(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	ctx := withPeer(context.Background())
	applied, err := server.Apply(ctx, &pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Simulate the daemon having restarted: the in-memory pending record is
	// gone, but the lease itself (in Leases) is a separate, still-armed
	// object in this same test process, mirroring how it would still be
	// armed via a real systemd unit after a daemon restart.
	server.mu.Lock()
	delete(server.pending, applied.GetLeaseId())
	server.mu.Unlock()
	_, err = server.Confirm(ctx, &pb.ConfirmRequest{LeaseId: applied.GetLeaseId()})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal (lost pending record), got %v", err)
	}
}

func TestGetStateSurfacesAnNftReadFailure(t *testing.T) {
	server, nftRunner, _, _ := newTestServer(t, nil)
	nftRunner.err = errors.New("nft: command not found")
	_, err := server.GetState(withPeer(context.Background()), &pb.GetStateRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
}

func TestGetStateSurfacesANetconfigReadFailure(t *testing.T) {
	server, _, netconfigRunner, _ := newTestServer(t, nil)
	netconfigRunner.err = errors.New("ip: command not found")
	_, err := server.GetState(withPeer(context.Background()), &pb.GetStateRequest{})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// netconfig domain
// ---------------------------------------------------------------------------

func TestApplyNetconfigRejectsANonAdditiveAction(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	bad := `{"actions":[["down","eth0"]]}`
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "netconfig", DesiredStateJson: bad, DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument for a non-additive action, got %v", err)
	}
}

func TestApplyNetconfigArmsALeaseAndRunsActions(t *testing.T) {
	server, _, netconfigRunner, _ := newTestServer(t, []string{"tag:stack-deployer"})
	resp, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "netconfig", DesiredStateJson: validNetconfigDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if resp.GetLeaseId() == "" {
		t.Fatalf("expected a non-empty lease id")
	}
	_ = netconfigRunner
}

func TestApplyNetconfigLeaseStaysArmedWhenExecutionFails(t *testing.T) {
	server, _, netconfigRunner, _ := newTestServer(t, []string{"tag:stack-deployer"})
	netconfigRunner.err = errors.New("sysctl: permission denied")
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "netconfig", DesiredStateJson: validNetconfigDesiredStateJSON, DeadManSwitchSeconds: 300})
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "stays armed") {
		t.Fatalf("expected an Internal error noting the lease stays armed, got %v", err)
	}
}

func TestConfirmNetconfigPersistsTheAppliedDesiredStateNotALiveRead(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	ctx := withPeer(context.Background())
	applied, err := server.Apply(ctx, &pb.ApplyRequest{Domain: "netconfig", DesiredStateJson: validNetconfigDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := server.Confirm(ctx, &pb.ConfirmRequest{LeaseId: applied.GetLeaseId()}); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	saved, err := server.store.Load(NetconfigState)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if string(saved) != validNetconfigDesiredStateJSON {
		t.Fatalf("expected the applied desired state to be persisted verbatim, got %q", saved)
	}
}

func TestApplyNetconfigArmsTheLeaseWithItsOwnDomain(t *testing.T) {
	server, _, _, leaseRunner := newTestServer(t, []string{"tag:stack-deployer"})
	_, err := server.Apply(withPeer(context.Background()),
		&pb.ApplyRequest{Domain: "netconfig", DesiredStateJson: validNetconfigDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	joined := strings.Join(leaseRunner.calls[0], " ")
	if !strings.Contains(joined, "--revert-domain=netconfig") {
		t.Fatalf("expected the revert command to carry its own domain, got %v", leaseRunner.calls[0])
	}
}

func TestFirewallAndNetconfigLeasesAreIndependent(t *testing.T) {
	server, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	ctx := withPeer(context.Background())
	fw, err := server.Apply(ctx, &pb.ApplyRequest{Domain: "firewall", DesiredStateJson: validDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("firewall Apply: %v", err)
	}
	nc, err := server.Apply(ctx, &pb.ApplyRequest{Domain: "netconfig", DesiredStateJson: validNetconfigDesiredStateJSON, DeadManSwitchSeconds: 300})
	if err != nil {
		t.Fatalf("netconfig Apply: %v", err)
	}
	// Confirming one must not disturb the other's still-armed lease.
	if _, err := server.Confirm(ctx, &pb.ConfirmRequest{LeaseId: fw.GetLeaseId()}); err != nil {
		t.Fatalf("Confirm firewall: %v", err)
	}
	if _, err := server.Confirm(ctx, &pb.ConfirmRequest{LeaseId: nc.GetLeaseId()}); err != nil {
		t.Fatalf("Confirm netconfig (should still be independently armed): %v", err)
	}
}

// ---------------------------------------------------------------------------
// internal/netconfig.Runner used by the fakeNetconfigRunner above
// ---------------------------------------------------------------------------

var _ netconfig.Runner = (*fakeNetconfigRunner)(nil)

// Package rpc wires the gRPC surface (proto/hoststate.proto) to
// internal/auth, internal/state, internal/nft and internal/netconfig. No
// policy decisions live here: every method either reads live state or
// enacts a state Nornir already resolved — see FIREWALL.md.
package rpc

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"smarthome/ghostd/internal/auth"
	"smarthome/ghostd/internal/netconfig"
	"smarthome/ghostd/internal/nft"
	"smarthome/ghostd/internal/state"
	pb "smarthome/ghostd/proto"
)

// NftRuleset is the state.Store blob name for the firewall domain's
// last-confirmed ruleset — named once so Save/Load/boot-restore cannot
// drift onto different keys.
const NftRuleset = "nft-ruleset.json"

// NetconfigState is the state.Store blob name for the netconfig domain's
// last-confirmed DesiredState (see internal/netconfig.Restore's own doc on
// why this persists the applied desired state, not a live re-read, unlike
// NftRuleset).
const NetconfigState = "netconfig-state.json"

// domainFirewall and domainNetconfig are the only values ApplyRequest.domain
// accepts — named once so Apply's dispatch and Confirm's routing cannot
// drift onto different spellings.
const (
	domainFirewall  = "firewall"
	domainNetconfig = "netconfig"
)

// pendingApply is what Confirm needs to persist the right thing under the
// right key for a lease Apply already armed. Kept in-memory, on this one
// running daemon process, deliberately: the dead-man's-switch's own revert
// path (internal/state.Leases.Arm) does not depend on it at all — the
// domain travels to that separate process via the revert command's own
// argv (--revert-domain=) precisely because this map cannot survive a
// crash or restart. If the daemon does restart between Apply and Confirm,
// Confirm fails (the lease is gone from this map) and the dead-man's-switch
// reverts on schedule — safe, if less convenient than confirming, and
// never a wrong or silent outcome.
type pendingApply struct {
	domain           string
	desiredStateJSON string
}

type Server struct {
	pb.UnimplementedHostStateServer

	authenticator   *auth.Authenticator
	store           *state.Store
	leases          *state.Leases
	nftRunner       nft.Runner
	netconfigRunner netconfig.Runner
	guard           nft.ReachabilityGuard

	mu      sync.Mutex
	pending map[string]pendingApply
}

func NewServer(authenticator *auth.Authenticator, store *state.Store,
	leases *state.Leases, nftRunner nft.Runner, netconfigRunner netconfig.Runner,
	guard nft.ReachabilityGuard) *Server {
	return &Server{authenticator: authenticator, store: store, leases: leases,
		nftRunner: nftRunner, netconfigRunner: netconfigRunner, guard: guard,
		pending: make(map[string]pendingApply)}
}

func peerAddr(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "", status.Error(codes.Unauthenticated, "rpc: no peer address on this connection")
	}
	return p.Addr.String(), nil
}

// GetState answers with the live nft ruleset and netconfig facts — read-only,
// any tailnet member may call it (the listener itself is already
// tailnet-only; see cmd/ghostd/main.go), no deployer tag required. Both
// domains are always read together: State is one thin envelope over
// whichever domains this daemon has learned to speak, not something a
// caller selects a slice of (see the proto's own comment).
func (s *Server) GetState(ctx context.Context, _ *pb.GetStateRequest) (*pb.State, error) {
	addr, err := peerAddr(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.authenticator.Identify(ctx, addr); err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}
	ruleset, err := nft.ReadRulesetJSON(ctx, s.nftRunner)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	netconfigJSON, err := netconfig.ReadLiveJSON(ctx, s.netconfigRunner)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &pb.State{NftRulesetJson: ruleset, NetconfigJson: netconfigJSON}, nil
}

// Apply dispatches on req.domain to the matching domain's own
// parse-validate-arm-execute sequence. Order matters within each: nothing
// is armed or loaded until the desired state is known to be both
// syntactically valid and (for firewall) reachability-safe, so a rejected
// Apply leaves the kernel/filesystem and the lease table untouched.
func (s *Server) Apply(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	addr, err := peerAddr(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.authenticator.AuthorizeDeployer(ctx, addr); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}
	if req.GetDeadManSwitchSeconds() <= 0 {
		return nil, status.Error(codes.InvalidArgument,
			"rpc: dead_man_switch_seconds is required and must be positive — "+
				"an Apply with no revert path is exactly the failure this daemon exists to prevent")
	}

	switch req.GetDomain() {
	case domainFirewall:
		return s.applyFirewall(ctx, req)
	case domainNetconfig:
		return s.applyNetconfig(ctx, req)
	default:
		return nil, status.Errorf(codes.InvalidArgument,
			"rpc: domain must be %q or %q, got %q", domainFirewall, domainNetconfig, req.GetDomain())
	}
}

func (s *Server) applyFirewall(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	desired, err := nft.ParseDesiredState(req.GetDesiredStateJson())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "rpc: desired_state_json: %v", err)
	}
	script, err := nft.Render(desired, s.guard)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "rpc: %v", err)
	}
	if err := nft.ValidateSyntax(ctx, s.nftRunner, script); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "rpc: %v", err)
	}

	leaseID := state.NewLeaseID()
	timeout := time.Duration(req.GetDeadManSwitchSeconds()) * time.Second
	if err := s.leases.Arm(leaseID, domainFirewall, timeout); err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	s.recordPending(leaseID, domainFirewall, req.GetDesiredStateJson())
	if err := nft.Commit(ctx, s.nftRunner, script); err != nil {
		// The lease stays armed: if this host is now in some half-applied
		// state, the dead-man's-switch reverting to last-confirmed in
		// GetDeadManSwitchSeconds() is exactly the safety net that
		// matters most here, not something to disarm on a commit failure.
		return nil, status.Errorf(codes.Internal, "rpc: %v (dead-man's-switch for lease %s stays armed)", err, leaseID)
	}
	return &pb.ApplyResponse{LeaseId: leaseID}, nil
}

func (s *Server) applyNetconfig(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	desired, err := netconfig.ParseDesiredState(req.GetDesiredStateJson())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "rpc: desired_state_json: %v", err)
	}
	if err := netconfig.Validate(desired); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "rpc: %v", err)
	}

	leaseID := state.NewLeaseID()
	timeout := time.Duration(req.GetDeadManSwitchSeconds()) * time.Second
	if err := s.leases.Arm(leaseID, domainNetconfig, timeout); err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	s.recordPending(leaseID, domainNetconfig, req.GetDesiredStateJson())
	if err := netconfig.Apply(ctx, s.netconfigRunner, desired); err != nil {
		// Same reasoning as applyFirewall's Commit failure: the lease
		// stays armed on purpose.
		return nil, status.Errorf(codes.Internal, "rpc: %v (dead-man's-switch for lease %s stays armed)", err, leaseID)
	}
	return &pb.ApplyResponse{LeaseId: leaseID}, nil
}

func (s *Server) recordPending(leaseID, domain, desiredStateJSON string) {
	s.mu.Lock()
	s.pending[leaseID] = pendingApply{domain: domain, desiredStateJSON: desiredStateJSON}
	s.mu.Unlock()
}

func (s *Server) takePending(leaseID string) (pendingApply, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.pending[leaseID]
	if ok {
		delete(s.pending, leaseID)
	}
	return rec, ok
}

// Confirm cancels lease's dead-man's-switch — call only from a fresh
// connection, after independently reproving reachability (FIREWALL.md).
// This RPC does not itself prove anything about reachability; it trusts
// the caller reached it, which is only meaningful if the caller opened a
// new connection to do so.
func (s *Server) Confirm(ctx context.Context, req *pb.ConfirmRequest) (*pb.ConfirmResponse, error) {
	addr, err := peerAddr(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.authenticator.AuthorizeDeployer(ctx, addr); err != nil {
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	}
	if req.GetLeaseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "rpc: lease_id is required")
	}
	if err := s.leases.Cancel(req.GetLeaseId()); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	rec, ok := s.takePending(req.GetLeaseId())
	if !ok {
		// Cancel just proved this lease was armed, so the daemon (this
		// process) restarted between Apply and Confirm and lost the
		// in-memory record of what to persist — see the pendingApply doc.
		// The revert unit itself is unaffected (its domain travelled via
		// argv, not this map), so the host is not at risk; only this
		// Confirm cannot complete, and the caller sees a plain failure
		// rather than a wrong or silent persist.
		return nil, status.Errorf(codes.Internal,
			"rpc: lease %s was armed but this daemon lost track of what to persist "+
				"(a restart between Apply and Confirm) — the dead-man's-switch will still revert on schedule",
			req.GetLeaseId())
	}
	switch rec.domain {
	case domainFirewall:
		// last-good is only ever overwritten by a state that reached here —
		// see the package doc on state.Store. Persisting the live ruleset
		// (not rec.desiredStateJSON) keeps this honest: what gets restored
		// on a future revert/boot is what was actually proven live, not
		// merely what was asked for.
		ruleset, err := nft.ReadRulesetJSON(ctx, s.nftRunner)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "rpc: confirmed but could not re-read live state to persist it: %v", err)
		}
		if err := s.store.Save(NftRuleset, []byte(ruleset)); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
	case domainNetconfig:
		// See internal/netconfig.Restore's doc: netconfig persists the
		// already-applied desired state, not a live re-read.
		if err := s.store.Save(NetconfigState, []byte(rec.desiredStateJSON)); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
	default:
		return nil, status.Errorf(codes.Internal, "rpc: lease %s has an unrecognized pending domain %q",
			req.GetLeaseId(), rec.domain)
	}
	return &pb.ConfirmResponse{Ok: true}, nil
}

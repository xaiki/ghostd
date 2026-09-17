// Package rpc wires the gRPC surface (proto/ghoststate.proto) to
// internal/auth, internal/state, internal/nft and internal/netconfig. No
// policy decisions live here: every method either reads live state or
// enacts a state Nornir already resolved — see FIREWALL.md.
package rpc

import (
	"context"
	"log"
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

// Legacy blob names are read only when a domain has no transaction record.
// New confirmations atomically persist confirmed bytes and clear the pending
// lease in <domain>-transaction.json (state.DomainState).
const NftRuleset = "nft-ruleset.json"
const NetconfigState = "netconfig-state.json"

// domainFirewall and domainNetconfig are the only values ApplyRequest.domain
// accepts — named once so Apply's dispatch and Confirm's routing cannot
// drift onto different spellings.
const (
	domainFirewall  = "firewall"
	domainNetconfig = "netconfig"
)

type Server struct {
	// ObserveOnly rejects every mutation RPC, independently of authorization.
	ObserveOnly bool
	pb.UnimplementedHostStateServer

	authenticator   *auth.Authenticator
	store           *state.Store
	leases          *state.Leases
	nftRunner       nft.Runner
	netconfigRunner netconfig.Runner
	guard           nft.ReachabilityGuard
}

func NewServer(authenticator *auth.Authenticator, store *state.Store,
	leases *state.Leases, nftRunner nft.Runner, netconfigRunner netconfig.Runner,
	guard nft.ReachabilityGuard) *Server {
	return &Server{authenticator: authenticator, store: store, leases: leases,
		nftRunner: nftRunner, netconfigRunner: netconfigRunner, guard: guard}
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
	if s.ObserveOnly {
		return nil, status.Error(codes.FailedPrecondition, "ghostd is observation-only")
	}
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

	// Bound command execution even when a client supplies no RPC deadline.
	// The independent revert process must not wait forever for our store lock.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(req.GetDeadManSwitchSeconds())*time.Second)
	defer cancel()
	unlock, err := s.store.Lock()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	defer unlock()
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

	raw, err := nft.ReadRulesetJSON(ctx, s.nftRunner)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "snapshot: %v", err)
	}
	snapshot, err := nft.OwnedRuleset([]byte(raw))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "snapshot: %v", err)
	}
	leaseID, err := s.begin(ctx, req, snapshot)
	if err != nil {
		return nil, err
	}
	if err := nft.Commit(ctx, s.nftRunner, script); err != nil {
		// The lease stays armed: if this host is now in some half-applied
		// state, the dead-man's-switch restoring the pre-apply snapshot in
		// GetDeadManSwitchSeconds() is exactly the safety net that
		// matters most here, not something to disarm on a commit failure.
		return nil, status.Errorf(codes.Internal, "rpc: %v (dead-man's-switch for lease %s stays armed)", err, leaseID)
	}
	return s.finishApply(ctx, req.GetDomain(), leaseID)
}

func (s *Server) applyNetconfig(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	desired, err := netconfig.ParseDesiredState(req.GetDesiredStateJson())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "rpc: desired_state_json: %v", err)
	}
	if err := netconfig.Validate(desired); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "rpc: %v", err)
	}

	snapshot, err := netconfig.Snapshot(ctx, s.netconfigRunner, desired)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "snapshot: %v", err)
	}
	leaseID, err := s.begin(ctx, req, snapshot)
	if err != nil {
		return nil, err
	}
	if err := netconfig.Apply(ctx, s.netconfigRunner, desired); err != nil {
		// Same reasoning as applyFirewall's Commit failure: the lease
		// stays armed on purpose.
		return nil, status.Errorf(codes.Internal, "rpc: %v (dead-man's-switch for lease %s stays armed)", err, leaseID)
	}
	return s.finishApply(ctx, req.GetDomain(), leaseID)
}

// finishApply makes only a successfully completed mutation confirmable.
// A crash or save failure leaves the pre-apply snapshot armed for recovery.
func (s *Server) finishApply(ctx context.Context, domain, id string) (*pb.ApplyResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, status.Errorf(codes.DeadlineExceeded, "apply did not complete in time; rollback stays armed: %v", err)
	}
	d, err := s.store.Domain(domain, legacyName(domain))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	d.Pending.Applied = true
	if err := s.store.SaveDomain(domain, d); err != nil {
		return nil, status.Errorf(codes.Internal, "%v (rollback stays armed)", err)
	}
	return &pb.ApplyResponse{LeaseId: id}, nil
}

func legacyName(domain string) string {
	if domain == domainFirewall {
		return NftRuleset
	}
	return NetconfigState
}

// begin is called with the store lock held, before the first mutation.
func (s *Server) begin(ctx context.Context, req *pb.ApplyRequest, snapshot []byte) (string, error) {
	domain := req.GetDomain()
	d, err := s.store.Domain(domain, legacyName(domain))
	if err != nil {
		return "", status.Errorf(codes.Internal, "%v", err)
	}
	if d.Pending != nil {
		return "", status.Error(codes.FailedPrecondition, "domain already has an unconfirmed apply; wait for rollback")
	}
	id := state.NewLeaseID()
	timeout := time.Duration(req.GetDeadManSwitchSeconds()) * time.Second
	addr, _ := peerAddr(ctx)
	d.Pending = &state.Pending{ID: id, Deadline: time.Now().Add(timeout), Snapshot: snapshot,
		Target: []byte(req.GetDesiredStateJson()), Peer: addr}
	if err := s.store.SaveDomain(domain, d); err != nil {
		return "", status.Errorf(codes.Internal, "%v", err)
	}
	if err := s.leases.Arm(id, domain, timeout, s.store.Dir()); err != nil {
		d.Pending = nil
		_ = s.store.SaveDomain(domain, d) // no mutation has occurred
		return "", status.Errorf(codes.Internal, "%v", err)
	}
	return id, nil
}

// Confirm requires a new transport peer and an unexpired, durable lease.
// Committing the record also revokes the timer's authority to roll back.
func (s *Server) Confirm(ctx context.Context, req *pb.ConfirmRequest) (*pb.ConfirmResponse, error) {
	if s.ObserveOnly {
		return nil, status.Error(codes.FailedPrecondition, "ghostd is observation-only")
	}
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
	unlock, err := s.store.Lock()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	defer unlock()
	for _, domain := range []string{domainFirewall, domainNetconfig} {
		d, err := s.store.Domain(domain, legacyName(domain))
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		if d.Pending == nil || d.Pending.ID != req.GetLeaseId() {
			continue
		}
		if !time.Now().Before(d.Pending.Deadline) {
			return nil, status.Error(codes.FailedPrecondition, "lease expired; rollback must complete")
		}
		if d.Pending.Peer == addr {
			return nil, status.Error(codes.FailedPrecondition, "confirm requires a fresh connection")
		}
		if !d.Pending.Applied {
			return nil, status.Error(codes.FailedPrecondition, "apply did not complete; rollback must complete")
		}
		ctx, cancel := context.WithDeadline(ctx, d.Pending.Deadline)
		defer cancel()
		confirmed := d.Pending.Target
		if domain == domainFirewall {
			raw, err := nft.ReadRulesetJSON(ctx, s.nftRunner)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "%v", err)
			}
			confirmed, err = nft.OwnedRuleset([]byte(raw))
			if err != nil {
				return nil, status.Errorf(codes.Internal, "%v", err)
			}
		}
		if !time.Now().Before(d.Pending.Deadline) || ctx.Err() != nil {
			return nil, status.Error(codes.FailedPrecondition, "confirmation exceeded lease deadline; rollback stays armed")
		}
		d.Confirmed, d.Pending = confirmed, nil
		if err := s.store.SaveDomain(domain, d); err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		// Cleanup only: the durable record above already disarmed rollback. If
		// systemd is unavailable, the timer will later observe no pending lease.
		if err := s.leases.Cancel(req.GetLeaseId()); err != nil {
			log.Printf("ghostd: confirmed lease timer cleanup: %v", err)
		}
		return &pb.ConfirmResponse{Ok: true}, nil
	}
	return nil, status.Error(codes.FailedPrecondition, "unknown or completed lease")
}

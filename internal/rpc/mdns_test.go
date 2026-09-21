//go:build mdns

package rpc

import (
	"context"
	"testing"

	"github.com/xaiki/ghostd/internal/mdns"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMDNSDomainRidesTheOrdinaryLease(t *testing.T) {
	s, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	s.MDNS = mdns.NewService()
	t.Cleanup(s.MDNS.Close)
	ctx := withPeer(context.Background())
	if _, e := s.Apply(ctx, &pb.ApplyRequest{Domain: domainMDNS, DesiredStateJson: `{"interfaces":["eth0"],"host":"NAS","records":[{"service":"_smb._tcp","instance":"N","port":445}]}`, DeadManSwitchSeconds: 60}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("invalid record set accepted:", e)
	}
	// An empty target advertises nothing, needs no sockets, and is confirmable.
	applied, e := s.Apply(ctx, &pb.ApplyRequest{Domain: domainMDNS, DesiredStateJson: `{}`, DeadManSwitchSeconds: 60})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Apply(ctx, &pb.ApplyRequest{Domain: domainMDNS, DesiredStateJson: `{}`, DeadManSwitchSeconds: 60}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("second apply allowed while a lease is pending:", e)
	}
	if _, e = s.Confirm(freshPeer(context.Background()), &pb.ConfirmRequest{LeaseId: applied.LeaseId}); e != nil {
		t.Fatal(e)
	}
	// A record set that cannot start (unknown interface) leaves rollback armed.
	bad := `{"interfaces":["ghostd-none0"],"host":"nas","records":[{"service":"_smb._tcp","instance":"N","port":445}]}`
	if _, e = s.Apply(ctx, &pb.ApplyRequest{Domain: domainMDNS, DesiredStateJson: bad, DeadManSwitchSeconds: 60}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal(e)
	}
	d, _ := s.store.Domain(domainMDNS, legacyName(domainMDNS))
	if d.Pending == nil {
		t.Fatal("a failed start must leave the lease armed, not silently commit")
	}
	s.MDNS = nil
	if _, e = s.Apply(ctx, &pb.ApplyRequest{Domain: domainMDNS, DesiredStateJson: `{}`, DeadManSwitchSeconds: 60}); status.Code(e) != codes.Unimplemented {
		t.Fatal(e)
	}
}

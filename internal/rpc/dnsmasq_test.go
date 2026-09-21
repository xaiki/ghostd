//go:build dhcp && dnsmasq

package rpc

import (
	"context"
	"testing"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/state"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type rpcLegacy struct {
	running bool
	stops   int
	leases  string
}

func (l *rpcLegacy) Stop() error { l.running = false; l.stops++; return nil }

func (l *rpcLegacy) ReadLeases() (string, error) { return l.leases, nil }

func (l *rpcLegacy) Validate(addressbook.Config) error { return nil }

func handoverRequest(action string) *pb.RegistryDocument {
	return &pb.RegistryDocument{Json: `{"action":"` + action + `","seconds":60,"target":` + dormantScope + `}`}
}

func TestHandoverInteractionWithOrdinaryApplyOverRPC(t *testing.T) {
	s := registryServer(t)
	legacy := &rpcLegacy{running: true}
	s.Legacy = func(addressbook.LegacySpec) addressbook.LegacyAuthority { return legacy }
	ctx := withPeer(context.Background())

	// An unconfirmed ordinary Apply blocks the handover before dnsmasq is touched.
	applied, e := s.Apply(ctx, &pb.ApplyRequest{Domain: domainDHCP, DesiredStateJson: dormantScope, DeadManSwitchSeconds: 60})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DHCPHandover(ctx, handoverRequest("begin")); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("handover began over an unconfirmed apply:", e)
	}
	if legacy.stops != 0 || !legacy.running {
		t.Fatal("dnsmasq was stopped by a blocked handover")
	}
	if _, e = s.Confirm(freshPeer(context.Background()), &pb.ConfirmRequest{LeaseId: applied.LeaseId}); e != nil {
		t.Fatal(e)
	}

	// An expired Apply is recovered first, then the handover proceeds.
	d, e := s.store.Domain(domainDHCP, legacyName(domainDHCP))
	if e != nil {
		t.Fatal(e)
	}
	d.Pending = &state.Pending{ID: "expired", Snapshot: []byte(`{"scopes":[]}`), Deadline: time.Now().Add(-time.Second)}
	if e = s.store.SaveDomain(domainDHCP, d); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DHCPHandover(ctx, handoverRequest("begin")); e != nil {
		t.Fatal("expired apply was not recovered before handover:", e)
	}
	if d, _ = s.store.Domain(domainDHCP, legacyName(domainDHCP)); d.Pending != nil {
		t.Fatal("expired lease still pending", d.Pending)
	}
	if legacy.running {
		t.Fatal("dnsmasq still running during takeover")
	}

	// While the handover is pending, an ordinary Apply is refused.
	if _, e = s.Apply(ctx, &pb.ApplyRequest{Domain: domainDHCP, DesiredStateJson: dormantScope, DeadManSwitchSeconds: 60}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("ordinary apply allowed during pending handover:", e)
	}

	// Rolling back restores dnsmasq and re-opens ordinary applies.
	if _, e = s.DHCPHandover(ctx, handoverRequest("rollback")); e != nil {
		t.Fatal(e)
	}
	if !legacy.running {
		t.Fatal("rollback did not restart dnsmasq")
	}
	if _, e = s.Apply(ctx, &pb.ApplyRequest{Domain: domainDHCP, DesiredStateJson: dormantScope, DeadManSwitchSeconds: 60}); e != nil {
		t.Fatal("apply blocked after rollback:", e)
	}
}

func (l *rpcLegacy) Start() error { l.running = true; return nil }

func (l *rpcLegacy) WriteLeases(s string) error { l.leases = s; return nil }

//go:build dhcp && dnsmasq

package rpc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// dnsmasqState is the dnsmasq feature's part of Server.
type dnsmasqState struct {
	// Legacy builds the allocator being replaced by a handover; nil means the
	// real systemd-managed dnsmasq. Tests substitute a fake.
	Legacy func(addressbook.LegacySpec) addressbook.LegacyAuthority
}

// handoverAction is the transactional takeover from a legacy dnsmasq.
func (s *Server) handoverAction(ctx context.Context, req *pb.RegistryDocument) (*pb.RegistryResponse, error) {
	var request struct {
		Action  string                 `json:"action"`
		Target  addressbook.Config     `json:"target"`
		Legacy  addressbook.LegacySpec `json:"legacy"`
		Seconds int                    `json:"seconds"`
		// RequireEvidence makes confirmation wait for observed client
		// renewal and fresh allocation in every enabled scope.
		RequireEvidence bool `json:"require_evidence"`
		// Probes are active checks confirmation requires to pass.
		Probes []addressbook.Probe `json:"probes"`
		// AllowPD accepts that a rollback abandons prefix delegations.
		AllowPD bool `json:"allow_pd"`
	}
	if e := decodeDocument(req.GetJson(), &request); e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}
	if e := s.registryAuth(ctx, request.Action != "status" && request.Action != "history"); e != nil {
		return nil, e
	}
	unlock, e := s.store.Lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	if request.Action == "begin" {
		if e = s.recoverExpired(ctx, domainDHCP); e != nil {
			return nil, e
		}
	}
	j, e := s.DHCP.Store.HandoverJournal()
	if e != nil {
		return nil, e
	}
	spec := j.Legacy
	if request.Action == "begin" {
		spec = request.Legacy
	}
	var legacy addressbook.LegacyAuthority = addressbook.SystemDNSmasq{Spec: spec}
	if s.Legacy != nil {
		legacy = s.Legacy(spec)
	}
	handover := addressbook.Handover{Manager: s.DHCP, Legacy: legacy, SaveConfig: func(c addressbook.Config) error {
		raw, e := json.Marshal(c)
		if e != nil {
			return e
		}
		return s.store.SaveExternallyManagedConfig(domainDHCP, addressbook.ConfigFile, raw)
	}, RequireEvidence: request.RequireEvidence, AllowPD: request.AllowPD, Probes: request.Probes}
	switch request.Action {
	case "status":
		st, e := handover.Status()
		if e != nil {
			return nil, e
		}
		return document(st)
	case "probe":
		results, e := handover.Probe(ctx)
		if e != nil {
			return nil, status.Error(codes.FailedPrecondition, e.Error())
		}
		return document(results)
	case "history":
		history, e := s.DHCP.Store.HandoverHistory()
		if e != nil {
			return nil, e
		}
		return document(history)
	case "begin":
		e = handover.Begin(request.Target, spec, time.Duration(request.Seconds)*time.Second)
	case "confirm":
		e = handover.Confirm()
	case "rollback":
		e = handover.Rollback()
	default:
		return nil, status.Error(codes.InvalidArgument, "unknown handover action")
	}
	if e != nil {
		return nil, status.Error(codes.FailedPrecondition, e.Error())
	}
	j, e = s.DHCP.Store.HandoverJournal()
	if e != nil {
		return nil, e
	}
	return document(j)
}

// handoverPending reports whether a dnsmasq takeover is in flight, which blocks
// ordinary configuration changes.
func (s *Server) handoverPending() (bool, error) {
	journal, err := s.DHCP.Store.HandoverJournal()
	if err != nil {
		return false, err
	}
	return journal.Phase != "" && journal.Phase != "confirmed" && journal.Phase != "rolled-back", nil
}

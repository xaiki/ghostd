package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/mdns"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const domainDHCP = "dhcp-v1"
const domainMDNS = "mdns-v1"

func (s *Server) applyDHCP(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	if s.DHCP == nil {
		return nil, status.Error(codes.Unimplemented, "DHCP registry unavailable")
	}
	journal, journalErr := s.DHCP.Store.HandoverJournal()
	if journalErr != nil {
		return nil, journalErr
	}
	if journal.Phase != "" && journal.Phase != "confirmed" && journal.Phase != "rolled-back" {
		return nil, status.Error(codes.FailedPrecondition, "finish or roll back pending DHCP handover before changing configuration")
	}
	desired, err := addressbook.ParseConfig([]byte(req.GetDesiredStateJson()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err = s.recoverExpired(ctx, domainDHCP); err != nil {
		return nil, err
	}
	snapshot, err := json.Marshal(s.DHCP.Config())
	if err != nil {
		return nil, err
	}
	lease, err := s.begin(ctx, req, snapshot)
	if err != nil {
		return nil, err
	}
	if err = s.DHCP.Apply(desired, func() error { return s.store.Save(addressbook.ConfigFile, []byte(req.GetDesiredStateJson())) }); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "DHCP apply failed; configuration rollback remains armed: %v", err)
	}
	return s.finishApply(ctx, domainDHCP, lease)
}
func (s *Server) restoreDHCP(raw []byte) error {
	config, err := addressbook.ParseConfig(raw)
	if err != nil {
		return err
	}
	if s.DHCP == nil {
		return fmt.Errorf("DHCP manager unavailable")
	}
	return s.DHCP.Apply(config, func() error { return s.store.Save(addressbook.ConfigFile, raw) })
}
func (s *Server) registryAuth(ctx context.Context, write bool) error {
	return s.registryAuthMode(ctx, write, false)
}

// registryAuthMode is registryAuth; a warm standby refuses every registry write
// (its ledger belongs to the leader it mirrors) unless the call is the
// promotion machinery itself.
func (s *Server) registryAuthMode(ctx context.Context, write, allowStandby bool) error {
	if write && !allowStandby && s.DHCP != nil && s.DHCP.Standby() {
		return status.Error(codes.FailedPrecondition, "this daemon is a warm standby; its ledger belongs to the leader it mirrors until it is promoted")
	}
	addr, err := peerAddr(ctx)
	if err != nil {
		return err
	}
	if write {
		if s.ObserveOnly {
			return status.Error(codes.FailedPrecondition, "observation-only")
		}
		_, err = s.authenticator.AuthorizeDeployer(ctx, addr)
	} else {
		_, err = s.authenticator.Identify(ctx, addr)
	}
	if err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	if s.DHCP == nil {
		return status.Error(codes.Unimplemented, "DHCP registry unavailable")
	}
	return nil
}
func document(v any) (*pb.RegistryResponse, error) {
	raw, err := json.Marshal(v)
	return &pb.RegistryResponse{Json: string(raw)}, err
}
func decodeDocument(raw string, v any) error {
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}
func (s *Server) GetRegistry(ctx context.Context, req *pb.RegistryRequest) (*pb.RegistryResponse, error) {
	if err := s.registryAuth(ctx, false); err != nil {
		return nil, err
	}
	if req.GetEventLimit() > 0 {
		events, err := s.DHCP.Store.Events(req.GetAfterEvent(), int(req.GetEventLimit()))
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return document(events)
	}
	snapshot, err := s.DHCP.Store.Snapshot(req.GetScope(), req.GetAddress(), req.GetAtUnix())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return document(snapshot)
}
func (s *Server) ImportLeases(ctx context.Context, req *pb.RegistryDocument) (*pb.RegistryResponse, error) {
	if err := s.registryAuth(ctx, true); err != nil {
		return nil, err
	}
	var doc addressbook.ImportDocument
	var decodeErr error
	if strings.HasPrefix(strings.TrimSpace(req.GetJson()), "[") {
		decodeErr = decodeDocument(req.GetJson(), &doc.Leases)
	} else {
		decodeErr = decodeDocument(req.GetJson(), &doc)
	}
	if err := decodeErr; err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	unlock, err := s.store.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err = s.DHCP.Store.ImportDocument(s.DHCP.Config(), doc); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return document(map[string]bool{"imported": true})
}
func (s *Server) ReportHost(ctx context.Context, req *pb.RegistryDocument) (*pb.RegistryResponse, error) {
	if s.ObserveOnly {
		return nil, status.Error(codes.FailedPrecondition, "observation-only")
	}
	if s.DHCP != nil && s.DHCP.Standby() {
		return nil, status.Error(codes.FailedPrecondition, "warm standby: report to the authority")
	}
	addr, err := peerAddr(ctx)
	if err != nil {
		return nil, err
	}
	identity, err := s.authenticator.AuthorizeReporter(ctx, addr)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	if s.DHCP == nil {
		return nil, status.Error(codes.Unimplemented, "DHCP registry unavailable")
	}
	var report struct {
		Interfaces []addressbook.InterfaceReport `json:"interfaces"`
	}
	if err = decodeDocument(req.GetJson(), &report); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	unlock, err := s.store.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	node := addressbook.Node{ID: identity.NodeID, DNSName: identity.DNSName, Addresses: identity.Addresses, Interfaces: report.Interfaces}
	joined, err := s.DHCP.Store.Report(s.DHCP.Config(), node)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return document(joined)
}

func (s *Server) RepairIdentity(ctx context.Context, req *pb.RegistryDocument) (*pb.RegistryResponse, error) {
	if e := s.registryAuth(ctx, true); e != nil {
		return nil, e
	}
	var changes []addressbook.IdentityRepair
	if e := decodeDocument(req.GetJson(), &changes); e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}
	unlock, e := s.store.Lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	if e = s.DHCP.Store.Repair(s.DHCP.Config(), changes); e != nil {
		return nil, status.Error(codes.FailedPrecondition, e.Error())
	}
	return document(map[string]bool{"repaired": true})
}
func (s *Server) DHCPHandover(ctx context.Context, req *pb.RegistryDocument) (*pb.RegistryResponse, error) {
	var request struct {
		Action  string                 `json:"action"`
		Target  addressbook.Config     `json:"target"`
		Legacy  addressbook.LegacySpec `json:"legacy"`
		Seconds int                    `json:"seconds"`
		// RequireEvidence makes confirmation wait for observed client
		// renewal and fresh allocation in every enabled scope.
		RequireEvidence bool `json:"require_evidence"`
		// Force promotes a standby although the leader still answers.
		Force bool `json:"force"`
	}
	if e := decodeDocument(req.GetJson(), &request); e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}
	standbyAction := request.Action == "promote" || request.Action == "standby-status"
	if e := s.registryAuthMode(ctx, request.Action != "status" && request.Action != "history" && request.Action != "standby-status", standbyAction); e != nil {
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
	switch request.Action {
	case "standby-status":
		if s.Standby == nil {
			return nil, status.Error(codes.FailedPrecondition, "this daemon is not a standby")
		}
		return document(s.Standby.Status())
	case "promote":
		if s.Standby == nil {
			return nil, status.Error(codes.FailedPrecondition, "this daemon is not a standby")
		}
		if !s.DHCP.Standby() {
			return nil, status.Error(codes.FailedPrecondition, "already promoted")
		}
		if !request.Force && s.Standby.LeaderAlive(ctx) {
			return nil, status.Error(codes.FailedPrecondition, "the leader still answers: stop or fence it first (two authorities would hand out the same addresses), or promote with force")
		}
		if e := s.Standby.Promote(ctx); e != nil {
			return nil, status.Error(codes.FailedPrecondition, e.Error())
		}
		return document(map[string]bool{"promoted": true})
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
	}, RequireEvidence: request.RequireEvidence}
	switch request.Action {
	case "status":
		st, e := handover.Status()
		if e != nil {
			return nil, e
		}
		return document(st)
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

// ImportObservations records switch evidence (DHCP snooping, MAC tables). It
// is a deployer call: the exporter describes what it saw, and the ledger keeps
// that apart from any grant.
func (s *Server) ImportObservations(ctx context.Context, req *pb.RegistryDocument) (*pb.RegistryResponse, error) {
	if e := s.registryAuth(ctx, true); e != nil {
		return nil, e
	}
	var doc struct {
		TTL          int64                     `json:"ttl_seconds"`
		Observations []addressbook.Observation `json:"observations"`
	}
	if e := decodeDocument(req.GetJson(), &doc); e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}
	if doc.TTL == 0 {
		doc.TTL = 300
	}
	unlock, e := s.store.Lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	if e = s.DHCP.Store.ObserveSwitch(s.DHCP.Config(), doc.Observations, doc.TTL); e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}
	return document(map[string]int{"observed": len(doc.Observations)})
}

// GetSuggestions lists reviewable peer associations. It is read-only.
func (s *Server) GetSuggestions(ctx context.Context, _ *pb.RegistryRequest) (*pb.RegistryResponse, error) {
	if e := s.registryAuth(ctx, false); e != nil {
		return nil, e
	}
	suggestions, e := s.DHCP.Store.Suggest(s.DHCP.Config())
	if e != nil {
		return nil, e
	}
	return document(suggestions)
}

// applyMDNS moves the advertised record set behind the ordinary lease: a bad
// record set, a bound port or a name another host already owns leaves the old
// set running, and an unconfirmed change reverts.
func (s *Server) applyMDNS(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	if s.MDNS == nil {
		return nil, status.Error(codes.Unimplemented, "mDNS advertisement unavailable")
	}
	desired, err := mdns.ParseConfig([]byte(req.GetDesiredStateJson()))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err = s.recoverExpired(ctx, domainMDNS); err != nil {
		return nil, err
	}
	snapshot, err := json.Marshal(s.MDNS.Config())
	if err != nil {
		return nil, err
	}
	lease, err := s.begin(ctx, req, snapshot)
	if err != nil {
		return nil, err
	}
	if err = s.MDNS.Apply(desired); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "mDNS apply failed; configuration rollback remains armed: %v", err)
	}
	if err = s.store.Save(mdns.ConfigFile, []byte(req.GetDesiredStateJson())); err != nil {
		return nil, status.Errorf(codes.Internal, "%v (rollback stays armed)", err)
	}
	return s.finishApply(ctx, domainMDNS, lease)
}
func (s *Server) restoreMDNS(raw []byte) error {
	if s.MDNS == nil {
		return fmt.Errorf("mDNS service unavailable")
	}
	cfg, err := mdns.ParseConfig(raw)
	if err != nil {
		return err
	}
	if err = s.MDNS.Apply(cfg); err != nil {
		return err
	}
	if len(raw) == 0 {
		raw = []byte(`{}`)
	}
	return s.store.Save(mdns.ConfigFile, raw)
}

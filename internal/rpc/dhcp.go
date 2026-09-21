//go:build dhcp

package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xaiki/ghostd/internal/addressbook"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const domainDHCP = "dhcp-v1"

// dhcpState is the dhcp feature's part of Server.
type dhcpState struct {
	DHCP *addressbook.Manager
	// Standby, when set, makes this daemon a warm standby (internal/replica).
	Standby StandbyControl
}

func init() {
	registerDomain(domainDHCP, domainImpl{
		configKey: addressbook.ConfigFile,
		apply:     (*Server).applyDHCP,
		restore:   (*Server).restoreDHCP,
	})
	registerStateExtender(func(s *Server, out *pb.State) error {
		if s.DHCP == nil {
			return nil
		}
		raw, err := json.Marshal(s.DHCP.Config())
		if err != nil {
			return err
		}
		out.DhcpConfigJson = string(raw)
		return nil
	})
}

func (s *Server) applyDHCP(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	if s.DHCP == nil {
		return nil, status.Error(codes.Unimplemented, "DHCP registry unavailable")
	}
	if pending, err := s.handoverPending(); err != nil {
		return nil, err
	} else if pending {
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

// DHCPHandover routes the authority-transition actions: warm-standby promotion
// here, and (when the dnsmasq feature is built in) takeover from a legacy
// allocator in handoverAction.
func (s *Server) DHCPHandover(ctx context.Context, req *pb.RegistryDocument) (*pb.RegistryResponse, error) {
	var head struct {
		Action string `json:"action"`
		Force  bool   `json:"force"`
	}
	if e := json.Unmarshal([]byte(req.GetJson()), &head); e != nil {
		return nil, status.Error(codes.InvalidArgument, e.Error())
	}
	if head.Action != "promote" && head.Action != "standby-status" {
		return s.handoverAction(ctx, req)
	}
	if e := s.registryAuthMode(ctx, head.Action == "promote", true); e != nil {
		return nil, e
	}
	unlock, e := s.store.Lock()
	if e != nil {
		return nil, e
	}
	defer unlock()
	if s.Standby == nil {
		return nil, status.Error(codes.FailedPrecondition, "this daemon is not a standby")
	}
	if head.Action == "standby-status" {
		return document(s.Standby.Status())
	}
	if !s.DHCP.Standby() {
		return nil, status.Error(codes.FailedPrecondition, "already promoted")
	}
	if !head.Force && s.Standby.LeaderAlive(ctx) {
		return nil, status.Error(codes.FailedPrecondition, "the leader still answers: stop or fence it first (two authorities would hand out the same addresses), or promote with force")
	}
	if e := s.Standby.Promote(ctx); e != nil {
		return nil, status.Error(codes.FailedPrecondition, e.Error())
	}
	return document(map[string]bool{"promoted": true})
}

// StandbyControl is what the RPC layer needs from a warm standby.
type StandbyControl interface {
	LeaderAlive(ctx context.Context) bool
	Promote(ctx context.Context) error
	Status() any
}

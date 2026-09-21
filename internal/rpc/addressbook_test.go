package rpc

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/auth"
	"github.com/xaiki/ghostd/internal/mdns"
	"github.com/xaiki/ghostd/internal/state"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type reportIdentity struct{ allowed bool }

func (f reportIdentity) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) {
	caps := tailcfg.PeerCapMap{}
	if f.allowed {
		caps["ghostd.local/cap/report"] = []tailcfg.RawMessage{`{"report":true}`}
	}
	return &apitype.WhoIsResponse{Node: &tailcfg.Node{StableID: "node-a", Name: "node-a.example.ts.net."}, CapMap: caps}, nil
}
func registryServer(t *testing.T) *Server {
	s, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	db, e := addressbook.Open(filepath.Join(t.TempDir(), "leases.db"))
	if e != nil {
		t.Fatal(e)
	}
	s.DHCP = addressbook.NewManager(db)
	t.Cleanup(func() { s.DHCP.Close(); db.Close() })
	return s
}

const dormantScope = `{"scopes":[{"id":"lan","interface":"eth0","subnet":"10.0.0.0/24","server":"10.0.0.1","router":"10.0.0.1","start":"10.0.0.6","end":"10.0.0.8","zone":"home.arpa","lease_seconds":600,"enabled":false}]}`

func TestDHCPConfigRevertPreservesImports(t *testing.T) {
	s := registryServer(t)
	ctx := withPeer(context.Background())
	applied, e := s.Apply(ctx, &pb.ApplyRequest{Domain: domainDHCP, DesiredStateJson: dormantScope, DeadManSwitchSeconds: 60})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Confirm(freshPeer(context.Background()), &pb.ConfirmRequest{LeaseId: applied.LeaseId}); e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal([]addressbook.ImportedLease{{Scope: "lan", Address: "10.0.0.6", MAC: "00:11:22:33:44:55", Expiry: time.Now().Add(time.Hour).Unix()}})
	if _, e = s.ImportLeases(ctx, &pb.RegistryDocument{Json: string(raw)}); e != nil {
		t.Fatal(e)
	}
	if e = s.restoreDHCP([]byte(`{"scopes":[]}`)); e != nil {
		t.Fatal(e)
	}
	got, e := s.GetRegistry(ctx, &pb.RegistryRequest{})
	if e != nil {
		t.Fatal(e)
	}
	var snapshot addressbook.Snapshot
	json.Unmarshal([]byte(got.Json), &snapshot)
	if len(snapshot.Bindings) != 1 || snapshot.Bindings[0].State != "active" {
		t.Fatal(got)
	}
}
func TestReporterCapabilityAndNoChosenIdentity(t *testing.T) {
	s := registryServer(t)
	ctx := withPeer(context.Background())
	c, e := addressbook.ParseConfig([]byte(dormantScope))
	if e != nil {
		t.Fatal(e)
	}
	if e = s.DHCP.Apply(c, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = s.DHCP.Store.Import(c, []addressbook.ImportedLease{{Scope: "lan", Address: "10.0.0.6", MAC: "00:11:22:33:44:55", Expiry: time.Now().Add(time.Hour).Unix()}}); e != nil {
		t.Fatal(e)
	}
	s.authenticator = auth.NewAuthenticator(reportIdentity{}, "tag:stack-deployer")
	report := &pb.RegistryDocument{Json: `{"interfaces":[{"mac":"00:11:22:33:44:55","addresses":["10.0.0.6"]}]}`}
	if _, e = s.ReportHost(ctx, report); status.Code(e) != codes.PermissionDenied {
		t.Fatal(e)
	}
	s.authenticator = auth.NewAuthenticator(reportIdentity{true}, "tag:stack-deployer")
	if _, e = s.ReportHost(ctx, &pb.RegistryDocument{Json: `{"node_id":"forged","interfaces":[]}`}); status.Code(e) != codes.InvalidArgument {
		t.Fatal(e)
	}
	reply, e := s.ReportHost(ctx, report)
	if e != nil {
		t.Fatal(e)
	}
	var bindings []addressbook.Binding
	json.Unmarshal([]byte(reply.Json), &bindings)
	if len(bindings) != 1 || bindings[0].NodeID != "node-a" || bindings[0].Name != "node-a" {
		t.Fatal(reply)
	}
	// Reporting does not grant permission to import leases or change authority.
	if _, e = s.ImportLeases(ctx, &pb.RegistryDocument{Json: `[]`}); status.Code(e) != codes.PermissionDenied {
		t.Fatal(e)
	}
}

func TestRegistryMutationsRequireDeployer(t *testing.T) {
	s := registryServer(t)
	ctx := withPeer(context.Background())
	s.authenticator = auth.NewAuthenticator(reportIdentity{allowed: true}, "tag:stack-deployer")
	if _, e := s.RepairIdentity(ctx, &pb.RegistryDocument{Json: `[]`}); status.Code(e) != codes.PermissionDenied {
		t.Fatal(e)
	}
	if _, e := s.DHCPHandover(ctx, &pb.RegistryDocument{Json: `{"action":"rollback"}`}); status.Code(e) != codes.PermissionDenied {
		t.Fatal(e)
	}
	if _, e := s.DHCPHandover(ctx, &pb.RegistryDocument{Json: `{"action":"status"}`}); e != nil {
		t.Fatal(e)
	}
}

type rpcLegacy struct {
	running bool
	stops   int
	leases  string
}

func (l *rpcLegacy) Stop() error                       { l.running = false; l.stops++; return nil }
func (l *rpcLegacy) Start() error                      { l.running = true; return nil }
func (l *rpcLegacy) ReadLeases() (string, error)       { return l.leases, nil }
func (l *rpcLegacy) WriteLeases(s string) error        { l.leases = s; return nil }
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

func TestSwitchObservationsAndSuggestionsOverRPC(t *testing.T) {
	s := registryServer(t)
	ctx := withPeer(context.Background())
	if _, e := s.Apply(ctx, &pb.ApplyRequest{Domain: domainDHCP, DesiredStateJson: dormantScope, DeadManSwitchSeconds: 60}); e != nil {
		t.Fatal(e)
	}
	doc := `{"ttl_seconds":600,"observations":[{"scope":"lan","address":"10.0.0.50","mac":"00:11:22:33:44:77","detail":"sw1 Gi1/0/7"}]}`
	if _, e := s.ImportObservations(ctx, &pb.RegistryDocument{Json: doc}); e != nil {
		t.Fatal(e)
	}
	got, e := s.GetRegistry(ctx, &pb.RegistryRequest{})
	if e != nil || !strings.Contains(got.Json, `"switch-snooping"`) || !strings.Contains(got.Json, "sw1 Gi1/0/7") {
		t.Fatal(got, e)
	}
	// Bad input and unknown fields are refused, and a plain peer may not write.
	if _, e = s.ImportObservations(ctx, &pb.RegistryDocument{Json: `{"observations":[{"scope":"lan","address":"10.0.0.50","mac":"zz"}]}`}); status.Code(e) != codes.InvalidArgument {
		t.Fatal(e)
	}
	if _, e = s.ImportObservations(ctx, &pb.RegistryDocument{Json: `{"observations":[],"extra":1}`}); status.Code(e) != codes.InvalidArgument {
		t.Fatal(e)
	}
	plain, _, _, _ := newTestServer(t, nil)
	plain.DHCP = s.DHCP
	if _, e = plain.ImportObservations(ctx, &pb.RegistryDocument{Json: doc}); status.Code(e) != codes.PermissionDenied {
		t.Fatal("plain peer wrote switch evidence:", e)
	}
	if _, e = plain.GetSuggestions(ctx, &pb.RegistryRequest{}); e != nil {
		t.Fatal("suggestions are read-only:", e)
	}
	sg, e := s.GetSuggestions(ctx, &pb.RegistryRequest{})
	if e != nil || sg.Json != "[]" {
		t.Fatal(sg, e)
	}
}

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

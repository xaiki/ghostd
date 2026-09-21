//go:build dhcp

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
	if _, e := s.DHCPHandover(ctx, &pb.RegistryDocument{Json: `{"action":"rollback"}`}); status.Code(e) != codes.PermissionDenied && status.Code(e) != codes.Unimplemented {
		t.Fatal(e)
	}
	if _, e := s.DHCPHandover(ctx, &pb.RegistryDocument{Json: `{"action":"status"}`}); e != nil && status.Code(e) != codes.Unimplemented {
		t.Fatal(e)
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

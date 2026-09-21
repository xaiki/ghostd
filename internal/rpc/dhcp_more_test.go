//go:build dhcp

package rpc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xaiki/ghostd/internal/addressbook"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetRegistryFiltersPagesAndRejectsBadRanges(t *testing.T) {
	s := registryServer(t)
	ctx := withPeer(context.Background())
	if _, e := s.Apply(ctx, &pb.ApplyRequest{Domain: domainDHCP, DesiredStateJson: dormantScope, DeadManSwitchSeconds: 60}); e != nil {
		t.Fatal(e)
	}
	live := addressbook.Config{Scopes: []addressbook.Scope{{ID: "lan", Interface: "eth0", Subnet: "10.0.0.0/24", Server: "10.0.0.1", Router: "10.0.0.1", Start: "10.0.0.6", End: "10.0.0.8", Zone: "home.arpa", LeaseSeconds: 600, Enabled: true}}}
	for i, mac := range []string{"00:11:22:33:44:55", "00:11:22:33:44:66"} {
		addr := []string{"10.0.0.6", "10.0.0.7"}[i]
		if _, e := s.DHCP.Store.Allocate(live, "lan", "mac:"+mac, mac, "", addr, true); e != nil {
			t.Fatal(e)
		}
	}
	snapshot := func(req *pb.RegistryRequest) addressbook.Snapshot {
		t.Helper()
		r, e := s.GetRegistry(ctx, req)
		if e != nil {
			t.Fatal(e)
		}
		var out addressbook.Snapshot
		if json.Unmarshal([]byte(r.Json), &out) != nil {
			t.Fatal(r.Json)
		}
		return out
	}
	if got := snapshot(&pb.RegistryRequest{Address: "10.0.0.7"}); len(got.Bindings) != 1 || got.Bindings[0].Address != "10.0.0.7" {
		t.Fatal("address filter:", got.Bindings)
	}
	if got := snapshot(&pb.RegistryRequest{Scope: "nope"}); len(got.Bindings) != 0 {
		t.Fatal("scope filter:", got.Bindings)
	}
	// Events page with an increasing cursor.
	first, e := s.GetRegistry(ctx, &pb.RegistryRequest{EventLimit: 1})
	if e != nil {
		t.Fatal(e)
	}
	var page []addressbook.Event
	json.Unmarshal([]byte(first.Json), &page)
	if len(page) != 1 {
		t.Fatal(first.Json)
	}
	rest, _ := s.GetRegistry(ctx, &pb.RegistryRequest{AfterEvent: page[0].ID, EventLimit: 100})
	var more []addressbook.Event
	json.Unmarshal([]byte(rest.Json), &more)
	if len(more) == 0 || more[0].ID <= page[0].ID {
		t.Fatal("pagination must move forward:", more)
	}
	if _, e = s.GetRegistry(ctx, &pb.RegistryRequest{EventLimit: 5000}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("an oversized page must be refused:", e)
	}
	if _, e = s.GetRegistry(ctx, &pb.RegistryRequest{AtUnix: -5}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("a negative instant:", e)
	}
	if _, e = s.GetRegistry(ctx, &pb.RegistryRequest{AtUnix: 4102444800}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("the future is not attributable:", e)
	}
}

func TestRepairIdentityOverRPCValidatesAndApplies(t *testing.T) {
	s := registryServer(t)
	ctx := withPeer(context.Background())
	if _, e := s.RepairIdentity(ctx, &pb.RegistryDocument{Json: `not json`}); status.Code(e) != codes.InvalidArgument {
		t.Fatal(e)
	}
	if _, e := s.RepairIdentity(ctx, &pb.RegistryDocument{Json: `[{"scope":"lan","bogus":1}]`}); status.Code(e) != codes.InvalidArgument {
		t.Fatal("unknown fields are refused:", e)
	}
	if _, e := s.RepairIdentity(ctx, &pb.RegistryDocument{Json: `[]`}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("an empty repair is not a repair:", e)
	}
	live := addressbook.Config{Scopes: []addressbook.Scope{{ID: "lan", Interface: "eth0", Subnet: "10.0.0.0/24", Server: "10.0.0.1", Router: "10.0.0.1", Start: "10.0.0.6", End: "10.0.0.8", Zone: "home.arpa", LeaseSeconds: 600, Enabled: true}}}
	b, e := s.DHCP.Store.Allocate(live, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	doc, _ := json.Marshal([]addressbook.IdentityRepair{{Scope: "lan", Address: b.Address, Client: b.Client, ExpectedDevice: b.Device, Device: "kitchen", Name: "kitchen", Reason: "verified", Persist: true}})
	if _, e = s.RepairIdentity(ctx, &pb.RegistryDocument{Json: string(doc)}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.RepairIdentity(ctx, &pb.RegistryDocument{Json: string(doc)}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("a stale repair must be refused:", e)
	}
	got, _ := s.GetRegistry(ctx, &pb.RegistryRequest{})
	if !strings.Contains(got.Json, `"associations"`) || !strings.Contains(got.Json, "kitchen") {
		t.Fatal("the durable association is visible:", got.Json)
	}
}

func TestGetStateCarriesTheDHCPConfiguration(t *testing.T) {
	s := registryServer(t)
	ctx := withPeer(context.Background())
	if _, e := s.Apply(ctx, &pb.ApplyRequest{Domain: domainDHCP, DesiredStateJson: dormantScope, DeadManSwitchSeconds: 60}); e != nil {
		t.Fatal(e)
	}
	st, e := s.GetState(ctx, &pb.GetStateRequest{})
	if e != nil || !strings.Contains(st.GetDhcpConfigJson(), `"lan"`) {
		t.Fatal("the standby mirror reads the configuration from GetState:", st, e)
	}
}

func TestStandbyActionsWithoutAStandby(t *testing.T) {
	s := registryServer(t)
	ctx := withPeer(context.Background())
	for _, action := range []string{"promote", "standby-status"} {
		if _, e := s.DHCPHandover(ctx, &pb.RegistryDocument{Json: `{"action":"` + action + `"}`}); status.Code(e) != codes.FailedPrecondition {
			t.Fatalf("%s on a daemon that is not a standby: %v", action, e)
		}
	}
	if _, e := s.DHCPHandover(ctx, &pb.RegistryDocument{Json: `nonsense`}); status.Code(e) != codes.InvalidArgument {
		t.Fatal(e)
	}
}

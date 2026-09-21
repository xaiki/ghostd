//go:build dhcp

package replica

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xaiki/ghostd/internal/addressbook"
	"github.com/xaiki/ghostd/internal/auth"
	"github.com/xaiki/ghostd/internal/nft"
	"github.com/xaiki/ghostd/internal/overlay"
	"github.com/xaiki/ghostd/internal/rpc"
	"github.com/xaiki/ghostd/internal/state"
	pb "github.com/xaiki/ghostd/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type deployer struct{}

func (deployer) Whois(context.Context, string) (*overlay.Caller, error) {
	return &overlay.Caller{Tags: []string{"tag:stack-deployer"}, NodeID: "op", Login: "op@example.com"}, nil
}

type runner struct{}

func (runner) Output(context.Context, string, ...string) ([]byte, error) {
	return []byte(`{"nftables":[]}`), nil
}
func (runner) RunStdin(context.Context, string, string, ...string) ([]byte, error) {
	return nil, nil
}

type netRunner struct{}

func (netRunner) Output(context.Context, string, ...string) ([]byte, error) { return []byte(`[]`), nil }

var _ nft.Runner = runner{}

type node struct {
	store   *state.Store
	manager *addressbook.Manager
	server  *rpc.Server
	addr    string
	stop    func()
}

// newNode is a real ghostd RPC surface over a real ledger, on a loopback port.
func newNode(t *testing.T) *node {
	t.Helper()
	dir := t.TempDir()
	st, err := state.NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := addressbook.Open(filepath.Join(dir, "addressbook.db"))
	if err != nil {
		t.Fatal(err)
	}
	m := addressbook.NewManager(db)
	srv := rpc.NewServer(auth.NewAuthenticator(deployer{}, "tag:stack-deployer"), st, state.NewLeases("/opt/ghostd/ghostd", state.ExecRunner{}), runner{}, netRunner{}, nft.ReachabilityGuard{})
	srv.DHCP = m
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer()
	pb.RegisterHostStateServer(g, srv)
	go g.Serve(lis)
	n := &node{store: st, manager: m, server: srv, addr: lis.Addr().String(), stop: func() { g.Stop(); m.Close(); db.Close() }}
	t.Cleanup(n.stop)
	return n
}

func operator(ctx context.Context) context.Context {
	return peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("100.64.0.9"), Port: 50000}})
}

func scopeConfig(enabled bool) addressbook.Config {
	return addressbook.Config{Scopes: []addressbook.Scope{{ID: "lan", Interface: "eth0", Subnet: "10.0.0.0/24", Server: "10.0.0.1", Router: "10.0.0.1", Start: "10.0.0.6", End: "10.0.0.8", Zone: "home.arpa", LeaseSeconds: 600, Enabled: enabled}}}
}

func TestStandbyFollowsLeaderAndPromotesOnlyWhenTheLeaderIsGone(t *testing.T) {
	leader, standby := newNode(t), newNode(t)
	// The leader's confirmed configuration and some live state. (Binding the real
	// interface is the lab's job; the ledger is what replication carries.)
	cfg := scopeConfig(false)
	if e := leader.manager.Apply(cfg, func() error { return nil }); e != nil {
		t.Fatal(e)
	}
	live := scopeConfig(true)
	a, e := leader.manager.Store.Allocate(live, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "kitchen", "10.0.0.6", true)
	if e != nil {
		t.Fatal(e)
	}
	leader.manager.Store.ServerDUID()

	standby.manager.SetStandby(true)
	f := &Follower{Store: standby.store, Manager: standby.manager, Leader: leader.addr}
	standby.server.Standby = f
	if e := f.SyncOnce(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := standby.manager.Store.Snapshot("", "", 0)
	if len(got.Bindings) != 1 || got.Bindings[0].Address != a.Address || got.Bindings[0].State != "active" {
		t.Fatal("standby did not mirror the lease:", got.Bindings)
	}
	if raw, _ := standby.store.Load(ConfigMirror); !strings.Contains(string(raw), `"scopes"`) {
		t.Fatal("leader configuration not mirrored:", string(raw))
	}

	ctx := operator(context.Background())
	handover := func(doc string) (*pb.RegistryResponse, error) {
		return standby.server.DHCPHandover(ctx, &pb.RegistryDocument{Json: doc})
	}
	// While standby: ledger writes are refused, status works.
	if _, e = standby.server.ImportLeases(ctx, &pb.RegistryDocument{Json: `[]`}); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("a standby accepted a ledger write:", e)
	}
	if r, e := handover(`{"action":"standby-status"}`); e != nil || !strings.Contains(r.Json, `"promoted":false`) {
		t.Fatal(r, e)
	}
	// The leader still answers: promotion is refused, forced or not... only force overrides.
	if _, e = handover(`{"action":"promote"}`); status.Code(e) != codes.FailedPrecondition || !strings.Contains(e.Error(), "leader still answers") {
		t.Fatal("promoted over a live leader:", e)
	}
	// The leader dies. Promotion needs a serving configuration, and the standby
	// cannot bind eth0 here, so it must fail cleanly and stay a standby.
	leader.stop()
	time.Sleep(200 * time.Millisecond)
	if e = standby.store.Save(ConfigMirror, mustJSON(scopeConfig(true))); e != nil {
		t.Fatal(e)
	}
	if _, e = handover(`{"action":"promote"}`); e == nil {
		t.Fatal("promotion succeeded although the scope cannot bind on this host")
	}
	if !standby.manager.Standby() {
		t.Fatal("a failed promotion must leave the node a standby")
	}
	// With the mirrored scope disabled (nothing to bind) promotion succeeds and
	// the standby carries on from the mirror.
	if e = standby.store.Save(ConfigMirror, mustJSON(scopeConfig(false))); e != nil {
		t.Fatal(e)
	}
	if _, e = handover(`{"action":"promote"}`); e != nil {
		t.Fatal(e)
	}
	if standby.manager.Standby() {
		t.Fatal("still standby after promotion")
	}
	if b, e := standby.manager.Store.Allocate(live, "lan", "mac:00:11:22:33:44:55", "00:11:22:33:44:55", "", a.Address, true); e != nil || b.Address != a.Address {
		t.Fatal("promoted node lost the leader's lease:", b, e)
	}
	if _, e = handover(`{"action":"promote"}`); status.Code(e) != codes.FailedPrecondition {
		t.Fatal("promoting twice:", e)
	}
	// Writes are accepted again.
	if _, e = standby.server.ImportLeases(ctx, &pb.RegistryDocument{Json: `[]`}); e != nil {
		t.Fatal("promoted node still refuses writes:", e)
	}
}

func mustJSON(c addressbook.Config) []byte {
	raw, err := jsonMarshal(c)
	if err != nil {
		panic(err)
	}
	return raw
}

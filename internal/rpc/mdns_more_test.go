//go:build mdns

package rpc

import (
	"context"
	"strings"
	"testing"

	"github.com/xaiki/ghostd/internal/mdns"
	pb "github.com/xaiki/ghostd/proto"
)

func TestRestoreMDNSAppliesAndPersists(t *testing.T) {
	s, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	if err := s.restoreMDNS([]byte(`{}`)); err == nil {
		t.Fatal("no service, no restore")
	}
	s.MDNS = mdns.NewService()
	defer s.MDNS.Close()
	if err := s.restoreMDNS([]byte(`{"host":"BAD"}`)); err != nil {
		t.Fatal("an empty record set is valid whatever the host says:", err)
	}
	if err := s.restoreMDNS(nil); err != nil {
		t.Fatal(err)
	}
	if raw, _ := s.store.Load(mdns.ConfigFile); string(raw) != `{}` {
		t.Fatal(string(raw))
	}
	if err := s.restoreMDNS([]byte(`{"interfaces":["eth0"],"host":"X y","records":[{"service":"_a._tcp","instance":"n","port":1}]}`)); err == nil {
		t.Fatal("an invalid snapshot restored")
	}
}

func TestGetStateCarriesTheMDNSConfiguration(t *testing.T) {
	s, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	s.MDNS = mdns.NewService()
	t.Cleanup(s.MDNS.Close)
	ctx := withPeer(context.Background())
	// An empty target needs no sockets and is confirmable without touching
	// the network — the same shape TestMDNSDomainRidesTheOrdinaryLease uses.
	applied, e := s.Apply(ctx, &pb.ApplyRequest{Domain: domainMDNS, DesiredStateJson: `{}`, DeadManSwitchSeconds: 60})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Confirm(freshPeer(context.Background()), &pb.ConfirmRequest{LeaseId: applied.LeaseId}); e != nil {
		t.Fatal(e)
	}
	st, e := s.GetState(ctx, &pb.GetStateRequest{})
	if e != nil || !strings.Contains(st.GetMdnsConfigJson(), `"interfaces"`) {
		t.Fatal("a caller reads the advertised set back from GetState:", st, e)
	}
}

func TestGetStateOmitsMDNSConfigWhenTheFeatureIsNotBuiltIn(t *testing.T) {
	s, _, _, _ := newTestServer(t, []string{"tag:stack-deployer"})
	// s.MDNS is nil: the feature is not built in for this daemon.
	st, e := s.GetState(withPeer(context.Background()), &pb.GetStateRequest{})
	if e != nil || st.GetMdnsConfigJson() != "" {
		t.Fatal("no MDNS service must mean no mdns_config_json, not a stale or default value:", st, e)
	}
}

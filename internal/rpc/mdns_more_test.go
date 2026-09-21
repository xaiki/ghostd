//go:build mdns

package rpc

import (
	"testing"

	"github.com/xaiki/ghostd/internal/mdns"
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

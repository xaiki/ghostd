package state

import "testing"

func init() { RegisterDomain("dhcp-v1") }

func TestExternalConfigUpdatesBootRestoreWithoutOverridingPendingLease(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	old := []byte(`{"scopes":[]}`)
	if e := s.SaveDomain("dhcp-v1", DomainState{Confirmed: old}); e != nil {
		t.Fatal(e)
	}
	want := []byte(`{"scopes":[{"id":"new"}]}`)
	if e := s.SaveExternallyManagedConfig("dhcp-v1", "dhcp-config.json", want); e != nil {
		t.Fatal(e)
	}
	restored, e := s.Domain("dhcp-v1", "dhcp-config.json")
	if e != nil || string(restored.Confirmed) != string(want) {
		t.Fatal(restored, e)
	}
	actual, e := s.Load("dhcp-config.json")
	if e != nil || string(actual) != string(want) {
		t.Fatal(string(actual), e)
	}
	restored.Pending = &Pending{ID: "unconfirmed"}
	if e = s.SaveDomain("dhcp-v1", restored); e != nil {
		t.Fatal(e)
	}
	if e = s.SaveExternallyManagedConfig("dhcp-v1", "dhcp-config.json", old); e == nil {
		t.Fatal("overrode pending lease")
	}
}

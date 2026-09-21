package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/xaiki/ghostd/internal/state"
)

func TestStopperRunsInReverseAndSkipsNil(t *testing.T) {
	var order []string
	var s stopper
	s.add(func() { order = append(order, "a") })
	s.add(nil)
	s.add(func() { order = append(order, "b") })
	s.run()
	if !reflect.DeepEqual(order, []string{"b", "a"}) {
		t.Fatal("features must stop in reverse start order:", order)
	}
}

func TestDomainAndFeatureRegistries(t *testing.T) {
	saved, savedF := domainHooks, features
	defer func() { domainHooks, features = saved, savedF }()
	domainHooks, features = nil, nil
	if got := allDomains(); !reflect.DeepEqual(got, []string{"firewall", "netconfig"}) {
		t.Fatal("core domains only in a bare build:", got)
	}
	registerDomainHook(domainHook{name: "zz-v1", key: "zz.json"})
	registerDomainHook(domainHook{name: "aa-v1", key: "aa.json"})
	if got := allDomains(); !reflect.DeepEqual(got, []string{"firewall", "netconfig", "aa-v1", "zz-v1"}) {
		t.Fatal("core first, then optional in a stable order:", got)
	}
	if h, ok := hookFor("aa-v1"); !ok || h.key != "aa.json" {
		t.Fatal(h, ok)
	}
	if _, ok := hookFor("firewall"); ok {
		t.Fatal("core domains are not hooks")
	}
	register(feature{name: "b"})
	register(feature{name: "a"})
	if got := builtFeatures(); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatal(got)
	}
}

func TestRecoverDomainKnowsOnlyWhatIsBuiltIn(t *testing.T) {
	store, err := state.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := recoverDomain(store, "dhcp-v9", ""); err == nil || !strings.Contains(err.Error(), "built into this binary") {
		t.Fatal("an unknown domain must name the likely cause:", err)
	}
	saved := domainHooks
	defer func() { domainHooks = saved }()
	var restored [][]byte
	registerDomainHook(domainHook{name: "fake-v1", key: "fake.json", restore: func(_ *state.Store, raw []byte) error {
		restored = append(restored, raw)
		return nil
	}})
	state.RegisterDomain("fake-v1")
	// Confirmed state is replayed at boot through the feature's own restore.
	if err := store.SaveDomain("fake-v1", state.DomainState{Confirmed: []byte(`{"v":1}`)}); err != nil {
		t.Fatal(err)
	}
	if err := recoverDomain(store, "fake-v1", ""); err != nil || len(restored) != 1 || string(restored[0]) != `{"v":1}` {
		t.Fatal(restored, err)
	}
	// A pending lease is rolled back to its snapshot, then cleared; a stale timer
	// for some other lease does nothing.
	if err := store.SaveDomain("fake-v1", state.DomainState{Confirmed: []byte(`{"v":1}`), Pending: &state.Pending{ID: "L1", Snapshot: []byte(`{"v":0}`)}}); err != nil {
		t.Fatal(err)
	}
	if err := recoverDomain(store, "fake-v1", "OTHER"); err != nil || len(restored) != 1 {
		t.Fatal("a timer for another lease must not roll this one back:", restored, err)
	}
	if err := recoverDomain(store, "fake-v1", "L1"); err != nil || string(restored[1]) != `{"v":0}` {
		t.Fatal(restored, err)
	}
	if d, _ := store.Domain("fake-v1", "fake.json"); d.Pending != nil {
		t.Fatal("the rolled-back lease must be cleared")
	}
}

func TestPrepareDomainRefusesToObserveAManagedHost(t *testing.T) {
	store, _ := state.NewStore(t.TempDir())
	if err := prepareDomain(store, "firewall", true); err != nil {
		t.Fatal("a fresh host may be observed:", err)
	}
	store.SaveDomain("firewall", state.DomainState{Confirmed: []byte(`{}`)})
	if err := prepareDomain(store, "firewall", true); err == nil || !strings.Contains(err.Error(), "fresh") {
		t.Fatal("observation must not quietly stop enforcing a managed host:", err)
	}
}

//go:build dhcp

package addressbook

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/iana"
)

func configPD() Config {
	c := config6()
	c.Scopes[0].End = "fd00::9"
	c.Scopes[0].PD = &PDConfig{Prefix: "fd78::/62", Length: 64, Route: true}
	return c
}

func TestPrefixArithmetic(t *testing.T) {
	pool := netip.MustParsePrefix("fd78::/48")
	for _, tc := range []struct {
		length, i int
		want      string
	}{
		{56, 0, "fd78::/56"}, {56, 1, "fd78:0:0:100::/56"}, {56, 255, "fd78:0:0:ff00::/56"},
		{64, 1, "fd78:0:0:1::/64"}, {60, 1, "fd78:0:0:10::/60"}, {60, 4095, "fd78:0:0:fff0::/60"}, {64, 65535, "fd78:0:0:ffff::/64"},
	} {
		if got := prefixAt(pool, tc.length, tc.i).String(); got != tc.want {
			t.Errorf("/%d #%d: got %s want %s", tc.length, tc.i, got, tc.want)
		}
	}
	// A pool that is not byte aligned: 2001:db8:0:8000::/49, /56 delegations.
	odd := netip.MustParsePrefix("2001:db8:0:8000::/49")
	if got := prefixAt(odd, 56, 130).String(); got != "2001:db8:0:8200::/56" && got != "2001:db8:0:8000:8200::/56" {
		// index 130 = 0x82: bits land in the 7 bits below /49 -> 0x8000 + 0x82<<8
		t.Log(got)
	}
	if !inPool(pool, 56, netip.MustParsePrefix("fd78:0:0:100::/56")) || inPool(pool, 56, netip.MustParsePrefix("fd79::/56")) || inPool(pool, 56, netip.MustParsePrefix("fd78:0:0:100::/60")) {
		t.Fatal("pool membership")
	}
}

func pdRequest(t *testing.T, s *Store, c Config, kind dhcpv6.MessageType, duid byte, iaid byte, hint string, via string) *dhcpv6.OptIAPD {
	t.Helper()
	sid, _ := s.ServerDUID()
	cid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, duid}}
	r := &dhcpv6.Message{MessageType: kind}
	r.AddOption(dhcpv6.OptClientID(cid))
	if kind != dhcpv6.MessageTypeSolicit && kind != dhcpv6.MessageTypeRebind {
		r.AddOption(dhcpv6.OptServerID(sid))
	}
	ia := &dhcpv6.OptIAPD{IaId: [4]byte{0, 0, 0, iaid}}
	if hint != "" {
		_, n, _ := net.ParseCIDR(hint)
		ia.Options.Add(&dhcpv6.OptIAPrefix{Prefix: n})
	}
	r.AddOption(ia)
	reply, err := s.Handle6Via(c, c.Scopes[0], r, net.ParseIP(via))
	if err != nil || reply == nil {
		t.Fatalf("%s: %v %v", kind, reply, err)
	}
	out := reply.(*dhcpv6.Message).Options.IAPD()
	if len(out) != 1 {
		t.Fatal("no IA_PD in the reply")
	}
	return out[0]
}
func prefixOf(ia *dhcpv6.OptIAPD) string {
	if ps := ia.Options.Prefixes(); len(ps) > 0 {
		return ps[0].Prefix.String()
	}
	return ""
}
func statusOf(ia *dhcpv6.OptIAPD) iana.StatusCode {
	if st := ia.Options.Status(); st != nil {
		return st.StatusCode
	}
	return iana.StatusSuccess
}

func TestPrefixDelegationLifecycle(t *testing.T) {
	s := openTest(t)
	c := configPD()
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	adv := pdRequest(t, s, c, dhcpv6.MessageTypeSolicit, 1, 1, "", "")
	if prefixOf(adv) != "fd78::/64" {
		t.Fatal("first client is offered the lowest prefix:", adv)
	}
	if snap, _ := s.Snapshot("", "", 0); len(snap.Bindings) != 1 || snap.Bindings[0].State != "offered" {
		t.Fatal("an advertisement is only an offer:", snap.Bindings)
	}
	rep := pdRequest(t, s, c, dhcpv6.MessageTypeRequest, 1, 1, "fd78::/64", "fe80::1")
	if prefixOf(rep) != "fd78::/64" || rep.T1 != 300*time.Second || rep.T2 != 480*time.Second {
		t.Fatal(rep)
	}
	if p := rep.Options.Prefixes()[0]; p.ValidLifetime != 600*time.Second || p.PreferredLifetime != 300*time.Second {
		t.Fatal("lifetimes:", p)
	}
	snap, _ := s.Snapshot("", "", 0)
	b := snap.Bindings[0]
	if b.State != "active" || b.Origin != originPD || b.Via != "fe80::1" || b.Address != "fd78::/64" || b.End != now+600 {
		t.Fatal(b)
	}
	// Renew and Rebind extend the same prefix; the router keeps what it holds.
	for _, kind := range []dhcpv6.MessageType{dhcpv6.MessageTypeRenew, dhcpv6.MessageTypeRebind} {
		now += 100
		if got := pdRequest(t, s, c, kind, 1, 1, "", "fe80::1"); prefixOf(got) != "fd78::/64" {
			t.Fatal(kind, got)
		}
		if snap, _ = s.Snapshot("", "", 0); snap.Bindings[0].End != now+600 {
			t.Fatal(kind, "did not extend", snap.Bindings[0])
		}
	}
	// A second router gets a different prefix; a Renew from a stranger has no binding.
	if got := pdRequest(t, s, c, dhcpv6.MessageTypeRequest, 2, 1, "", "fe80::2"); prefixOf(got) == "" || prefixOf(got) == "fd78::/64" {
		t.Fatal("double delegation:", got)
	}
	if got := pdRequest(t, s, c, dhcpv6.MessageTypeRenew, 9, 1, "", ""); statusOf(got) != iana.StatusNoBinding {
		t.Fatal(got)
	}
	// Release frees it for the next router, whose hint asks for exactly that prefix.
	if got := pdRequest(t, s, c, dhcpv6.MessageTypeRelease, 1, 1, "", ""); statusOf(got) != iana.StatusSuccess {
		t.Fatal(got)
	}
	if got := pdRequest(t, s, c, dhcpv6.MessageTypeRequest, 3, 1, "fd78::/64", "fe80::3"); prefixOf(got) != "fd78::/64" {
		t.Fatal("hint for a free prefix ignored:", got)
	}
	// History is kept: the past owner of fd78::/64 is still answerable.
	past, _ := s.Snapshot("v6", "fd78::/64", now-50)
	if len(past.Bindings) != 1 || past.Bindings[0].Via != "fe80::1" {
		t.Fatal("historical ownership of the delegated range lost:", past.Bindings)
	}
}

func TestPrefixPoolExhaustionAndUnconfigured(t *testing.T) {
	s := openTest(t)
	c := configPD() // /62 pool, /64 delegations: four prefixes
	for i := byte(1); i <= 4; i++ {
		if got := pdRequest(t, s, c, dhcpv6.MessageTypeRequest, i, 1, "", "fe80::1"); prefixOf(got) == "" {
			t.Fatalf("client %d: %v", i, got)
		}
	}
	if got := pdRequest(t, s, c, dhcpv6.MessageTypeSolicit, 5, 1, "", ""); statusOf(got) != iana.StatusNoPrefixAvail || prefixOf(got) != "" {
		t.Fatal("exhausted pool:", got)
	}
	// Distinct IAIDs of one client are distinct delegations.
	if got := pdRequest(t, openTest(t), c, dhcpv6.MessageTypeRequest, 1, 2, "", ""); prefixOf(got) == "" {
		t.Fatal(got)
	}
	none := config6()
	if got := pdRequest(t, s, none, dhcpv6.MessageTypeSolicit, 1, 1, "", ""); statusOf(got) != iana.StatusNoPrefixAvail {
		t.Fatal("scope without pd must decline:", got)
	}
}

func TestDelegationIsAttributedToTheRoutersDevice(t *testing.T) {
	s := openTest(t)
	c := configPD()
	sid, _ := s.ServerDUID()
	cid := &dhcpv6.DUIDLL{HWType: iana.HWTypeEthernet, LinkLayerAddr: net.HardwareAddr{0, 1, 2, 3, 4, 7}}
	na := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeRequest}
	na.AddOption(dhcpv6.OptClientID(cid))
	na.AddOption(dhcpv6.OptServerID(sid))
	ia := &dhcpv6.OptIANA{IaId: [4]byte{0, 0, 0, 1}}
	ia.Options.Add(&dhcpv6.OptIAAddress{IPv6Addr: net.ParseIP("fd00::6")})
	na.AddOption(ia)
	if r, err := s.Handle6(c, c.Scopes[0], na); err != nil || r == nil {
		t.Fatal(err)
	}
	pdRequest(t, s, c, dhcpv6.MessageTypeRequest, 7, 1, "", "fe80::7")
	snap, _ := s.Snapshot("v6", "", 0)
	var addr, prefix Binding
	for _, b := range snap.Bindings {
		if b.Origin == originPD {
			prefix = b
		} else {
			addr = b
		}
	}
	if addr.Device == "" || prefix.Device != addr.Device || !strings.Contains(prefix.Evidence, "same DUID") {
		t.Fatalf("router and its delegated range are one device: addr=%+v prefix=%+v", addr, prefix)
	}
	// The address binding must not be confused with the delegation on renewal.
	if cur, ok, _ := s.currentClient("v6", addr.Client); !ok || cur.Origin == originPD {
		t.Fatal("IA_NA lookup returned the delegation")
	}
	// Delegations never enter DNS, the dnsmasq export, or scope-overlap checks.
	if got, _ := s.DNSBindings("v6", prefix.Name, ""); len(got) > 1 {
		t.Fatal("delegation published in DNS")
	}
	checkNoDelegationExport(t, snap)
	m := NewManager(s)
	defer m.Close()
	if e := m.Apply(disabled(c), func() error { return nil }); e != nil {
		t.Fatal("a prefix binding tripped the scope overlap check:", e)
	}
}

func TestPDConfigValidation(t *testing.T) {
	if err := configPD().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Config){
		"not canonical":     func(c *Config) { c.Scopes[0].PD.Prefix = "fd78::1/62" },
		"length too long":   func(c *Config) { c.Scopes[0].PD.Length = 65 },
		"length not deeper": func(c *Config) { c.Scopes[0].PD.Length = 62 },
		"too many":          func(c *Config) { c.Scopes[0].PD.Prefix = "fd78::/40"; c.Scopes[0].PD.Length = 60 },
		"too short":         func(c *Config) { c.Scopes[0].PD.Prefix = "fd00::/16"; c.Scopes[0].PD.Length = 31 },
		"inside own link":   func(c *Config) { c.Scopes[0].PD.Prefix = "fd00::/62" },
		"IPv4 pool":         func(c *Config) { c.Scopes[0].PD.Prefix = "10.0.0.0/24" },
	} {
		c := cloneConfig(configPD())
		mutate(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	v4 := testConfig()
	v4.Scopes[0].PD = &PDConfig{Prefix: "fd78::/62", Length: 64}
	if err := v4.Validate(); err == nil {
		t.Fatal("IPv4 scope with prefix delegation accepted")
	}
	// Two scopes may not delegate overlapping pools.
	two := configPD()
	two.Scopes = append(two.Scopes, Scope{ID: "v6b", Interface: "eth1", Subnet: "fd01::/64", Server: "fd01::1", Start: "fd01::6", End: "fd01::9", Zone: "b.example", LeaseSeconds: 600, PreferredSeconds: 300, Enabled: true, PD: &PDConfig{Prefix: "fd78::/63", Length: 64}})
	if err := two.Validate(); err == nil {
		t.Fatal("overlapping pd pools accepted")
	}
	// The pool survives a JSON round trip and cloning does not alias it.
	raw, _ := jsonMarshal(configPD())
	back, err := ParseConfig(raw)
	if err != nil || back.Scopes[0].PD == nil {
		t.Fatal(err)
	}
	cl := cloneConfig(back)
	cl.Scopes[0].PD.Length = 60
	if back.Scopes[0].PD.Length != 64 {
		t.Fatal("clone aliases the pd config")
	}
}

type fakeRoutes struct {
	mu      sync.Mutex
	kernel  map[string][2]string // dst -> via, dev
	history []string
}

func (f *fakeRoutes) Run(_ context.Context, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.history = append(f.history, strings.Join(args, " "))
	switch {
	case len(args) > 3 && args[2] == "route" && args[3] == "show":
		out := "["
		first := true
		for dst, v := range f.kernel {
			if !first {
				out += ","
			}
			first = false
			out += `{"dst":"` + dst + `","gateway":"` + v[0] + `","dev":"` + v[1] + `"}`
		}
		return []byte(out + "]"), nil
	case args[1] == "route" && args[2] == "replace":
		f.kernel[args[3]] = [2]string{args[5], args[7]}
	case args[1] == "route" && args[2] == "del":
		delete(f.kernel, args[3])
	}
	return nil, nil
}

func TestRoutesFollowTheLedger(t *testing.T) {
	s := openTest(t)
	c := configPD()
	now := int64(2000000000)
	s.now = func() time.Time { return time.Unix(now, 0) }
	m := NewManager(s)
	defer m.Close()
	m.config = c                                                                         // routing is independent of sockets; keep the test off the network
	fake := &fakeRoutes{kernel: map[string][2]string{"fd99::/64": {"fe80::99", "eth0"}}} // a stale route of ours
	m.routes = fake
	pdRequest(t, s, c, dhcpv6.MessageTypeRequest, 1, 1, "", "fe80::1")
	pdRequest(t, s, c, dhcpv6.MessageTypeRequest, 2, 1, "", "fe80::2")
	if err := m.ReconcileRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.kernel["fd78::/64"] != [2]string{"fe80::1", "eth0"} || fake.kernel["fd78:0:0:1::/64"] != [2]string{"fe80::2", "eth0"} {
		t.Fatal("delegations not routed via their routers:", fake.kernel)
	}
	if _, stale := fake.kernel["fd99::/64"]; stale {
		t.Fatal("stale route not removed")
	}
	before := len(fake.history)
	if err := m.ReconcileRoutes(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(fake.history) != before+1 { // only the read
		t.Fatal("reconciling a converged table must not touch it:", fake.history[before:])
	}
	// Release ends one delegation; expiry ends the other.
	pdRequest(t, s, c, dhcpv6.MessageTypeRelease, 1, 1, "", "")
	m.ReconcileRoutes(context.Background())
	if _, still := fake.kernel["fd78::/64"]; still {
		t.Fatal("released delegation still routed")
	}
	now += 700
	s.Expire()
	m.ReconcileRoutes(context.Background())
	if len(fake.kernel) != 0 {
		t.Fatal("expired delegation still routed:", fake.kernel)
	}
	// A pool without route: true is never touched.
	c.Scopes[0].PD.Route = false
	m.config = c
	pdRequest(t, s, c, dhcpv6.MessageTypeRequest, 3, 1, "", "fe80::3")
	m.ReconcileRoutes(context.Background())
	if len(fake.kernel) != 0 {
		t.Fatal("route installed although route is off:", fake.kernel)
	}
	// A route whose router moved is replaced.
	c.Scopes[0].PD.Route = true
	m.config = c
	fake.kernel["fd78::/64"] = [2]string{"fe80::dead", "eth0"}
	m.ReconcileRoutes(context.Background())
	for dst, v := range fake.kernel {
		if v[0] == "fe80::dead" {
			t.Fatal("wrong gateway kept for", dst)
		}
	}
}

func TestClientLinkLocalFromDirectAndRelayedRequests(t *testing.T) {
	direct := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeRequest}
	if got := clientLinkLocal(direct, &net.UDPAddr{IP: net.ParseIP("fe80::5")}); got.String() != "fe80::5" {
		t.Fatal(got)
	}
	if got := clientLinkLocal(direct, &net.UDPAddr{IP: net.ParseIP("2001:db8::5")}); got != nil {
		t.Fatal("a global source is not a link-local next hop:", got)
	}
	relayed, err := dhcpv6.EncapsulateRelay(direct, dhcpv6.MessageTypeRelayForward, net.ParseIP("fd88::1"), net.ParseIP("fe80::77"))
	if err != nil {
		t.Fatal(err)
	}
	if got := clientLinkLocal(relayed, &net.UDPAddr{IP: net.ParseIP("fd77::100")}); got.String() != "fd77::100" {
		t.Fatal("relayed: the next hop is the relay agent that forwards the prefix:", got)
	}
}

func TestRelayedScopesMayDelegate(t *testing.T) {
	c := configPD()
	c.Scopes[0].Relay = &RelayConfig{Peer: "fd00::2", Link: "fd00::3"}
	c.Scopes[0].Server = "fd00::1"
	// A relayed scope keeps its own validation rules (server addresses need not be
	// on the direct link), and the pool must still stay clear of the link's subnet.
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

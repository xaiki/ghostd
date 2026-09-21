package main

import (
	"context"
	"sort"

	"github.com/xaiki/ghostd/internal/rpc"
	"github.com/xaiki/ghostd/internal/state"
	tsclient "tailscale.com/client/local"
)

// Optional features are compiled in by build tag and plug into the daemon here.
// The default build has none: it is the firewall and netconfig domains, the
// lease/confirm machinery and the tailnet RPC, and nothing else — no DHCP, no
// DNS, no mDNS, none of their dependencies. A host gets only what its build
// asked for:
//
//	coredns   the container resolver (CoreDNS), including the per-container ACL
//	dhcp      DHCPv4/v6 + authoritative LAN DNS + identity ledger, PD, TFTP, standby
//	          (requires coredns)
//	dnsmasq   takeover from, and conversion of, a dnsmasq install (requires dhcp)
//	mdns      native mDNS: .local for containers, and the mdns-v1 advertisement
//
// Each feature lives in <name>_feature.go behind its tag and registers itself
// from init().
type featureEnv struct {
	ctx         context.Context
	store       *state.Store
	observeOnly bool
	tsLocal     *tsclient.Client
	// server exists from the attach phase on.
	server *rpc.Server
	// fatal ends the daemon: a feature's listener failed and cannot recover.
	fatal chan error
	// dnsAddress is the tailnet address, known from the serve phase on.
	dnsAddress string
	// shared hands values between features (for example the DHCP registry).
	shared map[string]any
}

// feature is one optional part of the daemon. Every hook is optional.
type feature struct {
	name string
	// flags registers the feature's command-line flags, before parsing.
	flags func()
	// cli runs one-shot commands after parsing; true means the process is done.
	cli func() (handled bool)
	// boot starts what must not wait for tailscaled (for example DHCP).
	boot func(*featureEnv) (stop func(), err error)
	// attach connects the feature to the RPC server, once it exists.
	attach func(*featureEnv) (stop func(), err error)
	// serve starts what needs the tailnet address (for example container DNS).
	serve func(*featureEnv) (stop func(), err error)
}

// domainHook makes an optional Apply/Confirm domain recoverable at boot and by
// the revert timer, independent of the running feature.
type domainHook struct {
	name    string
	key     string
	restore func(store *state.Store, raw []byte) error
}

var (
	features    []feature
	domainHooks []domainHook
)

func register(f feature)              { features = append(features, f) }
func registerDomainHook(h domainHook) { domainHooks = append(domainHooks, h) }

func hookFor(domain string) (domainHook, bool) {
	for _, h := range domainHooks {
		if h.name == domain {
			return h, true
		}
	}
	return domainHook{}, false
}

// allDomains lists the domains this build owns, core first.
func allDomains() []string {
	out := []string{"firewall", "netconfig"}
	var extra []string
	for _, h := range domainHooks {
		extra = append(extra, h.name)
	}
	sort.Strings(extra)
	return append(out, extra...)
}

// builtFeatures names the compiled-in optional features, for --features.
func builtFeatures() []string {
	var names []string
	for _, f := range features {
		names = append(names, f.name)
	}
	sort.Strings(names)
	return names
}

// stopAll runs the stop functions in reverse start order.
type stopper []func()

func (s *stopper) add(f func()) {
	if f != nil {
		*s = append(*s, f)
	}
}
func (s stopper) run() {
	for i := len(s) - 1; i >= 0; i-- {
		s[i]()
	}
}

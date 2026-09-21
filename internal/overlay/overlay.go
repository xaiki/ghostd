// Package overlay is ghostd's seam to the private network it authenticates
// callers over and binds its listeners to. Everything ghostd needs from the
// network — the one address to listen on, who a remote address is, and (for
// features that want it) which other nodes exist — sits behind Provider, so the
// control plane can be swapped: Tailscale, Headscale, or another overlay, chosen
// at build time by tag and at run time by --overlay. The RPC layer, the
// authorizer and the DHCP/DNS features never see a provider's own types.
package overlay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Caller is what a provider can prove about the node behind a remote address.
type Caller struct {
	// Login is the human or service account that owns the node.
	Login string
	// NodeID is a stable identifier for the node (not its address).
	NodeID  string
	DNSName string
	// Tags are the node's ACL tags, for example "tag:stack-deployer".
	Tags      []string
	Addresses []string
	// Capabilities are application capabilities granted to the caller for this
	// destination by the network's policy, by name. A control plane with no such
	// grants (Headscale) leaves it empty; a provider must never fabricate entries.
	Capabilities map[string][]json.RawMessage
}

// Peer is another node on the overlay, as the local node's client sees it.
type Peer struct {
	ID        string
	DNSName   string
	HostName  string
	Addresses []string
	// Endpoints are the "ip:port" paths the client knows for the peer, direct
	// LAN paths included.
	Endpoints []string
	Online    bool
}

// ErrUnsupported is returned by an optional operation a provider lacks.
var ErrUnsupported = errors.New("overlay: not supported by this provider")

// Provider is one overlay network integration.
type Provider interface {
	// Name is the provider's registered name.
	Name() string
	// ListenAddress returns "host:port" on the overlay's own address. ghostd binds
	// its RPC listener and container DNS there and never to a wildcard or a LAN
	// address, so reaching the socket already means being on the overlay.
	ListenAddress(ctx context.Context, port int) (string, error)
	// Whois resolves the remote address of a connection (host:port) to a Caller.
	// An error means the address is not a recognised overlay node.
	Whois(ctx context.Context, remoteAddr string) (*Caller, error)
	// Peers lists the other nodes, or ErrUnsupported.
	Peers(ctx context.Context) ([]Peer, error)
}

// Options are the run-time settings every provider may honour.
type Options struct {
	// Socket overrides where the local client daemon's API socket is.
	Socket string
}

// Factory builds a provider.
type Factory func(Options) (Provider, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register adds a provider; providers call it from init() behind their build tag.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	factories[name] = f
}

// Names lists the providers built into this binary.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(factories))
	for n := range factories {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// New builds the named provider. An empty name picks the only one built in, or
// tailscale when several are.
func New(name string, o Options) (Provider, error) {
	mu.RLock()
	defer mu.RUnlock()
	if len(factories) == 0 {
		return nil, fmt.Errorf("overlay: no provider is built into this binary (build with -tags tailscale or -tags headscale)")
	}
	if name == "" {
		if len(factories) == 1 {
			for n := range factories {
				name = n
			}
		} else {
			name = "tailscale"
		}
	}
	f, ok := factories[name]
	if !ok {
		return nil, fmt.Errorf("overlay: %q is not built into this binary (have %v)", name, namesLocked())
	}
	return f(o)
}

func namesLocked() []string {
	out := make([]string, 0, len(factories))
	for n := range factories {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// CapMap is a set of application capabilities by name.
type CapMap = map[string][]json.RawMessage

// Caps builds a CapMap with one capability whose values are the given JSON
// documents; it exists for tests and fakes.
func Caps(name string, values ...string) CapMap {
	m := CapMap{}
	for _, v := range values {
		m[name] = append(m[name], json.RawMessage(v))
	}
	return m
}

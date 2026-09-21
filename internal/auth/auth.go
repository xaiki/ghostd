// Package auth resolves and authorizes every RPC caller through the overlay
// provider (the host's own tailscaled, or another)  — never through which Unix user is making the call. This is
// the whole reason ghostd exists instead of another firewalld-shaped polkit
// grant; see docs/security.md.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xaiki/ghostd/internal/overlay"
)

// Resolver is the one thing this package needs from the overlay provider
// (internal/overlay): who a remote address is. A test can fake it without any
// overlay daemon.
type Resolver interface {
	Whois(ctx context.Context, remoteAddr string) (*overlay.Caller, error)
}

// Capability names granted by the overlay's policy engine, when it has one.
const (
	DeployCapability = "ghostd.local/cap/deploy"
	ReportCapability = "ghostd.local/cap/report"
)

// Identity is the caller identity and permissions proved by the overlay provider.
type Identity struct {
	Login     string
	Tags      []string
	CanDeploy bool
	CanReport bool
	NodeID    string
	DNSName   string
	Addresses []string
}

func (id Identity) HasTag(tag string) bool {
	for _, t := range id.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

var ErrNotOnOverlay = errors.New("auth: caller is not a recognized overlay node")

// Authenticator resolves a remote address to an Identity via WhoIs, and
// authorizes mutations using a destination-scoped capability or node tag.
// Reachability itself is the first gate: the RPC listener only ever binds the tailscale interface
// (cmd/ghostd/main.go), so a caller reaching this code already dialed in over
// the tailnet — WhoIs is what turns "reached the socket" into "is this
// identity", the gate that replaces Unix login.
type Authenticator struct {
	client      Resolver
	deployerTag string
	// deployerUsers may deploy by login, for control planes without application
	// capabilities (Headscale) where a node tag is too coarse for a workstation.
	deployerUsers map[string]bool
}

func NewAuthenticator(client Resolver, deployerTag string) *Authenticator {
	return &Authenticator{client: client, deployerTag: deployerTag}
}

// WithDeployerUsers additionally authorizes callers whose owning login is listed.
func (a *Authenticator) WithDeployerUsers(logins ...string) *Authenticator {
	if a.deployerUsers == nil {
		a.deployerUsers = map[string]bool{}
	}
	for _, l := range logins {
		if l != "" {
			a.deployerUsers[l] = true
		}
	}
	return a
}

// Identify resolves remoteAddr (host:port, as gRPC's peer info gives it) to
// the tailnet identity behind it.
func (a *Authenticator) Identify(ctx context.Context, remoteAddr string) (Identity, error) {
	caller, err := a.client.Whois(ctx, remoteAddr)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrNotOnOverlay, err)
	}
	if caller == nil {
		return Identity{}, fmt.Errorf("%w: no node answered", ErrNotOnOverlay)
	}
	identity := Identity{Login: caller.Login, Tags: caller.Tags, NodeID: caller.NodeID, DNSName: caller.DNSName, Addresses: caller.Addresses}
	for _, raw := range caller.Capabilities[DeployCapability] {
		var permission struct {
			Deploy bool `json:"deploy"`
		}
		if err := json.Unmarshal(raw, &permission); err == nil && permission.Deploy {
			identity.CanDeploy = true
		}
	}
	for _, raw := range caller.Capabilities[ReportCapability] {
		var permission struct {
			Report bool `json:"report"`
		}
		if json.Unmarshal(raw, &permission) == nil && permission.Report {
			identity.CanReport = true
		}
	}
	return identity, nil
}

func (a *Authenticator) AuthorizeReporter(ctx context.Context, remoteAddr string) (Identity, error) {
	id, err := a.Identify(ctx, remoteAddr)
	if err != nil {
		return Identity{}, err
	}
	if id.NodeID == "" || (!id.CanReport && !id.CanDeploy && !id.HasTag(a.deployerTag)) {
		return Identity{}, fmt.Errorf("auth: host report requires a stable node ID and report capability")
	}
	return id, nil
}

// AuthorizeDeployer accepts an explicit deploy capability from local tailscaled,
// the configured node tag for dedicated automation, or a listed login. User-owned workstations
// need no identity changes. GetState requires only Identify.
func (a *Authenticator) AuthorizeDeployer(ctx context.Context, remoteAddr string) (Identity, error) {
	id, err := a.Identify(ctx, remoteAddr)
	if err != nil {
		return Identity{}, err
	}
	if !id.CanDeploy && !id.HasTag(a.deployerTag) && !a.deployerUsers[id.Login] {
		return Identity{}, fmt.Errorf("auth: %s lacks ghostd deploy capability, tag %s and a deployer login; mutating calls refused",
			id.Login, a.deployerTag)
	}
	return id, nil
}

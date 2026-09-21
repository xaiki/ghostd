// Package auth resolves and authorizes every RPC caller through the host's
// own tailscaled — never through which Unix user is making the call. See
// FIREWALL.md: this is the whole reason ghostd exists instead of another
// firewalld-shaped polkit grant.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

// WhoIs is the one thing this package needs from tailscaled — narrowed from
// *tailscale.LocalClient so a test can fake it without a running tailscaled.
type WhoIs interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// DeployCapability is destination-scoped by the tailnet policy engine.
const DeployCapability tailcfg.PeerCapability = "ghostd.local/cap/deploy"

// Identity is the caller identity and permissions proved by local tailscaled.
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

var ErrNotOnTailnet = errors.New("auth: caller is not a recognized tailnet peer")

// Authenticator resolves a remote address to an Identity via WhoIs, and
// authorizes mutations using a destination-scoped capability or node tag.
// Reachability itself is the first gate: the RPC listener only ever binds the tailscale interface
// (cmd/ghostd/main.go), so a caller reaching this code already dialed in over
// the tailnet — WhoIs is what turns "reached the socket" into "is this
// identity", the gate FIREWALL.md means by "never Unix login".
type Authenticator struct {
	client      WhoIs
	deployerTag string
}

func NewAuthenticator(client WhoIs, deployerTag string) *Authenticator {
	return &Authenticator{client: client, deployerTag: deployerTag}
}

// Identify resolves remoteAddr (host:port, as gRPC's peer info gives it) to
// the tailnet identity behind it.
func (a *Authenticator) Identify(ctx context.Context, remoteAddr string) (Identity, error) {
	resp, err := a.client.WhoIs(ctx, remoteAddr)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrNotOnTailnet, err)
	}
	if resp == nil || resp.Node == nil {
		return Identity{}, fmt.Errorf("%w: WhoIs answered no node", ErrNotOnTailnet)
	}
	login := ""
	if resp.UserProfile != nil {
		login = resp.UserProfile.LoginName
	}
	canDeploy := false
	for _, raw := range resp.CapMap[DeployCapability] {
		var permission struct {
			Deploy bool `json:"deploy"`
		}
		if err := json.Unmarshal([]byte(raw), &permission); err == nil && permission.Deploy {
			canDeploy = true
		}
	}
	identity := Identity{Login: login, Tags: resp.Node.Tags, CanDeploy: canDeploy,
		NodeID: string(resp.Node.StableID), DNSName: resp.Node.Name}
	for _, address := range resp.Node.Addresses {
		if address.IsSingleIP() {
			identity.Addresses = append(identity.Addresses, address.Addr().String())
		}
	}
	for _, raw := range resp.CapMap[tailcfg.PeerCapability("ghostd.local/cap/report")] {
		var permission struct {
			Report bool `json:"report"`
		}
		if json.Unmarshal([]byte(raw), &permission) == nil && permission.Report {
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
// or the configured node tag for dedicated automation. User-owned workstations
// need no identity changes. GetState requires only Identify.
func (a *Authenticator) AuthorizeDeployer(ctx context.Context, remoteAddr string) (Identity, error) {
	id, err := a.Identify(ctx, remoteAddr)
	if err != nil {
		return Identity{}, err
	}
	if !id.CanDeploy && !id.HasTag(a.deployerTag) {
		return Identity{}, fmt.Errorf("auth: %s lacks ghostd deploy capability and tag %s; mutating calls refused",
			id.Login, a.deployerTag)
	}
	return id, nil
}

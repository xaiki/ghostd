// Package auth resolves and authorizes every RPC caller through the host's
// own tailscaled — never through which Unix user is making the call. See
// FIREWALL.md: this is the whole reason ghostd exists instead of another
// firewalld-shaped polkit grant.
package auth

import (
	"context"
	"errors"
	"fmt"

	"tailscale.com/client/tailscale/apitype"
)

// WhoIs is the one thing this package needs from tailscaled — narrowed from
// *tailscale.LocalClient so a test can fake it without a running tailscaled.
type WhoIs interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// Identity is what one caller's WhoIs answer proved: a real tailnet login,
// cryptographically backed by WireGuard and the tailnet control plane — not
// "whichever Unix uid opened the socket".
type Identity struct {
	Login string
	Tags  []string
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
// authorizes mutating calls against one ACL tag. Reachability itself is the
// first gate: the RPC listener only ever binds the tailscale interface
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
	if resp.Node == nil {
		return Identity{}, fmt.Errorf("%w: WhoIs answered no node", ErrNotOnTailnet)
	}
	login := ""
	if resp.UserProfile != nil {
		login = resp.UserProfile.LoginName
	}
	return Identity{Login: login, Tags: resp.Node.Tags}, nil
}

// AuthorizeDeployer is the gate on every mutating RPC (Apply, Confirm):
// only the identity carrying the configured ACL tag — reusing
// machines/tailscale_policy.py's tag-owner machinery on the Python side,
// not a credential store this daemon invents itself — may call them.
// GetState carries no such requirement (use Identify alone): any tailnet
// member may read state.
func (a *Authenticator) AuthorizeDeployer(ctx context.Context, remoteAddr string) (Identity, error) {
	id, err := a.Identify(ctx, remoteAddr)
	if err != nil {
		return Identity{}, err
	}
	if !id.HasTag(a.deployerTag) {
		return Identity{}, fmt.Errorf("auth: %s is not tagged %s; mutating calls refused",
			id.Login, a.deployerTag)
	}
	return id, nil
}

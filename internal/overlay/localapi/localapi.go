//go:build tailscale || headscale

// Package localapi is the client for a tailscaled-compatible local daemon's API.
// Tailscale and Headscale differ in their control plane, not in the client node:
// a Headscale-managed host still runs tailscaled, so both providers speak this
// same local API and differ only in what they trust it to say.
package localapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	tsclient "tailscale.com/client/local"

	"github.com/xaiki/ghostd/internal/overlay"
)

// Client is a tailscaled local-API client.
type Client struct {
	c *tsclient.Client
	// TrustCapabilities says whether the control plane can grant application
	// capabilities. Headscale cannot, so it drops whatever the client reports.
	TrustCapabilities bool
	ProviderName      string
}

func New(name string, o overlay.Options, trustCaps bool) *Client {
	c := &tsclient.Client{}
	if o.Socket != "" {
		c.Socket = o.Socket
		c.UseSocketOnly = true
	}
	return &Client{c: c, TrustCapabilities: trustCaps, ProviderName: name}
}

func (c *Client) Name() string { return c.ProviderName }

// ListenAddress is this node's first overlay address: never 0.0.0.0, never a
// LAN or management interface. Binding a specific address, rather than trusting
// firewall policy to keep other traffic out, is the primary control.
func (c *Client) ListenAddress(ctx context.Context, port int) (string, error) {
	status, err := c.c.Status(ctx)
	if err != nil {
		return "", fmt.Errorf("%s: local client status: %w (is the client daemon running and joined?)", c.ProviderName, err)
	}
	if status.Self == nil || len(status.Self.TailscaleIPs) == 0 {
		return "", fmt.Errorf("%s: this host has no overlay address yet (not joined?)", c.ProviderName)
	}
	return net.JoinHostPort(status.Self.TailscaleIPs[0].String(), fmt.Sprintf("%d", port)), nil
}

func (c *Client) Whois(ctx context.Context, remoteAddr string) (*overlay.Caller, error) {
	resp, err := c.c.WhoIs(ctx, remoteAddr)
	if err != nil {
		return nil, err
	}
	if resp == nil || resp.Node == nil {
		return nil, fmt.Errorf("whois answered no node")
	}
	caller := &overlay.Caller{NodeID: string(resp.Node.StableID), DNSName: resp.Node.Name, Tags: resp.Node.Tags}
	if resp.UserProfile != nil {
		caller.Login = resp.UserProfile.LoginName
	}
	for _, a := range resp.Node.Addresses {
		if a.IsSingleIP() {
			caller.Addresses = append(caller.Addresses, a.Addr().String())
		}
	}
	if c.TrustCapabilities && len(resp.CapMap) > 0 {
		caller.Capabilities = map[string][]json.RawMessage{}
		for name, values := range resp.CapMap {
			for _, v := range values {
				caller.Capabilities[string(name)] = append(caller.Capabilities[string(name)], json.RawMessage(v))
			}
		}
	}
	return caller, nil
}

func (c *Client) Peers(ctx context.Context) ([]overlay.Peer, error) {
	status, err := c.c.Status(ctx)
	if err != nil {
		return nil, err
	}
	var peers []overlay.Peer
	for _, p := range status.Peer {
		peer := overlay.Peer{ID: string(p.ID), DNSName: p.DNSName, HostName: p.HostName, Online: p.Online,
			Endpoints: append([]string{p.CurAddr}, p.Addrs...)}
		for _, a := range p.TailscaleIPs {
			peer.Addresses = append(peer.Addresses, a.String())
		}
		peers = append(peers, peer)
	}
	return peers, nil
}

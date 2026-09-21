//go:build headscale

package localapi

import "github.com/xaiki/ghostd/internal/overlay"

// Headscale: a self-hosted Tailscale control server. Hosts still run tailscaled,
// so the local API is the same, but Headscale's policy has node tags and users
// and no application-capability grants. The provider therefore trusts no
// capabilities the client reports and authorizes by tag or user only.
func init() {
	overlay.Register("headscale", func(o overlay.Options) (overlay.Provider, error) { return New("headscale", o, false), nil })
}

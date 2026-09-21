//go:build tailscale

package localapi

import "github.com/xaiki/ghostd/internal/overlay"

// Tailscale: the local tailscaled's API, with application capabilities
// (ghostd.local/cap/*) granted by the tailnet policy trusted.
func init() {
	overlay.Register("tailscale", func(o overlay.Options) (overlay.Provider, error) { return New("tailscale", o, true), nil })
}

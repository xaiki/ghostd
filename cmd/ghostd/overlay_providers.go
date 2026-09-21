//go:build tailscale || headscale

package main

// The overlay providers built into this binary register themselves from init().
import _ "github.com/xaiki/ghostd/internal/overlay/localapi"

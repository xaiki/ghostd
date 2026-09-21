//go:build !dnsmasq

package rpc

// `!dnsmasq` rather than `!(dhcp && dnsmasq)`: dnsmasq without dhcp is a
// violation, not a configuration, so the stub must not be what lets it compile.
type dnsmasqState struct{}

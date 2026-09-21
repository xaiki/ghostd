//go:build dhcp

package addressbook

import "github.com/coredhcp/coredhcp/config"

// DHCPPlugins composes registered CoreDHCP plugins around ghostleases.
// Before plugins may reject requests; After plugins may decorate replies.
// Keep allocation in ghostleases: chaining a second allocator would violate
// durable ownership. Register extensions using CoreDHCP's RegisterPlugin API.
type DHCPPlugins struct {
	Before4, After4 []config.PluginConfig
	Before6, After6 []config.PluginConfig
}

// NewManagerWithPlugins freezes the plugin configuration for the manager's
// lifetime. Scope/lease configuration can still be applied independently.
func NewManagerWithPlugins(s *Store, p DHCPPlugins) *Manager {
	m := NewManager(s)
	m.plugins = DHCPPlugins{copyPlugins(p.Before4), copyPlugins(p.After4), copyPlugins(p.Before6), copyPlugins(p.After6)}
	return m
}

func copyPlugins(in []config.PluginConfig) []config.PluginConfig {
	out := append([]config.PluginConfig(nil), in...)
	for i := range out {
		out[i].Args = append([]string(nil), out[i].Args...)
	}
	return out
}

func (p DHCPPlugins) chain(family, token string) []config.PluginConfig {
	before, after := p.Before4, p.After4
	if family == "6" {
		before, after = p.Before6, p.After6
	}
	chain := copyPlugins(before)
	chain = append(chain, config.PluginConfig{Name: "ghostleases", Args: []string{token}})
	return append(chain, copyPlugins(after)...)
}

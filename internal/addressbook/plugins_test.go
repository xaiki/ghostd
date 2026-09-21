package addressbook

import (
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
)

func TestCoreDHCPPluginComposition(t *testing.T) {
	for _, family := range []string{"4", "6"} {
		t.Run(family, func(t *testing.T) {
			m := NewManager(openTest(t))
			m.config = testConfig()
			if family == "6" {
				m.config.Scopes = []Scope{{ID: "lan6", Interface: "eth0", Subnet: "fd00::/64", Server: "fd00::1", Start: "fd00::6", End: "fd00::8", Zone: "home.arpa", LeaseSeconds: 600, PreferredSeconds: 300, Enabled: true}}
			}
			token := fmt.Sprint(instanceID.Add(1))
			instances.Store(token, pluginInstance{m, family + "/eth0"})
			defer instances.Delete(token)
			var calls []string
			register := func(stage string) config.PluginConfig {
				name := "test" + stage + token
				err := plugins.RegisterPlugin(&plugins.Plugin{Name: name,
					Setup4: func(...string) (handler.Handler4, error) {
						return func(r, reply *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
							calls = append(calls, stage)
							if stage == "after" && (reply == nil || reply.MessageType() != dhcpv4.MessageTypeOffer) {
								t.Error("post plugin did not receive lease reply")
							}
							return reply, false
						}, nil
					},
					Setup6: func(...string) (handler.Handler6, error) {
						return func(r, reply dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
							calls = append(calls, stage)
							if stage == "after" && (reply == nil || reply.Type() != dhcpv6.MessageTypeReply) {
								t.Error("post plugin did not receive lease reply")
							}
							return reply, false
						}, nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				return config.PluginConfig{Name: name}
			}
			before, after := register("before"), register("after")
			p := DHCPPlugins{Before4: []config.PluginConfig{before}, After4: []config.PluginConfig{after}, Before6: []config.PluginConfig{before}, After6: []config.PluginConfig{after}}
			cfg := &config.Config{}
			sc := &config.ServerConfig{Plugins: p.chain(family, token)}
			if family == "4" {
				cfg.Server4 = sc
			} else {
				cfg.Server6 = sc
			}
			h4, h6, err := plugins.LoadPlugins(cfg)
			if err != nil {
				t.Fatal(err)
			}
			run := func(valid bool) {
				calls = nil
				if family == "4" {
					mac, _ := net.ParseMAC("00:11:22:33:44:55")
					req, err := dhcpv4.NewDiscovery(mac)
					if err != nil {
						t.Fatal(err)
					}
					if !valid {
						req.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("10.0.0.99")))
					}
					var reply *dhcpv4.DHCPv4
					for _, h := range h4 {
						var stop bool
						reply, stop = h(req, reply)
						if stop {
							break
						}
					}
				} else {
					req := &dhcpv6.Message{MessageType: dhcpv6.MessageTypeInformationRequest}
					if !valid {
						req.MessageType = dhcpv6.MessageTypeRequest
					} // missing client/server IDs
					var reply dhcpv6.DHCPv6
					for _, h := range h6 {
						var stop bool
						reply, stop = h(req, reply)
						if stop {
							break
						}
					}
				}
				want := []string{"before"}
				if valid {
					want = append(want, "after")
				}
				if !reflect.DeepEqual(calls, want) {
					t.Fatalf("calls %v, want %v", calls, want)
				}
			}
			run(true)
			run(false)
		})
	}
}

func TestPluginConfigurationFrozen(t *testing.T) {
	p := DHCPPlugins{After4: []config.PluginConfig{{Name: "example", Args: []string{"original"}}}}
	m := NewManagerWithPlugins(openTest(t), p)
	p.After4[0].Name = "changed"
	p.After4[0].Args[0] = "changed"
	chain := m.plugins.chain("4", "registry")
	if chain[1].Name != "example" || chain[1].Args[0] != "original" {
		t.Fatal(chain)
	}
	chain[1].Args[0] = "changed again"
	if m.plugins.After4[0].Args[0] != "original" {
		t.Fatal("chain aliases configuration")
	}
}

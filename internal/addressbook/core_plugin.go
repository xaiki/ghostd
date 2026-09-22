//go:build dhcp

package addressbook

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coredhcp/coredhcp/config"
	"github.com/coredhcp/coredhcp/handler"
	"github.com/coredhcp/coredhcp/plugins"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	core "github.com/xaiki/ghostd/internal/coredhcpserver"
	"github.com/xaiki/ghostd/internal/wellknown"
)

type pluginInstance struct {
	manager *Manager
	key     string
}

var instances sync.Map
var instanceID atomic.Uint64

func init() {
	err := plugins.RegisterPlugin(&plugins.Plugin{Name: "ghostleases", Setup4: func(args ...string) (handler.Handler4, error) {
		instance, e := loadInstance(args)
		if e != nil {
			return nil, e
		}
		return func(r, _ *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, bool) {
			m := instance.manager
			for _, s := range m.config.Scopes {
				if s.Enabled && s.socketKey() == instance.key && ((s.Relay == nil && r.GatewayIPAddr.IsUnspecified()) || (s.Relay != nil && r.GatewayIPAddr.Equal(net.ParseIP(s.Relay.Link)))) {
					reply, e := m.Store.Handle4(m.config, s, r)
					if e != nil {
						log.Printf("ghostleases %s: %v", s.ID, e)
						return nil, true
					}
					if reply != nil {
						reply.ServerIPAddr = net.ParseIP(s.Server)
					}
					return reply, reply == nil
				}
			}
			return nil, true
		}, nil
	}, Setup6: func(args ...string) (handler.Handler6, error) {
		instance, e := loadInstance(args)
		if e != nil {
			return nil, e
		}
		return func(r, _ dhcpv6.DHCPv6) (dhcpv6.DHCPv6, bool) {
			m := instance.manager
			for _, s := range m.config.Scopes {
				if !s.Enabled || s.socketKey() != instance.key {
					continue
				}
				link := relayLink(r)
				if (s.Relay == nil && !r.IsRelay()) || (s.Relay != nil && link.Equal(net.ParseIP(s.Relay.Link))) {
					var via net.IP
					if peer, ok := core.PeerOf(r); ok {
						via = clientLinkLocal(r, peer)
					}
					reply, e := m.Store.Handle6Via(m.config, s, r, via)
					if e != nil {
						log.Printf("ghostleases %s: %v", s.ID, e)
						return nil, true
					}
					if reply != nil && s.PD != nil && s.PD.Route {
						// Route the delegation now, not at the next periodic pass.
						go func() {
							if err := m.ReconcileRoutes(context.Background()); err != nil {
								log.Printf("ghostleases %s: delegated routes: %v", s.ID, err)
							}
						}()
					}
					return reply, reply == nil
				}
			}
			return nil, true
		}, nil
	}})
	if err != nil {
		panic(err)
	}
}
func loadInstance(args []string) (pluginInstance, error) {
	if len(args) != 1 {
		return pluginInstance{}, fmt.Errorf("ghostleases requires one registry instance")
	}
	v, ok := instances.Load(args[0])
	if !ok {
		return pluginInstance{}, fmt.Errorf("unknown ghostleases registry")
	}
	return v.(pluginInstance), nil
}

// clientLinkLocal is the next hop a delegation is routed to. For a direct request
// it is the requester's own link-local address, straight from the transport. For a
// relayed one the requester is on another link, so the next hop is the relay
// agent itself (the transport peer): it forwards the delegated prefix onward, as
// DHCPv6 relay deployments expect.
func clientLinkLocal(r dhcpv6.DHCPv6, peer *net.UDPAddr) net.IP {
	if peer == nil {
		return nil
	}
	if r.IsRelay() {
		if peer.IP.IsUnspecified() || peer.IP.IsMulticast() {
			return nil
		}
		return peer.IP
	}
	if peer.IP.IsLinkLocalUnicast() {
		return peer.IP
	}
	return nil
}
func relayLink(r dhcpv6.DHCPv6) net.IP {
	for n := 0; r.IsRelay() && n < 32; n++ {
		relay, ok := r.(*dhcpv6.RelayMessage)
		if !ok {
			return nil
		}
		r = relay.Options.RelayMessage()
		if r == nil {
			return nil
		}
		if !r.IsRelay() {
			return relay.LinkAddr
		}
	}
	return nil
}
func (m *Manager) startCore(key string, conn net.PacketConn) (*core.Servers, error) {
	token := fmt.Sprint(instanceID.Add(1))
	instances.Store(token, pluginInstance{m, key})
	defer instances.Delete(token)
	family, iface, _ := strings.Cut(key, "/")
	sc := &config.ServerConfig{Plugins: m.plugins.chain(family, token)}
	c := &config.Config{}
	options := core.Options{}
	if family == "4" {
		sc.Addresses = []net.UDPAddr{{IP: net.IPv4zero, Port: wellknown.PortDHCPv4Server, Zone: iface}}
		c.Server4 = sc
		options.Conn4 = conn
		options.Guard4 = func(r *dhcpv4.DHCPv4, peer net.Addr) func() {
			m.mu.RLock()
			for _, s := range m.config.Scopes {
				if s.Enabled && s.socketKey() == key && matches4(s, r, peer) {
					return m.mu.RUnlock
				}
			}
			m.mu.RUnlock()
			return nil
		}
	} else {
		sc.Addresses = []net.UDPAddr{{IP: net.IPv6unspecified, Port: wellknown.PortDHCPv6Server, Zone: iface}}
		c.Server6 = sc
		options.Conn6 = conn
		options.Guard6 = func(r dhcpv6.DHCPv6, peer net.Addr) func() {
			m.mu.RLock()
			for _, s := range m.config.Scopes {
				if s.Enabled && s.socketKey() == key && matches6(s, r, peer) {
					return m.mu.RUnlock
				}
			}
			m.mu.RUnlock()
			return nil
		}
	}
	return core.Start(c, options)
}

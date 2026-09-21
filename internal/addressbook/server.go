package addressbook

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/coredns/coredns/plugin"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/miekg/dns"
	core "github.com/xaiki/ghostd/internal/coredhcpserver"
)

type Manager struct {
	Store   *Store
	Errors  chan error
	Forward plugin.Handler
	mu      sync.RWMutex
	config  Config
	plugins DHCPPlugins
	dhcp    map[string]*core.Servers
	dns     map[string]*dnsPair
	ra      map[string]*raListener
}
type dnsPair struct {
	udp, tcp *dns.Server
	ready    chan struct{}
	done     sync.WaitGroup
}

func NewManager(s *Store) *Manager {
	return &Manager{Store: s, Errors: make(chan error, 1), dhcp: map[string]*core.Servers{}, dns: map[string]*dnsPair{}, ra: map[string]*raListener{}}
}
func (m *Manager) Config() Config { m.mu.RLock(); defer m.mu.RUnlock(); return cloneConfig(m.config) }
func (p *dnsPair) close()         { p.udp.PacketConn.Close(); p.tcp.Listener.Close() }
func (m *Manager) Close() {
	m.mu.Lock()
	sockets, dnses, ras := m.dhcp, m.dns, m.ra
	m.dhcp = map[string]*core.Servers{}
	m.dns = map[string]*dnsPair{}
	m.ra = map[string]*raListener{}
	m.config = Config{}
	m.mu.Unlock()
	for _, s := range sockets {
		s.Close()
	}
	for _, s := range dnses {
		s.close()
		s.done.Wait()
	}
	for _, r := range ras {
		r.Close()
	}
}
func (m *Manager) Apply(c Config, save func() error) error {
	c = cloneConfig(c)
	if e := c.Validate(); e != nil {
		return e
	}
	m.mu.Lock()
	var retiredRA []*raListener
	defer func() {
		m.mu.Unlock()
		for _, r := range retiredRA {
			r.Close()
		}
	}()
	snapshot, e := m.Store.Snapshot("", "", 0)
	if e != nil {
		return e
	}
	for _, b := range snapshot.Bindings {
		if b.State != "active" && b.State != "offered" && b.State != "declined" {
			continue
		}
		for _, s := range c.Scopes {
			if s.ID != b.Scope && netip.MustParsePrefix(s.Subnet).Contains(netip.MustParseAddr(b.Address)) {
				return fmt.Errorf("scope %s overlaps outstanding binding in %s; retain original scope ID", s.ID, b.Scope)
			}
		}
	}
	added := map[string]*core.Servers{}
	addedDNS := map[string]*dnsPair{}
	addedRA := map[string]*raListener{}
	cleanup := func() {
		for _, s := range added {
			s.Close()
		}
		for _, s := range addedDNS {
			s.close()
		}
		for _, r := range addedRA {
			r.abort()
		}
	}
	wanted, wantDNS, wantRA := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, scope := range c.Scopes {
		if !scope.Enabled {
			continue
		}
		if e := ownsAddress(scope.Interface, scope.Server); e != nil {
			cleanup()
			return e
		}
		key := scope.socketKey()
		wanted[key] = true
		wantDNS[scope.Server] = true
		if _, ok := m.dhcp[key]; !ok && added[key] == nil {
			var conn net.PacketConn
			var err error
			if scope.Is6() {
				conn, err = listenDHCP6(scope.Interface)
			} else {
				conn, err = listenDHCP(scope.Interface)
			}
			if err != nil {
				cleanup()
				return fmt.Errorf("DHCP bind %s (stop previous authority first): %w", key, err)
			}
			srv, err := m.startCore(key, conn)
			if err != nil {
				conn.Close()
				cleanup()
				return err
			}
			added[key] = srv
		}
		if m.dns[scope.Server] == nil && addedDNS[scope.Server] == nil {
			udp, e := net.ListenPacket("udp", net.JoinHostPort(scope.Server, "53"))
			if e != nil {
				cleanup()
				return e
			}
			tcp, e := net.Listen("tcp", net.JoinHostPort(scope.Server, "53"))
			if e != nil {
				udp.Close()
				cleanup()
				return e
			}
			handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				code, e := (&DNS{Store: m.Store, Config: m.Config, Next: m.Forward}).ServeDNS(context.Background(), w, r)
				if code != 0 || e != nil {
					reply := new(dns.Msg)
					if code == 0 {
						code = dns.RcodeServerFailure
					}
					reply.SetRcode(r, code)
					_ = w.WriteMsg(reply)
				}
			})
			addedDNS[scope.Server] = &dnsPair{udp: &dns.Server{PacketConn: udp, Handler: handler}, tcp: &dns.Server{Listener: tcp, Handler: handler}}
		}
		if scope.RA != nil {
			if old, ok := m.config.Scope(scope.ID); ok && m.ra[scope.ID] != nil && (old.Interface != scope.Interface || old.Subnet != scope.Subnet || old.Server != scope.Server) {
				cleanup()
				return fmt.Errorf("disable RA before moving its interface, prefix or DNS address")
			}

			wantRA[scope.ID] = true
			if m.ra[scope.ID] == nil {
				r, e := newRA(scope, func() Config { return m.Config() })
				if e != nil {
					cleanup()
					return e
				}
				addedRA[scope.ID] = r
			}
		}
	}
	if e := save(); e != nil {
		cleanup()
		return e
	}
	m.config = c
	for k, s := range m.dhcp {
		if !wanted[k] {
			s.Close()
			delete(m.dhcp, k)
		}
	}
	for k, s := range m.dns {
		if !wantDNS[k] {
			s.close()
			delete(m.dns, k)
		}
	}
	for k, r := range m.ra {
		if !wantRA[k] {
			retiredRA = append(retiredRA, r)
			delete(m.ra, k)
		}
	}
	for k, s := range added {
		m.dhcp[k] = s
		go func() { m.listenerExit(s.Wait()) }()
	}
	for k, s := range addedDNS {
		m.dns[k] = s
		s.done.Add(2)
		go func() { defer s.done.Done(); m.listenerExit(s.udp.ActivateAndServe()) }()
		go func() { defer s.done.Done(); m.listenerExit(s.tcp.ActivateAndServe()) }()
	}
	for k, r := range addedRA {
		m.ra[k] = r
		r.Start()
	}
	return nil
}
func matches4(s Scope, r *dhcpv4.DHCPv4, peer net.Addr) bool {
	if s.Is6() {
		return false
	}
	if s.Relay == nil {
		return r.GatewayIPAddr.IsUnspecified()
	}
	p, ok := peer.(*net.UDPAddr)
	return ok && p.Port == 67 && p.IP.Equal(net.ParseIP(s.Relay.Peer)) && r.GatewayIPAddr.Equal(net.ParseIP(s.Relay.Link)) && r.HopCount <= 16
}
func matches6(s Scope, r dhcpv6.DHCPv6, peer net.Addr) bool {
	if !s.Is6() {
		return false
	}
	if s.Relay == nil {
		return !r.IsRelay()
	}
	p, ok := peer.(*net.UDPAddr)
	if !ok || p.Port != 547 || !p.IP.Equal(net.ParseIP(s.Relay.Peer)) {
		return false
	}
	depth := 0
	for r.IsRelay() {
		relay, ok := r.(*dhcpv6.RelayMessage)
		if !ok || relay.MessageType != dhcpv6.MessageTypeRelayForward || relay.HopCount > 32 || depth >= 32 {
			return false
		}
		depth++
		inner := relay.Options.RelayMessage()
		if inner == nil {
			return false
		}
		if !inner.IsRelay() {
			return relay.LinkAddr.Equal(net.ParseIP(s.Relay.Link))
		}
		r = inner
	}
	return false
}
func (m *Manager) listenerExit(err error) {
	if err != nil && !errors.Is(err, net.ErrClosed) {
		select {
		case m.Errors <- err:
		default:
		}
	}
}

func ownsAddress(iface, address string) error {
	link, err := net.InterfaceByName(iface)
	if err != nil {
		return err
	}
	addresses, err := link.Addrs()
	if err != nil {
		return err
	}
	for _, a := range addresses {
		ip, _, err := net.ParseCIDR(a.String())
		if err == nil && ip.Equal(net.ParseIP(address)) {
			return nil
		}
	}
	return fmt.Errorf("%s does not own server address %s", iface, address)
}

var ErrUnavailable = errors.New("address unavailable")

func (s *Store) Handle4(c Config, scope Scope, r *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	if r.OpCode != dhcpv4.OpcodeBootRequest || len(r.ClientHWAddr) != 6 {
		return nil, nil
	}
	if scope.Relay == nil && !r.GatewayIPAddr.IsUnspecified() {
		return nil, nil
	}
	server := net.ParseIP(scope.Server)
	if id := r.ServerIdentifier(); id != nil && !id.Equal(server) {
		return nil, nil
	}
	client := "mac:" + r.ClientHWAddr.String()
	if id := r.Options.Get(dhcpv4.OptionClientIdentifier); len(id) > 0 {
		client = "id:" + hex.EncodeToString(id)
	}
	requested := ""
	if ip := r.RequestedIPAddress(); ip != nil {
		requested = ip.String()
	} else if !r.ClientIPAddr.Equal(net.IPv4zero) {
		requested = r.ClientIPAddr.String()
	}
	kind := r.MessageType()
	replyType := dhcpv4.MessageTypeOffer
	switch kind {
	case dhcpv4.MessageTypeDiscover, dhcpv4.MessageTypeRequest:
		if kind == dhcpv4.MessageTypeRequest {
			replyType = dhcpv4.MessageTypeAck
		}
		b, err := s.Allocate(c, scope.ID, client, r.ClientHWAddr.String(), r.HostName(), requested, kind == dhcpv4.MessageTypeRequest)
		if err != nil {
			if kind == dhcpv4.MessageTypeRequest && errors.Is(err, ErrUnavailable) {
				return dhcpv4.NewReplyFromRequest(r, dhcpv4.WithMessageType(dhcpv4.MessageTypeNak), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(server)))
			}
			return nil, err
		}
		_, network, _ := net.ParseCIDR(scope.Subnet)
		return dhcpv4.NewReplyFromRequest(r, dhcpv4.WithMessageType(replyType), dhcpv4.WithClientIP(r.ClientIPAddr), dhcpv4.WithYourIP(net.ParseIP(b.Address)), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(server)), dhcpv4.WithNetmask(network.Mask), dhcpv4.WithRouter(net.ParseIP(scope.Router)), dhcpv4.WithOption(dhcpv4.OptDNS(server)), dhcpv4.WithLeaseTime(uint32(scope.LeaseSeconds)), dhcpv4.WithDomainSearchList(scope.Zone))
	case dhcpv4.MessageTypeRelease, dhcpv4.MessageTypeDecline:
		return nil, s.Release(scope.ID, client, requested, kind == dhcpv4.MessageTypeDecline)
	case dhcpv4.MessageTypeInform:
		return dhcpv4.NewReplyFromRequest(r, dhcpv4.WithMessageType(dhcpv4.MessageTypeAck), dhcpv4.WithClientIP(r.ClientIPAddr), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(server)), dhcpv4.WithOption(dhcpv4.OptDNS(server)), dhcpv4.WithDomainSearchList(scope.Zone))
	}
	return nil, nil
}

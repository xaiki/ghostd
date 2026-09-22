//go:build dhcp

package addressbook

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/mdlayher/ndp"
	"golang.org/x/net/ipv6"

	"github.com/xaiki/ghostd/internal/wellknown"
)

type raListener struct {
	conn       *ndp.Conn
	scope      Scope
	config     func() Config
	stop, done chan struct{}
	once       sync.Once
}

func newRA(scope Scope, config func() Config) (*raListener, error) {
	if scope.RA.RouterLifetime > 0 {
		raw, e := os.ReadFile("/proc/sys/net/ipv6/conf/all/forwarding")
		if e != nil || len(raw) == 0 || raw[0] != '1' {
			return nil, fmt.Errorf("RA default-router advertising requires IPv6 forwarding enabled")
		}
	}
	iface, e := net.InterfaceByName(scope.Interface)
	if e != nil {
		return nil, e
	}
	conn, _, e := ndp.Listen(iface, ndp.LinkLocal)
	if e != nil {
		return nil, e
	}
	if e = conn.JoinGroup(netip.MustParseAddr(wellknown.AllRouters6)); e != nil {
		conn.Close()
		return nil, e
	}
	if e = conn.SetControlMessage(ipv6.FlagHopLimit, true); e != nil {
		conn.Close()
		return nil, e
	}
	return &raListener{conn: conn, scope: scope, config: config, stop: make(chan struct{}), done: make(chan struct{})}, nil
}
func (r *raListener) abort() { r.conn.Close() }
func (r *raListener) Close() { r.once.Do(func() { close(r.stop) }); <-r.done }
func (r *raListener) Start() { go r.run() }
func Advertisement(s Scope, withdraw bool) *ndp.RouterAdvertisement {
	lifetime := time.Duration(s.RA.RouterLifetime) * time.Second
	dnsLife := time.Duration(s.RA.Interval*3) * time.Second
	if withdraw {
		lifetime = 0
		dnsLife = 0
	}
	p := netip.MustParsePrefix(s.Subnet)
	return &ndp.RouterAdvertisement{CurrentHopLimit: 64, ManagedConfiguration: true, OtherConfiguration: true, RouterLifetime: lifetime, Options: []ndp.Option{
		&ndp.PrefixInformation{PrefixLength: uint8(p.Bits()), Prefix: p.Addr(), OnLink: true, AutonomousAddressConfiguration: s.RA.SLAAC, ValidLifetime: time.Duration(s.LeaseSeconds) * time.Second, PreferredLifetime: time.Duration(s.PreferredSeconds) * time.Second},
		&ndp.RecursiveDNSServer{Lifetime: dnsLife, Servers: []netip.Addr{netip.MustParseAddr(s.Server)}},
		&ndp.DNSSearchList{Lifetime: dnsLife, DomainNames: []string{s.Zone}},
	}}
}
func (r *raListener) run() {
	defer close(r.done)
	defer r.conn.Close()
	solicit := make(chan netip.Addr, 1)
	go func() {
		for {
			m, cm, peer, e := r.conn.ReadFrom()
			if e != nil {
				return
			}
			if _, ok := m.(*ndp.RouterSolicitation); !ok || cm == nil || cm.HopLimit != 255 || (!peer.IsUnspecified() && !peer.IsLinkLocalUnicast()) {
				continue
			}
			select {
			case solicit <- peer:
			default:
			}
		}
	}()
	last := time.Time{}
	send := func(dst netip.Addr, withdraw bool) {
		if !dst.IsValid() || dst.IsUnspecified() {
			dst = netip.MustParseAddr(wellknown.AllNodes6)
		}
		r.conn.SetWriteDeadline(time.Now().Add(time.Second))
		if e := r.conn.WriteTo(Advertisement(r.scope, withdraw), nil, dst); e != nil {
			log.Printf("ghostd RA %s: %v", r.scope.ID, e)
		}
		last = time.Now()
	}
	send(netip.Addr{}, false)
	timer := time.NewTimer(time.Duration(r.scope.RA.Interval) * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-r.stop:
			send(netip.Addr{}, true)
			return
		case peer := <-solicit:
			if time.Since(last) >= 3*time.Second {
				send(peer, false)
			}
		case <-timer.C:
			for _, s := range r.config().Scopes {
				if s.ID == r.scope.ID && s.Enabled && s.RA != nil {
					r.scope = s
					break
				}
			}
			send(netip.Addr{}, false)
			timer.Reset(time.Duration(r.scope.RA.Interval) * time.Second)
		}
	}
}

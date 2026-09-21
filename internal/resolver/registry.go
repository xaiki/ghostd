package resolver

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"smarthome/ghostd/internal/addressbook"
)

var registry atomic.Pointer[addressbook.Manager]

func SetRegistry(m *addressbook.Manager) { registry.Store(m) }
func init() {
	plugin.Register("ghostleases", func(c *caddy.Controller) error {
		for c.Next() {
			if len(c.RemainingArgs()) != 0 {
				return c.ArgErr()
			}
		}
		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
				manager := registry.Load()
				if manager == nil {
					return plugin.NextOrFailure("ghostleases", next, ctx, w, r)
				}
				return (&addressbook.DNS{Store: manager.Store, Config: manager.Config, Next: next}).ServeDNS(ctx, w, r)
			})
		})
		return nil
	})
}

// Forward is used by explicitly bound LAN DNS listeners. Never consult the
// host's resolv.conf, which might itself point at the local authoritative DNS.
var Forward plugin.Handler = plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	reply, _, err := client.ExchangeContext(ctx, r, "100.100.100.100:53")
	if err == nil && reply.Truncated {
		client.Net = "tcp"
		reply, _, err = client.ExchangeContext(ctx, r, "100.100.100.100:53")
	}
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	return dns.RcodeSuccess, w.WriteMsg(reply)
})

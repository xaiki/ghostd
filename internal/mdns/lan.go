//go:build mdns

package mdns

import (
	"context"
	"net"

	"github.com/miekg/dns"
)

// LAN adapts a Querier to the resolver's LAN client: native .local host lookups
// and DNS-SD browsing for containers, with no mDNS daemon on the host.
type LAN struct{ Q *Querier }

func NewLAN(q *Querier) *LAN { return &LAN{Q: q} }

// Lookup resolves a .local host. It reports an error only when no interface
// could send the query, so the caller can fall back to the host's NSS.
func (l *LAN) Lookup(ctx context.Context, name string) ([]net.IP, error) {
	var ips []net.IP
	seen := map[string]bool{}
	for i, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		rrs, err := l.Q.Query(ctx, name, qt)
		if err != nil && len(rrs) == 0 {
			if i == 0 {
				return nil, err
			}
			continue
		}
		for _, rr := range Answers(rrs, name, qt) {
			var ip net.IP
			switch v := rr.(type) {
			case *dns.A:
				ip = v.A
			case *dns.AAAA:
				ip = v.AAAA
			}
			if ip != nil && !seen[ip.String()] {
				seen[ip.String()] = true
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// Browse asks the LAN for a DNS-SD record set.
func (l *LAN) Browse(ctx context.Context, name string, qtype uint16) ([]dns.RR, []dns.RR, error) {
	rrs, err := l.Q.Query(ctx, name, qtype)
	if err != nil && len(rrs) == 0 {
		return nil, nil, err
	}
	answers := Answers(rrs, name, qtype)
	return answers, Related(rrs, answers), nil
}

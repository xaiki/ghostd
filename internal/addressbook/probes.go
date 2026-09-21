//go:build dhcp && dnsmasq

package addressbook

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Probes are active checks a takeover can require before it is confirmed. The
// evidence gate proves the ledger saw real clients; a probe goes further and
// *does* what a client would, from this host, over the real network path:
//
//   - "dhcp": a complete DORA exchange on the scope's interface as a synthetic
//     client, then verification that the lease's router and DNS are the scope's,
//     that the scope's DNS resolves the leased name and address back, and a
//     Release. It exercises the same wire path a client uses.
//   - "dns": a resolver query through the scope's DNS server (a name, expecting an
//     address).
//   - "tcp": a connection from this host to an address, for example the router or
//     a service that must stay reachable through the new authority.
//
// The synthetic client's MAC carries a fixed prefix so it never counts as the
// real-client evidence.
type Probe struct {
	Kind  string `json:"kind"`
	Scope string `json:"scope,omitempty"`
	// Name and Expect are for "dns": resolve Name through the scope's server and
	// require Expect among the answers.
	Name   string `json:"name,omitempty"`
	Expect string `json:"expect,omitempty"`
	// Addr is for "tcp": host:port to connect to.
	Addr string `json:"addr,omitempty"`
}

// ProbeResult records one probe run.
type ProbeResult struct {
	Probe  Probe  `json:"probe"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	At     int64  `json:"at"`
}

// probeMACPrefix marks synthetic probe clients (02: locally administered, then "ghost").
const probeMACPrefix = "02:67:68:6f:73:"

func isProbeMAC(mac string) bool { return strings.HasPrefix(strings.ToLower(mac), probeMACPrefix) }

func (p Probe) validate(c Config) error {
	switch p.Kind {
	case "dhcp":
		sc, ok := c.Scope(p.Scope)
		if !ok || sc.Is6() || !sc.Enabled {
			return fmt.Errorf("dhcp probe needs an enabled IPv4 scope, got %q", p.Scope)
		}
	case "dns":
		if _, ok := c.Scope(p.Scope); !ok || p.Name == "" || p.Expect == "" {
			return fmt.Errorf("dns probe needs a scope, a name and the address to expect")
		}
		if _, e := netip.ParseAddr(p.Expect); e != nil {
			return fmt.Errorf("dns probe: expect must be an address")
		}
	case "tcp":
		if _, _, e := net.SplitHostPort(p.Addr); e != nil {
			return fmt.Errorf("tcp probe needs host:port")
		}
	default:
		return fmt.Errorf("unknown probe kind %q", p.Kind)
	}
	return nil
}

// RunProbe executes one probe; tests substitute Handover.ProbeRunner.
func RunProbe(ctx context.Context, p Probe, c Config) ProbeResult {
	res := ProbeResult{Probe: p, At: time.Now().Unix()}
	var err error
	switch p.Kind {
	case "dhcp":
		res.Detail, err = probeDHCP(ctx, p, c)
	case "dns":
		res.Detail, err = probeDNS(ctx, p, c)
	case "tcp":
		var d net.Dialer
		var conn net.Conn
		if conn, err = (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", p.Addr); err == nil {
			conn.Close()
			res.Detail = "connected to " + p.Addr
		}
		_ = d
	}
	res.OK = err == nil
	if err != nil {
		res.Detail = err.Error()
	}
	return res
}

func probeDNS(ctx context.Context, p Probe, c Config) (string, error) {
	sc, _ := c.Scope(p.Scope)
	want := netip.MustParseAddr(p.Expect)
	qt := dns.TypeA
	if want.Is6() {
		qt = dns.TypeAAAA
	}
	for _, network := range []string{"udp", "tcp"} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(p.Name), qt)
		r, _, err := (&dns.Client{Net: network, Timeout: 2 * time.Second}).ExchangeContext(ctx, q, net.JoinHostPort(sc.Server, "53"))
		if err != nil {
			return "", fmt.Errorf("%s query of %s via %s: %w", network, p.Name, sc.Server, err)
		}
		found := false
		for _, rr := range r.Answer {
			switch v := rr.(type) {
			case *dns.A:
				found = found || v.A.String() == want.String()
			case *dns.AAAA:
				found = found || v.AAAA.String() == want.String()
			}
		}
		if !found {
			return "", fmt.Errorf("%s: %s did not resolve to %s", network, p.Name, want)
		}
	}
	return fmt.Sprintf("%s resolves to %s over UDP and TCP", p.Name, want), nil
}

// verifyLeaseThroughDNS checks what a client would rely on after DHCP: the
// scope's DNS answers for the leased address, both ways.
func verifyLeaseThroughDNS(ctx context.Context, sc Scope, leased netip.Addr) (string, error) {
	arpa, err := dns.ReverseAddr(leased.String())
	if err != nil {
		return "", err
	}
	q := new(dns.Msg)
	q.SetQuestion(arpa, dns.TypePTR)
	r, _, err := (&dns.Client{Net: "udp", Timeout: 2 * time.Second}).ExchangeContext(ctx, q, net.JoinHostPort(sc.Server, "53"))
	if err != nil || len(r.Answer) == 0 {
		return "", fmt.Errorf("no PTR for the leased address %s from %s: %v", leased, sc.Server, err)
	}
	ptr, ok := r.Answer[0].(*dns.PTR)
	if !ok || !strings.HasSuffix(strings.TrimSuffix(ptr.Ptr, "."), sc.Zone) {
		return "", fmt.Errorf("PTR %v is not in zone %s", r.Answer[0], sc.Zone)
	}
	q.SetQuestion(ptr.Ptr, dns.TypeA)
	r, _, err = (&dns.Client{Net: "tcp", Timeout: 2 * time.Second}).ExchangeContext(ctx, q, net.JoinHostPort(sc.Server, "53"))
	if err != nil || len(r.Answer) == 0 {
		return "", fmt.Errorf("%s does not resolve back: %v", ptr.Ptr, err)
	}
	if a, ok := r.Answer[0].(*dns.A); !ok || a.A.String() != leased.String() {
		return "", fmt.Errorf("%s resolves to %v, not %s", ptr.Ptr, r.Answer[0], leased)
	}
	return strings.TrimSuffix(ptr.Ptr, "."), nil
}

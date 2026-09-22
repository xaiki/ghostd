//go:build coredns

// Package resolver embeds the small CoreDNS chain used by stack containers.
// Host /etc/resolv.conf is never rewritten: NSS/mDNS must not recurse into us.
package resolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"

	"github.com/xaiki/ghostd/internal/wellknown"
)

const RuntimeDir = "/run/ghostd"

// lookupFunc and browseFunc are the LAN lookups the plugin uses; tests replace them.
var (
	lookupFunc = lookupLocal
	browseFunc = browseLocal
)

// LANClient is the LAN-side client behind .local answers and DNS-SD browsing.
// It is optional: a build without it resolves .local through the host's NSS
// (getent) and does not answer DNS-SD questions. The mdns feature provides one.
type LANClient interface {
	// Lookup resolves a .local host name to addresses. An error means the client
	// could not ask the LAN at all (no usable interface), not that nobody answered.
	Lookup(ctx context.Context, name string) ([]net.IP, error)
	// Browse asks for a DNS-SD record set (PTR/SRV/TXT) and returns the answers
	// and the related SRV/TXT/address records.
	Browse(ctx context.Context, name string, qtype uint16) (answers, extra []dns.RR, err error)
}

var errNoLAN = errors.New("no LAN discovery client in this build")

type lanBox struct{ c LANClient }

var lanClient atomic.Pointer[lanBox]

func init() {
	plugin.Register("ghostlocal", func(c *caddy.Controller) error {
		for c.Next() {
			if len(c.RemainingArgs()) != 0 {
				return c.ArgErr()
			}
		}
		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			return &localHandler{next: next, lookup: lookupFunc, browse: browseFunc, slots: make(chan struct{}, 16)}
		})
		return nil
	})
}

// Option customises Start.
type Option func(*options)
type options struct {
	acl ACL
	lan LANClient
}

// WithACL gives each identity its own resolver listener and access policy.
func WithACL(a ACL) Option { return func(o *options) { o.acl = a } }

// WithLAN sets the native client used for .local names and DNS-SD.
func WithLAN(c LANClient) Option { return func(o *options) { o.lan = c } }

// Start binds TCP and UDP before publishing the environment consumed by Quadlet.
// The address is the host tailnet IP, never a wildcard/public listener.
func Start(address, directory string, opts ...Option) (func(), error) {
	return start(address, wellknown.PortDNS, wellknown.Quad100, directory, opts...)
}

func start(address string, port int, upstream, directory string, opts ...Option) (func(), error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid DNS bind address %q", address)
	}
	var o options
	for _, f := range opts {
		f(&o)
	}
	if err := o.acl.Validate(); err != nil {
		return nil, err
	}
	for _, id := range o.acl.Identities {
		if net.ParseIP(id.Listen).Equal(ip) {
			return nil, fmt.Errorf("identity %s listens on the base resolver address", id.Name)
		}
	}
	setPolicies(o.acl)
	if o.lan != nil {
		lanClient.Store(&lanBox{o.lan})
	}
	corefile := pluginCorefile(port, ip.String(), upstream, o.acl.Identities...)
	instance, err := caddy.Start(caddy.CaddyfileInput{Contents: []byte(corefile), ServerTypeName: "dns"})
	if err != nil {
		clearPolicies()
		return nil, err
	}
	stop := func() { instance.ShutdownCallbacks(); _ = instance.Stop(); clearPolicies(); lanClient.Store(nil) }
	if err := os.MkdirAll(directory, 0755); err != nil {
		stop()
		return nil, err
	}
	files := map[string]string{
		"dns.env":     "GHOSTD_DNS_ADDRESS=" + ip.String() + "\n",
		"resolv.conf": "# Managed by ghostd; for clients without Podman service discovery.\nnameserver " + ip.String() + "\n",
	}
	for _, id := range o.acl.Identities {
		files["dns-"+id.Name+".env"] = "GHOSTD_DNS_ADDRESS=" + id.Listen + "\n"
		files["resolv-"+id.Name+".conf"] = "# Managed by ghostd; resolver for identity " + id.Name + " only.\nnameserver " + id.Listen + "\n"
	}
	for name, content := range files {
		if err := publish(directory, name, content); err != nil {
			stop()
			return nil, err
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for name := range files {
				_ = os.Remove(filepath.Join(directory, name))
			}
			stop()
		})
	}, nil
}

func publish(directory, name, content string) error {
	f, err := os.CreateTemp(directory, ".dns-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	if err = f.Chmod(0644); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(directory, name))
}

type localHandler struct {
	next   plugin.Handler
	lookup func(context.Context, string) ([]net.IP, error)
	// browse answers DNS-SD questions (PTR/SRV/TXT) from the LAN; nil disables them.
	browse func(ctx context.Context, name string, qtype uint16) (answers, extra []dns.RR, err error)
	slots  chan struct{}
}

func (h *localHandler) Name() string { return "ghostlocal" }
func (h *localHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) != 1 {
		return dns.RcodeFormatError, nil
	}
	q := r.Question[0]
	if !strings.HasSuffix(strings.ToLower(q.Name), ".local.") {
		return plugin.NextOrFailure(h.Name(), h.next, ctx, w, r)
	}
	if q.Qclass != dns.ClassINET {
		return dns.RcodeRefused, nil
	}
	if _, isService := serviceClass(q.Name); isService && h.browse != nil && (q.Qtype == dns.TypePTR || q.Qtype == dns.TypeSRV || q.Qtype == dns.TypeTXT) {
		return h.serveBrowse(ctx, w, r, q)
	}
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		return dns.RcodeNotImplemented, nil
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		return dns.RcodeServerFailure, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := h.lookup(ctx, strings.TrimSuffix(q.Name, "."))
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.RecursionAvailable = true
	if len(ips) == 0 {
		reply.Rcode = dns.RcodeNameError
	}
	for _, ip := range ips {
		header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 30}
		if q.Qtype == dns.TypeA && ip.To4() != nil {
			reply.Answer = append(reply.Answer, &dns.A{Hdr: header, A: ip.To4()})
		} else if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
			reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: header, AAAA: ip})
		}
	}
	return dns.RcodeSuccess, w.WriteMsg(reply)
}

// serveBrowse answers a DNS-SD question from the LAN. Under an ACL identity the
// hosts a browse names become resolvable for that identity alone.
func (h *localHandler) serveBrowse(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, q dns.Question) (int, error) {
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		return dns.RcodeServerFailure, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	answers, extra, err := h.browse(ctx, q.Name, q.Qtype)
	if errors.Is(err, errNoLAN) {
		return dns.RcodeNotImplemented, nil
	}
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.RecursionAvailable = true
	reply.Answer, reply.Extra = answers, extra
	if len(answers) == 0 {
		reply.Rcode = dns.RcodeNameError
	}
	if p := identityOf(ctx); p != nil {
		for _, rr := range append(append([]dns.RR{}, answers...), extra...) {
			if srv, ok := rr.(*dns.SRV); ok {
				p.GrantHost(srv.Target)
			}
		}
	}
	return dns.RcodeSuccess, w.WriteMsg(reply)
}

// browseLocal asks the LAN for a DNS-SD record set through the LAN client.
func browseLocal(ctx context.Context, name string, qtype uint16) ([]dns.RR, []dns.RR, error) {
	box := lanClient.Load()
	if box == nil {
		return nil, nil, errNoLAN
	}
	return box.c.Browse(ctx, name, qtype)
}

// lookupLocal resolves a .local host natively when there is a LAN client. Only
// when it cannot ask (or there is none) does it fall back to the host's NSS via
// getent, so a host that still runs avahi keeps working.
func lookupLocal(ctx context.Context, name string) ([]net.IP, error) {
	if box := lanClient.Load(); box != nil {
		if ips, err := box.c.Lookup(ctx, name); err == nil {
			return ips, nil
		}
	}
	return lookupHost(ctx, name)
}

func lookupHost(ctx context.Context, name string) ([]net.IP, error) {
	// ghostd is cross-compiled without cgo: getent keeps the host's NSS/Avahi
	// behavior instead of Go silently treating .local as ordinary unicast DNS.
	output, err := exec.CommandContext(ctx, "getent", "ahosts", "--", name).Output()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 2 {
			return nil, nil
		}
		return nil, err
	}
	var ips []net.IP
	seen := map[string]bool{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		ip := net.ParseIP(fields[0])
		if ip != nil && !seen[ip.String()] {
			ips = append(ips, ip)
			seen[ip.String()] = true
		}
	}
	return ips, nil
}

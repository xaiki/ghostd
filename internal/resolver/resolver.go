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
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

const RuntimeDir = "/run/ghostd"

func init() {
	plugin.Register("ghostlocal", func(c *caddy.Controller) error {
		for c.Next() {
			if len(c.RemainingArgs()) != 0 {
				return c.ArgErr()
			}
		}
		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			return &localHandler{next: next, lookup: lookupHost, slots: make(chan struct{}, 16)}
		})
		return nil
	})
}

// Start binds TCP and UDP before publishing the environment consumed by Quadlet.
// The address is the host tailnet IP, never a wildcard/public listener.
func Start(address, directory string) (func(), error) {
	return start(address, 53, "100.100.100.100", directory)
}

func start(address string, port int, upstream, directory string) (func(), error) {
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, fmt.Errorf("invalid DNS bind address %q", address)
	}
	corefile := pluginCorefile(port, ip.String(), upstream)
	instance, err := caddy.Start(caddy.CaddyfileInput{Contents: []byte(corefile), ServerTypeName: "dns"})
	if err != nil {
		return nil, err
	}
	stop := func() { instance.ShutdownCallbacks(); _ = instance.Stop() }
	if err := os.MkdirAll(directory, 0755); err != nil {
		stop()
		return nil, err
	}
	for name, content := range map[string]string{
		"dns.env":     "GHOSTD_DNS_ADDRESS=" + ip.String() + "\n",
		"resolv.conf": "# Managed by ghostd; for clients without Podman service discovery.\nnameserver " + ip.String() + "\n",
	} {
		if err := publish(directory, name, content); err != nil {
			stop()
			return nil, err
		}
	}
	return func() {
		_ = os.Remove(filepath.Join(directory, "dns.env"))
		_ = os.Remove(filepath.Join(directory, "resolv.conf"))
		stop()
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

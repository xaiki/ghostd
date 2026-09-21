//go:build dhcp

package addressbook

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// DNS answers authoritative data before CoreDNS's shared recursive cache.
// Lease changes are therefore visible immediately at the server; client TTLs
// remain bounded by the lease lifetime.
type DNS struct {
	Store  *Store
	Config func() Config
	Next   plugin.Handler
}

func (h *DNS) Name() string { return "ghostleases" }
func (h *DNS) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) != 1 {
		return dns.RcodeFormatError, nil
	}
	q := r.Question[0]
	name := strings.ToLower(q.Name)
	c := h.Config()
	var scope *Scope
	reverse := false
	for _, s := range c.Scopes {
		candidate := s
		if name == s.Zone+"." || strings.HasSuffix(name, "."+s.Zone+".") {
			scope = &candidate
			break
		}
		if ip, ok := reverseIP(name); ok && netip.MustParsePrefix(s.Subnet).Contains(ip) {
			scope = &candidate
			reverse = true
			break
		}
	}
	if scope == nil {
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}
	if q.Qclass != dns.ClassINET {
		return dns.RcodeRefused, nil
	}
	address, label := "", strings.TrimSuffix(name, "."+scope.Zone+".")
	if reverse {
		ip, _ := reverseIP(name)
		address = ip.String()
	}
	lookupName := name
	if !reverse {
		for _, d := range c.Devices {
			for _, alias := range d.Aliases {
				if label == alias {
					label = d.Name
					lookupName = d.Name + "." + scope.Zone + "."
				}
			}
		}
	}
	var bindings []Binding
	var err error
	for _, candidate := range c.Scopes {
		if candidate.Zone == scope.Zone {
			var found []Binding
			found, err = h.Store.DNSBindings(candidate.ID, label, address)
			if err != nil {
				break
			}
			bindings = append(bindings, found...)
		}
	}
	if err != nil {
		return dns.RcodeServerFailure, err
	}
	reply := new(dns.Msg)
	reply.SetReply(r)
	reply.Authoritative = true
	now := h.Store.now().Unix()
	exists := name == scope.Zone+"."
	for _, b := range bindings {
		if b.State != "active" || b.End <= now {
			continue
		}
		owner := b.Name + "." + scope.Zone + "."
		reverseName, _ := dns.ReverseAddr(b.Address)
		if (!reverse && owner != lookupName) || (reverse && reverseName != name) {
			continue
		}
		exists = true
		ttl := int64(30)
		if b.End-now < ttl {
			ttl = b.End - now
		}
		header := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: uint32(ttl)}
		if reverse && q.Qtype == dns.TypePTR {
			reply.Answer = append(reply.Answer, &dns.PTR{Hdr: header, Ptr: owner})
		}
		if !reverse && q.Qtype == dns.TypeA && net.ParseIP(b.Address).To4() != nil {
			reply.Answer = append(reply.Answer, &dns.A{Hdr: header, A: net.ParseIP(b.Address).To4()})
		}
		if !reverse && q.Qtype == dns.TypeAAAA && net.ParseIP(b.Address).To4() == nil {
			reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: header, AAAA: net.ParseIP(b.Address)})
		}
	}
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: scope.Zone + ".", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1}, Ns: "ns." + scope.Zone + ".", Mbox: "hostmaster." + scope.Zone + ".", Serial: h.Store.Revision(), Refresh: 30, Retry: 5, Expire: 300, Minttl: 1}
	if reverse { // A host-specific reverse zone avoids claiming neighboring CIDRs.
		soa.Hdr.Name = q.Name
	}
	if name == "ns."+scope.Zone+"." {
		exists = true
		for _, s := range c.Scopes {
			if s.Zone != scope.Zone {
				continue
			}
			ip := net.ParseIP(s.Server)
			hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 30}
			if q.Qtype == dns.TypeA && ip.To4() != nil {
				reply.Answer = append(reply.Answer, &dns.A{Hdr: hdr, A: ip.To4()})
			}
			if q.Qtype == dns.TypeAAAA && ip.To4() == nil {
				reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: hdr, AAAA: ip})
			}
		}
	}
	if name == scope.Zone+"." && q.Qtype == dns.TypeSOA {
		reply.Answer = append(reply.Answer, soa)
	}
	if name == scope.Zone+"." && q.Qtype == dns.TypeNS {
		reply.Answer = append(reply.Answer, &dns.NS{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 30}, Ns: soa.Ns})
	}
	if !exists {
		reply.Rcode = dns.RcodeNameError
	}
	if len(reply.Answer) == 0 {
		reply.Ns = append(reply.Ns, soa)
	}
	return dns.RcodeSuccess, w.WriteMsg(reply)
}
func reverseIP(name string) (netip.Addr, bool) {
	if strings.HasSuffix(name, ".ip6.arpa.") {
		parts := strings.Split(strings.TrimSuffix(name, ".ip6.arpa."), ".")
		if len(parts) != 32 {
			return netip.Addr{}, false
		}
		text := ""
		for i := 31; i >= 0; i-- {
			if len(parts[i]) != 1 {
				return netip.Addr{}, false
			}
			text += parts[i]
		}
		raw, e := hex.DecodeString(text)
		if e != nil {
			return netip.Addr{}, false
		}
		ip, ok := netip.AddrFromSlice(raw)
		return ip, ok
	}

	if !strings.HasSuffix(name, ".in-addr.arpa.") {
		return netip.Addr{}, false
	}
	parts := strings.Split(strings.TrimSuffix(name, ".in-addr.arpa."), ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0]))
	return ip, err == nil
}

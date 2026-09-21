//go:build mdns

package mdns

import (
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// The per-container mDNS reflector.
//
// A container network (one Podman network per container or pod) is a multicast
// domain of its own, so what is reflected into it is exactly what that network
// is allowed to see: the permission is a property of the network, not of a
// packet. For each rule ghostd relays, between the LAN interface and the
// container network's interface,
//
//   - container -> LAN: only *queries* about the service classes the network
//     allows (and about hosts those services named), plus the service-type
//     enumeration, whose answers are filtered like any other record;
//   - LAN -> container: only *records* for those classes, plus the SRV, TXT and
//     address records of the instances they name.
//
// Everything else stays where it is. A container's own advertisement is not
// relayed outward either — its address is private to the bridge — but with
// `advertise` it is re-advertised from the LAN under ghostd's own address, with
// a DNAT into the container: see nat.go.

// ReflectRule connects one container network to a LAN.
type ReflectRule struct {
	// LAN is the LAN interface whose mDNS is reflected.
	LAN string `json:"lan"`
	// Network is the container network's bridge interface. One rule per
	// network: a network is one permission set.
	Network string `json:"network"`
	// AllowServices are the DNS-SD classes (_ipp._tcp) this network may browse.
	AllowServices []string `json:"allow_services"`
	// Advertise re-advertises the container network's own service instances on the
	// LAN under ghostd's address, with DNAT into the container (see nat.go).
	Advertise *NATConfig `json:"advertise,omitempty"`
}

// classOf extracts the "_type._proto" a DNS-SD name belongs to, whether it is
// the browse name, an instance or a subtype query.
func classOf(name string) (string, bool) {
	labels := strings.Split(strings.TrimSuffix(norm(name), "."), ".")
	if len(labels) < 3 || labels[len(labels)-1] != "local" {
		return "", false
	}
	labels = labels[:len(labels)-1]
	for i := len(labels) - 1; i >= 1; i-- {
		if (labels[i] == "_tcp" || labels[i] == "_udp") && strings.HasPrefix(labels[i-1], "_") {
			return labels[i-1] + "." + labels[i], true
		}
	}
	return "", false
}

// enumerateName is the DNS-SD service-type enumeration name. It names no class of
// its own, so it cannot be permitted by class: the query goes out for what a
// browser needs, and the ACL is applied to the classes that come back.
const enumerateName = "_services._dns-sd._udp.local."

func enumeration(q dns.Question) bool {
	return q.Qtype == dns.TypePTR && norm(q.Name) == enumerateName
}

// enumerable is an enumeration answer naming a class the network may see.
func (f *filter) enumerable(rr dns.RR) bool {
	if rr.Header().Rrtype != dns.TypePTR || norm(rr.Header().Name) != enumerateName {
		return false
	}
	p, ok := rr.(*dns.PTR)
	return ok && f.allowedName(p.Ptr)
}

// filter decides what one container network may see.
type filter struct {
	allow map[string]bool
	mu    sync.Mutex
	hosts map[string]time.Time // .local hosts named by allowed services
	now   func() time.Time
}

func newFilter(services []string) *filter {
	f := &filter{allow: map[string]bool{}, hosts: map[string]time.Time{}, now: time.Now}
	for _, s := range services {
		f.allow[strings.ToLower(s)] = true
	}
	return f
}

func (f *filter) allowedName(name string) bool {
	c, ok := classOf(name)
	return ok && f.allow[c]
}

func (f *filter) grant(host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := f.now()
	for h, exp := range f.hosts {
		if !now.Before(exp) {
			delete(f.hosts, h)
		}
	}
	if len(f.hosts) < 4096 {
		f.hosts[norm(host)] = now.Add(2 * time.Minute)
	}
}

func (f *filter) granted(host string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.hosts[norm(host)]
	return ok && f.now().Before(exp)
}

// Queries reduces a container's query to what the network may ask, or nil.
func (f *filter) Queries(m *dns.Msg) *dns.Msg {
	out := new(dns.Msg)
	out.Id = m.Id
	for _, q := range m.Question {
		switch {
		case f.allowedName(q.Name), enumeration(q):
			out.Question = append(out.Question, q)
		case (q.Qtype == dns.TypeA || q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY) && f.granted(q.Name):
			out.Question = append(out.Question, q)
		}
	}
	if len(out.Question) == 0 {
		return nil
	}
	for _, k := range m.Answer { // known answers only for what may be asked
		if f.allowedName(k.Header().Name) || f.enumerable(k) {
			out.Answer = append(out.Answer, k)
		}
	}
	return out
}

// Responses reduces LAN records to what the network may see, or nil.
func (f *filter) Responses(m *dns.Msg) *dns.Msg {
	all := append(append([]dns.RR{}, m.Answer...), m.Extra...)
	// Hosts named by an allowed service's SRV become resolvable for the network.
	for _, rr := range all {
		if srv, ok := rr.(*dns.SRV); ok && f.allowedName(srv.Hdr.Name) {
			f.grant(srv.Target)
		}
	}
	out := new(dns.Msg)
	out.Response, out.Authoritative = true, true
	keep := func(rr dns.RR) bool {
		h := rr.Header()
		switch h.Rrtype {
		case dns.TypePTR:
			return f.allowedName(h.Name) || f.enumerable(rr) // enumeration names no class; only the allowed classes it lists are kept
		case dns.TypeSRV, dns.TypeTXT:
			return f.allowedName(h.Name)
		case dns.TypeA, dns.TypeAAAA:
			return f.granted(h.Name)
		}
		return false
	}
	for _, rr := range m.Answer {
		if keep(rr) {
			out.Answer = append(out.Answer, rr)
		}
	}
	for _, rr := range m.Extra {
		if keep(rr) {
			out.Extra = append(out.Extra, rr)
		}
	}
	if len(out.Answer) == 0 && len(out.Extra) == 0 {
		return nil
	}
	return out
}

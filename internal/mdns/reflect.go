//go:build mdns

package mdns

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// The directed mDNS relay.
//
// A domain is one interface carrying its own mDNS: a VLAN, a physical LAN, a
// container network's bridge. A rule {from, to} says that from's services
// become visible on to — a record heard on from is delivered to to, and a
// question heard on to is delivered to from so from's own responders answer it.
// Direction belongs to the rule, so {from: a, to: b} and {from: b, to: a} are
// independent permissions and writing one says nothing about the other.
//
// Rules compose into a reachability relation: if a's services reach b and b's
// reach c then a's reach c, and the same rules carry the question back the other
// way. That relation is computed once per applied configuration rather than by
// re-reflecting packets, so a forwarded packet is never one ghostd has to hear
// again and cannot loop. Every ordered pair a path connects gets its own filter
// carrying only the classes allowed on *every* rule along a path (permissions
// intersect as they compose, and a pair several paths reach sees the union of
// what each path allows), so the host names one pair has learned to resolve are
// not another pair's business. A domain never receives its own records back, so
// two domains exporting to each other cannot echo.
//
// A rule with `advertise` is not a relay: it translates the source's records
// onto the destination instead (nat.go), because the addresses they name are not
// reachable there. That translation is terminal — a translated record is
// ghostd's own announcement on that interface, not something it exports onward,
// and the DNAT it installs is scoped to the interface it is published on, so an
// onward copy would advertise a port that could not work.

// ReflectRule connects two mDNS domains, directionally.
type ReflectRule struct {
	// From is the interface whose services this rule exports.
	From string `json:"from"`
	// To is the interface they become visible on.
	To string `json:"to"`
	// AllowServices are the DNS-SD classes exported; ["*"] is every class.
	AllowServices []string `json:"allow_services,omitempty"`
	// Advertise translates instead of relaying: the source's records are
	// re-advertised on the destination under ghostd's own address there, with a
	// DNAT into the source (nat.go). Exactly one of this and AllowServices.
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

// filter decides what one pair — everything one domain may show another — sees.
type filter struct {
	allow map[string]bool
	all   bool
	mu    sync.Mutex
	hosts map[string]time.Time // .local hosts named by allowed services
	now   func() time.Time
}

func newFilter(services []string) *filter {
	f := &filter{allow: map[string]bool{}, hosts: map[string]time.Time{}, now: time.Now}
	for _, s := range services {
		if s == "*" {
			f.all = true
			continue
		}
		f.allow[strings.ToLower(s)] = true
	}
	return f
}

func (f *filter) allowedName(name string) bool {
	c, ok := classOf(name)
	return ok && (f.all || f.allow[c])
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

// classSet is what a rule, or a pair reached through several rules, may carry:
// every class, or a set of them.
type classSet struct {
	all bool
	set map[string]bool
}

func classesOf(services []string) classSet {
	cs := classSet{set: map[string]bool{}}
	for _, s := range services {
		if s == "*" {
			cs.all = true
			continue
		}
		cs.set[strings.ToLower(s)] = true
	}
	return cs
}

func (c classSet) empty() bool { return !c.all && len(c.set) == 0 }

// intersect is what composing two rules may carry: a class has to be allowed by
// both, so the narrower rule bounds the wider one.
func (c classSet) intersect(o classSet) classSet {
	switch {
	case o.all:
		return c
	case c.all:
		return o
	}
	out := classSet{set: map[string]bool{}}
	for k := range c.set {
		if o.set[k] {
			out.set[k] = true
		}
	}
	return out
}

// union is what reaching one pair by two paths may carry.
func (c classSet) union(o classSet) classSet {
	if c.all || o.all {
		return classSet{all: true}
	}
	out := classSet{set: map[string]bool{}}
	for k := range c.set {
		out.set[k] = true
	}
	for k := range o.set {
		out.set[k] = true
	}
	return out
}

func (c classSet) equal(o classSet) bool {
	if c.all != o.all || len(c.set) != len(o.set) {
		return false
	}
	for k := range c.set {
		if !o.set[k] {
			return false
		}
	}
	return true
}

func (c classSet) services() []string {
	if c.all {
		return []string{"*"}
	}
	out := make([]string, 0, len(c.set))
	for k := range c.set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// relaying is one relay rule resolved to interface indexes.
type relaying struct {
	cfg      ReflectRule
	from, to int
}

// relay is one effective pair: the filter deciding what from's domain may show
// to's domain. Relay rules are the edges; advertise rules are not (they
// translate, see nat.go), so they take no part in the relation.
type relay struct {
	from, to int
	f        *filter
}

// planRelays resolves the relay rules into every pair a path connects. Rules
// compose with an intersecting class set, so for each source the relation is
// walked outward from it: a pair carries the classes every rule on a path
// allows, and a pair several paths reach keeps the union of what each path
// allows. Only a strict improvement is propagated, which ends the walk even
// when the source is reachable from itself through a cycle — and such a cycle
// can never widen a pair, because the classes it contributes are the ones a path
// reaching the same pair without revisiting the source already allows.
func planRelays(rules []*relaying) []*relay {
	byFrom := map[int][]*relaying{}
	for _, e := range rules {
		byFrom[e.from] = append(byFrom[e.from], e)
	}
	var out []*relay
	for source := range byFrom {
		best := map[int]classSet{}
		var queue []int
		push := func(to int, cs classSet) {
			if cs.empty() {
				return
			}
			merged := cs
			if prev, ok := best[to]; ok {
				if merged = prev.union(cs); prev.equal(merged) {
					return
				}
			}
			best[to] = merged
			queue = append(queue, to)
		}
		for _, e := range byFrom[source] {
			push(e.to, classesOf(e.cfg.AllowServices))
		}
		for len(queue) > 0 {
			via := queue[0]
			queue = queue[1:]
			for _, e := range byFrom[via] {
				push(e.to, best[via].intersect(classesOf(e.cfg.AllowServices)))
			}
		}
		for to, cs := range best {
			if to == source {
				continue // a domain never receives its own records back
			}
			out = append(out, &relay{from: source, to: to, f: newFilter(cs.services())})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].from != out[j].from {
			return out[i].from < out[j].from
		}
		return out[i].to < out[j].to
	})
	return out
}

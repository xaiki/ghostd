package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

// The per-container DNS access policy.
//
// Identity model: a source address behind a shared forwarder is not a
// credential, so the identity of a query is the resolver *listener* it arrived
// on. Each identity is given its own resolver address, published to that
// container alone (dns-<name>.env, resolv-<name>.conf), and tailnet/host
// firewall policy admits only that container's source to it. The policy is
// enforced by a plugin that runs before the lease answers and before the
// cache, and every identity's listener has its own cache instance, so one
// container's cached answer is never another container's visible data.

// Identity is one container's DNS permissions.
type Identity struct {
	Name   string `json:"name"`
	Listen string `json:"listen"`
	// AllowNames are names (and everything beneath them) the identity may
	// resolve; "*" allows every non-.local name, and "local" allows raw .local
	// host names.
	AllowNames []string `json:"allow_names,omitempty"`
	// AllowServices are DNS-SD service classes (for example _ipp._tcp) the
	// identity may browse on the LAN. Hosts named by a browse it was allowed
	// become resolvable for it, and only for it.
	AllowServices []string `json:"allow_services,omitempty"`
}

// ACL is the file dns-acl.json.
type ACL struct {
	Identities []Identity `json:"identities"`
}

const ACLFile = "dns-acl.json"

func ParseACL(raw []byte) (ACL, error) {
	var a ACL
	if len(strings.TrimSpace(string(raw))) == 0 {
		return a, nil
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return a, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return a, fmt.Errorf("trailing ACL data")
	}
	return a, a.Validate()
}

var validName = func(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func (a ACL) Validate() error {
	names, listens := map[string]bool{}, map[string]bool{}
	for _, id := range a.Identities {
		if !validName(id.Name) || names[id.Name] {
			return fmt.Errorf("identity name %q must be a unique lower-case label", id.Name)
		}
		names[id.Name] = true
		ip := net.ParseIP(id.Listen)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
			return fmt.Errorf("identity %s: listen must be one specific address, never a wildcard", id.Name)
		}
		if listens[ip.String()] {
			return fmt.Errorf("identity %s: listen address %s is already another identity's", id.Name, id.Listen)
		}
		listens[ip.String()] = true
		for _, n := range id.AllowNames {
			if n != "*" && (strings.ContainsAny(n, " /\t") || strings.HasPrefix(n, ".") || n == "") {
				return fmt.Errorf("identity %s: bad allow_names entry %q", id.Name, n)
			}
		}
		for _, s := range id.AllowServices {
			if c, ok := serviceClass(s + ".local."); !ok || c != strings.ToLower(s) {
				return fmt.Errorf("identity %s: %q is not a service class like _ipp._tcp", id.Name, s)
			}
		}
	}
	return nil
}

// serviceClass extracts the "_type._proto" a DNS-SD name belongs to, whether it
// is the browse name, an instance or a subtype query.
func serviceClass(name string) (string, bool) {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
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

// Policy is the compiled, concurrency-safe form of one identity.
type Policy struct {
	id      Identity
	mu      sync.Mutex
	granted map[string]time.Time
	now     func() time.Time
}

func newPolicy(id Identity) *Policy {
	return &Policy{id: id, granted: map[string]time.Time{}, now: time.Now}
}

func (p *Policy) matchesName(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, allowed := range p.id.AllowNames {
		allowed = strings.TrimSuffix(strings.ToLower(allowed), ".")
		if allowed == "*" && !strings.HasSuffix(name, ".local") && name != "local" {
			return true
		}
		if name == allowed || strings.HasSuffix(name, "."+allowed) {
			return true
		}
	}
	return false
}

// Decide says whether the identity may ask this question at all.
func (p *Policy) Decide(q dns.Question) (bool, string) {
	if q.Qclass != dns.ClassINET {
		return false, "unsupported class"
	}
	name := strings.ToLower(q.Name)
	if strings.HasSuffix(name, ".local.") {
		if class, ok := serviceClass(name); ok {
			for _, s := range p.id.AllowServices {
				if s == class {
					return true, ""
				}
			}
			return false, "service class " + class + " not allowed"
		}
		if p.matchesName(name) {
			return true, ""
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if exp, ok := p.granted[name]; ok && p.now().Before(exp) {
			return true, ""
		}
		return false, "host not offered by any service this identity may browse"
	}
	if p.matchesName(name) {
		return true, ""
	}
	return false, "name not allowed"
}

// GrantHost makes a .local host resolvable for this identity, because a browse
// it was allowed named it as a service target.
func (p *Policy) GrantHost(host string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for h, exp := range p.granted {
		if !now.Before(exp) {
			delete(p.granted, h)
		}
	}
	if len(p.granted) < 4096 {
		p.granted[strings.ToLower(host)] = now.Add(2 * time.Minute)
	}
}

// policies is what the running plugins consult; it is replaced atomically.
var policies atomic.Pointer[map[string]*Policy]

func setPolicies(a ACL) {
	m := map[string]*Policy{}
	for _, id := range a.Identities {
		m[id.Name] = newPolicy(id)
	}
	policies.Store(&m)
}
func clearPolicies() { policies.Store(nil) }
func policyFor(name string) *Policy {
	if m := policies.Load(); m != nil {
		return (*m)[name]
	}
	return nil
}

type ctxKey struct{}

func identityOf(ctx context.Context) *Policy {
	name, _ := ctx.Value(ctxKey{}).(string)
	if name == "" {
		return nil
	}
	return policyFor(name)
}

func init() {
	plugin.Register("ghostacl", func(c *caddy.Controller) error {
		var name string
		for c.Next() {
			args := c.RemainingArgs()
			if len(args) != 1 {
				return c.ArgErr()
			}
			name = args[0]
		}
		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			return &aclHandler{name: name, next: next}
		})
		return nil
	})
}

type aclHandler struct {
	name string
	next plugin.Handler
}

func (h *aclHandler) Name() string { return "ghostacl" }
func (h *aclHandler) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	p := policyFor(h.name)
	// A listener whose policy is missing refuses everything rather than falling
	// back to open access.
	if p == nil || len(r.Question) != 1 {
		return dns.RcodeRefused, nil
	}
	if ok, _ := p.Decide(r.Question[0]); !ok {
		reply := new(dns.Msg)
		reply.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(reply)
		return dns.RcodeRefused, nil
	}
	return plugin.NextOrFailure(h.Name(), h.next, context.WithValue(ctx, ctxKey{}, h.name), w, r)
}

//go:build mdns

package mdns

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// ConfigFile is the persisted advertisement target (the mdns-v1 domain).
const ConfigFile = "mdns-config.json"

// Config declares what ghostd advertises on behalf of things that cannot do it
// themselves (a container on a bridge). The record set is data the operator
// supplies, not something the daemon invents: a Time Machine record set in
// particular must come from a captured, known-good advertisement.
type Config struct {
	// Interfaces are the LAN interfaces to advertise on and answer from.
	Interfaces []string `json:"interfaces"`
	// Host is the .local host name whose address records ghostd answers with the
	// addresses of the advertising interface.
	Host    string   `json:"host"`
	Records []Record `json:"records"`
	// Reflect relays mDNS between the LAN and per-container networks, filtered by
	// what each network may see (see reflect.go).
	Reflect []ReflectRule `json:"reflect,omitempty"`
}

// Record is one DNS-SD service instance.
type Record struct {
	Service  string   `json:"service"`  // _smb._tcp
	Instance string   `json:"instance"` // human name, any UTF-8 up to 63 bytes
	Port     uint16   `json:"port"`
	TXT      []string `json:"txt,omitempty"`
	Subtypes []string `json:"subtypes,omitempty"` // _universal
	// Host is the .local host this instance's SRV points at, and whose address
	// ghostd answers for it: empty means Config.Host. A name learned from a
	// container is kept as the container advertised it (nat.go), which is why it
	// is per record rather than per config.
	Host string `json:"host,omitempty"`
}

var (
	serviceRE = regexp.MustCompile(`^_[a-z0-9][a-z0-9-]{0,14}\._(tcp|udp)$`)
	hostRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	subtypeRE = regexp.MustCompile(`^_[a-z0-9][a-z0-9-]{0,62}$`)
)

func ParseConfig(raw []byte) (Config, error) {
	var c Config
	if len(strings.TrimSpace(string(raw))) == 0 {
		return c, nil
	}
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("trailing mdns config data")
	}
	return c, c.Validate()
}

// Empty reports whether the config advertises and reflects nothing.
func (c Config) Empty() bool { return len(c.Records) == 0 && len(c.Reflect) == 0 }

func (c Config) Validate() error {
	if c.Empty() {
		return nil
	}
	if err := c.validateReflect(); err != nil {
		return err
	}
	if len(c.Records) == 0 {
		return nil
	}
	if len(c.Interfaces) == 0 || len(c.Interfaces) > 16 {
		return fmt.Errorf("mdns: name 1..16 interfaces")
	}
	for _, i := range c.Interfaces {
		if i == "" || len(i) > 15 || strings.ContainsAny(i, " /") {
			return fmt.Errorf("mdns: bad interface %q", i)
		}
	}
	if !hostRE.MatchString(c.Host) {
		return fmt.Errorf("mdns: host must be one lower-case DNS label")
	}
	if len(c.Records) > 64 {
		return fmt.Errorf("mdns: at most 64 records")
	}
	seen := map[string]bool{}
	for _, r := range c.Records {
		if !serviceRE.MatchString(r.Service) {
			return fmt.Errorf("mdns: %q is not a service like _smb._tcp", r.Service)
		}
		if r.Instance == "" || len(r.Instance) > 63 || strings.ContainsAny(r.Instance, "\x00\r\n.") {
			return fmt.Errorf("mdns: instance name %q must be 1..63 bytes without dots", r.Instance)
		}
		if r.Host != "" && !hostRE.MatchString(r.Host) {
			return fmt.Errorf("mdns: host %q must be one lower-case DNS label", r.Host)
		}
		if r.Port == 0 && r.Service != "_adisk._tcp" && r.Service != "_device-info._tcp" {
			return fmt.Errorf("mdns: %s/%s needs a port (only _adisk and _device-info are conventionally port 0)", r.Service, r.Instance)
		}
		key := strings.ToLower(r.Instance + "." + r.Service)
		if seen[key] {
			return fmt.Errorf("mdns: duplicate %s", key)
		}
		seen[key] = true
		total := 0
		for _, t := range r.TXT {
			if len(t) > 255 {
				return fmt.Errorf("mdns: TXT string over 255 bytes in %s", key)
			}
			total += len(t) + 1
		}
		if total > 1300 {
			return fmt.Errorf("mdns: TXT record for %s too large", key)
		}
		for _, s := range r.Subtypes {
			if !subtypeRE.MatchString(s) {
				return fmt.Errorf("mdns: bad subtype %q", s)
			}
		}
	}
	return nil
}

// InterfaceAddrs lists an interface's routable address prefixes.
func InterfaceAddrs(name string) ([]netip.Prefix, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := i.Addrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil || p.Addr().IsLinkLocalUnicast() || p.Addr().IsLoopback() {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

const (
	ttlHost    = 120
	ttlService = 4500
)

// answerer builds responses from a Config. It is pure: no sockets, so the
// record logic is testable without a network.
type answerer struct {
	cfg   Config
	addrs func(iface string) ([]netip.Prefix, error)
}

// norm makes a name comparable: miekg presents a space in a label as \032 and
// so on, while configured instance names carry the raw character.
func norm(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '\\' && i+1 < len(name) {
			if i+3 < len(name) && name[i+1] >= '0' && name[i+1] <= '9' && name[i+2] >= '0' && name[i+2] <= '9' && name[i+3] >= '0' && name[i+3] <= '9' {
				n := int(name[i+1]-'0')*100 + int(name[i+2]-'0')*10 + int(name[i+3]-'0')
				if n < 256 {
					b.WriteByte(byte(n))
					i += 3
					continue
				}
			}
			i++
			b.WriteByte(name[i])
			continue
		}
		b.WriteByte(c)
	}
	return strings.ToLower(b.String())
}

func fq(parts ...string) string { return strings.Join(parts, ".") + "." }

func (a answerer) hostName() string { return fq(a.cfg.Host, "local") }

// hostFor is the .local host one record points at: its own, or the config's.
func (a answerer) hostFor(r Record) string {
	if r.Host != "" {
		return fq(r.Host, "local")
	}
	return a.hostName()
}

// hostNames is every distinct host the record set names, so the address records
// ghostd publishes follow the SRV targets rather than a name nothing points at.
func (a answerer) hostNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range a.cfg.Records {
		if h := a.hostFor(r); !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

// hostForName resolves an already-normalized queried name to the host it names.
func (a answerer) hostForName(name string) (string, bool) {
	for _, host := range a.hostNames() {
		if norm(host) == name {
			return host, true
		}
	}
	return "", false
}

func (a answerer) instanceName(r Record) string {
	return fq(r.Instance, r.Service, "local")
}

func (a answerer) hostRecords(iface, host string) []dns.RR {
	ips, err := a.addrs(iface)
	if err != nil {
		return nil
	}
	var out []dns.RR
	for _, p := range ips {
		ip := p.Addr()
		h := dns.RR_Header{Name: host, Class: dns.ClassINET | 0x8000, Ttl: ttlHost}
		if ip.Is4() {
			h.Rrtype = dns.TypeA
			out = append(out, &dns.A{Hdr: h, A: net.IP(ip.AsSlice())})
		} else {
			h.Rrtype = dns.TypeAAAA
			out = append(out, &dns.AAAA{Hdr: h, AAAA: net.IP(ip.AsSlice())})
		}
	}
	return out
}

func (a answerer) instanceRecords(r Record) (srv, txt dns.RR) {
	name := a.instanceName(r)
	srv = &dns.SRV{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET | 0x8000, Ttl: ttlHost}, Port: r.Port, Target: a.hostFor(r)}
	strs := r.TXT
	if len(strs) == 0 {
		strs = []string{""} // RFC 6763: an empty TXT record is a single zero-length string
	}
	txt = &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET | 0x8000, Ttl: ttlService}, Txt: strs}
	return
}

func (a answerer) ptr(owner string, r Record) dns.RR {
	return &dns.PTR{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttlService}, Ptr: a.instanceName(r)}
}

// all returns every record ghostd advertises on an interface: the announcement.
func (a answerer) all(iface string, ttl uint32) []dns.RR {
	var out []dns.RR
	types := map[string]bool{}
	for _, r := range a.cfg.Records {
		out = append(out, a.ptr(fq(r.Service, "local"), r))
		for _, sub := range r.Subtypes {
			out = append(out, a.ptr(fq(sub, "_sub", r.Service, "local"), r))
		}
		srv, txt := a.instanceRecords(r)
		out = append(out, srv, txt)
		types[r.Service] = true
	}
	for svc := range types {
		out = append(out, &dns.PTR{Hdr: dns.RR_Header{Name: enumerateName, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttlService}, Ptr: fq(svc, "local")})
	}
	for _, host := range a.hostNames() {
		out = append(out, a.hostRecords(iface, host)...)
	}
	if ttl != ttlService {
		for _, rr := range out {
			rr.Header().Ttl = ttl
		}
	}
	return out
}

// Answer produces the response for a query received on iface, or nil when
// there is nothing to say. Known-answer suppression (RFC 6762 7.1) applies to
// shared PTR records.
func (a answerer) Answer(q *dns.Msg, iface string) *dns.Msg {
	if q.Response || q.Opcode != dns.OpcodeQuery {
		return nil
	}
	known := map[string]bool{}
	for _, k := range q.Answer {
		if k.Header().Ttl >= ttlService/2 {
			known[strings.ToLower(k.String())] = false
			if p, ok := k.(*dns.PTR); ok {
				known[norm(p.Hdr.Name)+"|"+norm(p.Ptr)] = true
			}
		}
	}
	resp := new(dns.Msg)
	resp.Response, resp.Authoritative = true, true
	haveAnswer := map[string]bool{}
	add := func(list *[]dns.RR, rr dns.RR) {
		key := strings.ToLower(rr.String())
		if haveAnswer[key] {
			return
		}
		haveAnswer[key] = true
		*list = append(*list, rr)
	}
	for _, question := range q.Question {
		name := norm(question.Name)
		want := func(t uint16) bool { return question.Qtype == t || question.Qtype == dns.TypeANY }
		if name == enumerateName && want(dns.TypePTR) {
			for _, rr := range a.all(iface, ttlService) {
				if p, ok := rr.(*dns.PTR); ok && norm(p.Hdr.Name) == name {
					add(&resp.Answer, rr)
				}
			}
			continue
		}
		if want(dns.TypeA) || want(dns.TypeAAAA) {
			if host, ok := a.hostForName(name); ok {
				for _, rr := range a.hostRecords(iface, host) {
					if want(rr.Header().Rrtype) {
						add(&resp.Answer, rr)
					}
				}
				continue
			}
		}
		for _, r := range a.cfg.Records {
			srv, txt := a.instanceRecords(r)
			owners := []string{fq(r.Service, "local")}
			for _, sub := range r.Subtypes {
				owners = append(owners, fq(sub, "_sub", r.Service, "local"))
			}
			for _, owner := range owners {
				if norm(owner) == name && want(dns.TypePTR) {
					p := a.ptr(owner, r)
					if known[norm(owner)+"|"+norm(p.(*dns.PTR).Ptr)] {
						continue
					}
					add(&resp.Answer, p)
					add(&resp.Extra, srv)
					add(&resp.Extra, txt)
					for _, h := range a.hostRecords(iface, a.hostFor(r)) {
						add(&resp.Extra, h)
					}
				}
			}
			if norm(a.instanceName(r)) == name {
				if want(dns.TypeSRV) {
					add(&resp.Answer, srv)
					for _, h := range a.hostRecords(iface, a.hostFor(r)) {
						add(&resp.Extra, h)
					}
				}
				if want(dns.TypeTXT) {
					add(&resp.Answer, txt)
				}
			}
		}
	}
	if len(resp.Answer) == 0 {
		return nil
	}
	return resp
}

// conflicts reports whether a response from another host claims one of the
// names ghostd is about to advertise (a probing failure, RFC 6762 section 8).
func (a answerer) conflicts(resp *dns.Msg) string {
	if !resp.Response {
		return ""
	}
	mine := map[string]bool{}
	for _, host := range a.hostNames() {
		mine[norm(host)] = true
	}
	for _, r := range a.cfg.Records {
		mine[norm(a.instanceName(r))] = true
	}
	for _, rr := range append(append([]dns.RR{}, resp.Answer...), resp.Extra...) {
		h := rr.Header()
		if !mine[norm(h.Name)] {
			continue
		}
		switch h.Rrtype {
		case dns.TypeSRV, dns.TypeTXT, dns.TypeA, dns.TypeAAAA:
			return h.Name
		}
	}
	return ""
}

var probeGap = 250 * time.Millisecond

func (c Config) validateReflect() error {
	if len(c.Reflect) > 32 {
		return fmt.Errorf("mdns: at most 32 reflect rules")
	}
	networks := map[string]bool{}
	for _, r := range c.Reflect {
		for _, n := range []string{r.LAN, r.Network} {
			if n == "" || len(n) > 15 || strings.ContainsAny(n, " /") {
				return fmt.Errorf("mdns: bad reflect interface %q", n)
			}
		}
		if r.LAN == r.Network {
			return fmt.Errorf("mdns: reflect lan and network are both %s", r.LAN)
		}
		if networks[r.Network] {
			return fmt.Errorf("mdns: network %s has two reflect rules; a network is one permission set, list its services once", r.Network)
		}
		networks[r.Network] = true
		if (len(r.AllowServices) == 0 && r.Advertise == nil) || len(r.AllowServices) > 32 {
			return fmt.Errorf("mdns: network %s needs 1..32 allow_services", r.Network)
		}
		for _, s := range r.AllowServices {
			if !serviceRE.MatchString(s) {
				return fmt.Errorf("mdns: %q is not a service class like _ipp._tcp", s)
			}
		}
		if r.Advertise != nil {
			if err := r.Advertise.validate(); err != nil {
				return fmt.Errorf("mdns: network %s: %w", r.Network, err)
			}
		}
	}
	for _, r := range c.Reflect {
		if networks[r.LAN] {
			return fmt.Errorf("mdns: %s is both a LAN and a container network", r.LAN)
		}
	}
	return nil
}

package addressbook

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// FileReader abstracts the filesystem so conversion is testable and previewable.
type FileReader struct {
	ReadFile func(path string) (string, error)
	ListDir  func(path string) ([]string, error)
}

// OSFiles reads the real filesystem.
var OSFiles = FileReader{
	ReadFile: func(p string) (string, error) { b, e := os.ReadFile(p); return string(b), e },
	ListDir: func(p string) ([]string, error) {
		entries, e := os.ReadDir(p)
		var names []string
		for _, en := range entries {
			if !en.IsDir() {
				names = append(names, filepath.Join(p, en.Name()))
			}
		}
		return names, e
	},
}

// FlattenDNSmasq expands conf-file= and conf-dir= includes, in dnsmasq's own
// order, into one text. Includes nest at most five deep and every file is
// visited once, so a cycle cannot recurse. conf-dir skips editor and package
// backup names (leading '.', trailing '~', '#name#') and the suffixes listed
// after the directory, as dnsmasq does.
func FlattenDNSmasq(path string, fs FileReader) (string, error) {
	seen := map[string]bool{}
	var out []string
	var walk func(p string, depth int) error
	walk = func(p string, depth int) error {
		if depth > 5 {
			return fmt.Errorf("dnsmasq includes nest deeper than 5 at %s", p)
		}
		p = filepath.Clean(p)
		if seen[p] {
			return fmt.Errorf("dnsmasq include cycle or repeat at %s", p)
		}
		seen[p] = true
		text, e := fs.ReadFile(p)
		if e != nil {
			return e
		}
		for _, line := range strings.Split(text, "\n") {
			trimmed := strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			key, value, _ := strings.Cut(trimmed, "=")
			switch key {
			case "conf-file":
				if e := walk(value, depth+1); e != nil {
					return e
				}
			case "conf-dir":
				fields := strings.Split(value, ",")
				files, e := fs.ListDir(fields[0])
				if e != nil {
					return e
				}
				sort.Strings(files)
			files:
				for _, f := range files {
					base := filepath.Base(f)
					if strings.HasPrefix(base, ".") || strings.HasSuffix(base, "~") || (strings.HasPrefix(base, "#") && strings.HasSuffix(base, "#")) {
						continue
					}
					for _, ext := range fields[1:] {
						if strings.HasSuffix(base, strings.TrimPrefix(strings.TrimSpace(ext), "*")) {
							continue files
						}
					}
					if e := walk(f, depth+1); e != nil {
						return e
					}
				}
			default:
				out = append(out, line)
			}
		}
		return nil
	}
	if e := walk(path, 0); e != nil {
		return "", e
	}
	return strings.Join(out, "\n"), nil
}

// ConvertPlan is the previewable result of reading a dnsmasq configuration.
type ConvertPlan struct {
	Target   Config     `json:"target"`
	Legacy   LegacySpec `json:"legacy"`
	Warnings []string   `json:"warnings,omitempty"`
}

// ConvertOptions supplies what the file alone cannot: the server address of
// each interface and the unit being replaced.
type ConvertOptions struct {
	Files  FileReader
	Unit   string
	Addrs  func(iface string) ([]netip.Prefix, error)
	Config string
}

// InterfaceAddrs reads addresses from the running host.
func InterfaceAddrs(iface string) ([]netip.Prefix, error) {
	i, e := net.InterfaceByName(iface)
	if e != nil {
		return nil, e
	}
	addrs, e := i.Addrs()
	if e != nil {
		return nil, e
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if p, e := netip.ParsePrefix(a.String()); e == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

func parseDNSmasqDuration(s string) (int, error) {
	if s == "infinite" {
		return 0, fmt.Errorf("infinite leases are not supported by the converted scope")
	}
	mult := 1
	if n := len(s); n > 0 {
		switch s[n-1] {
		case 's':
			s = s[:n-1]
		case 'm':
			mult, s = 60, s[:n-1]
		case 'h':
			mult, s = 3600, s[:n-1]
		case 'd':
			mult, s = 86400, s[:n-1]
		case 'w':
			mult, s = 604800, s[:n-1]
		}
	}
	v, e := strconv.Atoi(s)
	if e != nil || v <= 0 {
		return 0, fmt.Errorf("unsupported lease lifetime")
	}
	return v * mult, nil
}

// ConvertDNSmasq turns an explicit dnsmasq configuration into a target plan,
// and refuses — before anything is stopped — every semantic it cannot preserve.
// The plan is only returned if the same validator that guards the takeover
// accepts it, so a plan that previews cleanly will also begin cleanly.
func ConvertDNSmasq(path string, o ConvertOptions) (ConvertPlan, error) {
	plan := ConvertPlan{Legacy: LegacySpec{Unit: o.Unit, ConfigPath: path}}
	text, e := FlattenDNSmasq(path, o.Files)
	if e != nil {
		return plan, e
	}
	var interfaces []string
	var ranges [][]string
	var hosts [][]string
	var globalZone, routerOpt string
	zoneFor := map[string]string{}
	ra := false
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		bad := func(why string) error {
			return fmt.Errorf("unsupported dnsmasq directive %q (%s); convert it by hand or remove it", key+"="+value, why)
		}
		switch key {
		case "interface":
			interfaces = append(interfaces, value)
		case "except-interface", "no-dhcp-interface":
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s=%s excludes that interface from DHCP; no scope is generated for it", key, value))
			interfaces = removeString(interfaces, value)
		case "domain":
			f := strings.Split(value, ",")
			if len(f) == 1 {
				globalZone = f[0]
			} else if len(f) == 2 {
				zoneFor[f[1]] = f[0]
			} else {
				return plan, bad("domain with range is not supported")
			}
		case "dhcp-leasefile":
			plan.Legacy.LeasePath = value
		case "dhcp-range":
			f := strings.Split(value, ",")
			if len(f) != 4 {
				return plan, bad("use explicit start,end,netmask/prefix,lifetime; tags, static and interface: ranges need manual conversion")
			}
			ranges = append(ranges, f)
		case "dhcp-option":
			f := strings.Split(value, ",")
			if len(f) != 2 {
				return plan, bad("multi-value or tagged options are scoped in ways a scope cannot express")
			}
			switch f[0] {
			case "option:router", "3":
				routerOpt = f[1]
			case "option:dns-server", "6":
				// A scope's DNS server is its own address; the validator checks equality.
			default:
				return plan, bad("only router and dns-server options are carried over")
			}
		case "dhcp-host":
			f := strings.Split(value, ",")
			if len(f) != 3 {
				return plan, bad("use MAC,address,name")
			}
			hosts = append(hosts, f)
		case "enable-ra":
			ra = true
		case "bind-interfaces", "no-resolv", "no-hosts", "log-dhcp", "log-queries", "dhcp-authoritative", "pid-file", "user", "group":
		default:
			return plan, fmt.Errorf("line %d: dnsmasq directive %q needs explicit conversion before takeover", n+1, key)
		}
	}
	if plan.Legacy.LeasePath == "" {
		return plan, fmt.Errorf("explicit dhcp-leasefile required")
	}
	if len(ranges) == 0 {
		return plan, fmt.Errorf("no dhcp-range: nothing to take over")
	}
	used := map[string]bool{}
	devices := map[string]bool{}
	for _, r := range ranges {
		start, e1 := netip.ParseAddr(r[0])
		end, e2 := netip.ParseAddr(r[1])
		if e1 != nil || e2 != nil {
			return plan, fmt.Errorf("invalid dhcp-range addresses %s..%s", r[0], r[1])
		}
		var prefix netip.Prefix
		if start.Is4() {
			mask := net.ParseIP(r[2]).To4()
			if mask == nil {
				return plan, fmt.Errorf("invalid netmask %q", r[2])
			}
			ones, _ := net.IPMask(mask).Size()
			prefix = netip.PrefixFrom(start, ones).Masked()
		} else {
			bits, e := strconv.Atoi(r[2])
			if e != nil {
				return plan, fmt.Errorf("invalid IPv6 prefix length %q", r[2])
			}
			prefix = netip.PrefixFrom(start, bits).Masked()
		}
		life, e := parseDNSmasqDuration(r[3])
		if e != nil {
			return plan, fmt.Errorf("range %s..%s: %w", r[0], r[1], e)
		}
		// Find the serving interface and address.
		var iface string
		var server netip.Addr
		for _, name := range interfaces {
			addrs, e := o.Addrs(name)
			if e != nil {
				return plan, fmt.Errorf("interface %s: %w", name, e)
			}
			for _, a := range addrs {
				if a.Addr().Is4() == start.Is4() && prefix.Contains(a.Addr()) && !a.Addr().IsLinkLocalUnicast() {
					iface, server = name, a.Addr()
				}
			}
		}
		if iface == "" {
			return plan, fmt.Errorf("range %s..%s: no listed interface has an address inside %s (add interface= or the address)", r[0], r[1], prefix)
		}
		zone := globalZone
		for cidr, z := range zoneFor {
			if p, e := netip.ParsePrefix(cidr); e == nil && p.Overlaps(prefix) {
				zone = z
			}
		}
		if zone == "" {
			return plan, fmt.Errorf("range %s..%s: no domain= applies; scopes need a local zone", r[0], r[1])
		}
		id := iface
		if start.Is6() {
			id += "-6"
		}
		if used[id] {
			return plan, fmt.Errorf("two ranges on %s: converted scopes must be one per interface and family", iface)
		}
		used[id] = true
		s := Scope{ID: id, Interface: iface, Subnet: prefix.String(), Server: server.String(), Start: start.String(), End: end.String(), Zone: zone, LeaseSeconds: life, Enabled: true}
		if start.Is4() {
			s.Router = server.String() // dnsmasq's own default
			if routerOpt != "" {
				if ra, e := netip.ParseAddr(routerOpt); e == nil && prefix.Contains(ra) {
					s.Router = routerOpt
				}
			}
		} else {
			s.PreferredSeconds = life
			if ra {
				s.RA = &RAConfig{Interval: 30, RouterLifetime: 1800}
				plan.Warnings = append(plan.Warnings, "enable-ra is carried over with interval 30s and router lifetime 1800s; check them against the network, and IPv6 forwarding must be on")
			}
		}
		for _, h := range hosts {
			addr, e := netip.ParseAddr(h[1])
			if e != nil || !prefix.Contains(addr) {
				continue
			}
			mac, e := net.ParseMAC(h[0])
			if e != nil {
				return plan, fmt.Errorf("dhcp-host: invalid MAC %q", h[0])
			}
			if !labelPattern.MatchString(h[2]) {
				return plan, fmt.Errorf("dhcp-host: name %q is not a valid device label", h[2])
			}
			if !devices[h[2]] {
				devices[h[2]] = true
				plan.Target.Devices = append(plan.Target.Devices, DeviceConfig{ID: h[2], Name: h[2]})
			}
			s.Reservations = append(s.Reservations, Reservation{Client: "mac:" + mac.String(), Address: addr.String(), Device: h[2]})
		}
		plan.Target.Scopes = append(plan.Target.Scopes, s)
	}
	for _, h := range hosts {
		addr, _ := netip.ParseAddr(h[1])
		placed := false
		for _, s := range plan.Target.Scopes {
			if netip.MustParsePrefix(s.Subnet).Contains(addr) {
				placed = true
			}
		}
		if !placed {
			return plan, fmt.Errorf("dhcp-host %s,%s,%s lies outside every converted range", h[0], h[1], h[2])
		}
	}
	if e = plan.Target.Validate(); e != nil {
		return plan, fmt.Errorf("converted target invalid: %w", e)
	}
	if e = ValidateDNSmasqConfig(plan.Target, text, plan.Legacy.LeasePath); e != nil {
		return plan, fmt.Errorf("converted target does not reproduce the legacy behaviour: %w", e)
	}
	return plan, nil
}

func removeString(in []string, v string) []string {
	var out []string
	for _, s := range in {
		if s != v {
			out = append(out, s)
		}
	}
	return out
}

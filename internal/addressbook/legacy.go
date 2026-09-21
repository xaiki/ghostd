package addressbook

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type LegacySpec struct {
	Unit       string `json:"unit"`
	ConfigPath string `json:"config_path"`
	LeasePath  string `json:"lease_path"`
}

type SystemDNSmasq struct{ Spec LegacySpec }

func (l SystemDNSmasq) command(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, e := exec.CommandContext(ctx, "systemctl", args...).CombinedOutput()
	if e != nil {
		return "", fmt.Errorf("systemctl %s: %w: %s", strings.Join(args, " "), e, strings.TrimSpace(string(raw)))
	}
	return strings.TrimSpace(string(raw)), nil
}
func (l SystemDNSmasq) Stop() error {
	// Persistently mask the old authority so a reboot cannot start two allocators.
	if _, e := l.command("mask", l.Spec.Unit); e != nil {
		return e
	}
	if _, e := l.command("stop", l.Spec.Unit); e != nil {
		return e
	}
	state, e := l.command("show", l.Spec.Unit, "--property=ActiveState", "--value")
	if e != nil {
		return e
	}
	if state != "inactive" && state != "failed" {
		return fmt.Errorf("dnsmasq did not stop: %s", state)
	}
	return nil
}
func (l SystemDNSmasq) Start() error {
	if _, e := l.command("unmask", l.Spec.Unit); e != nil {
		return e
	}
	if _, e := l.command("start", l.Spec.Unit); e != nil {
		return e
	}
	// Type=simple can acknowledge start before dnsmasq has bound its sockets, and
	// "active" only proves a process exists. Rollback is complete only when the
	// service's own process holds the DHCP server socket (UDP 67 or 547).
	deadline := time.Now().Add(servingTimeout)
	var last error
	for {
		time.Sleep(200 * time.Millisecond)
		state, e := l.command("show", l.Spec.Unit, "--property=ActiveState", "--value")
		if e != nil {
			return e
		}
		if state != "active" {
			return fmt.Errorf("dnsmasq startup failed: %s", state)
		}
		pidText, e := l.command("show", l.Spec.Unit, "--property=MainPID", "--value")
		if e != nil {
			return e
		}
		pid, _ := strconv.Atoi(pidText)
		owns, e := processOwnsUDPPort(pid, 67, 547)
		if owns {
			return nil
		}
		last = e
		if time.Now().After(deadline) {
			if last == nil {
				last = fmt.Errorf("its process holds no DHCP server socket")
			}
			return fmt.Errorf("dnsmasq is active but not serving DHCP: %w", last)
		}
	}
}

// servingTimeout bounds how long a restarted legacy allocator gets to bind.
var servingTimeout = 10 * time.Second

func (l SystemDNSmasq) ReadLeases() (string, error) {
	raw, e := os.ReadFile(l.Spec.LeasePath)
	return string(raw), e
}
func (l SystemDNSmasq) WriteLeases(text string) error {
	// Lstat: replacing a symlink by rename would silently redirect the file.
	info, e := os.Lstat(l.Spec.LeasePath)
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("lease path %s is not a regular file", l.Spec.LeasePath)
	}
	f, e := os.CreateTemp(filepath.Dir(l.Spec.LeasePath), ".ghostd-leases-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(info.Mode().Perm()); e != nil {
		f.Close()
		return e
	}
	if _, e = f.WriteString(text); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		if e = os.Chown(f.Name(), int(st.Uid), int(st.Gid)); e != nil {
			return e
		}
	}
	if e = os.Rename(f.Name(), l.Spec.LeasePath); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(l.Spec.LeasePath))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}
func (l SystemDNSmasq) Validate(c Config) error {
	if !regexp.MustCompile(`^dnsmasq(?:@[a-zA-Z0-9_.-]+)?\.service$`).MatchString(l.Spec.Unit) {
		return fmt.Errorf("expected dnsmasq service unit")
	}
	for _, p := range []string{l.Spec.ConfigPath, l.Spec.LeasePath} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fmt.Errorf("legacy paths must be absolute")
		}
		info, e := os.Lstat(p)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("legacy path must be a regular file")
		}
	}
	command, e := l.command("show", l.Spec.Unit, "--property=ExecStart", "--value")
	if e != nil {
		return e
	}
	if !strings.Contains(command, "dnsmasq") || !regexp.MustCompile(`(?:=|\s)`+regexp.QuoteMeta(l.Spec.ConfigPath)+`(?:\s|;|$)`).MatchString(command) {
		return fmt.Errorf("unit ExecStart must explicitly name the checked dnsmasq config")
	}
	// Includes are followed, so what is validated is what dnsmasq would read.
	text, e := FlattenDNSmasq(l.Spec.ConfigPath, OSFiles)
	if e != nil {
		return e
	}
	return ValidateDNSmasqConfig(c, text, l.Spec.LeasePath)
}

// ValidateDNSmasqConfig refuses implicit defaults and includes: takeover must
// account for every served scope and option, not silently lose hidden settings.
func ValidateDNSmasqConfig(c Config, text, leasePath string) error {
	ranges := map[string]bool{}
	interfaces := map[string]bool{}
	domains := map[string]bool{}
	scopedDomains := map[netip.Prefix]string{}
	excluded := map[string]bool{}
	lease := false
	ra := false
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		switch key {
		case "interface":
			interfaces[value] = true
		case "domain":
			f := strings.Split(value, ",")
			switch len(f) {
			case 1:
				domains[value] = true
			case 2:
				p, e := netip.ParsePrefix(f[1])
				if e != nil {
					return fmt.Errorf("scoped domain needs a CIDR, got %q", f[1])
				}
				scopedDomains[p.Masked()] = f[0]
			default:
				return fmt.Errorf("unsupported domain directive %q", value)
			}
		case "except-interface", "no-dhcp-interface":
			excluded[value] = true
		case "dhcp-leasefile":
			if value != leasePath {
				return fmt.Errorf("lease path differs from config")
			}
			lease = true
		case "dhcp-range":
			f := strings.Split(value, ",")
			if len(f) != 4 {
				return fmt.Errorf("use explicit start,end,netmask/prefix,lifetime ranges")
			}
			found := false
			for _, s := range c.Scopes {
				if s.Start == f[0] && s.End == f[1] {
					p := netip.MustParsePrefix(s.Subnet)
					if p.Addr().Is6() {
						bits, e := strconv.Atoi(f[2])
						if e != nil || bits != p.Bits() {
							return fmt.Errorf("legacy IPv6 prefix differs")
						}
					} else {
						mask := net.ParseIP(f[2]).To4()
						if mask == nil {
							return fmt.Errorf("invalid legacy netmask")
						}
						ones, bits := net.IPMask(mask).Size()
						if bits != 32 || ones != p.Bits() {
							return fmt.Errorf("legacy subnet mask differs")
						}
					}
					duration := f[3]
					if _, e := strconv.Atoi(duration); e == nil {
						duration += "s"
					}
					life, e := time.ParseDuration(duration)
					if e != nil || life != time.Duration(s.LeaseSeconds)*time.Second {
						return fmt.Errorf("legacy lease lifetime differs or is unsupported")
					}

					ranges[s.ID] = true
					found = true
				}
			}
			if !found {
				return fmt.Errorf("dnsmasq range is not represented in target")
			}
		case "dhcp-option":
			f := strings.Split(value, ",")
			if len(f) != 2 {
				return fmt.Errorf("unsupported multi-value DHCP option")
			}
			matched := false
			for _, s := range c.Scopes {
				if (f[0] == "option:router" || f[0] == "3") && f[1] == s.Router {
					matched = true
				}
				if (f[0] == "option:dns-server" || f[0] == "6") && f[1] == s.Server {
					matched = true
				}
			}
			if !matched {
				return fmt.Errorf("unsupported or different DHCP option %s", f[0])
			}
		case "dhcp-host":
			f := strings.Split(value, ",")
			if len(f) != 3 {
				return fmt.Errorf("unsupported reservation; use MAC,address,name")
			}
			matched := false
			for _, s := range c.Scopes {
				for _, r := range s.Reservations {
					d, _ := c.Device(r.Device)
					if r.Client == "mac:"+strings.ToLower(f[0]) && r.Address == f[1] && d.Name == f[2] {
						matched = true
					}
				}
			}
			if !matched {
				return fmt.Errorf("reservation is absent from target")
			}
		case "enable-ra":
			ra = true
		case "bind-interfaces", "no-resolv", "no-hosts", "log-dhcp", "log-queries", "dhcp-authoritative":
		case "pid-file", "user", "group":
		default:
			return fmt.Errorf("dnsmasq directive %q needs explicit conversion before takeover", key)
		}
	}
	if !lease {
		return fmt.Errorf("explicit dhcp-leasefile required")
	}
	for _, s := range c.Scopes {
		if s.Is6() && (s.RA != nil) != ra {
			return fmt.Errorf("target must preserve explicit RA enablement")
		}
		zoneOK := domains[s.Zone]
		for p, z := range scopedDomains {
			if z == s.Zone && p.Overlaps(netip.MustParsePrefix(s.Subnet)) {
				zoneOK = true
			}
		}
		if excluded[s.Interface] {
			return fmt.Errorf("scope %s is on interface %s, which the legacy configuration excludes from DHCP", s.ID, s.Interface)
		}
		if !s.Enabled || !ranges[s.ID] || !interfaces[s.Interface] || !zoneOK {
			return fmt.Errorf("scope %s does not match explicit legacy range/interface/domain", s.ID)
		}
	}
	return nil
}

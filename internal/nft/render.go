package nft

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// ReachabilityGuard is what Apply always adds to the input chain itself,
// never something a caller's desired_state can omit or override: a hard-coded
// reachability guard, independent of the dead-man's-switch. A desired_state
// that would leave this daemon's own listener unreachable is refused before
// it is ever loaded into the kernel, not rolled back five minutes later.
// See docs/firewall.md.
type ReachabilityGuard struct {
	TailscaleInterface string
	Port               int
}

const tableName = "stack_ghostd"

// builtinServices maps a firewalld-style service name to (port, proto)
// pairs — a small, explicit set. An unrecognized name is a render error,
// never a silently-dropped rule: see Render's own doc.
var builtinServices = map[string][]PortRule{
	"mdns":          {{Port: 5353, Proto: "udp"}},
	"dns":           {{Port: 53, Proto: "tcp"}, {Port: 53, Proto: "udp"}},
	"dhcp":          {{Port: 67, Proto: "udp"}},
	"dhcpv6-client": {{Port: 546, Proto: "udp"}},
	"http":          {{Port: 80, Proto: "tcp"}},
	"https":         {{Port: 443, Proto: "tcp"}},
}

// nfsPorts is deliberately TCP-only (rpcbind, nfsd, mountd) — the common
// case for a modern NFSv4-only export; a UDP variant can be added if a
// real export ever needs it, rather than guessed at now.
var nfsPorts = []int{111, 2049, 20048}

// Render replaces only our table in one atomic nft transaction. An add is
// idempotent, so add/delete works on both the first and subsequent applies.
func Render(ds DesiredState, guard ReachabilityGuard) (string, error) {
	if !validInterface(guard.TailscaleInterface) || !validPort(guard.Port) {
		return "", fmt.Errorf("nft: invalid reachability guard")
	}
	if err := validate(ds); err != nil {
		return "", err
	}
	names := sortedZoneNames(ds.Zones)

	var b strings.Builder
	b.WriteString("# Atomic replacement: ensure the table exists, delete it, then recreate it below.\n")
	b.WriteString("# nft applies this entire file as one transaction; other tables are untouched.\n")
	fmt.Fprintf(&b, "add table inet %s\ndelete table inet %s\n", tableName, tableName)
	fmt.Fprintf(&b, "table inet %s {\n", tableName)

	if ds.RedirectOnly {
		writePreroutingChain(&b, ds)
		b.WriteString("}\n")
		return b.String(), nil
	}

	writeInputChain(&b, ds, guard, names)
	writeForwardChain(&b, ds, names)
	writeOutputChain(&b, ds.Output)
	writePreroutingChain(&b, ds)
	writePostroutingChain(&b, ds, names)
	for _, name := range names {
		if err := writeZoneChain(&b, name, ds.Zones[name]); err != nil {
			return "", err
		}
	}

	b.WriteString("}\n")
	return b.String(), nil
}

var zoneName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9_.:-]{1,15}$`)

func validInterface(name string) bool {
	return interfaceName.MatchString(name) && name != "." && name != ".."
}
func validPort(port int) bool { return port >= 1 && port <= 65535 }

func validate(ds DesiredState) error {
	if ds.RedirectOnly && (ds.Output != nil || ds.Ingress != nil) {
		return fmt.Errorf("nft: redirect-only policy cannot contain output or ingress policy")
	}
	if err := validateOutput(ds.Output); err != nil {
		return err
	}
	if len(ds.Zones) == 0 {
		return fmt.Errorf("nft: no zones declared")
	}
	if ds.Ingress != nil {
		if !validPort(ds.Ingress.HTTPPort) || len(ds.Ingress.Interfaces) == 0 {
			return fmt.Errorf("nft: ingress requires interfaces and a valid HTTP port")
		}
		for _, iface := range ds.Ingress.Interfaces {
			if !validInterface(iface) {
				return fmt.Errorf("nft: invalid ingress interface %q", iface)
			}
		}
	}
	assigned := map[string]string{}
	hasReachableZone := false
	for name, zone := range ds.Zones {
		if ds.RedirectOnly && (zone.SSH != nil || zone.NFS != nil || len(zone.Services) > 0 || len(zone.Ports) > 0 || len(zone.Forward) > 0 || zone.Masquerade || (zone.Target != "" && zone.Target != "DROP")) {
			return fmt.Errorf("nft: redirect-only zone cannot contain filtering or forwarding policy")
		}
		if !zoneName.MatchString(name) {
			return fmt.Errorf("nft: invalid zone name %q", name)
		}
		if zone.Target != "" && !strings.EqualFold(zone.Target, "DROP") && !strings.EqualFold(zone.Target, "ACCEPT") {
			return fmt.Errorf("nft: invalid target %q", zone.Target)
		}
		for _, iface := range zone.Interfaces {
			if !validInterface(iface) {
				return fmt.Errorf("nft: invalid interface %q", iface)
			}
			if previous, ok := assigned[iface]; ok {
				return fmt.Errorf("nft: interface %q repeated in zones %q and %q", iface, previous, name)
			}
			assigned[iface] = name
		}
		if zone.SSH != nil && !validPort(zone.SSH.Port) {
			return fmt.Errorf("nft: invalid SSH port")
		}
		for _, rule := range zone.Ports {
			if !validPort(rule.Port) || (rule.Proto != "tcp" && rule.Proto != "udp") {
				return fmt.Errorf("nft: invalid port rule %+v", rule)
			}
		}
		seenRedirects := map[string]bool{}
		for _, rule := range zone.Redirects {
			key := fmt.Sprintf("%s/%d", rule.Proto, rule.Port)
			if !validPort(rule.Port) || !validPort(rule.ToPort) || rule.Port == rule.ToPort || (rule.Proto != "tcp" && rule.Proto != "udp") || seenRedirects[key] {
				return fmt.Errorf("nft: invalid or duplicate redirect %+v", rule)
			}
			seenRedirects[key] = true
		}
		if zone.NFS != nil {
			for _, source := range zone.NFS.Exports {
				prefix, err := netip.ParsePrefix(source)
				addr, addrErr := netip.ParseAddr(source)
				if (err != nil || !prefix.Addr().Is4()) && (addrErr != nil || !addr.Is4()) {
					return fmt.Errorf("nft: NFS source must be an IPv4 address or CIDR: %q", source)
				}
			}
		}

		if name == "trusted" || zone.SSH != nil {
			hasReachableZone = true
		}
		for _, egress := range zone.Forward {
			if _, ok := ds.Zones[egress]; !ok {
				return fmt.Errorf("nft: zone %q forwards to undeclared zone %q", name, egress)
			}
		}
		for _, svc := range zone.Services {
			if _, ok := builtinServices[svc]; !ok {
				return fmt.Errorf("nft: zone %q declares unrecognized service %q", name, svc)
			}
		}
		if len(zone.Interfaces) == 0 {
			return fmt.Errorf("nft: zone %q declares no interfaces", name)
		}
	}
	if !hasReachableZone && !ds.RedirectOnly {
		return fmt.Errorf("nft: no zone declares ssh (and no zone is named \"trusted\") — this host would be unreachable")
	}
	return nil
}

func sortedZoneNames(zones map[string]Zone) []string {
	names := make([]string, 0, len(zones))
	for name := range zones {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedStrings(items []string) []string {
	out := append([]string(nil), items...)
	sort.Strings(out)
	return out
}

func ifaceSet(interfaces []string) string {
	quoted := make([]string, len(interfaces))
	for i, iface := range sortedStrings(interfaces) {
		quoted[i] = fmt.Sprintf("%q", iface)
	}
	return "{ " + strings.Join(quoted, ", ") + " }"
}

func writeInputChain(b *strings.Builder, ds DesiredState, guard ReachabilityGuard, names []string) {
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority 0; policy drop;\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    iifname \"lo\" accept\n")
	// Rootful Podman bridges reach the host resolver through input; rootless
	// forwarding originates on the host and uses the loopback rule above.
	// ghostd binds DNS only to its tailnet address, never the public address.
	b.WriteString("    iifname \"podman*\" udp dport 53 accept\n")
	b.WriteString("    iifname \"podman*\" tcp dport 53 accept\n")
	// IPv6 addressing needs NDP/RA even when no application service is open.
	// Neighbor/router discovery is link-local in scope (hop limit 255); ICMP
	// errors are required for path MTU discovery and transport correctness.
	b.WriteString("    meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept\n")
	b.WriteString("    meta l4proto ipv6-icmp icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } ip6 hoplimit 255 accept\n")
	// The reachability guard: hardcoded here, never derived from
	// ds.Zones, so a desired_state that never mentions the tailnet
	// interface at all still leaves this daemon reachable.
	if guard.TailscaleInterface != "" && guard.Port != 0 {
		fmt.Fprintf(b, "    iifname %q tcp dport %d accept\n", guard.TailscaleInterface, guard.Port)
	}
	for _, name := range names {
		zone := ds.Zones[name]
		fmt.Fprintf(b, "    iifname %s jump zone_%s\n", ifaceSet(zone.Interfaces), name)
	}
	if ds.Ingress != nil && len(ds.Ingress.Interfaces) > 0 {
		fmt.Fprintf(b, "    iifname %s tcp dport { %d, 8443 } accept\n",
			ifaceSet(ds.Ingress.Interfaces), ds.Ingress.HTTPPort)
	}
	b.WriteString("  }\n")
}

func writeForwardChain(b *strings.Builder, ds DesiredState, names []string) {
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0; policy drop;\n")
	b.WriteString("    ct state established,related accept\n")
	for _, name := range names {
		zone := ds.Zones[name]
		for _, egress := range sortedStrings(zone.Forward) {
			fmt.Fprintf(b, "    iifname %s oifname %s accept\n",
				ifaceSet(zone.Interfaces), ifaceSet(ds.Zones[egress].Interfaces))
		}
	}
	b.WriteString("  }\n")
}

func writePreroutingChain(b *strings.Builder, ds DesiredState) {
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority -100;\n")
	for _, name := range sortedZoneNames(ds.Zones) {
		zone := ds.Zones[name]
		for _, iface := range sortedStrings(zone.Interfaces) {
			for _, rule := range zone.Redirects {
				fmt.Fprintf(b, "    iifname %q fib daddr type local %s dport %d redirect to :%d\n", iface, rule.Proto, rule.Port, rule.ToPort)
			}
		}
	}
	if ds.Ingress != nil {
		for _, iface := range sortedStrings(ds.Ingress.Interfaces) {
			fmt.Fprintf(b, "    iifname %q fib daddr type local tcp dport 80 dnat to :%d\n", iface, ds.Ingress.HTTPPort)
			fmt.Fprintf(b, "    iifname %q fib daddr type local tcp dport 443 dnat to :8443\n", iface)
		}
	}
	b.WriteString("  }\n")
}

func writePostroutingChain(b *strings.Builder, ds DesiredState, names []string) {
	b.WriteString("  chain postrouting {\n")
	b.WriteString("    type nat hook postrouting priority 100;\n")
	for _, name := range names {
		zone := ds.Zones[name]
		if zone.Masquerade {
			for _, iface := range sortedStrings(zone.Interfaces) {
				fmt.Fprintf(b, "    oifname %q masquerade\n", iface)
			}
		}
	}
	b.WriteString("  }\n")
}

func writeZoneChain(b *strings.Builder, name string, zone Zone) error {
	fmt.Fprintf(b, "  chain zone_%s {\n", name)
	if name == "trusted" {
		// The one intentional builtin reuse (docs/firewall.md): full
		// accept, matching firewalld's own trusted-zone convention this
		// schema was already written against.
		b.WriteString("    accept\n")
		b.WriteString("  }\n")
		return nil
	}
	if zone.SSH != nil {
		fmt.Fprintf(b, "    tcp dport %d accept\n", zone.SSH.Port)
	}
	for _, rule := range zone.Redirects {
		fmt.Fprintf(b, "    ct status dnat meta l4proto %s ct original proto-dst %d %s dport %d accept\n", rule.Proto, rule.Port, rule.Proto, rule.ToPort)
	}
	if zone.NFS != nil {
		for _, export := range sortedStrings(zone.NFS.Exports) {
			ports := make([]string, len(nfsPorts))
			for i, p := range nfsPorts {
				ports[i] = fmt.Sprintf("%d", p)
			}
			fmt.Fprintf(b, "    ip saddr %s tcp dport { %s } accept\n", export, strings.Join(ports, ", "))
		}
	}
	for _, svc := range sortedStrings(zone.Services) {
		for _, rule := range builtinServices[svc] {
			fmt.Fprintf(b, "    %s dport %d accept\n", rule.Proto, rule.Port)
		}
	}
	for _, rule := range zone.Ports {
		fmt.Fprintf(b, "    %s dport %d accept\n", rule.Proto, rule.Port)
	}
	if strings.EqualFold(zone.Target, "ACCEPT") {
		b.WriteString("    accept\n")
	}
	b.WriteString("  }\n")
	return nil
}

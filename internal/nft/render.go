package nft

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/xaiki/ghostd/internal/wellknown"
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
// serviceReplyPorts are source ports a service's peers answer from. mDNS
// responders reply to a legacy-unicast query from the mDNS port straight to the
// asker's ephemeral port, which conntrack does not associate with the multicast
// question; without this, ghostd's own native .local client is silent behind
// its own default-drop policy. Only unprivileged destination ports are opened.
var serviceReplyPorts = map[string][]PortRule{
	"mdns": {{Port: wellknown.PortMDNS, Proto: "udp"}},
}

var builtinServices = map[string][]PortRule{
	"mdns":          {{Port: wellknown.PortMDNS, Proto: "udp"}},
	"tftp":          {{Port: wellknown.PortTFTP, Proto: "udp"}},
	"dns":           {{Port: wellknown.PortDNS, Proto: "tcp"}, {Port: wellknown.PortDNS, Proto: "udp"}},
	"dhcp":          {{Port: wellknown.PortDHCPv4Server, Proto: "udp"}},
	"dhcpv6-client": {{Port: wellknown.PortDHCPv6Client, Proto: "udp"}},
	"http":          {{Port: wellknown.PortHTTP, Proto: "tcp"}},
	"https":         {{Port: wellknown.PortHTTPS, Proto: "tcp"}},
}

// nfsPorts is deliberately TCP-only (rpcbind, nfsd, mountd) — the common
// case for a modern NFSv4-only export; a UDP variant can be added if a
// real export ever needs it, rather than guessed at now.
var nfsPorts = []int{wellknown.PortRPCBind, wellknown.PortNFS, wellknown.PortMountd}

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

	writeTFTPHelper(&b, ds, names)
	writeInputChain(&b, ds, guard, names)
	writeForwardChain(&b, ds, names)
	writeOutputChain(&b, ds.Output)
	writePreroutingChain(&b, ds)
	writeIngressOutputChain(&b, ds)
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
	if ds.RedirectOnly && (ds.Output != nil || ds.Ingress != nil || ds.AllowDNATForward) {
		return fmt.Errorf("nft: redirect-only policy cannot contain output or ingress policy")
	}
	if err := validateOutput(ds.Output); err != nil {
		return err
	}
	if len(ds.Zones) == 0 {
		return fmt.Errorf("nft: no zones declared")
	}
	if ds.Ingress != nil {
		if len(ds.Ingress.Interfaces) == 0 || len(ds.Ingress.Redirects) == 0 {
			return fmt.Errorf("nft: ingress requires interfaces and the ports to redirect")
		}
		for _, iface := range ds.Ingress.Interfaces {
			if !validInterface(iface) {
				return fmt.Errorf("nft: invalid ingress interface %q", iface)
			}
		}
		seenIngress := map[int]bool{}
		for _, rule := range ds.Ingress.Redirects {
			if !validPort(rule.Port) || !validPort(rule.ToPort) || rule.Port == rule.ToPort || rule.Proto != "tcp" || seenIngress[rule.Port] {
				return fmt.Errorf("nft: invalid or duplicate ingress redirect %+v", rule)
			}
			seenIngress[rule.Port] = true
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

// ingressOutputDestinations is the destination scope of the locally generated
// redirect: the private and tailnet ranges the standalone stack_ingress table
// covered, never the loopback or public ones.
var ingressOutputDestinations = []struct{ family, prefix string }{
	{"ip", wellknown.TailnetCGNAT4},
	{"ip6", wellknown.TailnetULA6},
	{"ip", "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }"},
	{"ip6", "fc00::/7"},
}

// sortedIngressRedirects makes wire order stable, so the same policy renders
// the same ruleset twice.
func sortedIngressRedirects(ingress *Ingress) []RedirectRule {
	redirects := append([]RedirectRule(nil), ingress.Redirects...)
	sort.Slice(redirects, func(i, j int) bool { return redirects[i].Port < redirects[j].Port })
	return redirects
}

// backendPorts is the deduplicated set of translated ports the input chain
// must accept for the interfaces that carry the ingress.
func backendPorts(ingress *Ingress) []int {
	seen := map[int]bool{}
	ports := []int{}
	for _, rule := range sortedIngressRedirects(ingress) {
		if !seen[rule.ToPort] {
			seen[rule.ToPort] = true
			ports = append(ports, rule.ToPort)
		}
	}
	sort.Ints(ports)
	return ports
}

func portSet(ports []int) string {
	parts := make([]string, len(ports))
	for i, port := range ports {
		parts[i] = strconv.Itoa(port)
	}
	return strings.Join(parts, ", ")
}

func writeInputChain(b *strings.Builder, ds DesiredState, guard ReachabilityGuard, names []string) {
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority 0; policy drop;\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    iifname \"lo\" accept\n")
	// Rootful Podman bridges reach the host resolver through input; rootless
	// forwarding originates on the host and uses the loopback rule above.
	// ghostd binds DNS only to its tailnet address, never the public address.
	fmt.Fprintf(b, "    iifname \"podman*\" udp dport %d accept\n", wellknown.PortDNS)
	fmt.Fprintf(b, "    iifname \"podman*\" tcp dport %d accept\n", wellknown.PortDNS)
	// A container's own mDNS has to reach the host too, for the relay to carry
	// it anywhere: a bridge is not a zone (the schema takes explicit interface
	// names, never a glob), so it is admitted here, beside the DNS rules above.
	// The port is the boundary, as it is for a zone's own mdns service, and it
	// cannot be the group address instead: the relay's forwarded question leaves
	// from the mDNS port, so a responder that answers it directly (the QU bit)
	// answers to that port as well, and a group-scoped rule would drop exactly
	// that answer. UDP 5353, the same podman* bridges, nothing wider.
	fmt.Fprintf(b, "    iifname \"podman*\" udp dport %d accept\n", wellknown.PortMDNS)
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
	if ds.Ingress != nil && len(ds.Ingress.Redirects) > 0 {
		fmt.Fprintf(b, "    iifname %s tcp dport { %s } accept\n",
			ifaceSet(ds.Ingress.Interfaces), portSet(backendPorts(ds.Ingress)))
	}
	b.WriteString("  }\n")
}

func writeForwardChain(b *strings.Builder, ds DesiredState, names []string) {
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0; policy drop;\n")
	b.WriteString("    ct state established,related accept\n")
	if ds.AllowDNATForward {
		b.WriteString("    ct status dnat accept\n")
	}
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
			for _, rule := range sortedIngressRedirects(ds.Ingress) {
				fmt.Fprintf(b, "    iifname %q fib daddr type local tcp dport %d dnat to :%d\n",
					iface, rule.Port, rule.ToPort)
			}
		}
	}
	b.WriteString("  }\n")
}

// writeIngressOutputChain covers what the prerouting redirect cannot see: a
// packet this host generates itself never traverses prerouting, so the
// interface-scoped DNAT above leaves the machine unable to reach its own
// ingress address -- and so does anything already running on it. The rootful
// stack_ingress table this daemon replaced wrote the same rules into both the
// prerouting and output hooks for exactly that reason, with the same
// destination scope: local destinations in the private and tailnet ranges,
// never the loopback or public ones. Redirect, not DNAT, so the rewritten
// destination is the loopback address the ingress backend itself listens on.
func writeIngressOutputChain(b *strings.Builder, ds DesiredState) {
	if ds.Ingress == nil || len(ds.Ingress.Redirects) == 0 {
		return
	}
	b.WriteString("  chain output_redirect {\n")
	b.WriteString("    type nat hook output priority -100;\n")
	for _, rule := range sortedIngressRedirects(ds.Ingress) {
		for _, destination := range ingressOutputDestinations {
			fmt.Fprintf(b, "    fib daddr type local %s daddr %s tcp dport %d redirect to :%d\n",
				destination.family, destination.prefix, rule.Port, rule.ToPort)
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
		for _, rule := range serviceReplyPorts[svc] {
			fmt.Fprintf(b, "    %s sport %d %s dport 1024-65535 accept\n", rule.Proto, rule.Port, rule.Proto)
		}
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

// writeTFTPHelper attaches the kernel's TFTP conntrack helper to inbound
// requests on zones that open the tftp service. A TFTP server answers from a
// fresh ephemeral port, so without the helper the client's ACKs to that port
// would fall to the default-drop input policy: the helper is what turns them
// into ct state related, which the input chain already accepts.
func writeTFTPHelper(b *strings.Builder, ds DesiredState, names []string) {
	var ifaces []string
	for _, name := range names {
		for _, svc := range ds.Zones[name].Services {
			if svc == "tftp" {
				ifaces = append(ifaces, ds.Zones[name].Interfaces...)
			}
		}
	}
	if len(ifaces) == 0 {
		return
	}
	b.WriteString("  ct helper ghost_tftp {\n    type \"tftp\" protocol udp\n  }\n")
	b.WriteString("  chain tftp_helper {\n    type filter hook prerouting priority -300; policy accept;\n")
	fmt.Fprintf(b, "    iifname %s udp dport %d ct helper set \"ghost_tftp\"\n  }\n", ifaceSet(ifaces), wellknown.PortTFTP)
}

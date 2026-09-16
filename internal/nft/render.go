package nft

import (
	"fmt"
	"sort"
	"strings"
)

// ReachabilityGuard is what Apply always adds to the input chain itself,
// never something a caller's desired_state can omit or override — the
// "hard-coded reachability guard, independent of the dead-man's-switch"
// FIREWALL.md requires: a desired_state that would leave this daemon's own
// listener unreachable is refused before it is ever loaded into the
// kernel, not rolled back five minutes later.
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

// Render turns a validated DesiredState into a complete nft(8) script —
// one atomic `table inet stack_ghostd { ... }` definition, replacing
// whatever this table held before (nft loads a script transactionally: a
// `table inet X { ... }` block with the same name as an existing table
// replaces it in one kernel transaction, never a flicker of "table
// missing"). Callers must still run `nft -c -f -` on the result before
// ever loading it (see internal/rpc.Server.Apply) — this function renders,
// it does not validate nft's own grammar.
//
// Every zone is walked in sorted name order and every interface list is
// rendered in sorted order — nft ruleset text becomes part of what
// Confirm persists as "last-confirmed state" (see internal/rpc.Server),
// so two renders of the same DesiredState must produce byte-identical
// text for that persistence to be meaningful.
func Render(ds DesiredState, guard ReachabilityGuard) (string, error) {
	if err := validate(ds); err != nil {
		return "", err
	}
	names := sortedZoneNames(ds.Zones)

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", tableName)

	writeInputChain(&b, ds, guard, names)
	writeForwardChain(&b, ds, names)
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

func validate(ds DesiredState) error {
	if len(ds.Zones) == 0 {
		return fmt.Errorf("nft: no zones declared")
	}
	hasReachableZone := false
	for name, zone := range ds.Zones {
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
	if !hasReachableZone {
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
	if ds.Ingress != nil {
		for _, iface := range sortedStrings(ds.Ingress.Interfaces) {
			fmt.Fprintf(b, "    iifname %q tcp dport 80 dnat to :%d\n", iface, ds.Ingress.HTTPPort)
			fmt.Fprintf(b, "    iifname %q tcp dport 443 dnat to :8443\n", iface)
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
		// The one intentional builtin reuse (docs/ops/firewall.md): full
		// accept, matching firewalld's own trusted-zone convention this
		// schema was already written against.
		b.WriteString("    accept\n")
		b.WriteString("  }\n")
		return nil
	}
	if zone.SSH != nil {
		fmt.Fprintf(b, "    tcp dport %d accept\n", zone.SSH.Port)
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

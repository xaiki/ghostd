package nft

import (
	"fmt"
	"net/netip"
	"strings"
)

func validateOutput(output *OutputPolicy) error {
	if output == nil {
		return nil
	}
	if output.Policy != "DROP" && output.Policy != "ACCEPT" {
		return fmt.Errorf("nft: output policy must be DROP or ACCEPT")
	}
	for _, rule := range output.Rules {
		if !validPort(rule.Port) || (rule.Proto != "tcp" && rule.Proto != "udp") {
			return fmt.Errorf("nft: invalid output port/protocol")
		}
		if rule.Family != "" && rule.Family != "ip" && rule.Family != "ip6" {
			return fmt.Errorf("nft: invalid output family")
		}
		if rule.Interface != "" && !validInterface(rule.Interface) {
			return fmt.Errorf("nft: invalid output interface")
		}
		if rule.Destination != "" {
			addr, err := netip.ParseAddr(rule.Destination)
			if err != nil {
				prefix, e := netip.ParsePrefix(rule.Destination)
				if e != nil {
					return fmt.Errorf("nft: invalid output destination")
				}
				addr = prefix.Addr()
			}
			if addr.Zone() != "" || rule.Family == "ip" && !addr.Is4() || rule.Family == "ip6" && addr.Is4() {
				return fmt.Errorf("nft: output destination family mismatch")
			}
		}
	}
	return nil
}

func writeOutputChain(b *strings.Builder, output *OutputPolicy) {
	if output == nil {
		return
	}
	b.WriteString("  chain output {\n")
	fmt.Fprintf(b, "    type filter hook output priority 0; policy %s;\n", strings.ToLower(output.Policy))
	if output.EstablishedRelated {
		b.WriteString("    ct state established,related accept\n")
	}
	if output.Loopback {
		b.WriteString("    oifname \"lo\" accept\n")
	}
	for _, rule := range output.Rules {
		b.WriteString("    ")
		if rule.Family != "" {
			family := "ipv4"
			if rule.Family == "ip6" {
				family = "ipv6"
			}
			fmt.Fprintf(b, "meta nfproto %s ", family)
		}
		if rule.Interface != "" {
			fmt.Fprintf(b, "oifname %q ", rule.Interface)
		}
		if rule.Destination != "" {
			family := "ip"
			if strings.Contains(rule.Destination, ":") {
				family = "ip6"
			}
			fmt.Fprintf(b, "%s daddr %s ", family, rule.Destination)
		}
		fmt.Fprintf(b, "%s dport %d accept\n", rule.Proto, rule.Port)
	}
	b.WriteString("  }\n")
}

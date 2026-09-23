// Package wellknown names the protocol ports and address conventions ghostd
// relies on, so a value is referenced by what it is rather than by its number.
// Protocols are reassigned and address conventions move: a literal copied into
// five packages is five places to get one change wrong, while a name is one.
//
// The package is deliberately untagged and dependency-free: mdns, nft, resolver,
// addressbook and the daemon all need these names, and several of them sit
// behind mutually exclusive build tags.
package wellknown

import (
	"net"
	"strconv"
)

// Well-known transport ports, by the protocol that owns them.
const (
	PortDNS          = 53   // DNS
	PortDHCPv4Server = 67   // DHCP/BOOTP server
	PortDHCPv4Client = 68   // DHCP/BOOTP client
	PortTFTP         = 69   // TFTP
	PortHTTP         = 80   // HTTP
	PortHTTPS        = 443  // HTTPS
	PortDHCPv6Client = 546  // DHCPv6 client
	PortDHCPv6Server = 547  // DHCPv6 server
	PortMDNS         = 5353 // multicast DNS
)

// The NFS stack's ports: rpcbind, nfsd and mountd.
const (
	PortRPCBind = 111
	PortNFS     = 2049
	PortMountd  = 20048
)

// IPv6 multicast groups ghostd joins or sends to.
const (
	MDNSGroup4         = "224.0.0.251" // mDNS
	MDNSGroup6         = "ff02::fb"    // mDNS
	AllNodes6          = "ff02::1"     // all-nodes, link-local
	AllRouters6        = "ff02::2"     // all-routers, link-local
	DHCPv6RelayAgents6 = "ff02::1:2"   // All_DHCP_Relay_Agents_and_Servers
)

// Address conventions of the tailnet overlay (Tailscale and the tailscaled a
// Headscale-managed host still runs).
const (
	// Quad100 is tailscaled's own resolver, serving a node's MagicDNS and
	// split-DNS names.
	Quad100 = "100.100.100.100"
	// TailnetCGNAT4 and TailnetULA6 are the address space a tailnet node is given.
	TailnetCGNAT4 = "100.64.0.0/10"
	TailnetULA6   = "fd7a:115c:a1e0::/48"
)

// Public resolvers the container resolver falls back to when the tailnet
// resolver answers a definite error (SERVFAIL or REFUSED) for a name rather
// than resolving it. Quad100 stays authoritative and first; these are only
// reached after it has answered and been rejected.
const (
	CloudflareResolver = "1.1.1.1"
	GoogleResolver     = "8.8.8.8"
)

// HostPort is the "host:port" form net takes, with a well-known port named
// rather than formatted at each call site.
func HostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

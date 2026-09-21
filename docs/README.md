# ghostd documentation

The [project README](../README.md) is the front page: what ghostd is, how to build
and install it, the RPC contract in brief, and the security model.

These documents go deeper.

## Design and contracts

| Document | Read it when |
| --- | --- |
| [security.md](security.md) | You are granting someone access to a host, or deciding whether a caller should be able to read state |
| [operations.md](operations.md) | You are running ghostd: RPC workflow, leases, recovery, flags, testing |
| [firewall.md](firewall.md) | You are writing a firewall target |
| [netconfig.md](netconfig.md) | You are writing an interface-configuration target |

## Working with existing hosts

| Document | Read it when |
| --- | --- |
| [adoption.md](adoption.md) | You are taking over a host that is already configured and running something else |

## DHCP, DNS and identity

| Document | Read it when |
| --- | --- |
| [dhcp.md](dhcp.md) | You are serving DHCP, publishing authoritative DNS, or replacing dnsmasq |
| [dhcp-dns-identity.md](dhcp-dns-identity.md) | You want the reasoning behind the registry, allocation and identity model |
| [dhcp-remaining.md](dhcp-remaining.md) | You are about to trust DHCP rollback on a real network, or pick up this work |
| [lan-discovery.md](lan-discovery.md) | You are wondering why containerised apps cannot see the LAN |

## Contributor references

| Document | Contents |
| --- | --- |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Build, test, lint and proto-regeneration workflow |
| [internal/resolver/PLUGINS.md](../internal/resolver/PLUGINS.md) | Extending the embedded CoreDNS and CoreDHCP plugin chains |
| [internal/coredhcpserver/README.md](../internal/coredhcpserver/README.md) | The embedded CoreDHCP server copy and its deliberate divergences from upstream |

## Conventions in these documents

- Commands assume the repository root as the working directory unless a section
  says otherwise.
- `100.64.0.10` is a placeholder for a host's tailnet address, and `deployer@example.com`
  or `node-a` for a tailnet identity. Every address in the `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24` or `10.0.0.0/8` ranges is illustrative.
- Statements about what has been verified are separated from plans and proposals.
  Where a document describes something not built, it says so at the top.
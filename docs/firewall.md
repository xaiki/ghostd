# The firewall domain

The `firewall` domain owns exactly one nftables table:

```
table inet stack_ghostd
```

A target replaces that table atomically and nothing else. Removing a port or a
zone removes its rules on the next apply, rather than leaving them behind.
Other writers' tables are excluded from both the pre-apply snapshot and the
replay, and `/etc/nftables.conf` is never touched.

Two consequences are worth knowing before you rely on it:

- Existing conntrack flows are not flushed. Withdrawing an opening does not
  terminate connections that are already established.
- An `accept` in one base chain cannot override a `drop` in another writer's base
  chain. ghostd owning its own table does not make it the only firewall on the
  host. Arrange ownership and boot ordering with any other firewall manager
  before relying on ghostd's reachability guard.

## Rendering without root

The renderer is available as a standalone mode — no root, no tailscaled, no host
changes:

```sh
bin/ghostd --render-firewall < firewall.json > firewall.nft
sudo nft -c -f firewall.nft   # Linux: syntax check only
```

The RPC performs this same syntax check before arming a lease, so a target that
would not render is rejected without touching the host.

## Target shape

```json
{
  "zones": {
    "trusted": {"interfaces": ["tailscale0"]},
    "lan": {
      "interfaces": ["eth0"],
      "ssh": {"port": 22},
      "ports": [{"port": 53, "proto": "udp"}, {"port": 53, "proto": "tcp"}],
      "forward": ["wan"]
    },
    "wan": {"interfaces": ["eth1"], "masquerade": true}
  }
}
```

Interface names and policy must be adjusted for the host. The client owns
service discovery, VLAN placement, plugin activation and port-catalogue lookup;
the daemon has no dependency on any particular policy generator.

### Zones

- A zone name is an identifier. Interfaces must be explicit names, and each is
  assigned to at most one zone.
- `trusted` accepts all input from its interfaces, by convention. More generally
  `target: "ACCEPT"` permits all remaining input in that zone;
  `target: "DROP"` is the default.
- Zones other than `trusted` allow their declared TCP/UDP ports and SSH, with
  input otherwise dropping.
- At least one zone must declare SSH, or be named `trusted`. A policy cannot leave
  the host with no way in.
- Every rendered policy also permits ghostd's own TCP port on its configured
  Tailscale interface. This is the reachability guard: the apply path always
  leaves its own listener reachable, so a bad policy does not silently cut off
  the confirmation that would cancel it.

Independent of zone services, every rendered policy permits loopback,
established and related input, IPv6 error traffic, and IPv6 neighbour and router
discovery with hop limit 255.

### Forwarding and masquerade

Forwarding defaults to drop, except established/related flows and explicit
zone-to-zone `forward` declarations, which name an egress zone that must exist.
`masquerade: true` applies NAT on that zone's egress interfaces.

Kernel forwarding must also be enabled separately — that is the `sysctl` action
in the [netconfig](netconfig.md) domain, not a firewall feature.

### Services

Legacy `services` names are `mdns`, `tftp`, `dns`, `dhcp`, `dhcpv6-client`, `http`
and `https`. Two of them open more than their own port:

- `mdns` opens UDP 5353 **and** admits UDP source port 5353 to unprivileged
  destination ports. mDNS responders answer a legacy-unicast query straight to the
  asker's ephemeral port, which conntrack does not associate with the multicast
  question; without this, ghostd's own native `.local` resolution is silent behind a
  default-drop input policy.
- `tftp` opens UDP 69 and attaches the kernel TFTP conntrack helper (a
  `ct helper` object and a prerouting rule) so a TFTP server's replies from an
  ephemeral port, and the client's ACKs to it, are `ct state related`. Load the
  `nf_conntrack_tftp` module on hosts where it is not autoloaded. `nfs: {"exports": ["10.0.0.0/24"]}` permits TCP 111, 2049 and 20048 from
those IPv4 CIDRs. For anything else, supply explicit `ports`.

### Ingress

```json
"ingress": {"interfaces": ["eth0"], "http_port": 18080}
```

This redirects host-destined TCP 80 to `http_port` and TCP 443 to **8443**, and
admits those destination ports on those interfaces. Traffic forwarded through the
host to another machine is not redirected.

### Port redirects

A zone can publish a rootless listener on a privileged port:

```json
"redirects": [{"port": 514, "to_port": 15514, "proto": "udp"}]
```

Incoming host-destined traffic on that zone's interfaces is redirected to
`to_port`, and only the translated flow is admitted. The backend port is not
opened directly — a `trusted` or `ACCEPT` zone keeps whatever broad access it
already had. TCP and UDP, IPv4 and IPv6 are supported. Locally originated traffic
is not redirected. Removing the declaration removes the redirect on the next
apply.

This exists so a rootless container can serve on a low port without lowering
`net.ipv4.ip_unprivileged_port_start`.

### Output policy

Output filtering is opt-in. Omitting `output` keeps the historical unfiltered
output path:

```json
"output": {
  "policy": "DROP",
  "established_related": true,
  "loopback": true,
  "rules": [{"proto": "tcp", "port": 443, "family": "ip", "interface": "eth0",
             "destination": "192.0.2.0/24"}]
}
```

`policy` is `DROP` or `ACCEPT`. Each rule narrows by protocol and port, and
optionally by address family (`ip` or `ip6`), interface, and destination address
or CIDR. No input service is implicitly allowed outbound, and omitted booleans
mean false.

## Versioned domains

A client that needs a field an older daemon does not know sends the target under
a versioned domain name instead of `firewall`, so the request is rejected
outright rather than mis-rendered:

| Domain | Sent when the target contains |
| --- | --- |
| `firewall` | Zones and ingress only |
| `firewall-output-v1` | An `output` section |
| `firewall-redirect-v1` | `redirect_only: true` for NAT-only adoption |

The daemon renders all three through the same code path and normalizes them onto
the same firewall lease, so atomic table replacement, fresh-connection
confirmation and rollback cover them identically. There is no legacy fallback:
an older daemon rejects the versioned name.

## Redirect-only adoption

`redirect_only: true`, combined with interface-scoped zones and `redirects`,
manages only the NAT rules it needs in the owned table. It preserves the host's
existing filtering instead of replacing it, which is what makes it usable on a
host that is not yet ready for a full ghostd firewall.

Filtering fields are rejected in this mode, and it cannot replace an existing
ghostd filter table.

## Rollback

Recovery restores the pre-apply snapshot of ghostd's own table only. A failed
first apply restores the table's prior absence. See
[operations.md](operations.md) for the lease and timer mechanics.
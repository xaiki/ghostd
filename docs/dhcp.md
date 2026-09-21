# ghostd DHCP, DNS and device identity

Ghostd embeds CoreDHCP for IPv4/IPv6 and CoreDNS for authoritative lease DNS and
local-name resolution. Both use upstream plugin APIs; see the
[plugin extension guide](../internal/resolver/PLUGINS.md).
The durable bbolt ledger is shared by those plugins. It is never reverted with
configuration and has no automatic history deletion.

## Configuration

Declare `dhcp.scopes` and optional `dhcp.devices` on the authority in
machines.yaml. Each scope has a stable ID, interface, canonical subnet/prefix,
server address, start/end pool, zone, lease_seconds, enabled, and optional
reservations. Pools are bounded to 65536 addresses. Overlapping scopes on one
authority are rejected; separate authorities may use the same private ranges.
IPv6 scopes additionally require `preferred_seconds` (positive, at most the
lease lifetime). DHCPv6 uses IA_NA, a persistent server DUID, and client DUID/IAID
identities. Prefix delegation and multi-authority HA are outside this increment.

For IPv4 declare `dns` and `dhcp` on the interface's services; for IPv6 declare
`dns` and `dhcpv6`. Use the ghostd-managed firewall. The server address must already
exist on its interface. Restrictive output policies must allow replies to UDP
68/546; IPv6 requires working ICMPv6 neighbor discovery. DHCP-only apply assumes
network, firewall, ghostd and tailnet policy dependencies have already converged.

```sh
uv run machines apply AUTHORITY --plane dhcp
uv run machines apply AUTHORITY --plane dhcp --yes
```

Optional `relay: {peer: IP, link: IP}` declares one exact relay source and link.
Undeclared relays, wrong links and excessive hop counts are dropped before
allocation. Optional IPv6 `ra: {slaac: false, router_lifetime: 1800, interval: 30}`
advertises managed DHCP, prefix, DNS and search domain. A nonzero router lifetime
requires IPv6 forwarding already enabled. RA defaults are explicit; changing the
RA interface/prefix/server requires disabling it first. Setting `slaac: true`
allows kernel-generated client addresses, tracked as observations rather than
invented DHCP grants. Ghostd cannot enumerate every privacy address a host creates.

Device records support `id`, `name`, `aliases`, `tailnet_node_id` and additional
`tailnet_node_ids`. Reservations use `mac:...`, `id:<option61 hex>`, or for IPv6
`duid:<hex>/iaid:<eight hex digits>`. Names and aliases are validated and reserved.

## Transactional dnsmasq takeover

Prepare a reviewed JSON plan containing:

```json
{
  "target": {"scopes": [], "devices": []},
  "legacy": {
    "unit": "dnsmasq.service",
    "config_path": "/etc/dnsmasq.conf",
    "lease_path": "/var/lib/misc/dnsmasq.leases"
  },
  "seconds": 600
}
```

Populate `target` with the real enabled scopes/reservations. Existing ghostd
scopes must be disabled. The systemd unit must explicitly reference the inspected
single config file in ExecStart. Includes, hidden defaults and unsupported options
are refused: convert and review them before takeover. Supported legacy declarations
include explicit ranges, interfaces, domain, lease file, router/DNS options,
MAC/address/name reservations and RA enablement. This is a checked conversion,
not a general-purpose dnsmasq configuration translator.

```sh
uv run machines net dhcp-handover AUTHORITY --action begin --plan handover.json
uv run machines net dhcp-handover AUTHORITY --action begin --plan handover.json --yes
uv run machines net dhcp-handover AUTHORITY --action status
```

Begin persists recovery intent, masks/stops dnsmasq, reads its final lease file,
imports live leases and server DUID, then activates ghostd. Infinite leases remain
occupied. Imported start times are labelled as observation times. During the
pending window, test real client renewal, fresh allocation and LAN DNS. Then:

```sh
uv run machines net dhcp-handover AUTHORITY --action confirm --yes
```

Confirmation rechecks authoritative DNS over UDP and TCP. DHCP client tests must
be initiated on the affected LAN; the controller cannot manufacture a real client
there. Without confirmation, the daemon's recovery loop rolls back at the deadline.
An interrupted rollback is retried after restart. Systemd must supervise ghostd;
recovery cannot execute while the machine or daemon is down. The persistent dnsmasq
mask prevents the old allocator starting alongside ghostd during reboot.

```sh
uv run machines net dhcp-handover AUTHORITY --action rollback --yes
```

Rollback closes ghostd listeners, exports the **current** ledger (including new
grants, offers and quarantine), writes it with the original lease-file ownership,
and only then unmasks/restarts dnsmasq. Failed rollback remains visible and
retryable. Original configuration and registry history are retained.
Do not independently re-enable an authority during this transaction.

For manual adoption, `net import-leases AUTHORITY FILE --scope ID [--yes]` supports
both families and preserves server DUID; the selected scope must be disabled.
`net export-leases AUTHORITY --scope ID` requires a disabled scope and refuses
pending offers/quarantine; use transactional rollback for those cases.

## Tailnet identity

On reporting hosts set `ghostd.identity_authority: AUTHORITY` (a tailnet name or
IP; optional port). The deployed daemon reports its active interfaces every
minute. A standalone invocation also works:

```
/opt/smarthome/ghostd/ghostd --report-to AUTHORITY
```

The authority's `ghostd.reporters` accepts explicit user/group/tag selectors,
using `ghostd.policy_destinations` for its exact tailnet IPs. Existing tailnet
policy reconciliation emits a separate `ghostd.local/cap/report` capability;
this does **not** grant deploy permission. Apply that policy before reporting.
Deployer identities can also report their own interfaces.

The authority uses tailscaled WhoIs for stable node ID, DNS name and tailnet IPs.
The request cannot supply another node's identity. A report is correlated with an
active DHCP lease when MAC/address match, or a fresh kernel neighbor corroborates
a DUID without a MAC. Kernel-generated/static addresses are recorded separately
and can be associated through a matching authenticated report. Reservations can
supply explicit device IDs, names and optional `tailnet_node_id`. Hostnames from
DHCP clients are recorded as claims and never merge devices. Conflicting
associations are rejected, recorded as conflict events and left unchanged.
This is attribution from authorized hosts, not cryptographic proof of LAN address
ownership or a substitute for network access controls.

Without trusted identity evidence, devices use stable generated names. With a
matching report, a host such as node-a becomes `node-a.home.arpa`; its LAN lease and
current tailnet node/address list appear in one registry snapshot. Tailnet
addresses remain in the tailnet namespace rather than being mixed into LAN A
answers. Reporting does not turn static/SLAAC addresses into DHCP-issued leases.

## Inspecting ownership

```
uv run machines net leases AUTHORITY
uv run machines net leases AUTHORITY --scope lan --ip 192.0.2.100 --json
uv run machines net leases AUTHORITY --ip 192.0.2.100 --at 2026-09-20T15:00:00Z --json
uv run machines net lease-events AUTHORITY --after 0 --limit 100
```

The example address above is illustrative. Lookups return state, canonical device,
claimed name, expiry, origin and association evidence. Historical binding answers
use persisted events; node sightings in a snapshot are current and carry `seen`,
not a claim of historical node state. Events have increasing IDs for pagination.
No automatic history pruning is performed; monitor ledger disk use and back up
`addressbook.db` using a consistent filesystem snapshot or while ghostd is stopped.
The database belongs to ghostd's state directory and is never part of configuration
rollback. Do not delete it to reset a configuration problem.

Authoritative answers are evaluated before the recursive DNS cache. Only active
leases are published; release/expiry removes A/PTR answers. TTL is bounded by
30 seconds and remaining lease lifetime; unknown local names return authoritative
NXDOMAIN rather than escaping upstream. Configured LAN listeners support UDP/TCP
53. Local DHCP and authoritative DNS can continue while Tailscale is unavailable;
recursive queries through Quad100 and the remote control API still require it.

## Verification

Go tests cover DORA, DNS lifecycle, renewal/decline/import, concurrent allocation,
identity conflicts, authorization, configuration rollback and crash-after-ACK
recovery. The opt-in `TestLinuxListenerAndPortOwnership` runs in a disposable Linux
container with `--network none`, binding loopback DHCP/DNS ports and testing UDP/TCP,
port conflicts and disable without losing leases. It does not exercise physical
LAN broadcast delivery, client diversity or real firewall policy: perform those
checks on the test VLAN before production cutover.


## Identity repair

`machines net repair-identity AUTHORITY changes.json [--yes]` previews or applies
an array of explicit binding edits. Each edit includes `scope`, `address`,
`client`, `expected_device`, `device`, `name`, `tailnet_node_id` (empty to unlink),
and `reason`. Selecting several bindings supports merge/split operations. The
transaction rejects stale ownership and inventory conflicts; past events are not
rewritten. Only deployers may repair, import or control handover. Self-reporters
cannot choose another node's identity or perform those operations.

## Reproducible isolated acceptance test

Run `ghostd/tests/dhcp-lab/run.sh` with Podman (set `GHOSTD_LAB_ARCH=amd64` for an
AMD64 VM). It creates a disposable privileged container with **no external
network**, then independent client network namespaces. It runs real dnsmasq and
ISC dhclient, CoreDHCP takeover, authoritative UDP/TCP DNS, restart and rollback,
RA, SLAAC evidence, failure/deadline recovery, and declared/invalid relay packets.
It repeats those checks with a real systemd service, including persistent masking
and rollback startup verification. Privileges are for those isolated virtual
interfaces; no production interface or authority is changed. Unit/race tests
separately exercise durability, concurrency, IPv6 lifecycle and identity repair.
Per-container DNS ACL identity is a separate prerequisite, not supplied by DHCP.

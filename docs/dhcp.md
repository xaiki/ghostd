# DHCP, DNS and device identity

The optional `dhcp-v1` domain serves explicitly declared IPv4 and IPv6 scopes with
authoritative DNS and a durable lease, identity and event ledger. It embeds
CoreDHCP for the DHCP side and CoreDNS for authoritative lease DNS and local-name
resolution; both are driven through their upstream plugin APIs, described in
[the plugin extension guide](../internal/resolver/PLUGINS.md).

The ledger is never reverted with configuration and has no automatic history
deletion. A configuration rollback leaves granted leases exactly where they are:
rewinding them would hand out addresses clients still believe they own.

The domain is entirely optional. A host that only needs firewalling and netconfig
never declares a scope, and the daemon serves no DHCP on it.

## Configuration

The whole configuration is the `dhcp-v1` apply target:

```json
{
  "scopes": [{
    "id": "lan",
    "interface": "eth0",
    "subnet": "192.0.2.0/24",
    "server": "192.0.2.1",
    "start": "192.0.2.100",
    "end": "192.0.2.200",
    "router": "192.0.2.1",
    "zone": "home.arpa",
    "lease_seconds": 3600,
    "enabled": true
  }],
  "devices": [{"id": "node-a", "name": "node-a"}]
}
```

Each scope has a stable ID, an interface, a canonical subnet/prefix, the server
address, the pool bounds, a zone, a lease lifetime and optional `reservations`.
Pools are limited to 65536 addresses and overlapping scopes on one authority are
rejected. IPv6 scopes additionally require `preferred_seconds`, which must be
positive and no greater than the lease lifetime. DHCPv6 uses IA_NA with a
persistent server DUID and client DUID/IAID identities. A scope's zone may not be
`.local` or `.ts.net`, and nested authoritative zones are refused.

Apply it like any other domain, so it rides the ordinary lease and rollback
machinery:

```sh
jq -n --rawfile cfg dhcp.json \
  '{domain:"dhcp-v1", desired_state_json:$cfg, dead_man_switch_seconds:300}' \
  > dhcp-apply.json
grpcurl -plaintext -import-path proto -proto ghoststate.proto -d @ \
  100.64.0.10:7443 ghostd.HostState/Apply < dhcp-apply.json
```

Then confirm it from a fresh connection, as with any other domain. A pending
handover blocks configuration changes, and a pending configuration lease blocks a
handover from starting.

To enable the server on an interface, the firewall zone for that interface must
carry the matching services: `dns` and `dhcp` for IPv4, `dns` and `dhcpv6` for
IPv6. The declared server address must already exist on the interface. A
restrictive output policy must allow replies to UDP 68/546, and IPv6 requires
working ICMPv6 neighbour discovery. Enabling DHCP assumes the network, firewall
and tailnet policy have already converged — it is the last step, not the first.

### Relays

`relay: {"peer": "<address>", "link": "<address>"}` declares exactly one relay
source and its link address. Undeclared relays, the wrong link, and excessive hop
counts are dropped before allocation. A relayed scope's server address need not be
on the direct interface.

### Router advertisements

```json
"ra": {"slaac": false, "router_lifetime": 1800, "interval": 30}
```

RA requires a direct `/64`, an interval of 4..600 seconds, and a router lifetime
of either 0 or at least three times the interval. A nonzero lifetime requires IPv6
forwarding to be enabled already. RA defaults are explicit; changing the RA
interface, prefix or server requires disabling it first. Setting `slaac: true`
lets the kernel generate client addresses, which are tracked as observations
rather than invented DHCP grants — the daemon cannot enumerate every privacy
address a host creates.

### Devices and reservations

A device record has `id`, `name`, optional `aliases`, an optional
`tailnet_node_id`, and additional `tailnet_node_ids`. Names and aliases are
validated; collisions with a declared name, and the reserved name `ns`, are
refused.

Reservations bind a client to an address using `mac:...`, `id:<option-61 hex>`
for IPv4, or `duid:<hex>/iaid:<eight hex digits>` for IPv6. The client family must
match the scope's family.

## Transactional dnsmasq takeover

Replacing a running dnsmasq is a migration with two allocators competing for one
pool, so it is a transaction with its own grace period rather than an apply.

Prepare a reviewed plan, populating `target` with the real enabled scopes and
reservations:

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

Any scope already enabled in ghostd must be disabled first. The legacy unit must
reference the inspected single config file directly in its `ExecStart`: includes,
hidden defaults and unsupported options are refused, because a checked conversion
is not the same thing as a general-purpose dnsmasq configuration translator.
Supported legacy declarations are explicit ranges, interfaces, domain, lease
file, router/DNS options, MAC/address/name reservations, and RA enablement.

```sh
# begin
jq -n '{action:"begin",
        target:{scopes:[],devices:[]},
        legacy:{unit:"dnsmasq.service", config_path:"/etc/dnsmasq.conf",
                lease_path:"/var/lib/misc/dnsmasq.leases"},
        seconds:600}' > handover-request.json
grpcurl -plaintext -import-path proto -proto ghoststate.proto -d @ \
  100.64.0.10:7443 ghostd.HostState/DHCPHandover < handover-request.json

# status
grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  -d '{"action":"status"}' 100.64.0.10:7443 ghostd.HostState/DHCPHandover
```

`begin` persists its recovery intent, masks and stops dnsmasq, reads its final
lease file, imports the live leases and the server DUID, and then activates
ghostd. Infinite leases stay occupied, and imported start times are labelled as
observation times rather than being invented.

During the pending window, test real client renewal, a fresh allocation and LAN
DNS **from the affected LAN** — the controller cannot manufacture a real client
there. Then confirm:

```sh
grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  -d '{"action":"confirm"}' 100.64.0.10:7443 ghostd.HostState/DHCPHandover
```

Confirmation rechecks authoritative DNS over both UDP and TCP. Without it, the
daemon's recovery loop rolls the takeover back at the deadline; an interrupted
rollback is retried after restart. Systemd must supervise ghostd, since recovery
cannot run while the machine or the daemon is down. The persistent dnsmasq mask
is what prevents the old allocator starting alongside ghostd during a reboot.

```sh
grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  -d '{"action":"rollback"}' 100.64.0.10:7443 ghostd.HostState/DHCPHandover
```

Rollback closes the ghostd listeners, exports the **current** ledger — including
new grants, offers and quarantine — writes it with the original lease-file
ownership, and only then unmasks and restarts dnsmasq. A failed rollback stays
visible and retryable. The original configuration and the registry history are
retained.

Do not independently re-enable the authority during this transaction.

### Manual lease import

For adoption outside the transaction, `ImportLeases` imports leases and a server
DUID. The selected scope must be disabled first, and a single request is limited
to 10000 leases. Each lease needs at least a `scope` and an `address`, plus the
client identity the scope uses:

```json
{"server_duid": "00:01:00:01:2a:2b:2c:2d:<hex>",
 "leases": [{"scope": "lan", "address": "192.0.2.100", "mac": "02:00:5e:10:00:01",
             "client_id": "<option-61 hex>", "hostname": "node-a", "expiry": 1758384000}]}
```

```sh
jq -n --argjson doc "$(cat import.json)" '{json:($doc|tojson)}' > import-request.json
grpcurl -plaintext -import-path proto -proto ghoststate.proto -d @ \
  100.64.0.10:7443 ghostd.HostState/ImportLeases < import-request.json
```

A bare array of lease objects is also accepted in place of the document. IPv6
leases carry `duid` and `iaid` instead of `mac`, and require the server DUID.

There is no separate export RPC. Exporting the current ledger is what the handover
rollback path does internally before handing back to the legacy allocator. For
other cases, read the ledger through `GetRegistry` and back up `addressbook.db`
with a consistent filesystem snapshot. A disabled scope refuses pending offers and
quarantine entries, which is exactly why those cases must go through the rollback
path instead.

## Tailnet identity

A host can report its own interfaces to an authority, which is how a LAN lease
gets attributed to a known tailnet node. The identity in a report is resolved by
the *receiver* using `WhoIs`; the sender describes interfaces and can never choose
which tailnet node it claims to represent.

Set the authority in the reporting host's daemon environment:

```
GHOSTD_IDENTITY_AUTHORITY=100.64.0.10
```

The daemon then reports its active interfaces once a minute. A one-shot report
from the command line does the same thing:

```sh
/opt/ghostd/ghostd --report-to 100.64.0.10
```

A report is only ever sent to an address that resolves into the tailnet range; the
command refuses to send one to a LAN or public address, where plaintext gRPC would
lack the tailnet's protection.

The authority side needs a `ghostd.local/cap/report` grant for the reporting
hosts, with a body of `{"report": true}` — see [security.md](security.md).
Reporting does **not** grant deploy permission. Apply that policy before
reporting; deployers can also report their own interfaces.

The authority correlates a report with an active DHCP lease when the MAC or
address matches, or when a fresh kernel neighbour entry corroborates a DUID with
no MAC. Kernel-generated and static addresses are recorded separately, and can be
associated later through a matching authenticated report. Hostnames supplied by
DHCP clients are recorded as claims and never merge devices. Conflicting
associations are rejected, recorded as conflict events, and left unchanged.

This is attribution from authorized hosts. It is not cryptographic proof of LAN
address ownership, and it is not a substitute for network access controls.

Without trusted identity evidence, devices keep stable generated names. With a
matching report, a host such as `node-a` becomes `node-a.home.arpa`, and its LAN
lease plus its current tailnet node and address list appear in one registry
snapshot. Tailnet addresses stay in the tailnet namespace rather than being mixed
into LAN A answers, and reporting never converts a static or SLAAC address into a
DHCP-issued lease.

## Inspecting ownership

`GetRegistry` is read-only and needs no deployer permission. Called without event
parameters it returns a snapshot; with `after_event` and `event_limit` it returns
the event stream:

```sh
# Snapshot, optionally filtered by scope or address
grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  -d '{"scope":"lan","address":"192.0.2.100"}' \
  100.64.0.10:7443 ghostd.HostState/GetRegistry

# What held an address at a past instant
grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  -d '{"address":"192.0.2.100","at_unix":1758380400}' \
  100.64.0.10:7443 ghostd.HostState/GetRegistry

# Events, with increasing IDs for pagination
grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  -d '{"after_event":0,"event_limit":100}' \
  100.64.0.10:7443 ghostd.HostState/GetRegistry
```

The example addresses here are illustrative. Lookups return state, canonical
device, claimed name, expiry, origin and association evidence. Historical binding
answers come from persisted events; node sightings inside a snapshot are current
and carry `seen` rather than a claim about the past.

Events have increasing IDs for pagination, and no automatic pruning is performed.
Monitor the ledger's disk use and back up `addressbook.db` using a consistent
filesystem snapshot, or while ghostd is stopped. The database belongs to the
daemon's state directory, is never part of configuration rollback, and must not be
deleted to "reset" a configuration problem.

## Identity repair

`RepairIdentity` previews or applies an array of explicit binding edits. Each edit
carries `scope`, `address`, `client`, `expected_device`, `device`, `name`,
`tailnet_node_id` (empty to unlink), and `reason`:

```sh
jq -n --argjson changes "$(cat changes.json)" '{json:($changes|tojson)}' \
  > repair-request.json
grpcurl -plaintext -import-path proto -proto ghoststate.proto -d @ \
  100.64.0.10:7443 ghostd.HostState/RepairIdentity < repair-request.json
```

Selecting several bindings supports merge and split operations. The transaction
rejects stale ownership and inventory conflicts, and past events are never
rewritten. Only deployers may repair, import or control a handover: a
self-reporting host cannot choose another node's identity.

## Authoritative DNS

Lease answers are evaluated before the recursive cache. Only active leases are
published, and a release or expiry removes the A and PTR answers. TTL is bounded
by 30 seconds and by the remaining lease lifetime; an unknown local name gets an
authoritative NXDOMAIN rather than escaping upstream. Configured LAN listeners
answer UDP and TCP on port 53. Local DHCP and authoritative DNS keep working while
Tailscale is unavailable; recursive queries through Tailscale's Quad100 resolver,
and the remote control API, still require it.

The daemon separately runs a container resolver on port 53 **of its own tailnet
address**, described in [operations.md](operations.md). It never binds a public
wildcard and never rewrites the host's `/etc/resolv.conf`. `.local` A/AAAA queries
go through the host's NSS resolver via bounded `getent` calls, which preserves
Avahi behaviour in a static, cgo-free binary; other queries go to Quad100 and are
cached for at most 30 seconds.

Per-container DNS ACLs are not enforced. Aardvark and NAT can hide the original
container identity, so policy must not infer identity from a forwarded source
address. Any policy check must also run before the shared cache, or one
container's cached answer becomes another container's visible data. See
[lan-discovery.md](lan-discovery.md) for the identity this shares with the planned
LAN discovery domain.

## Verification

The ordinary Go test suite covers DORA, the DNS lifecycle,
renewal/decline/import, concurrent allocation, identity conflicts, authorization,
configuration rollback, and crash-after-ACK recovery. `TestLinuxListenerAndPortOwnership`
is opt-in behind `GHOSTD_DHCP_INTEGRATION` and binds loopback DHCP/DNS ports in a
disposable Linux container with no network to test UDP/TCP, port conflicts, and
disable-without-losing-leases.

The larger harness also needs Podman:

```sh
tests/dhcp-lab/run.sh
GHOSTD_LAB_ARCH=amd64 tests/dhcp-lab/run.sh   # matching AMD64 VM and image
```

It creates a disposable privileged container with **no external network** and
independent client network namespaces, then runs real dnsmasq and ISC dhclient,
CoreDHCP takeover, authoritative UDP/TCP DNS, restart and rollback, RA, SLAAC
evidence, failure and deadline recovery, and declared/invalid relay packets. It
repeats the checks against a real systemd-managed service, including persistent
masking and rollback startup verification. Keep `--network none`; never attach
this lab to a real LAN.

The lab does not exercise physical LAN broadcast delivery, client diversity, or
real firewall policy. Do those checks on a test VLAN before a production cutover.

## Current limits

Prefix delegation, multi-authority high availability, and authenticated
per-container DNS ACLs are separate increments, not gaps in the implemented
single-authority behaviour. Known defects and unverified paths in what has already
landed are listed in [dhcp-remaining.md](dhcp-remaining.md).
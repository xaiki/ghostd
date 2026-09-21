# DHCP, DNS and device identity

> **Build tags.** Everything here is optional and compiled in by tag: the DHCP
> server, authoritative DNS, identity ledger, prefix delegation, TFTP and warm
> standby need `dhcp` (which requires `coredns`); the dnsmasq takeover, converter
> and verification need `dnsmasq`; native `.local`/DNS-SD needs `mdns`; the
> per-container DNS ACL needs `coredns`. See the README's Build section. A binary
> without a tag has neither the code nor the RPCs, flags or sockets.

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

If the daemon restarts mid-takeover, boot recovery runs before the DHCP
configuration is applied: an interrupted or expired takeover is rolled back, and a
pending one whose target cannot bind is rolled back too rather than leaving the LAN
with no allocator. A rollback that fails is retried and stays visible; it never
keeps the RPC surface down.

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

Kernel neighbour sightings are history too: a first sighting, a changed MAC or a
sighting after the previous one expired appends an `observation` event (and an
`observation-end` closing the earlier one). A query with `at_unix` returns only the
sightings whose own validity window covered that instant, flagged `historical`;
current sightings carry `seen`. Configuration changes to zones, aliases or scopes
append a `dns-config` event, so the SOA serial advances with them as well as with
leases.

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

Add `"persist": true` to an edit to record a durable client association: allocation
then gives that client the device, name and tailnet node again after its lease
expires or its address changes, a later change keeps the replaced mapping in the
association's history, and `"forget": true` removes it. Inventory reservations
still win over an association. Repair validates against every declared
`tailnet_node_ids` entry and refuses a name held by another live device.

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
wildcard and never rewrites the host's `/etc/resolv.conf`. `.local` names are
resolved natively: ghostd multicasts a legacy-unicast query (RFC 6762 6.7) from an
ephemeral port on the LAN interfaces (`--mdns-interfaces`, default every up
multicast interface), collects answers for 700 ms and returns them with a TTL of at
most 30 seconds. It never binds UDP 5353, so no mDNS daemon has to be running on the
host; only if no interface can send does it fall back to the host's NSS via
`getent`. DNS-SD questions (PTR/SRV/TXT for `_type._proto.local`) are answered the
same way, with the instance's SRV/TXT/address records attached. Other queries go to
Quad100 and are cached for at most 30 seconds.

An mDNS query must be able to come back: `mdns` in a firewall zone's `services` also
admits UDP source port 5353 to unprivileged destination ports (see
[firewall.md](firewall.md)).

### Per-container DNS ACL

A source address behind a shared forwarder is not a credential, so the identity of
a query is the **resolver listener it arrived on**. Declare identities in
`dns-acl.json` in the store directory:

```json
{"identities": [
  {"name": "printing", "listen": "100.64.0.21",
   "allow_services": ["_ipp._tcp"], "allow_names": ["printers.home.arpa"]},
  {"name": "music", "listen": "100.64.0.22", "allow_services": ["_googlecast._tcp"]}
]}
```

Each identity gets its own listener address, its own server block and therefore its
own cache, and per-identity `dns-<name>.env` and `resolv-<name>.conf` in the runtime
directory to hand to that container alone. The check runs **before** lease answers
and the cache, so one container's cached answer is never another's visible data. An
identity resolves only what it lists: `allow_names` (a name and everything beneath
it; `*` means every ordinary name, never `.local`) and `allow_services` (DNS-SD
classes it may browse). Anything else is `REFUSED`. A `.local` host name is
resolvable for an identity only after a browse **that identity was allowed** named
it as a service target, and only for that identity, for two minutes. The base
resolver address stays unrestricted.

What this does and does not give you: the identity is a property of the network
path. Give each container only its own resolver address and let host firewall
policy admit only that container's source to it; ghostd cannot verify who is
holding an address. Changing the set of listener addresses needs a restart.

## Verifying a takeover with real clients

`begin` accepts `"require_evidence": true`. Confirmation then refuses until the
ledger has seen, per enabled scope since the takeover began, a client **renewal of
an inherited lease** (when the legacy pool held any) and a **fresh allocation** —
counted from the DHCP path's own `renew` and `grant` events, which only a real
client exchange writes. `status` reports what is still missing:

```sh
grpcurl ... -d '{"action":"status"}' 100.64.0.10:7443 ghostd.HostState/DHCPHandover
# {"phase":"pending","remaining_seconds":412,"retryable":false,
#  "evidence":{"lan":{"imported_leases":9,"renewals":0,"fresh_grants":0}},
#  "pending_verification":["scope lan: no client has renewed an inherited lease yet", ...],
#  "history_count":2}
```

Finished takeovers are archived (without the lease snapshot) and listed by
`{"action":"history"}`. The verification is evidence the ledger saw traffic, not
proof of routing or DNS reachability from a given client: still test those.

## Converting a dnsmasq configuration

```sh
ghostd --convert-dnsmasq=/etc/dnsmasq.conf --legacy-unit=dnsmasq.service
```

prints a handover plan (`target`, `legacy`, `warnings`) and changes nothing. It
follows `conf-file=` and `conf-dir=` (skipping dotfiles, `~` backups and listed
suffixes), determines each scope's interface and server address from the host,
takes the router option or dnsmasq's own default, and carries ranges, lifetimes,
domains (global or per subnet), `dhcp-host` reservations, `enable-ra`, `dhcp-boot`
and `enable-tftp`/`tftp-root`. It **refuses**, with the offending directive,
everything it cannot preserve: tagged or interface-limited ranges, tagged options,
options other than router and DNS server, infinite leases, unknown directives, a
missing domain or lease file, two ranges for one interface and family, and a
reservation outside every range. A plan is only printed if the same validator that
guards `begin` accepts it, so a plan that previews cleanly will also begin. The
validator follows the same includes, so a legacy configuration split over files is
no longer refused for that alone.

## Network boot (PXE/TFTP)

```json
{"scopes": [{"id": "lan", ..., "boot": {"file": "pxelinux.0", "next_server": "192.0.2.1"}}],
 "tftp": {"root": "/srv/tftp"}}
```

`boot` gives IPv4 clients siaddr, the file field and options 66/67, in offers and
acks. `tftp` runs a **read-only** TFTP server on every enabled IPv4 scope's server
address: writes are refused, names cannot leave the root (lexically or through a
symlink that resolves outside it), and only regular files up to 256 MiB are served.
Open UDP 69 with the firewall zone service `tftp`, which also attaches the kernel
TFTP conntrack helper — the server answers from an ephemeral port, which a
default-drop input policy would otherwise discard.

## Prefix delegation

```json
{"id": "lan6", "interface": "eth0", "subnet": "2001:db8:1::/64", "server": "2001:db8:1::1",
 ..., "pd": {"prefix": "2001:db8:100::/48", "length": 56, "route": true}}
```

Routers on the link can request IA_PD prefixes of `length` (32..64, at most 16 bits
below the pool, so at most 65536 delegations) from the pool, with Solicit, Request,
Renew, Rebind and Release, a hint honoured when the prefix is free, `NoPrefixAvail`
when exhausted, and T1/T2 and lifetimes as for addresses. A delegation is a ledger
binding (origin `dhcpv6-pd`, address `2001:db8:100::/56`), so its history is
queryable like a lease's, and it is attributed to the device that already holds the
same DUID's address. It never appears in DNS or a dnsmasq lease file, and a
takeover refuses a target that carries `pd`: add it with an ordinary apply after.

With `"route": true` ghostd installs `ip -6 route ... via <router link-local> proto 250`
for every live delegation (the link-local comes from the transport, or from the
relay's peer-address for a relayed request) and removes it on release or expiry. It
reconciles on each grant and periodically, which also restores routes after a
reboot, and it touches only routes carrying its own protocol number.

## Switch evidence and peer suggestions

`ImportObservations` (deployer) records DHCP-snooping / MAC-table evidence from a
switch as observations with their own `origin` (`switch-snooping`), `detail` (for
example a port) and `ttl_seconds` (10..3600, default 300). Like a kernel neighbour
sighting it corroborates an authenticated self-report and is history-tracked, and it
is never a grant:

```json
{"ttl_seconds": 600, "observations": [{"scope": "lan", "address": "192.0.2.50",
  "mac": "02:00:5e:10:00:07", "detail": "sw1 Gi1/0/7"}]}
```

The authority polls its own tailscaled for the peer inventory. `GetSuggestions`
(read-only) lists reviewable proposals linking live, unassociated bindings to
peers: **`endpoint`** strength when tailscaled reaches the peer directly at the very
LAN address the binding holds, **`hostname`** (marked weak) when only the name
matches. Suggestions are flagged `ambiguous` when several peers fit and with a
`conflict` when the peer already belongs to another device, they never self-apply,
and each carries a ready `repair` for `RepairIdentity`.

## Warm standby

```sh
ghostd --follow=100.64.0.10:7443     # on the standby
```

The standby mirrors the authority's ledger (bindings, quarantines, observations,
durable associations, tailnet nodes, the server DUID) and its confirmed DHCP
configuration, keeps every scope disabled and refuses ledger writes. If the
authority is lost:

```sh
grpcurl ... -d '{"action":"promote"}' standby:7443 ghostd.HostState/DHCPHandover
```

Promotion refuses while the leader still answers (`"force": true` overrides — you
are asserting it is fenced), starts the mirrored configuration, and fails cleanly,
staying a standby, if it cannot bind. `standby-status` shows the cursor and sync
age. **There is no automatic failover and no multi-master allocation, by design:**
two authorities that decide independently hand out the same address, and a standby
cannot tell a dead leader from a partition. Fence the old authority, promote, and
restart the old host with `--follow` pointing at the new one.

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

On top of the takeover, the lab covers an unrequested OFFER and a DECLINE left
outstanding across rollback to real dnsmasq (and a second takeover from that
export), real timer-driven DHCPv6 Renew and Rebind, and prefix delegation to
`dhclient -6 -P` with its route.

`tests/e2e/run.sh` is the end-to-end lab: the **real ghostd binary under real
systemd** with a fake tailscaled, real nft, a real dnsmasq unit, ISC clients, avahi
and python-zeroconf as third-party mDNS peers and busybox tftp — including a
container reboot. `tests/integration/run.sh` runs the opt-in privileged Go suites.
Both use a disposable privileged container with no external network.

The labs do not exercise physical LAN broadcast delivery, client diversity, or a
real tailnet. Do those checks on a test VLAN before a production cutover.

## Current limits

Multi-master allocation and automatic failover are not built and are excluded by
design (see [Warm standby](#warm-standby)); the multicast reflector is excluded by
the ACL design ([lan-discovery.md](lan-discovery.md)). Known gaps in what has
landed are listed in [dhcp-remaining.md](dhcp-remaining.md).
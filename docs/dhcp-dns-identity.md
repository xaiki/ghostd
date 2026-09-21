# DHCP, DNS and device identity — design

Status: implemented for the single-authority case, with isolated acceptance
tests. The operator-facing guide is [dhcp.md](dhcp.md); what is still missing is
tracked in [dhcp-remaining.md](dhcp-remaining.md).

Scope: one authoritative DHCP server per network scope, integrated into ghostd.
No active/active allocation and no automatic failover in the first version. The
addresses used here are illustrative only.

The operator should be able to ask which device held an address, on which network,
at a given time, and see that device's LAN interfaces and its tailnet
representation together. A hostname is a label; the persistent device ID is the
join key.

## Existing seams

- `internal/auth` authenticates RPC callers through local tailscaled `WhoIs`.
  The returned identity was extended with the caller's stable node ID for reports
  ([security.md](security.md)).
- The pinned tailscaled client exposes a peer's stable node ID, DNS name and
  tailnet addresses. `HostName` is explicitly not necessarily unique, and a peer's
  endpoint, relay addresses and routed subnets must never be treated as LAN
  addresses it owns.
- `internal/resolver` supplies the CoreDNS integration. The authoritative plugin
  is registry-backed and answers before the forwarding path, rather than writing
  host files as a second independent database.
- The existing `Apply`/`Confirm` transactions govern DHCP *configuration*, but
  their rollback snapshots must never rewind live lease allocations. That is why
  the ledger is a separate durable store, outside the transaction records.

## Data model and invariants

An embedded transactional store holds everything. The implementation chose bbolt:
maintained, cgo-free, and compatible with the existing static cross-builds.
Desired configuration, current allocation state, identity associations and history
are separate records.

| Record | Required information |
| --- | --- |
| Device | Stable internal ID, client-declared device ID, canonical name, aliases |
| Interface identity | Device ID, MAC, DHCPv4 client ID, DHCPv6 DUID and IAID/IA type, source and validity interval |
| Network scope | Scope ID, VLAN or relay scope, subnet/prefix, server authority |
| Address binding | Scope, address, device/interface, origin, start and end, state |
| Tailnet membership | Tailnet namespace, stable node ID, DNS name, tailnet addresses, last observation |
| Association evidence | Explicit declaration, authenticated self-report, lease, neighbour observation, timestamps, confidence and state |
| Event | Stable ID, authority sequence, event time, device, scope, address, transition and reason |

An address is keyed by network scope as well as by IP: different sites can reuse
the same private range. Store renewals, releases, expiries, declines, conflicts,
and identity merge/split events. Preserve history after reuse, and never rewrite
old lease ownership because of a new observation. Audit history has no automatic
deletion: compaction and retention must be an explicit policy. A disk-full or
failed durable commit prevents new grants rather than issuing untracked addresses.

Commit an allocation and its event before the ACK or Reply. Reserve offers against
concurrent requests. Persist the server identity and the leases across restart.
Use transactional uniqueness for live allocations, conflict quarantine and bounded
expiry processing. A failed reply is still a committed reservation until its lease
expires, so retransmissions must be idempotent.

DNS is a projection of committed bindings with a monotonic revision. Rebuild it
after restart, invalidate affected cache entries on updates, and bound TTL by the
remaining lease lifetime. Cache entries and packets already held by clients cannot
be recalled: do not claim instantaneous fleet-wide DNS changes.

Delegated prefixes are deliberately not modelled. They are a separate increment,
because pretending every downstream address was individually leased would be
wrong.

## Joining LAN and tailnet identities

1. Seed explicit declarations to interface identifiers and tailnet stable node
   IDs. Renaming a host must not create a new device.
2. Observe peers through local tailscaled. Missing visibility, or a temporarily
   offline node, makes an observation stale; it does not delete the device.
3. Managed hosts report their own interfaces and addresses to the authority over
   an authenticated RPC. Bind the report to `WhoIs`'s caller identity and ignore
   any caller-supplied identity as authority. A dedicated self-report capability
   permits this without granting deploy rights.
4. Correlate that report with the current scoped DHCP identity and binding and,
   where available, with neighbour evidence. Automatically associate only unique,
   corroborated matches. A report remains an assertion by that host, not proof of
   physical ownership. Explicit declaration conflicts require resolution.
5. For unmanaged tailnet hosts, use explicit declarations or collected evidence;
   otherwise display a suggested association. Names alone, NAT endpoints, a shared
   gateway, or advertised routes never cause an automatic merge.

Support many interfaces and potentially multiple tailnet nodes per device.
Randomised MACs, changed client IDs, and reinstall or re-enrolment are explicit
identity changes. Unknown clients receive their own records. Conflicts remain
visible and reversible.

The registry is attribution evidence, not a substitute for authenticated network
access policy.

## DNS behaviour

Use a configurable local authoritative zone per scope — `home.arpa` is the
proposed default per [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375.html) — and
keep `.local` for mDNS discovery. Publish A/AAAA and scoped PTR records only for
current eligible bindings. Sanitise client-supplied names, protect declared names,
and disambiguate collisions. An unknown client gets a stable generated name rather
than taking a known machine's name.

`node-a.home.arpa` can point to its LAN binding while its tailnet FQDN continues
to return tailnet addresses through MagicDNS. Both names and both address sets
refer to one registry device. DNS does not indiscriminately mix LAN and tailnet
addresses into one answer, and it does not take over Tailscale's reverse zones.

The resolver extends from its tailnet-only listener to explicitly declared
LAN/VLAN addresses, which must be allowed in the corresponding firewall zones.
DHCP and RA advertise a resolver reachable from that scope, so ordinary LAN clients
never need Tailscale. There is no public wildcard recursive listener.

**This identity has a second consumer, so design it for both at once.**
[lan-discovery.md](lan-discovery.md) advertises and browses DNS-SD on behalf of
containers, and it must show each container only the service *classes* it is
allowed to see. That allowlist has the same principal as this one — an
authenticated per-container identity, never a source address, for the same
Aardvark/NAT reason — and it puts three requirements on this design while it is
still open:

- **Isolation is a first-class answer, not a fallback.** An authenticated *or* an
  isolated per-container query path is acceptable; isolation is what makes
  per-container networks a legitimate route to a class allowlist, so keep both
  rather than committing to credentials alone.
- **Policy before the shared cache.** A class allowlist inherits that rule, or one
  container's cached answer becomes another container's visible service.
- **One identity, two permission sets.** What a name may *resolve* to, and which
  classes may be *discovered*, are declared and reviewed together. Neither should
  grow a private vocabulary for "who is allowed what".

## Delivery sequence

1. **Registry and adoption, read-only.** Import current dnsmasq leases, preserve
   client IDs and source timestamps, ingest tailnet and neighbour observations, and
   expose current and historical address lookup. Label unknown historical start
   times rather than inventing them. *Landed.*
2. **DHCPv4 and authoritative DNS.** Use an existing DHCP protocol library, with
   allocation and lease persistence owned by ghostd: scoped pools, reservations,
   lease lifetimes, router/DNS/search options, renewal/rebinding, decline/release,
   and explicit relay support when declared. Begin on one test VLAN, binding only
   configured interfaces. *Landed for IPv4; IPv6 landed with step 4.*
3. **Authenticated identity reports.** Join managed hosts' interface reports to
   their tailnet identity, with provenance, conflict display and reversible
   association operations. Reports and observations update the registry without
   depending on a continuously running client. *Landed.*
4. **IPv6.** DHCPv6 IA_NA bindings, a persistent server DUID, lifetimes,
   renew/rebind/release/decline and DNS options, with RA and SLAAC managed
   explicitly. SLAAC and privacy addresses are observed bindings, not DHCP-issued
   leases, and a complete list of every address a client creates cannot be
   promised. *Landed. Prefix delegation remains a separate increment.*
5. **Production cutover.** Import active leases and reservations, validate pools
   and exclusions, stop the old authority, then start ghostd on that scope. Never
   run independent allocators against the same pool. Verify real renewal, fresh
   allocation, DNS and restart recovery before retiring dnsmasq. *Tooling landed;
   not yet performed on a production network.*

Configuration rollback preserves every lease granted since cutover. Before
restarting dnsmasq, either transfer the current compatible leases back or exclude
their addresses through expiry: simply restoring its old lease file is unsafe.

## Acceptance criteria

- A lease for example `192.0.2.100` and an authenticated matching tailnet host
  report produce one device, `node-a`, with both address sets and association
  evidence.
- Two clients claiming `node-a` stay separate; an unrelated node cannot claim
  another node's tailnet identity; ambiguous reports do not silently merge.
- Address reuse answers correctly for both a current lookup and a lookup at a past
  timestamp, and equal addresses on two scopes remain distinct.
- An ACK or Reply followed immediately by a crash never loses the allocation, and a
  failed durable write never grants a new lease. Concurrent requests cannot
  double-assign.
- Expiry, release and reassignment change forward and reverse DNS and invalidate
  server caches. Existing client caches are bounded by the issued TTL.
- LAN-only clients resolve lease names without tailnet membership, and tailnet
  outages do not stop local DHCP or authoritative local DNS.
- IPv4 and IPv6 renewal, reboot, conflicts, pool exhaustion and configuration
  rollback preserve accounting and connectivity on an isolated test network.
- Failed cutover and rollback never produce simultaneous authorities or reuse
  still-valid addresses; DHCPv6 and SLAAC observations retain distinct origins.

## Dependencies

- [insomniacslk/dhcp](https://github.com/insomniacslk/dhcp) provides DHCPv4 and
  DHCPv6 protocol and server building blocks. It does not replace the allocation
  and identity model.
- [CoreDHCP](https://github.com/coredhcp/coredhcp) supplies reusable server
  behaviour. Embedding it does not require choosing CoreDNS, and vice versa.
- [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375.html) defines `home.arpa` for
  residential local naming. Check existing naming before adopting it.

Before any production cutover: discover the actual scopes, options, reservations,
relay configuration, RA behaviour, existing local DNS domain and lease storage.
The example addresses in this document are not configuration.

## Implementation checkpoint

CoreDHCP's v4/v6 framework is integrated through the `ghostleases` plugin, with
small documented embedding patches in `internal/coredhcpserver`. CoreDNS uses its
own `ghostleases` and `ghostlocal` plugins, backed by the same registry. IPv4 and
DHCPv6 IA_NA, persistent identity, A/AAAA/PTR, declared relays, RA/SLAAC
observation, authenticated reports, explicit identity repair, and transactional
dnsmasq handover and rollback are implemented. Operator commands and the supported
legacy configuration subset are documented in [dhcp.md](dhcp.md).

The Podman lab uses real dnsmasq, ISC clients and Linux network namespaces. It
checks lease preservation, DNS, restart recovery, rollback and relay admission. No
production authority has been replaced. Multi-authority high availability,
delegated prefixes, and per-container authenticated DNS ACLs remain explicitly
separate work.
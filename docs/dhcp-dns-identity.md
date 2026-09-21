# DHCP, DNS, and device identity — proposed implementation

Status: implementation in progress with isolated acceptance tests; see the
[remaining code/features](../ops/ghostd-dhcp-implementation-remaining.md) and
[remaining validation](../ops/ghostd-dhcp-validation-remaining.md). Scope: one authoritative DHCP server per
network scope, integrated into ghostd. No active/active allocation or automatic
failover in the first version. Example addresses below are illustrative only.

The operator should be able to ask which device held an address, on which
network, at a given time, and see its LAN interfaces and tailnet representation
together. A hostname is a label; the persistent device ID is the join key.

## Existing seams

- `machines/net_ops.py` reads dnsmasq leases, DHCP snooping bindings, and Linux
  neighbors. Its lease parser currently drops the optional client ID; migration
  must preserve it. A snapshot cannot reconstruct events before observation.
- `ghostd/internal/auth` authenticates RPC callers through local tailscaled
  WhoIs. Extend the returned identity with the caller's StableNodeID for reports.
- The pinned tailscaled client exposes peer StableNodeID, DNSName, and tailnet
  addresses. HostName is explicitly not necessarily unique. Endpoint/relay
  addresses and routed subnets must not be treated as a peer's owned LAN IPs.
- `ghostd/internal/resolver` supplies the CoreDNS integration. Add an
  authoritative registry-backed plugin before forwarding, rather than writing
  host files as a second independent database.
- Existing Apply/Confirm transactions can govern DHCP configuration, but their
  rollback snapshots must never rewind live lease allocations.

## Data model and invariants

Use an embedded transactional store, with a storage spike selecting a maintained
cgo-free implementation compatible with current cross-builds. Separate desired
configuration, current allocation state, identity associations, and history.

| Record | Required information |
| --- | --- |
| Device | Stable internal ID, optional inventory machine ID, canonical name, aliases |
| Interface identity | Device ID, MAC, DHCPv4 client ID, DHCPv6 DUID and IAID/IA type, source and validity interval |
| Network scope | Site/network ID, VLAN or relay scope, subnet/prefix, server authority |
| Address binding | Scope, address or delegated prefix, device/interface, origin, start/end, state |
| Tailnet membership | Tailnet namespace, StableNodeID, DNS name, tailnet addresses, last observation |
| Association evidence | Explicit binding, authenticated self-report, lease, neighbor/switch observation, timestamps, confidence/state |
| Event | Stable ID, authority sequence, event time, device, scope, address, transition and reason |

An address is keyed by network scope as well as IP: different sites can reuse
the same private range. Store renewals, releases, expiries, declines, conflicts,
and identity merge/split events. Preserve history after reuse; never rewrite old
lease ownership following a new observation. Audit history has no automatic
deletion by default; compaction/retention must be an explicit policy. Disk-full
or failed durable commit prevents new grants rather than issuing untracked IPs.

Commit allocation and its event before ACK/Reply. Reserve offers against
concurrent requests. Persist server identity and leases across restart. Use
transactional uniqueness for live allocations, conflict quarantine, and bounded
expiry processing. A failed reply is still a committed reservation until its
lease expires; retransmissions must be idempotent.

DNS is a projection of committed bindings with a monotonic revision. Rebuild it
after restart, invalidate affected cache entries on updates, and bound TTL by
remaining lease lifetime. Cache and packets already held by clients cannot be
recalled; do not claim instantaneous fleet-wide DNS changes.

## Joining LAN and tailnet identities

1. Seed explicit inventory associations to interface identifiers and tailnet
   StableNodeID. Renaming a host must not create a new device.
2. Observe peers through local tailscaled. Missing visibility or a temporarily
   offline node makes observations stale; it does not delete the device.
3. Managed hosts report their own interfaces and addresses to the authority over
   an authenticated RPC. Bind the report to WhoIs's caller identity; ignore a
   caller-supplied identity as authority. A dedicated self-report capability
   permits this without granting deploy rights.
4. Correlate that report with current scoped DHCP identity/binding and, where
   available, switch/neighbor evidence. Automatically associate only unique,
   corroborated matches. Reports remain assertions by that host, not proof of
   physical ownership. Explicit inventory conflicts require resolution.
5. For unmanaged tailnet hosts, use explicit bindings or collected evidence;
   otherwise display a suggested association. Names alone, NAT endpoints, a
   shared gateway, or advertised routes never cause an automatic merge.

Support many interfaces and potentially multiple tailnet nodes per device.
Randomized MACs, changed client IDs, and reinstall/re-enrollment are explicit
identity changes. Unknown clients receive their own records. Conflicts remain
visible and reversible. The registry is attribution evidence, not a substitute
for authenticated network access policy.

## DNS behavior

Use a configurable local authoritative zone, proposed default `home.arpa`;
keep `.local` as mDNS discovery. Publish A/AAAA and scoped PTR records only for
current eligible bindings. Sanitize client-supplied names, protect declared
names, and disambiguate collisions. Unknown clients can use stable generated
names instead of taking a known machine's name.

`node-a.home.arpa` can point to its LAN binding while its existing tailnet FQDN
continues to return tailnet addresses through MagicDNS. Both names and address
sets refer to one registry device. DNS does not indiscriminately mix LAN and
tailnet addresses in a single answer or take over Tailscale's reverse zones.

Extend the resolver from its current tailnet-only listener to explicitly
declared LAN/VLAN addresses and allow those listeners in the corresponding
firewall zones. DHCP/RA advertises a resolver reachable from that scope; ordinary
LAN clients must not need Tailscale. No public wildcard recursive listener.
Per-container DNS ACL identity remains a separate prerequisite; lease names or
source addresses behind a shared forwarder are not sufficient credentials.

**This identity now has a second consumer, so design it for both at once.**
`docs/arch/ghostd-lan-discovery.md` advertises and browses DNS-SD on behalf of
containers, and it must show each container only the service *classes* it is
allowed to see (`_ipp._tcp`, `_googlecast._tcp`, `_adisk._tcp`, …). That allowlist
has the same principal as this one — an authenticated per-container identity,
never a source address, for the same Aardvark/NAT reason recorded in
`ghostd/README.md`'s `Container DNS` note — and it puts three requirements on the
design while it is still open:

- **Isolation is a first-class answer, not a fallback.** That note allows an
  authenticated *or* an isolated per-container query path. Isolation is what makes
  per-container Podman networks a legitimate route to the class allowlist, so the
  design should keep both rather than committing to credentials alone.
- **Policy before the shared cache.** The same note requires any policy check to
  run ahead of the cache. A class allowlist inherits that, or one container's
  cached answer becomes another container's visible service.
- **One identity, two permission sets.** What a name may *resolve* to, and which
  classes may be *discovered*. They are declared and reviewed together; neither
  should grow a private vocabulary for "who is allowed what".

## Delivery sequence

1. **Registry and adoption, read-only:** import current dnsmasq leases, preserve
   client IDs and source timestamps, ingest tailnet/neighbor observations, expose
   current and historical address lookup in `machines net status`. No allocator
   change yet; label unknown historical start times rather than inventing them.
2. **DHCPv4 and authoritative DNS:** use an existing DHCP protocol library, with
   allocation and lease persistence owned by ghostd. Implement scoped pools,
   reservations, lease lifetimes, router/DNS/search options, renewal/rebinding,
   decline/release, and explicit relay support when declared. Begin on one test
   VLAN, binding only configured interfaces.
3. **Authenticated identity reports:** join managed hosts' interface reports to
   their tailnet identity, with provenance, conflict display, and reversible
   association operations. Reports and observations update the registry without
   dependency on a continuously running CLI. Hosts without ghostd can use a
   small scheduled reporter with a scoped capability.
4. **IPv6:** implement DHCPv6 IA_NA bindings, persistent server DUID, lifetimes,
   renew/rebind/release/decline, and DNS options. Manage RA/SLAAC explicitly.
   SLAAC/privacy addresses are observed bindings, not DHCP-issued leases; a
   complete list of all addresses a client creates cannot be promised. Prefix
   delegation is a separate increment: track delegated ranges and ownership,
   without pretending every downstream address was individually leased.
5. **Production cutover:** import active leases/reservations and config, validate
   pools and exclusions, stop the old authority, then start ghostd on that scope.
   Never run independent allocators against the same pool. Verify real renewal,
   fresh allocation, DNS, and restart recovery before retiring dnsmasq.

Configuration rollback preserves every lease granted since cutover. Before
restarting dnsmasq, transfer the current compatible leases back or exclude their
addresses through expiry. Simply restoring its old lease file is unsafe.

## Acceptance tests

- A lease for example `10.0.0.6` and an authenticated matching tailnet host report
  produce one device, `node-a`, with both address sets and association evidence.
- Two clients claiming `node-a` stay separate; an unrelated node cannot claim
  another node's tailnet identity. Ambiguous reports do not silently merge.
- Address reuse answers correctly for both current lookup and lookup at a past
  timestamp. Equal IPs on two scopes remain distinct.
- ACK/Reply followed immediately by a crash never loses the allocation; a failed
  durable write never grants a new lease. Concurrent requests cannot double-assign.
- Expiry/release/reassignment changes forward and reverse DNS and invalidates
  server caches. Existing client caches are bounded by the issued TTL.
- LAN-only clients resolve lease names without tailnet membership. Tailnet
  outages do not stop local DHCP or authoritative local DNS.
- IPv4 and IPv6 renewal, reboot, conflicts, pool exhaustion, and configuration
  rollback preserve accounting and connectivity on an isolated test network.
- Failed cutover and rollback do not produce simultaneous authorities or reuse
  still-valid addresses. DHCPv6/SLAAC observations retain their distinct origins.

## Dependencies to evaluate

- [insomniacslk/dhcp](https://github.com/insomniacslk/dhcp) provides DHCPv4/v6
  protocol and server building blocks; it does not replace our allocation and
  identity model.
- [CoreDHCP](https://github.com/coredhcp/coredhcp) is a candidate to evaluate for
  reusable server behavior, not a requirement imposed by choosing CoreDNS.
- [RFC 8375](https://www.rfc-editor.org/rfc/rfc8375.html) defines `home.arpa` for
  residential local naming. Existing naming should be checked before adoption.

Before production: discover the actual scopes, options, reservations, relay
configuration, RA behavior, existing local DNS domain, and lease storage. The
example IP in the request is not configuration.

## Implementation checkpoint

CoreDHCP's v4/v6 framework is integrated through the ghostleases plugin, with
small documented embedding patches in `internal/coredhcpserver`. CoreDNS uses its
own ghostleases/ghostlocal plugins backed by the same registry. IPv4 and DHCPv6
IA_NA, persistent identity, A/AAAA/PTR, declared relays, RA/SLAAC observation,
authenticated reports, explicit identity repair, and transactional dnsmasq
handover/rollback are implemented. Operator commands and supported legacy config
subset are documented in [the operator guide](../ops/ghostd-dhcp.md).

The Podman lab uses real dnsmasq, ISC clients and Linux namespaces. It checks
lease preservation, DNS, restart recovery, rollback and relay admission. No
production authority has been replaced. Multi-authority HA, delegated prefixes,
and per-container authenticated DNS ACLs remain explicitly separate work.

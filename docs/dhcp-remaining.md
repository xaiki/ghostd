# Remaining DHCP/DNS work

This is a work list, not a description of shipped behaviour. Everything below is a
known defect, an unverified path, or an increment that was deliberately excluded.
The implemented single-authority behaviour is in [dhcp.md](dhcp.md) and the design
rationale in [dhcp-dns-identity.md](dhcp-dns-identity.md).

Read this before trusting the DHCP domain's rollback path on a network you care
about.

## Cutover correctness (resolved)

- Rollback always exports the current ledger once ghostd was activated, even if the
  original lease file was empty (`TestHandoverRollbackFromEmptyPoolExportsNewGrants`).
- The journal records `activated` before ghostd can grant anything. Rolling back a
  takeover whose final snapshot could not be imported (malformed rows, an
  undeclared scope, DHCPv6 temporary addresses) restores the untouched legacy
  authority without re-parsing the snapshot
  (`TestHandoverRollbackAfterUnimportableSnapshot`).
- Handover recovery runs before the DHCP configuration is applied at boot, and a
  pending takeover whose target cannot bind is rolled back rather than stranding the
  host with no allocator (`TestBootRecoversInterruptedHandover`,
  `TestBootRollsBackPendingHandoverWhoseTargetCannotStart`). A rollback that itself
  fails stays journaled and is retried by the watcher; it does not keep the RPC
  surface down.

## Written but not fully validated

- `state.Store.SaveExternallyManagedConfig` now synchronises the live DHCP file and
  the boot-confirmed domain state, and the handover RPC and recovery callbacks use
  it. Finish verifying it through the actual boot and RPC paths, including partial
  persistence failures.
- Confirmed rollback now refuses configuration drift since takeover. Verify the
  guard and its regression test, and document the supported reconciliation path for
  an operator who intentionally changed scopes after confirmation.

## Incomplete identity and observation behaviour

- **Resolved:** durable associations (`RepairIdentity` with `persist`, removed with
  `forget`; allocation applies them and replaced mappings are kept in history),
  observation history (`observation` and `observation-end` events; historical
  snapshots return only sightings whose validity covered the instant, flagged
  `historical`), and repair validation against every declared `tailnet_node_ids`
  entry and against other live undeclared names.
- **Unmanaged hosts and suggested associations.** There is no continuous
  authority-side tailscale peer inventory, and no suggestion workflow for hosts that
  do not self-report. Current joins use explicit declarations or authenticated
  self-reports plus DHCP/neighbour evidence. Add peer sightings and reviewable
  suggestions, without merging on hostname alone.
- **Switch evidence.** DHCP-snooping and switch observations are not ingested into
  the durable registry; the implemented collector reads the local Linux neighbour
  table only.

## Incomplete migration and operator integration

- **Configuration conversion.** The handover path accepts a manually reviewed
  target plan, and the legacy validator supports a deliberately narrow explicit
  dnsmasq subset. It is not a configuration importer. Add a previewable converter
  that preserves includes, exclusions, reservations, scoped options and RA behaviour
  where supported, and rejects unsupported semantics before dnsmasq is stopped.
- **Client-side verification before confirmation.** Confirmation probes
  authoritative SOA locally over UDP and TCP. It does not prove actual LAN-client
  renewal, fresh allocation, routing or DNS reachability. Add a scoped verification
  flow and require its evidence before cancelling recovery. The lab is not a
  substitute for deployment-specific client reachability.
- **Progress and fleet views.** Handover returns JSON phase and status, and the
  registry exposes lease, event and repair reads. Persistent handover state and
  IP-to-device/tailnet attribution are not yet part of a normal network status view,
  including stale evidence, failures, retryability and pending verification.

## Operational hardening

- **Bound lookup work.** Expiry now reads an end-time index (at most 1000 entries
  per call, backfilled on upgrade). Some allocation and identity paths — pool
  scans, `Report`, name-collision checks — still scan all bindings; index them
  before retained history grows large.
- **Resolved:** the SOA serial also advances when zones, aliases or scopes change
  (`TestSOASerialFollowsDNSConfiguration`).
- **Lease-file replacement failure cases.** Exercise and harden ownership,
  permissions, file and directory synchronisation, and interrupted replacement in
  the real systemd adapter. Keep rollback pending until the restored allocator is
  actually serving; short sustained service activity is not a DHCP probe.
- **Recovery journal lifecycle.** There is one mutable handover journal, and it is
  not a durable history of all authority transitions. Decide how completed handovers
  are archived and how their audit history is retained.

## Explicitly separate increments

These were excluded from the single-authority DHCP increment rather than
implemented and awaiting tests:

- DHCPv6 prefix delegation and delegated-range attribution.
- Multi-authority allocation, replication and automatic failover.
- Authenticated per-container DNS ACLs, including identity through shared
  forwarders and enforcement ahead of cache and authoritative answers.
- General dnsmasq replacement beyond the implemented DHCP/DNS/RA subset — for
  example TFTP/PXE and arbitrary dnsmasq options.

CoreDHCP and CoreDNS plugin extension points are already in place. Implement new
protocol and policy features through those APIs, keep persistence and identity
shared, and keep transport lifecycle and recovery outside packet policy.

## Validation status

### Passing on the current tree

```sh
go test ./...
go test -race ./...
go vet ./...
```

The race suite is the one that matters here, and it passes as of the rename that
made this repository standalone.

### Previously demonstrated by the isolated lab

The lab in `tests/dhcp-lab/` has been observed to pass with real dnsmasq and ISC
DHCP clients: IPv4 and IPv6 adoption, new allocations, UDP/TCP authoritative DNS,
manager and ledger restart, rollback preserving new leases, repeat takeover after a
legacy renewal, injected configuration failure, deadline recovery, RA, SLAAC
neighbour evidence, and IPv4/IPv6 relay admission and rejection.

The same lab has passed using a real systemd-managed dnsmasq service, including
persistent masking and rollback startup verification.

The lab restarts the manager and store. It does **not** boot the complete ghostd
daemon through its production boot-restore path, and it does not reboot a machine.

### Coverage still to add and run

- **Now covered by unit tests:** boot recovery of an interrupted or expired
  takeover and rollback when the target cannot start (`cmd/ghostd`); ordinary
  `Apply` versus handover interaction over the authenticated RPC handlers
  (`TestHandoverInteractionWithOrdinaryApplyOverRPC`); and a simulated process kill
  at every takeover and rollback boundary — stop, read, export, start — with
  idempotent recovery (`TestHandoverSurvivesKillAtEveryBoundary`). Still open: a
  real reboot, and kills inside the state store's own persistence step.
- **Offers and declined-address rollback with real dnsmasq.** Verify that exported
  offers remain occupied and that synthetic quarantine identities stop the declining
  client, or a new client, from reacquiring the address until expiry.
- **IPv6 durability failures.** Add the equivalent of the existing IPv4 ACK/crash
  test for a DHCPv6 Reply, plus a failed durable-write check proving no Reply grants
  an unrecorded address.
- **Real timer-driven DHCPv6 Renew and Rebind.** The live ISC restart path exercises
  Confirm and INIT-REBOOT. Renew and Rebind have handler-level coverage only; add
  real-wire renewal and rebinding, and verify lease and DNS lifetime updates.

Prefix delegation, multi-authority high availability and authenticated
per-container DNS ACLs were excluded from this increment. They are separate feature
work, not unrun tests for implemented behaviour. No production or LAN cutover has
been performed.
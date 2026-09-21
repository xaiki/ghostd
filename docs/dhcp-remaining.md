# Remaining DHCP/DNS work

This is a work list, not a description of shipped behaviour. Everything below is a
known defect, an unverified path, or an increment that was deliberately excluded.
The implemented single-authority behaviour is in [dhcp.md](dhcp.md) and the design
rationale in [dhcp-dns-identity.md](dhcp-dns-identity.md).

Read this before trusting the DHCP domain's rollback path on a network you care
about.

## Correctness blockers

- **Rollback when the original lease file was empty.** In
  `internal/addressbook/handover.go`, the export of the current ledger sits inside
  `if j.Snapshot != ""`. An initially empty IPv4 lease file therefore skips the
  export even when ghostd granted leases after takeover. Current grants must always
  be exported before restarting the old allocator; the snapshot's content must not
  decide whether they are preserved. Needs a regression test for the empty-pool
  takeover, new client, then rollback sequence.
- **Rollback after a malformed or unsupported final lease snapshot.** `Begin`
  stores the snapshot before parsing and importing it, and rollback then parses that
  same snapshot again and can fail again — leaving dnsmasq stopped and masked even
  though ghostd never activated. Persist whether import and activation actually
  occurred, and restore the unchanged legacy authority without requiring the failed
  import to succeed. After activation, require the current-ledger export path.
  Needs tests for malformed rows and unsupported DHCPv6 lease types at that
  boundary.
- **Recovery when normal daemon startup cannot complete.** Handover recovery
  currently runs in the addressbook watcher after manager startup. If restoring the
  enabled target cannot bind or initialise, that watcher is not available. Add a
  recovery path before listener activation, or an independently supervised recovery
  helper, so an expired or interrupted handover is not stranded merely because the
  target configuration cannot start. Lease state must be preserved throughout.

## Written but not fully validated

- `state.Store.SaveExternallyManagedConfig` now synchronises the live DHCP file and
  the boot-confirmed domain state, and the handover RPC and recovery callbacks use
  it. Finish verifying it through the actual boot and RPC paths, including partial
  persistence failures.
- Confirmed rollback now refuses configuration drift since takeover. Verify the
  guard and its regression test, and document the supported reconciliation path for
  an operator who intentionally changed scopes after confirmation.

## Incomplete identity and observation behaviour

- **Durable interface associations beyond one lease lifetime.** Operator repair
  edits selected live bindings. It is not a persistent interface/client identity
  mapping that survives expiry, reallocation, changed addresses or a reinstall. Add
  explicit association records and have allocation and reporting use them, while
  preserving historical ownership when associations change.
- **Observation history.** Kernel neighbour sightings overwrite a
  latest-observation bucket; they do not append their own observation, change and
  expiry events. Preserve observation provenance and historical validity separately
  from DHCP grants, so that historical queries clearly distinguish contemporaneous
  evidence from current sightings.
- **Repair policy consistency.** Automatic reporting understands additional
  `tailnet_node_ids`, while repair validation mainly checks the singular
  `tailnet_node_id`. Align the two, and validate name collisions against other live,
  undeclared device records when applying repairs.
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

- **Bound total expiry and lookup work.** Expiry writes at most 1000 transitions per
  call but still scans the entire current-binding bucket, and some allocation and
  identity paths scan all bindings. Add indexes or cursors, or explicit work
  budgets, before claiming bounded work as retained history and IPv6 observations
  grow.
- **Configuration-driven DNS revision.** The SOA serial derives from the lease and
  event sequence. Alias, zone and configuration changes also need a durable DNS
  revision change, with restart and rollback tests.
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

- **Production boot path after handover.** Exercise the real daemon boot restore
  and recovery wiring, not just reopening the ledger: confirmed takeover survives
  restart, expired pending takeover rolls back, and an interrupted rollback resumes.
  Confirm that old domain-confirmed configuration does not replace the handover
  configuration. This is what validates the `SaveExternallyManagedConfig`
  integration in the RPC and recovery callbacks.
- **Transaction interaction over RPC.** An unconfirmed ordinary DHCP `Apply` must
  block handover before dnsmasq is stopped, and an expired `Apply` must recover
  first. Ordinary `Apply` must stay blocked during a pending handover.
- **Abrupt failure at handover boundaries.** Terminate and restart at the journal
  write, the old-service stop, the final lease import, configuration persistence,
  and the rollback export and start boundaries. Verify no simultaneous authorities
  and no lost or reused live grants. Current tests cover injected errors and orderly
  restart, not every process-kill or reboot window.
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
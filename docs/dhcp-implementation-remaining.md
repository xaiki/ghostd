# Remaining DHCP/DNS code and features

Checkpoint after the implementation turn was interrupted. This complements
[the remaining validation checklist](ghostd-dhcp-validation-remaining.md).
The implementation has passed substantial isolated testing, but the items below
mean it should not yet be described as complete or ready for production cutover.
This document records work; it does not implement the fixes.

## Cutover correctness blockers

- **Rollback when the original lease file was empty.** In
  `ghostd/internal/addressbook/handover.go`, export of the current ledger is
  inside `if j.Snapshot != ""`. An initially empty IPv4 lease file therefore
  skips export even if ghostd granted leases after takeover. Always export
  current grants before restarting the old allocator; snapshot content must
  not determine whether those grants are preserved. Add a real empty-pool
  takeover/new-client/rollback regression test.
- **Rollback after a malformed or unsupported final lease snapshot.** Begin
  stores the snapshot before parsing/importing it. Rollback then parses that
  same snapshot again and can fail again, leaving dnsmasq stopped and masked
  even though ghostd never activated. Persist whether import/activation actually
  occurred. Before any possible new grants, restore the unchanged legacy
  authority without requiring the failed import to succeed. After activation,
  require the current-ledger export path. Test malformed rows and unsupported
  DHCPv6 lease types at this boundary.
- **Recovery when normal daemon startup cannot complete.** Handover recovery
  currently runs in the addressbook watcher after manager startup. If restoring
  the enabled target cannot bind or initialize, that watcher is not available.
  Add a recovery path before listener activation, or an independently supervised
  recovery helper, so an expired/interrupted handover is not stranded merely
  because the target configuration cannot start. Preserve lease state throughout.

## Final fixes written but not fully validated

- `state.Store.SaveExternallyManagedConfig` now synchronizes the live DHCP file
  and boot-confirmed domain state. The handover RPC and recovery callbacks use
  it, and Begin checks ordinary Apply transactions first. Finish verification
  through the actual boot/RPC paths, including partial persistence failures.
- Confirmed rollback now refuses configuration drift since takeover. Verify the
  new guard and regression test, and document the supported reconciliation path
  when the operator intentionally changed scopes after confirmation.

## Incomplete identity and observation behavior

- **Durable interface associations beyond one lease lifetime.** Operator repair
  currently edits selected live bindings. It is not a persistent interface/client
  identity mapping that survives expiry, reallocation, changed addresses, or a
  reinstall. Add explicit association records and have allocation/reporting use
  them; preserve historical ownership when associations change.
- **Observation history.** Kernel neighbor sightings currently overwrite a
  latest-observation bucket. They do not append their own observation/change/
  expiry events. Preserve observation provenance and historical validity
  separately from DHCP grants, and make historical queries clearly distinguish
  contemporaneous evidence from current sightings.
- **Repair policy consistency.** Automatic reporting understands additional
  `tailnet_node_ids`, while repair validation mainly checks the singular
  `tailnet_node_id`. Align these rules. Also validate name collisions against
  other live, undeclared device records when applying repairs.
- **Unmanaged hosts and suggested associations.** There is no continuous
  authority-side tailscale peer inventory or suggestion workflow for hosts that
  do not self-report. Current joins use explicit declarations or authenticated
  self-reports plus DHCP/neighbor evidence. Add peer sightings and reviewable
  suggestions without merging on hostname alone.
- **Switch evidence.** Existing DHCP-snooping/switch observations are not yet
  ingested into the durable registry. The implemented collector reads the local
  Linux neighbor table only.

## Incomplete migration/operator integration

- **Configuration conversion.** The handover command accepts a manually reviewed
  target JSON plan. The legacy validator supports a deliberately narrow explicit
  dnsmasq configuration subset; it is not an inventory/configuration importer.
  Add a previewable converter for the intended deployment configurations,
  preserving includes, exclusions, reservations, scoped options and RA behavior
  where supported, and rejecting unsupported semantics before stopping dnsmasq.
- **Client-side verification before confirmation.** Confirmation currently probes
  authoritative SOA locally over UDP/TCP. It does not automatically prove actual
  LAN-client renewal, fresh allocation, routing or DNS reachability. Add a scoped
  verification worker/evidence flow and enforce the required results before
  cancelling recovery. The lab tests do not substitute for deployment-specific
  client reachability.
- **Progress and fleet views.** Handover currently returns JSON phase/status and
  has CLI lease/event/repair commands. Integrate persistent handover state and
  IP-to-device/tailnet attribution into the normal network status and progress UI,
  including stale evidence, failures, retryability and pending verification.

## Remaining operational hardening

- **Bound total expiry/lookup work.** Expiry writes at most 1000 transitions per
  call but still scans the entire current-binding bucket. Some allocation and
  identity paths also scan all bindings. Add indexes/cursors or explicit work
  budgets before claiming bounded work as retained history and IPv6 observations
  grow.
- **Configuration-driven DNS revision.** The SOA serial derives from lease/event
  sequence. Alias/zone/configuration changes also need a durable DNS revision
  change, with restart/rollback tests.
- **Lease-file replacement failure cases.** Exercise and harden ownership,
  permissions, file/directory synchronization and interrupted replacement in the
  real systemd adapter. Keep rollback pending until the restored allocator is
  actually serving; short sustained service activity is not a DHCP probe.
- **Recovery journal lifecycle.** Define how to archive completed handovers and
  retain their audit history. There is currently one mutable handover journal;
  it is not a durable history of all authority transitions.

## Explicitly separate feature increments

These were excluded from the single-authority DHCP increment, rather than
implemented and awaiting tests:

- DHCPv6 prefix delegation and delegated-range attribution.
- Multi-authority allocation, replication and automatic failover.
- Authenticated per-container DNS ACLs, including identity through shared
  forwarders and policy enforcement before cache/authoritative answers.
- General dnsmasq replacement beyond the implemented DHCP/DNS/RA subset
  (for example TFTP/PXE and arbitrary dnsmasq options).

CoreDHCP/CoreDNS plugin extension points are already present. Implement new
protocol/policy features through those APIs where appropriate; keep persistence
and identity shared, and keep transport lifecycle/recovery outside packet policy.

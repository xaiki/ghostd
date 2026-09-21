# Remaining DHCP/DNS work

Checkpoint after the implementation turn was interrupted. This is a handoff,
not a claim that the final working tree has passed all checks: it records work,
and does not implement any of it.

## Code and features


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

## Validation

## Already demonstrated

- The Go race suite passed before the final boot-state and configuration-drift fixes.
- Go vet and Linux AMD64/ARM64 daemon builds passed on an earlier revision.
- The targeted Python suite passed 46 tests; the DHCP-only suite subsequently
  passed 8 tests, including optional IPv6 configuration normalization.
- The isolated namespace lab passed with real dnsmasq and ISC DHCP clients:
  IPv4/IPv6 adoption, new allocations, UDP/TCP authoritative DNS, manager/ledger
  restart, rollback preserving new leases, repeat takeover after legacy renewal,
  injected configuration failure, deadline recovery, RA, SLAAC neighbor evidence,
  and IPv4/IPv6 relay admission/rejection.
- The same lab passed using a real systemd-managed dnsmasq service, including
  persistent masking and rollback startup verification (27.36 seconds).

The lab restarts the manager/store; it does **not** boot the complete ghostd
daemon through its production boot-restore path or reboot the machine.

## Run against the final working tree

1. **Go regression tests, especially the last two fixes.** Run from `ghostd/`:

   ```sh
   go test -race ./...
   go vet ./...
   ```

   Confirm these newly added tests pass:

   - `TestExternalConfigUpdatesBootRestoreWithoutOverridingPendingLease`
     (`internal/state/transaction_test.go`): handover updates both the boot
     configuration and live file, and cannot overwrite a pending Apply lease.
   - `TestRollbackRefusesChangedConfiguration`
     (`internal/addressbook/handover_test.go`): a confirmed handover cannot
     restore incompatible old configuration after subsequent scope changes.

   The last race command ran accidentally from the repository root and failed
   with “directory prefix . does not contain main module”; it tested no code.
   An earlier attempt also caught a test constructor typo, since corrected.

2. **Python controller and generated RPC regression tests.** From repository root:

   ```sh
   .venv/bin/python -m pytest packages/machines/tests/test_dhcp.py packages/machines/tests/test_ghostd_client.py packages/machines/tests/test_host_ghostd.py -q
   .venv/bin/machines net dhcp-handover --help
   .venv/bin/machines net repair-identity --help
   ```

   These gRPC tests require permission to bind loopback sockets. Sandbox
   `Operation not permitted` errors were previously resolved by rerunning with
   networking permission; they were not application failures.

3. **Rebuild both final daemon artifacts.** From `ghostd/`:

   ```sh
   GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /private/tmp/ghostd-dhcp-amd64 ./cmd/ghostd
   GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /private/tmp/ghostd-dhcp-arm64 ./cmd/ghostd
   ```

4. **Run the complete reproducible lab script.** From repository root:

   ```sh
   ghostd/tests/dhcp-lab/run.sh
   ```

   The individual namespace and systemd runs passed, but this combined script
   has only received a shell syntax check. It rebuilds the test binary, runs both
   modes, and should remove its temporary containers/binary on exit. Default is
   ARM64; use `GHOSTD_LAB_ARCH=amd64` only with a matching AMD64 Podman VM/image.
   Keep `--network none`; do not attach the test DHCP server to the LAN.

5. **Check the scoped diff and documentation after fixes.** Include untracked
   implementation/test files, which ordinary `git diff` does not display.
   Ensure operator documentation matches any changes to confirmation, rollback,
   configuration compatibility and service startup behavior.

## Additional acceptance coverage to add and run

- **Production boot path after handover:** exercise the actual daemon boot
  restore and recovery wiring, not just reopening the ledger. Verify confirmed
  takeover survives restart; expired pending takeover rolls back; and an
  interrupted rollback resumes. Ensure old domain-confirmed configuration does
  not replace the handover configuration. This directly validates the final
  `SaveExternallyManagedConfig` integration in the RPC and recovery callbacks.
- **Transaction interaction over RPC:** an unconfirmed ordinary DHCP Apply must
  block handover before dnsmasq is stopped; an expired Apply must recover first.
  Ordinary Apply must remain blocked during a pending handover. Exercise the
  authenticated Go RPC handlers and persisted domain/journal state together.
- **Abrupt failure at handover boundaries:** terminate/restart at journal write,
  old-service stop, final lease import, configuration persistence, and rollback
  export/start boundaries. Verify no simultaneous authorities and no lost or
  reused live grants. Current tests cover injected errors and orderly restart,
  not every process-kill/reboot window.
- **Offers and declined-address rollback with real dnsmasq:** verify exported
  offers remain occupied and synthetic quarantine identities prevent the
  declining client or a new client from reacquiring the address until expiry.
  Normal active-lease rollback passed; these special export cases need their
  own live-client test.
- **IPv6 durability failures:** add the equivalent of the existing IPv4
  ACK/crash test for DHCPv6 Reply, plus a failed durable-write check ensuring no
  Reply grants an unrecorded address. Existing IPv6 lifecycle and restart tests
  do not independently prove this crash boundary.
- **Real timer-driven DHCPv6 Renew/Rebind:** the live ISC restart path exercises
  Confirm/INIT-REBOOT. Renew/Rebind currently have handler-level coverage; add
  real-wire renewal/rebinding and verify lease/DNS lifetime updates.

## Cleanup and limits

The last known manually created container is `ghostd-dhcp-systemd-lab`; its test
finished successfully but the container was left running. Inspect it, then remove
that disposable container when finished. The Podman VM predates these tests and
must not be stopped or deleted as cleanup. The reusable lab image can remain.

Prefix delegation, multi-authority HA and authenticated per-container DNS ACLs
were excluded from this DHCP increment; they are separate feature work, not
unrun tests for implemented behavior. Production/LAN cutover has not been run.

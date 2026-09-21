# Remaining DHCP/DNS validation

Checkpoint after the implementation turn was interrupted. This is a validation
handoff, not a claim that the final working tree has passed all checks. No tests
were run while writing this checklist.

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

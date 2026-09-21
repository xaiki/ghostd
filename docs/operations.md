# Operating ghostd

This covers the RPC workflow, the lease and recovery mechanics, the flags, and how
to test a build. For the per-domain target schemas see
[firewall.md](firewall.md), [netconfig.md](netconfig.md) and [dhcp.md](dhcp.md).

## RPC workflow

1. Call `ghostd.HostState/GetState` to read the live domains.
2. Call `Apply` with `domain`, `desired_state_json` (a JSON **string**, not a
   nested object) and a positive `dead_man_switch_seconds`, for example 300.
3. Save the returned `lease_id` and close the apply connection.
4. Independently check the application and management paths you care about. Then
   open a **new** TCP connection to ghostd and call `Confirm` with that lease ID
   before it expires.
5. Require `ok: true`. If any step fails, leave the lease unconfirmed and inspect
   recovery before retrying.

A second apply to the same domain is rejected while a lease is pending. A failed
or interrupted apply cannot be confirmed at all; it can only be recovered.

Worked example with `grpcurl` and `jq`. Each `grpcurl` invocation opens a separate
connection, which is what the confirmation rule needs:

```sh
GHOSTD_ADDR=100.64.0.10:7443

grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  "$GHOSTD_ADDR" ghostd.HostState/GetState

jq -n --rawfile desired firewall.json \
  '{domain:"firewall", desired_state_json:$desired, dead_man_switch_seconds:300}' \
  > apply.json

grpcurl -plaintext -import-path proto -proto ghoststate.proto -d @ \
  "$GHOSTD_ADDR" ghostd.HostState/Apply < apply.json

# After checking connectivity, copy leaseId from the Apply response:
grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  -d '{"lease_id":"REPLACE-WITH-RETURNED-LEASE-ID"}' \
  "$GHOSTD_ADDR" ghostd.HostState/Confirm
```

Confirmation is a reachability check, not proof that every application works.
Any authorized deployer can confirm a known pending lease. Expired, incomplete,
unknown and already-completed leases are all rejected. Confirmation is **not
idempotent**: if the response is lost, inspect state rather than assuming that a
retry's rejection means rollback happened. See [security.md](security.md) for why
a different source endpoint is required.

## The dead-man's switch

Before any mutation, ghostd saves a pre-apply snapshot and arms a separate
transient systemd timer. The `systemd-run` invocation it builds is:

```
systemd-run --unit=ghostd-revert-<lease-id> \
  --description=ghostd dead-man's-switch revert \
  --on-active=<seconds> \
  --timer-property=AccuracySec=100ms \
  --property=Restart=on-failure --property=RestartSec=5s \
  -- /opt/ghostd/ghostd --revert-lease=<lease-id> --revert-domain=<domain> \
  --store-dir=<store-dir>
```

The timer re-invokes the installed binary. It needs neither the original daemon
process nor a working tailnet, which is the point: the revert path survives the
daemon exiting, and survives the tailnet being the thing that broke. The binary
must therefore remain at its installed path while any lease is pending. A
declared store directory is appended last, and a lease with no explicit store
directory uses the daemon's own default.

Which domain fired travels in the timer's own `argv` (`--revert-domain`), not
through in-memory state, for the same reason. Apply commands are bounded by the
requested timeout; a timer that fires during an in-flight operation waits for the
process-shared store lock rather than racing it.

Successful confirmation atomically saves the confirmed state and clears the
pending lease *before* cancelling the timer with `systemctl stop
ghostd-revert-<lease-id>.timer`. A timer that has already fired sees that its
lease is no longer pending and does nothing — recovery follows the durable
record, not the timer's opinion.

## State on disk

The default store is `/var/lib/ghostd/last-good`, created with mode 0700. It
contains:

| Path | Contents |
| --- | --- |
| `firewall-transaction.json` | Confirmed ruleset and/or the pending firewall lease |
| `netconfig-transaction.json` | Confirmed netconfig target and/or its pending lease |
| `dhcp-v1-transaction.json` | Confirmed DHCP configuration and/or its pending lease |
| `transaction.lock` | Process-shared lock serialising mutations and recovery |
| `addressbook.db` | The durable DHCP lease, identity and event ledger |
| `nft-ruleset.json`, `netconfig-state.json`, `dhcp-config.json` | Legacy blobs, read only when no transaction record exists for that domain |

Transaction files are mode 0600 and are replaced atomically, with the file and
then the directory synced. A transaction record holds the confirmed bytes and,
while a change is in flight, the lease ID, deadline, pre-apply snapshot, target,
source peer, and an "applied" marker that is set only once every mutation has
succeeded.

Preserve the store directory across upgrades, and do not edit it while the daemon
or a revert is running. The DHCP ledger is deliberately never rewound by a
configuration rollback and has no automatic history deletion — monitor its disk
use and back it up with a consistent filesystem snapshot, or while ghostd is
stopped.

## Recovery

On startup, with no pending transaction, ghostd replays the confirmed state for
each domain. With a pending transaction, it rolls back instead — even if the
original deadline has not elapsed, because transient timers do not survive a
reboot. It refuses to serve if recovery fails.

Domain-specific limits on what rollback restores are in
[firewall.md](firewall.md) and [netconfig.md](netconfig.md).

## Diagnostics

```sh
sudo journalctl -u ghostd.service -b
sudo systemctl list-timers 'ghostd-revert-*'
sudo journalctl -u 'ghostd-revert-*' -b
sudo nft list table inet stack_ghostd
```

If a revert fails, its pending record is deliberately kept. Correct the
underlying command or filesystem failure using your independent management path,
then restart ghostd to retry recovery.

Note what stopping ghostd does *not* do: it does not disarm outstanding timers,
and it does not remove its firewall table. Avoid upgrading or uninstalling the
binary until every pending lease has been confirmed or recovered.

## Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--port` | `7443` | TCP listener and firewall reachability-guard port |
| `--deployer-tag` | `tag:stack-deployer` | Alternative caller node tag for mutations |
| `--tailscale-interface` | `tailscale0` | Interface allowed by the reachability guard |
| `--store-dir` | `/var/lib/ghostd/last-good` | Durable transaction storage |
| `--watchdog-sec` | `0` | Watchdog interval; match systemd `WatchdogSec` |
| `--observe-only` | false | Reject writes, skip boot restore; fresh hosts only |
| `--render-firewall` | false | Render stdin JSON to nft syntax and exit |
| `--report-to` | empty | Report this host's interfaces once to a DHCP authority, then exit |
| `--revert-lease`, `--revert-domain` | empty | Internal timer recovery command; not for interactive use |

Use a systemd `ExecStart` override for different settings. Keep the daemon and
render-only flag values consistent when reviewing the resulting rules — the
reachability guard uses `--tailscale-interface` and `--port`, so a rendered file
built with different values is not what the daemon would apply.

## Environment

| Variable | Purpose |
| --- | --- |
| `GHOSTD_IDENTITY_AUTHORITY` | When set on the daemon's environment, report this host's interfaces to that authority once a minute. `--report-to` does the same thing once, from the command line. |

The recurring report is a daemon responsibility rather than a cron job: it needs
the tailnet identity that the daemon already resolves. Set it with a systemd
`Environment=` or `EnvironmentFile=` entry, and not together with
`--observe-only`, which does not report.

## Testing

```sh
go test ./...
go test -race ./...
go vet ./...
gofmt -l .
```

Unit tests use fake command runners and need no privileges. Privileged
integration tests are opt-in behind environment variables and must be run in a
**disposable Linux VM** with nftables, iproute2 and systemd. Network namespaces
isolate the nft tests, but the state and netconfig tests create transient systemd
units and temporary files under the real `/etc/network/interfaces.d/`.

| Variable | Covers |
| --- | --- |
| `GHOSTD_NFT_INTEGRATION` | nft replacement, rollback, packet-level isolation, revert-by-timer |
| `GHOSTD_SYSTEMD_INTEGRATION` | Transient timer cancellation and firing |
| `GHOSTD_NETCONFIG_INTEGRATION` | File and address snapshot/restore |
| `GHOSTD_DHCP_INTEGRATION` | Real UDP/TCP listener and port ownership (network namespace) |

```sh
go test -c ./internal/nft -o /tmp/ghostd-nft.test
go test -c ./cmd/ghostd -o /tmp/ghostd-main.test
go test -c ./internal/state -o /tmp/ghostd-state.test
go test -c ./internal/netconfig -o /tmp/ghostd-netconfig.test

sudo unshare -n env GHOSTD_NFT_INTEGRATION=1 /tmp/ghostd-nft.test -test.run TestIntegration -test.v
sudo unshare -n env GHOSTD_NFT_INTEGRATION=1 /tmp/ghostd-main.test -test.run TestIntegration -test.v
sudo env GHOSTD_SYSTEMD_INTEGRATION=1 /tmp/ghostd-state.test -test.run TestIntegration -test.v
sudo unshare -n env GHOSTD_NETCONFIG_INTEGRATION=1 /tmp/ghostd-netconfig.test -test.run TestIntegration -test.v
```

Integration coverage includes repeated firewall replacement, rule withdrawal,
foreign-table preservation, first-apply recovery, stale timer handling, durable
boot recovery, timer cancellation and firing, and netconfig file restoration.
None of it replaces a real-tailnet connectivity test before deployment.

The DHCP takeover lab is a separate, heavier harness — see
[dhcp.md](dhcp.md).

## Regenerating the proto bindings

The generated Go files under `proto/` are checked in. To regenerate them, install
the pinned plugins and run:

```sh
export PATH="$PATH:$(go env GOPATH)/bin"
protoc -I proto --go_out=proto --go_opt=paths=source_relative \
  --go-grpc_out=proto --go-grpc_opt=paths=source_relative proto/ghoststate.proto
```

Required versions, which are recorded in the generated files' header comments:
`protoc` 36.2, `protoc-gen-go` v1.36.12 and `protoc-gen-go-grpc` v1.6.2. Running
the command with those versions from a clean tree should be a no-op. Do not
hand-edit the generated files.
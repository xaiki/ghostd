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
| `mdns-v1-transaction.json` | Confirmed mDNS advertisement and/or its pending lease |
| `mdns-config.json`, `dhcp-config.json` | The live copies of those configurations, converged on by watchers |
| `dns-acl.json` | Per-container DNS identities (read at start; see [dhcp.md](dhcp.md#per-container-dns-acl)) |
| `replica-dhcp-config.json` | A warm standby's mirror of the leader's DHCP configuration |
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
| `--runtime-dir` | `/run/ghostd` | Where runtime files are published; one per daemon when several share a host |
| `--overlay` | the only provider built in, else `tailscale` | Overlay provider for caller identity and the listen address |
| `--overlay-socket` | provider default | Override the provider's local client API socket |
| `--deployer-user` | empty | Comma-separated logins that may deploy, in addition to the tag and capability paths |
| `--features` | false | List the optional features compiled into this binary and exit |
| `--report-to` (`dhcp`) | empty | Report this host's interfaces once to a DHCP authority, then exit |
| `--convert-dnsmasq` (`dnsmasq`) | empty | Preview a dnsmasq config as a handover plan and exit; changes nothing |
| `--legacy-unit` (`dnsmasq`) | `dnsmasq.service` | The unit `--convert-dnsmasq` records in the plan |
| `--mdns-interfaces` (`mdns`) | every up multicast interface | LAN interfaces the native mDNS client queries |
| `--follow` (`dhcp`) | empty | Run as a warm standby of the authority at this host:port |
| `--revert-lease`, `--revert-domain` | empty | Internal timer recovery command; not for interactive use |

Use a systemd `ExecStart` override for different settings. Keep the daemon and
render-only flag values consistent when reviewing the resulting rules — the
reachability guard uses `--tailscale-interface` and `--port`, so a rendered file
built with different values is not what the daemon would apply.

## mDNS advertisement

The `mdns-v1` domain rides the ordinary Apply/Confirm lease. Its target names the
LAN interfaces, the `.local` host name (answered with the interface's addresses)
and the DNS-SD instances to advertise:

```json
{"interfaces": ["eth0"], "host": "nas",
 "records": [{"service": "_smb._tcp", "instance": "NAS", "port": 445},
             {"service": "_ipp._tcp", "instance": "Queue", "port": 631,
              "txt": ["rp=ipp/print"], "subtypes": ["_universal"]}]}
```

ghostd answers multicast and legacy-unicast queries, announces on start and sends
goodbyes (TTL 0) on withdrawal. Every record's SRV points at its host — `host`
above, or the record's own `"host"` when it names one — and the address records
answered for it are the advertising interface's. It binds UDP 5353 **exclusively**:
with another mDNS daemon on the host the apply fails with the bind error rather
than sharing the port. Before advertising it probes each name, and a name another
host already advertises refuses the apply and leaves the previous set running. The
record set is yours to supply; ghostd ships none (a Time Machine set must be
captured from a known-good advertisement). An unconfirmed change reverts, and after
a reboot the confirmed set is re-advertised by a watcher that also retries a start
that failed because an interface was not up yet.

`GetState` reads the currently-applied target back as `mdns_config_json` (the
same JSON shape shown above) — empty when the `mdns` feature is not built in
or nothing is configured. This is what lets a caller diff its desired set
against what is actually live instead of blindly re-applying every run.

### Per-container reflector

`reflect` in the same target relays mDNS between the LAN and **per-container
networks** (one Podman network per container or pod, whose bridge is a multicast
domain of its own), so an application that speaks mDNS itself works on the
container network with no host networking:

```json
{"reflect": [
  {"lan": "eth0", "network": "podman-print", "allow_services": ["_ipp._tcp"]},
  {"lan": "eth0", "network": "podman-music", "allow_services": ["_googlecast._tcp"]}]}
```

The permission is the network: each rule has its own filter. Toward the container
go LAN records for the allowed classes and for the instances they name (PTR, SRV,
TXT, and the address records of the hosts their SRVs point at, remembered for two
minutes); nothing else — no other class, no unrelated host. Toward the LAN go only
the container's *queries* for allowed classes and the hosts those services named.
A browser that enumerates the service types first is served too: the enumeration
question names no class of its own, so it is relayed and its answers are filtered
like any other record — the classes it may see. One rule per network (a network is
one permission set); `records` and `host` are needed only if you also advertise.
The container bridge's firewall zone needs the `mdns` service.

#### mDNS NAT: containers advertising to the LAN

A service a container advertises on its bridge names a bridge-private address, so
reflecting it as-is would send LAN clients somewhere they cannot reach. Add
`advertise` to the rule and ghostd does what a router would:

```json
{"lan": "eth0", "network": "podman-print",
 "advertise": {"services": ["_ipp._tcp"], "ports": "20000-20999"}}
```

It learns the container's instances (PTR, SRV, TXT and its host's address, goodbyes
included) and re-advertises each on the LAN under **ghostd's own LAN address** and
a **port from the pool** (stable per container address and port), keeping the host
name the container itself advertised, and installs a DNAT from that port to the
container's address and port in its own nft table (`ghostd_mdns_nat`, replaced
atomically, removed on stop). A LAN client browsing `_ipp._tcp` finds the
container's service, resolves the container's own name to ghostd, and its
connection lands in the container: no host networking, nothing published by hand,
and the bridge address is never disclosed. It also answers LAN queries from what it
learned and relays them to the network so the container refreshes. Records lapse
with their own TTLs. Only IPv4 is mapped, so only IPv4 is published.

Nothing is asked of the container: it announces as it always would, on its own
network, and ghostd learns from that broadcast. Only an address the container
announced **on its own network** is translated — an address it also announces
elsewhere (its loopback, another network) is ignored, so a LAN port can never be
pointed off the container network — and the DNAT is scoped to traffic addressed to
ghostd itself (`fib daddr type local`), so a pool port does not intercept traffic
meant for another host on the LAN.

The firewall must let the translated flows through its default-drop forward
policy: set `"allow_dnat_forward": true` in the firewall target (it admits only
connections a DNAT rule actually rewrote, `ct status dnat`), enable IPv4
forwarding in netconfig, and give the container network's zone the `mdns` service.
Instance *and host* names learned this way are not conflict-probed on the LAN:
keep them distinct, and note that a name ghostd advertises itself (`host` above)
is never taken over by a container — such an instance keeps the network's name
instead. `records` entries accept their own `"host"` for the same reason a
container's do: the SRV points at it and the address records follow it.

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
go test ./...                     # the core only; add -tags for optional features
go test -race -tags "tailscale dhcp dnsmasq mdns coredns" ./...
go vet -tags "tailscale dhcp dnsmasq mdns coredns" ./...
gofmt -l .
tests/tags.sh                     # the whole tag matrix: every combination built and tested, or refused
GHOSTD_TAGS_FAST=1 tests/tags.sh  # the same matrix, build outcomes only
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

Three container harnesses need Podman and never touch a real network:

| Script | Covers |
| --- | --- |
| `tests/integration/run.sh` | The opt-in privileged suites above, plus the resolver ACL on loopback aliases |
| `tests/dhcp-lab/run.sh` | The DHCP takeover, relay, RA/SLAAC, DHCPv6 timers and prefix delegation, against real dnsmasq and ISC clients (see [dhcp.md](dhcp.md)) |
| `tests/tags.sh` | Every combination of the optional build tags builds, vets and tests, or fails to compile because it violates a dependency (`GHOSTD_TAGS_FAST=1` asserts the build outcomes only); the default build carries none of the optional dependencies |
| `GHOSTD_TAGS=tailscale GHOSTD_E2E_MODE=minimal tests/e2e/run.sh` | The core-only binary under systemd: core domains work, optional domains/RPCs are refused, and no DNS/DHCP/mDNS socket is open |
| `GHOSTD_E2E_MODE=standby tests/e2e/run.sh` | Two real daemons: a leader serving DHCP and a standby mirroring it; the leader is stopped, the standby promoted, and the clients renew the same addresses |
| `GHOSTD_TAGS=headscale GHOSTD_E2E_MODE=headscale tests/e2e/run.sh` | The headscale provider against a daemon that grants a deploy capability and no tag: the capability is ignored, a listed `--deployer-user` login is authorized |
| `tests/e2e/run.sh` | The **real ghostd binary under real systemd** with a fake tailscaled: firewall/netconfig apply, confirm, timer revert and crash recovery; a dnsmasq takeover through the RPC with the daemon killed mid-window; PXE/TFTP; native mDNS and the DNS ACL with avahi and python-zeroconf as third parties; peer suggestions; switch evidence; mDNS advertisement; and a container reboot |

Two things about that lab are deliberate, and both are about not hiding a
requirement the real world would have. A container namespace gets exactly what a
container runtime gives it — its address and a default route — and nothing for
mDNS: multicast leaves a bridge through the ordinary route, so a `224.0.0.0/4`
route in the fixture would hide whether an application needs one (it does not).
And the container-side advertiser declares its own addresses, because
python-zeroconf publishes A records only for what the application declares: a
`ServiceInfo` without addresses announces PTR/SRV/TXT and no address at all, and
an announcement with no address has nothing for a NAT to translate. That is the
application's business, not a ghostd requirement — and the fixture announces a
loopback address too, which ghostd must refuse to translate.

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
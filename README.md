# ghostd

A small, rootful Linux daemon for applying firewall and interface configuration
over a Tailscale network, with an independent rollback timer for every change.

Clients decide policy. ghostd validates and executes resolved JSON targets through
three gRPC methods: `GetState`, `Apply`, and `Confirm`. A change becomes persistent
only after a deployer reconnects and confirms its lease. Unconfirmed changes are
recovered from a durable pre-apply snapshot, even if the daemon exits.

The Go module is self-contained: this directory can be published as its own
repository. It needs neither Python nor the parent project's inventory, plugins,
or deployment tools. The current module name (`smarthome/ghostd`), service name,
and default paths are retained for existing installations.

## Requirements

- Linux, systemd as the service manager, and root privileges.
- `nft` with JSON input/output and inet-family NAT support; `ip` from iproute2;
  `sysctl`; `systemd-run` and `systemctl` on the daemon's `PATH`.
- A running, joined `tailscaled`, using a kernel Tailscale interface. The default
  interface is `tailscale0`; userspace-networking mode is not supported.
- Go **1.26.7 or newer** to build (see [go.mod](go.mod)).

The daemon listens on the first IP returned by the local Tailscale status API,
TCP port **7443** by default. It does not listen on wildcard or LAN addresses.
There is no application-layer TLS: transport encryption comes from Tailscale.
Do not expose the listener through a public proxy.

Each RPC resolves its caller using the local tailscaled `WhoIs` API. Any recognized
peer allowed to reach the port can read state. `Apply` and `Confirm` additionally
require the caller's **node** to carry `tag:stack-deployer` (configurable).
Configure tag ownership and network access in your tailnet policy; ghostd does
not manage either. A user login or membership in a similarly named group does
not substitute for the node tag.

Treat deployer access as host-administrator access. Interface configuration can
contain root-executed ifupdown hooks, and the legacy `forward` action executes an
existing root-owned script. The domain validators are not a sandbox for untrusted
administrators. `GetState` includes the host's full nftables ruleset and interface
configuration, so restrict read access through tailnet policy when appropriate.

## Build and install

Run from this directory (the root of the standalone repository):

```sh
go test ./...
go build -trimpath -o bin/ghostd ./cmd/ghostd
```

For a Linux ARM64 target built on another OS:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/ghostd-linux-arm64 ./cmd/ghostd
```

On the target Linux host, install its native binary and the supplied unit:

```sh
sudo install -D -m 0755 bin/ghostd /opt/smarthome/ghostd/ghostd
sudo install -m 0644 systemd/smarthome-ghostd.service /etc/systemd/system/smarthome-ghostd.service
sudo systemctl daemon-reload
sudo systemctl enable --now smarthome-ghostd.service
sudo systemctl status smarthome-ghostd.service
```

Use the cross-compiled binary instead of `bin/ghostd` when applicable. The unit
runs as root, restarts on failure, and enables a 30-second systemd watchdog.
On its first start, with an empty state directory, ghostd installs no policy.
On subsequent starts it recovers pending changes before restoring confirmed
state and opening the RPC listener. It refuses to serve if recovery fails.

Keep an independent console or management path available for the first cutover.
ghostd leaves `/etc/nftables.conf` and other nft tables untouched. However, an
accept in one base chain cannot override a drop in another writer's base chain;
coexisting firewalls can still block traffic. Arrange ownership and boot ordering
with any other firewall manager before relying on ghostd's reachability guard.

## Firewall target

Save this as `firewall.json`, adjusting interface names and policy for your host:

```json
{
  "zones": {
    "trusted": {"interfaces": ["tailscale0"]},
    "lan": {
      "interfaces": ["eth0"],
      "ssh": {"port": 22},
      "ports": [{"port": 53, "proto": "udp"}, {"port": 53, "proto": "tcp"}],
      "forward": ["wan"]
    },
    "wan": {"interfaces": ["eth1"], "masquerade": true}
  }
}
```

Render without root privileges, tailscaled, or any host changes:

```sh
bin/ghostd --render-firewall < firewall.json > firewall.nft
```

On Linux, `sudo nft -c -f firewall.nft` checks the result without applying it.
The RPC performs this same syntax check before arming a lease.

A target replaces only **`table inet stack_ghostd`**, atomically. Removing a port
or zone removes its rules on the next apply. Other writers' tables are excluded
from both snapshots and replay. Existing conntrack flows are not flushed, so
removing an opening does not immediately terminate established connections.

- Zone names are identifiers; interfaces must be explicit names, assigned to
  only one zone. `trusted` accepts all input from its interfaces.
- Other zones allow their declared TCP/UDP ports and SSH, with input defaulting
  to drop. `target: "ACCEPT"` permits all remaining input in that zone.
- At least one zone must declare SSH or be named `trusted`. Every rendered policy
  also permits ghostd's own TCP port on its configured Tailscale interface.
- Loopback, established/related input, IPv6 error traffic, and IPv6 neighbor/router
  discovery with hop limit 255 are permitted independently of zone services.
- Forwarding defaults to drop except established/related flows and explicit
  zone-to-zone `forward` declarations. `masquerade` applies on that zone's egress
  interfaces. Kernel forwarding must also be enabled separately.
- Optional `ingress: {"interfaces": ["eth0"], "http_port": 18080}` redirects
  host-destined TCP 80 to that port and TCP 443 to **8443**, and admits those
  destination ports. Forwarded traffic to other hosts is not redirected.
- Legacy `services` names are `mdns`, `dns`, `dhcp`, `dhcpv6-client`, `http`, and
  `https`. `nfs: {"exports": ["10.0.0.0/24"]}` permits TCP 111, 2049, and 20048
  from those IPv4 CIDRs. For other services, supply explicit `ports`.

Service discovery, plugin activation, VLAN placement, and port-catalog lookup
belong to the client. The daemon has no dependency on a specific policy generator.

## Netconfig target

The `netconfig` domain takes a file map and an ordered list of actions:

```json
{
  "files": {
    "/etc/network/interfaces.d/stack-eth0.10.conf": "auto eth0.10\niface eth0.10 inet static\n    address 192.0.2.1/24\n    vlan-raw-device eth0\n"
  },
  "actions": [
    ["vlan", "eth0", "eth0.10", "10"],
    ["addr", "eth0.10", "192.0.2.1/24"],
    ["up", "eth0.10"]
  ]
}
```

Supply the complete target and replayable actions, including configuration
already present on the host: confirmed targets are replayed at daemon startup.
The daemon writes declared files, then executes actions in order. It does not
remove omitted files, addresses, or interfaces, and does not reload a network
manager. Persisted interface files require an ifupdown-compatible host setup.

Allowed actions are `vlan` (base, device, VLAN ID), `addr` (device, address/prefix),
`up` (device), `sysctl` (`net.ipv4.ip_forward=0` or `=1`), and the legacy `forward`
(`/etc/stack-forward.sh`). Existing VLANs must match the requested parent and ID;
existing addresses must match the device, address, and prefix.

Files may be written below `/etc/network/interfaces.d/`, or to the two forwarding
files `/etc/sysctl.d/99-stack-forward.conf` and
`/etc/sysctl.d/99-stack-no-forward.conf`. The latter accept only an empty string
or `net.ipv4.ip_forward=0\n` / `net.ipv4.ip_forward=1\n`.

**Rollback restores touched file contents (including prior absence) and the
previous IPv4 forwarding value. It does not undo additive live link/address
changes or arbitrary effects of the legacy forwarding script.** Use the firewall
domain for nft policy rather than that script. There is no cross-domain atomic
transaction: each domain has its own lease and confirmed state.

## RPC workflow

The wire contract is [proto/ghoststate.proto](proto/ghoststate.proto); generated
Go bindings are included. Clients in other languages can generate bindings from
that file. No gRPC reflection service is enabled.

1. Call `ghostd.HostState/GetState` to read both live domains.
2. Call `Apply` with `domain`, `desired_state_json` (a JSON **string**, not a nested
   object), and positive `dead_man_switch_seconds`, for example 300.
3. Save the returned `lease_id`. Close the apply connection.
4. Independently check the required application/management paths. Open a new TCP
   connection to ghostd and call `Confirm` with that lease ID before expiry.
5. Require `ok: true`. If any step fails, leave the lease unconfirmed and inspect
   recovery before retrying. A second apply to the same domain is rejected while
   a pending lease remains.

For example, using `grpcurl` and `jq` from a deployer-tagged machine (each grpcurl
invocation opens a separate connection):

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

A different source TCP endpoint is required for confirmation. This is a
reachability check, not proof that every application works. Any authorized
deployer can confirm a known pending lease. Expired, incomplete, unknown, or
already completed leases are rejected. Confirmation is not idempotent: if its
response is lost, inspect state rather than assuming a retry's rejection means
rollback occurred.

## Persistence and recovery

The default store is `/var/lib/smarthome-ghostd/last-good`, created with mode 0700.
Transaction files are mode 0600 and atomically replaced with file and directory
syncs. They contain confirmed state and, while applying, the lease ID, deadline,
pre-apply snapshot, target, source peer, and successful-apply marker. Preserve this
directory across upgrades; do not edit it while the daemon or a revert is running.

Before mutation, ghostd saves the snapshot and arms a separate transient systemd
timer. The timer launches the installed binary with `--revert-lease`,
`--revert-domain`, and the same `--store-dir`. It needs neither the original daemon
process nor a working tailnet. The binary must remain at its installed path while
leases are pending. Apply commands are bounded by the requested timeout; the
timer may wait for an in-flight operation to release the process-shared lock.

Successful confirmation atomically saves the confirmed state and clears the
pending lease before stopping its `.timer`. A timer that has already fired sees
that its lease is no longer pending and does nothing. Failed or interrupted
applies cannot be confirmed. Startup rolls back any pending transaction even if
its original deadline has not elapsed, since transient timers do not survive a
reboot. With no pending transaction, startup replays confirmed state.

Firewall recovery replaces only ghostd's table; a failed first apply restores
its prior absence. Netconfig recovery has the limits described above. Existing
legacy `nft-ruleset.json` and `netconfig-state.json` stores are read only when a
new domain transaction record does not exist.

Useful diagnostics on the host:

```sh
sudo journalctl -u smarthome-ghostd.service -b
sudo systemctl list-timers 'smarthome-ghostd-revert-*'
sudo journalctl -u 'smarthome-ghostd-revert-*' -b
sudo nft list table inet stack_ghostd
```

If a revert fails, its pending record remains. Correct the underlying command or
filesystem failure using your independent management path, then restart ghostd
to retry recovery. Stopping ghostd alone does not disarm outstanding timers and
does not remove its firewall table. Avoid upgrades or uninstalling the binary
until all pending leases have been confirmed or recovered.

## Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `--port` | `7443` | TCP listener and firewall reachability-guard port |
| `--deployer-tag` | `tag:stack-deployer` | Required caller node tag for mutations |
| `--tailscale-interface` | `tailscale0` | Interface allowed by the reachability guard |
| `--store-dir` | `/var/lib/smarthome-ghostd/last-good` | Durable transaction storage |
| `--watchdog-sec` | `0` | Watchdog interval setting; match systemd `WatchdogSec` |
| `--render-firewall` | false | Render stdin JSON to nft syntax and exit |
| `--revert-lease`, `--revert-domain` | empty | Internal timer recovery command |

Use a systemd `ExecStart` override for different settings. Keep the daemon and
render-only flags consistent when reviewing the resulting rules.

## Tests

```sh
go test ./...
go test -race ./...
go vet ./...
```

Tests normally use fake command runners. Privileged integration tests are opt-in.
Run them only in a **disposable Linux VM** with nftables, iproute2, and systemd:
network namespaces isolate nft tests, but the other tests create transient units
and temporary files under the real `/etc/network/interfaces.d/`.

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
boot recovery, timer cancellation/firing, and netconfig file restoration.
These checks do not replace a real-tailnet connectivity test before deployment.

To regenerate Go bindings, use `protoc` with `protoc-gen-go` and
`protoc-gen-go-grpc` on `PATH` (generator versions are recorded in the generated
files):

```sh
protoc -I proto --go_out=proto --go_opt=paths=source_relative \
  --go-grpc_out=proto --go-grpc_opt=paths=source_relative proto/ghoststate.proto
```

## License

ghostd is licensed under **GNU GPL version 2 only** (`GPL-2.0-only`), without
warranty. See [LICENSE](LICENSE). Third-party dependencies retain their respective
licenses; this notice covers ghostd's own source.

# ghostd

A small, rootful Linux daemon that applies firewall and network-interface
configuration over a Tailscale network, with an independent rollback timer for
every change.

Clients decide policy; ghostd validates and executes it. A client sends a
fully-resolved declarative target as JSON over gRPC, ghostd renders and applies
it, then arms a dead-man's switch. The change becomes permanent only when the
client reconnects on a fresh TCP connection and confirms its lease. If no
confirmation arrives before the deadline, a separate transient systemd timer
restores a durable pre-apply snapshot — independently of the daemon process, the
tailnet, or whether anyone is watching. The full set of guarantees, and the
places they stop, is in [docs/operations.md](docs/operations.md).

ghostd is one Go binary and one systemd unit. It needs no Python, no
configuration-management system and no inventory: a client is anything that
speaks the methods in [proto/ghoststate.proto](proto/ghoststate.proto).

## Requirements

- Linux with systemd as the service manager, and root privileges.
- `nft` with JSON input/output and inet-family NAT support; `ip` from
  iproute2; `sysctl`; `getent`; and `systemd-run` plus `systemctl` on the
  daemon's `PATH`.
- A running, joined `tailscaled` using a kernel Tailscale interface. The default
  interface name is `tailscale0`; userspace-networking mode is not supported.
- Go **1.26.7 or newer** to build (see [go.mod](go.mod)). Go is needed on the
  build machine only, never on the target.

## Build

The default build is **the core only**: the firewall and netconfig domains, the
lease/confirm/rollback machinery and the tailnet RPC. Everything else is an
optional feature compiled in by build tag, so a host carries only the code — and
opens only the sockets — it asked for:

| Tag | Adds | Requires |
| --- | --- | --- |
| `tailscale` | Overlay provider: the local `tailscaled` API, with application capabilities | — |
| `headscale` | Overlay provider for a Headscale-managed host: same local API, tags and logins only | — |
| `coredns` | The container resolver (CoreDNS) on the tailnet address, with the per-container DNS ACL | — |
| `dhcp` | DHCPv4/v6, authoritative LAN DNS, the identity ledger, prefix delegation, TFTP/PXE, peer suggestions, warm standby, and their RPCs | `coredns` |
| `dnsmasq` | Takeover from, and conversion of, a dnsmasq install (`--convert-dnsmasq`, the handover RPCs) | `dhcp` |
| `mdns` | Native mDNS: `.local` and DNS-SD for containers (with `coredns`), and the `mdns-v1` advertisement domain | — |

```sh
go build -trimpath -o bin/ghostd ./cmd/ghostd                                         # core only
go build -trimpath -tags "coredns mdns" -o bin/ghostd ./cmd/ghostd                    # container DNS + native .local
go build -trimpath -tags "dhcp coredns" -o bin/ghostd ./cmd/ghostd                    # a DHCP/DNS authority
go build -trimpath -tags "tailscale dhcp dnsmasq mdns coredns" -o bin/ghostd ./cmd/ghostd       # everything
bin/ghostd --features                                                                 # what this binary contains
```

A combination that breaks a dependency (`dnsmasq` without `dhcp`, `dhcp` without
`coredns`) does not compile. Features that are not built in are absent, not
disabled: their domains are rejected (`domain must be one of [...]`), their RPCs
return `Unimplemented`, their flags do not exist, and their sockets are never
opened; the default binary contains none of their dependencies. The rest of this
documentation says which tag a feature needs.

For a Linux ARM64 target built on another OS, the binary is CGO-free:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -tags "dhcp coredns" -o bin/ghostd-linux-arm64 ./cmd/ghostd
```

Tests take the same tags (`go test -tags "tailscale dhcp dnsmasq mdns coredns" ./...`);
`tests/tags.sh` builds, vets and tests every supported combination.

## Install

```sh
sudo install -D -m 0755 bin/ghostd /opt/ghostd/ghostd
sudo install -m 0644 systemd/ghostd.service /etc/systemd/system/ghostd.service
sudo systemctl daemon-reload
```

Install the native binary, or the cross-compiled one where that applies. The
daemon must stay at its installed path while leases are pending: the
dead-man's-switch timer re-invokes that exact binary.

## Quick start

```sh
sudo systemctl enable --now ghostd.service
sudo systemctl status ghostd.service
sudo journalctl -u ghostd.service -b
```

The unit runs as root, restarts on failure, and enables a 30-second systemd
watchdog. On its first start, with an empty state directory, ghostd installs no
policy. On later starts it recovers any pending change, then restores confirmed
state before opening the RPC listener. It refuses to serve if recovery fails.

`ghostd` also has a render-only mode that needs no root, no tailscaled and makes
no host changes:

```sh
bin/ghostd --render-firewall < firewall.json > firewall.nft
sudo nft -c -f firewall.nft   # Linux: syntax check only
```

Keep an independent console or management path available for the first cutover.
ghostd leaves `/etc/nftables.conf` and other nft tables untouched, but an
`accept` in one base chain cannot override a `drop` in another writer's base
chain, so arrange ownership and boot ordering with any other firewall manager
before relying on ghostd's reachability guard.

## The RPC contract

The wire contract is [proto/ghoststate.proto](proto/ghoststate.proto), with Go
bindings checked in under `proto/`. Bindings for other languages can be
generated from that file. There is no gRPC reflection service.

| Method | Purpose |
| --- | --- |
| `GetState` | Read live firewall and interface state. Read-only, no deployer tag required. |
| `Apply` | Enact a resolved target behind a dead-man's switch; returns a lease ID. |
| `Confirm` | Cancel that switch, from a fresh TCP connection. |

`Apply` takes `domain`, `desired_state_json` (a JSON **string**, not a nested
object) and a positive `dead_man_switch_seconds`. A second apply to the same
domain is rejected while a lease is pending. Confirmation is not idempotent, and
any authorized deployer can confirm a known pending lease.

With the `dhcp` tag, a separate registry surface serves DHCP, DNS and device identity: `GetRegistry`,
`GetSuggestions`, `ImportLeases`, `ImportObservations`, `ReportHost`,
`RepairIdentity` and `DHCPHandover` (takeover, verification, history, and warm
standby promotion; `dnsmasq` adds the handover). See [docs/dhcp.md](docs/dhcp.md). Beyond `firewall` and
`netconfig`, the optional `dhcp-v1` (`dhcp`) and `mdns-v1` (`mdns`) domains ride the same lease.

A worked `grpcurl`/`jq` example, including the fresh-connection rule for
confirmation, is in [docs/operations.md](docs/operations.md).

## Security model

Each RPC resolves its caller with the local tailscaled `WhoIs` API. There is no
Unix-login path and no application-layer TLS: transport encryption comes from
Tailscale, and the listener binds a tailnet address only — never a wildcard or a
LAN address. Do not expose it through a public proxy.

Any recognised peer that can reach the port may read state. Mutations require
either the configured node tag (`tag:stack-deployer` by default) or a
`ghostd.local/cap/deploy` application capability containing `{"deploy": true}`.
Capabilities are read from local tailscaled on every call, including
confirmation; callers cannot supply permissions in an RPC payload, and missing,
false or malformed permissions do not authorize mutations. The full model,
including the separate `ghostd.local/cap/report` capability, is in
[docs/security.md](docs/security.md).

Two limits are worth stating plainly:

- **The domain validators are not a sandbox for untrusted administrators.**
  Treat deployer access as host-administrator access. Interface configuration can
  contain root-executed ifupdown hooks, and the legacy `forward` action executes
  an existing root-owned script.
- **`GetState` exposes the host's full nftables ruleset and interface
  configuration.** Restrict read access through tailnet policy where that
  matters.

An example grant for an authorized user — documentation addresses and identities
only, merged into existing policy rather than replacing it:

```json
{"grants": [{
  "src": ["deployer@example.com"],
  "dst": ["100.64.0.10"],
  "ip": ["tcp:7443"],
  "app": {"ghostd.local/cap/deploy": [{"deploy": true}]}
}]}
```

Keep workstations user-owned. No workstation tags or SSH policy changes are
required. Use the actual listener port if it was changed. The node-tag path
remains available for dedicated automation.

## Migrating from `smarthome-ghostd`

The project was previously published with a `smarthome` prefix. That prefix is
gone, and the rename is **breaking for existing installations**: the service
name, install paths and timer unit names all changed.

| Item | Old | New |
| --- | --- | --- |
| Go module path | `smarthome/ghostd` | `github.com/xaiki/ghostd` |
| proto `go_package` | `smarthome/ghostd/proto` | `github.com/xaiki/ghostd/proto` |
| systemd unit | `smarthome-ghostd.service` | `ghostd.service` |
| Installed binary | `/opt/smarthome/ghostd/ghostd` | `/opt/ghostd/ghostd` |
| Unit file | `/etc/systemd/system/smarthome-ghostd.service` | `/etc/systemd/system/ghostd.service` |
| State directory | `/var/lib/smarthome-ghostd/last-good` | `/var/lib/ghostd/last-good` |
| Runtime directory | `/run/smarthome-ghostd` | `/run/ghostd` |
| Revert timer units | `smarthome-ghostd-revert-*` | `ghostd-revert-*` |

Unchanged, and deliberately not renamed: the `ghostd.local/cap/deploy` and
`ghostd.local/cap/report` capability namespaces, the default deployer tag
`tag:stack-deployer`, the default listen port 7443, and the domain names.

To migrate a host, in order:

1. Confirm every pending lease, or let it recover, then stop the old unit. Do not
   uninstall the old binary while a revert timer is outstanding.
2. Move the state directory so confirmed state and the DHCP ledger survive:
   `sudo mv /var/lib/smarthome-ghostd /var/lib/ghostd`.
3. Install the new binary at `/opt/ghostd/ghostd` and the new unit as
   `/etc/systemd/system/ghostd.service`.
4. `sudo systemctl daemon-reload`, then `sudo systemctl disable --now
   smarthome-ghostd.service` and `sudo systemctl enable --now ghostd.service`.
5. Check `systemctl list-timers 'ghostd-revert-*'` and confirm the daemon
   restored the expected state. Remove the old unit and binary once no old timer
   remains.

## Documentation

| Document | Contents |
| --- | --- |
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/security.md](docs/security.md) | Authentication, capabilities and the privilege model |
| [docs/operations.md](docs/operations.md) | RPC workflow, persistence, recovery, flags, tests |
| [docs/firewall.md](docs/firewall.md) | Firewall domain: zones, services, NAT, redirects, output policy |
| [docs/netconfig.md](docs/netconfig.md) | Netconfig domain: files, actions, rollback limits |
| [docs/adoption.md](docs/adoption.md) | Observing and adopting an unmanaged host |
| [docs/dhcp.md](docs/dhcp.md) | DHCP, authoritative DNS, device identity, dnsmasq takeover |
| [docs/dhcp-dns-identity.md](docs/dhcp-dns-identity.md) | Design: registry, allocation and identity model |
| [docs/dhcp-remaining.md](docs/dhcp-remaining.md) | Known gaps and remaining DHCP/DNS work |
| [docs/lan-discovery.md](docs/lan-discovery.md) | LAN DNS-SD on behalf of containers: what was decided and built |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, test, lint and proto-generation workflow |

## License

ghostd is licensed under **GNU GPL version 2 only** (`GPL-2.0-only`), without
warranty. See [LICENSE](LICENSE). Third-party dependencies retain their own
licenses; this notice covers ghostd's own source.
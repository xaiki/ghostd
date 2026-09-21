# Contributing to ghostd

Thanks for looking. This document covers how to build and test the project, how
the code is laid out, and what a change is expected to include.

There is no CI. Every check below is run locally, so please run them before you
send a change.

## Requirements

- Go **1.26.7 or newer** (see [go.mod](go.mod)).
- For the privileged integration tests and the DHCP lab: a **disposable** Linux
  VM or container with systemd, nftables, iproute2 and Podman.
- `protoc` and the Go plugins only if you are changing the wire contract — see
  [Regenerating the proto bindings](#regenerating-the-proto-bindings).

## Build and test

```sh
go build ./...
go test ./...
go test -race ./...
go vet ./...
gofmt -l .        # must print nothing
```

`go test ./...` is the gate. The unit tests use fake command runners, so they need
no privileges, no root, no nftables and no tailscaled — an ordinary workstation
build is enough.

The race suite is worth running whenever you touch state, leases or the registry;
those paths are shared between the RPC handlers, the boot recovery path and the
independent revert process.

### Privileged integration tests

These are opt-in behind environment variables, and they must be run in a
**disposable Linux VM**. Network namespaces isolate the nft tests, but the state
and netconfig tests create transient systemd units and write temporary files under
the real `/etc/network/interfaces.d/`. Do not run them on a machine you care about.

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

`GHOSTD_DHCP_INTEGRATION=1` additionally runs the real UDP/TCP listener and port
ownership test in a network namespace.

The DHCP takeover lab is a heavier, self-contained harness that needs Podman:

```sh
tests/dhcp-lab/run.sh
GHOSTD_LAB_ARCH=amd64 tests/dhcp-lab/run.sh   # matching AMD64 VM and image
```

It builds its own test binary, runs a privileged container with `--network none`,
and cleans up its container on exit. Keep `--network none`; never attach it to a
real LAN. See [docs/operations.md](docs/operations.md) for the full list of
environment gates and their coverage.

## Code layout

| Path | Responsibility |
| --- | --- |
| `cmd/ghostd` | The binary: flags, daemon modes, render-only mode, revert command, identity report |
| `internal/rpc` | gRPC surface: dispatch, validation order, lease arming, confirmation |
| `internal/auth` | Caller identity and authorization through tailscaled `WhoIs` |
| `internal/state` | The durable store: domain transactions, locking, lease and revert timers |
| `internal/nft` | Firewall domain: parse, validate, render, apply, snapshot, restore |
| `internal/netconfig` | Netconfig domain: files, additive actions, snapshot, restore, routes |
| `internal/addressbook` | DHCP/DNS registry: configuration, allocation, identity, handover, listeners |
| `internal/coredhcpserver` | Embedded copy of the CoreDHCP server package |
| `internal/resolver` | Embedded CoreDNS integration and the container resolver |
| `internal/observation` | Fixed read-only evidence capture for host adoption |
| `internal/sdnotify` | `sd_notify` readiness and watchdog |
| `proto` | The wire contract and its generated Go bindings |
| `systemd` | The unit file |
| `tests/dhcp-lab` | The isolated DHCP takeover lab |

### Design invariants

Read the package doc comment before changing a package; several encode invariants
that are not obvious from the code:

- **Clients decide policy.** The daemon validates and executes a resolved target
  and never decides what the policy should be. Service discovery, VLAN placement
  and port-catalogue lookup deliberately do not live here.
- **Every mutation is behind a dead-man's switch.** Nothing is applied without a
  snapshot and an armed revert. If you add a mutation path, it takes a lease.
- **Additivity.** No netconfig action removes an address or brings an interface
  down. `Validate` enforces the closed action set as a hard refusal, rather than
  trusting the caller.
- **Rollback snapshots never rewind the DHCP ledger.** Configuration history and
  allocation history are separate, on purpose.
- **The revert path is independent.** It is a fresh invocation of the installed
  binary, and it can only learn its domain from its own `argv`.

## Expectations for a change

- **Behaviour changes come with tests.** A bug fix gets a regression test that
  fails before the fix. A new validation rule gets a test that proves it refuses.
  A new RPC path gets a handler test with a fake authenticator and runner.
- **Prefer a refusal to a guess.** Several validators reject a target outright
  rather than choosing a winner between conflicting declarations. Follow that: if
  the correct action is ambiguous, refuse.
- **Keep changes to the wire contract versioned.** An unfamiliar target shape must
  never be silently mis-rendered by an older daemon. Parse new input with
  `DisallowUnknownFields` where the existing code does, and use a versioned domain
  name when a client needs a field old daemons do not understand.
- **Do not hand-edit generated files.** `proto/ghoststate.pb.go` and
  `proto/ghoststate_grpc.pb.go` are generated; change the `.proto` and regenerate.
- **Keep dependency changes in their own commit.** Do not fold a dependency
  upgrade into a behaviour change, and do not rewrite `go.sum` as part of an
  unrelated fix. Prefer the standard library and the dependencies already present.
- **Never commit machine-specific data.** No real hostnames, addresses, tailnet
  names, or personal paths in code, tests, docs or fixtures — use the
  documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
  `10.0.0.0/8`) and the placeholder hosts `node-a`, `server` and `deployer`.

## Style

- `gofmt` is not negotiable. `go vet` must be clean.
- Errors are lowercase and wrapped with context, and are written for someone
  reading a journal at the point of failure.
- Comments explain *why*, and the ones that justify a non-obvious decision are the
  most valuable part of the file. If you had to reason your way to a design choice,
  leave that reasoning behind in a comment.
- Documentation and comments are in plain technical English, terse and factual.
  No marketing language.

## Commit messages

The history uses conventional commits with a `ghostd` scope, for example:

```
feat(ghostd): a DHCP server, authoritative DNS, and device identity
fix(ghostd): harden transactional recovery and document standalone deployment
docs(ghostd): finish the sort — one split, two merged, links repaired
```

Use `feat`, `fix`, `refactor`, `docs`, `test` or `chore`, and explain the *why* in
the body when the subject cannot carry it. Keep logically separate changes in
separate commits.

## Regenerating the proto bindings

The generated Go files under `proto/` are checked in, so a build never needs
`protoc`. Regenerate them when you change `proto/ghoststate.proto`, using the
pinned plugin versions:

```sh
export PATH="$PATH:$(go env GOPATH)/bin"

protoc -I proto --go_out=proto --go_opt=paths=source_relative \
  --go-grpc_out=proto --go-grpc_opt=paths=source_relative proto/ghoststate.proto
```

| Tool | Version |
| --- | --- |
| `protoc` | 36.2 |
| `protoc-gen-go` | v1.36.12 |
| `protoc-gen-go-grpc` | v1.6.2 |

The versions are recorded in the header comments of the generated files, so you can
confirm what the checked-in stubs were produced with. Running the command with
those versions from a clean tree should produce no diff. If it produces more than
the field you changed, your plugin versions differ — fix that rather than
committing the churn.

## Licence

ghostd is licensed under GNU GPL version 2 only (`GPL-2.0-only`), without
warranty. By contributing you agree that your contribution is released under the
same terms. See [LICENSE](LICENSE).
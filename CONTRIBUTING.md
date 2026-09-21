# Contributing

## Build and test

```sh
go build ./...
go vet ./...
gofmt -l .          # must print nothing
go test -race ./...
```

Unit tests use fake command runners and need no privileges. Privileged
integration tests are opt-in behind environment variables and belong in a
disposable Linux VM; see [docs/operations.md](docs/operations.md#testing) and
[docs/dhcp.md](docs/dhcp.md#verification) for the DHCP takeover lab.

The container labs (Podman, disposable and network-less) validate what unit tests
cannot: `tests/integration/run.sh`, `tests/dhcp-lab/run.sh` and
`tests/e2e/run.sh` (the real daemon under systemd, including a reboot). Run the
lab that covers what you changed; new behaviour that touches the network or the
boot path needs a lab step, not only a unit test. `GHOSTD_E2E_KEEP=1` leaves the
e2e container running for inspection.

The daemon is CGO-free and cross-compiles:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o bin/ghostd-linux-arm64 ./cmd/ghostd
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o bin/ghostd-linux-amd64 ./cmd/ghostd
```

## Regenerating proto bindings

The generated files under `proto/` are checked in and must not be hand-edited.
Pinned versions (`protoc` 36.2, `protoc-gen-go` v1.36.12, `protoc-gen-go-grpc`
v1.6.2) and the command are in
[docs/operations.md](docs/operations.md#regenerating-the-proto-bindings).

## Conventions

- Persistence and identity are shared; protocol and policy features go through
  the CoreDHCP/CoreDNS plugin APIs ([internal/resolver/PLUGINS.md](internal/resolver/PLUGINS.md)).
- A change to recovery, rollback or the ledger needs a regression test that
  fails without it, including the boundary it protects.
- Keep the docs true: update the relevant page and
  [docs/dhcp-remaining.md](docs/dhcp-remaining.md) in the same change.
- Licence: GPL-2.0-only.

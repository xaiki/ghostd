# Observe, review, adopt

Enable observation for a **fresh, unmanaged** Linux host:

```sh
uv run machines enable node-b
uv run machines apply node-b --plane ghostd --sudo --yes
uv run machines ghostd export node-b --output output/node-b-observation-1
```

`machines enable HOST` updates the inventory with `ghostd.enabled: true` and
`ghostd.observe_only: true`. It preserves an already-active host's management
mode on repeat runs. `machines ghostd enable HOST` is an equivalent spelling.
Both accept `--machines PATH` or the normal `--data-dir` / `--setup` selection. Omitting
HOST opens the standard Linux-host picker (one eligible host is selected
automatically). Cancelling leaves inventory untouched; ambiguous non-interactive
writes require an explicit host. Export also selects a host and defaults its
output to `output/ghostd/HOST-TIMESTAMP`. Compare can select saved observations
when paths are omitted.
Enablement edits inventory only; deployment uses the normal generate/apply flow.

Do not enable managed firewall/netconfig domains before reviewing the export.

The daemon's `--observe-only` flag rejects Apply/Confirm, skips boot restoration,
and refuses to start over existing confirmed state or a pending rollback. It is
not a way to disable enforcement on an already-managed host. Export itself works
against either mode using one read-only GetState RPC. Installing a daemon may
require allowing its tailnet TCP 7443 listener through the existing firewall;
observation mode does not modify that firewall to open its own port.

The private output directory contains:

* `observation.json`: complete nft observations, interface files and addresses,
  plus links/VLAN details, IPv4/IPv6 routes and policy rules from newer daemons.
* `machines.candidate.yaml`: one inventory entry preserving metadata, roles and
  SSH settings; proposed interfaces and simple interface/port firewall allowances.
* `review.json`: missing observations and untranslatable state.

This is a conservative importer, not a lossless translator of every Linux
network manager or nftables expression. Explicit simple ifupdown static addresses
must match live addresses. DHCP/unknown addressing is never pinned to the observed
lease. Bridges, unsupported options, routes, policy routing and firewall rules
with additional predicates remain review blockers; raw evidence is retained.
Simple port allowances never lose source-address restrictions during translation.
Base-chain, forwarding, NAT and ghostd's implicit rule differences always require
human policy review. The candidate does not activate managed domains.

Review the candidate against the observations; fill the unresolved policy using
the existing inventory schema. Merge the selected fields into the existing
machine entry (do not replace the whole inventory with this single-host document).
Clear `ghostd.adoption_blockers` only after resolving every item. The daemon
installer and firewall/netconfig/SSH network apply paths reject unresolved
adoption. No command in this workflow auto-merges inventory or retires a firewall.

After review, activate the declared domains:

```sh
uv run machines enable node-b --act
uv run python generate.py
```

`--act` refuses unresolved adoption blockers, conflicting ownership, non-Linux
hosts and an empty policy. It sets `observe_only: false` and assigns ghostd only
the domains already declared: a firewall policy (`generated` or `base.zones`)
and/or interface/forwarding configuration. It does not invent policy or enable
legacy firewall retirement. Preview the host changes before the normal apply. Firewall generation artifacts describe the proposed policy; they are not
proof of equivalence with arbitrary existing rules.

Capture another observation after a change into a **new** directory and compare:

```sh
uv run machines ghostd export node-b --output output/node-b-observation-2
uv run machines ghostd compare output/node-b-observation-1/observation.json output/node-b-observation-2/observation.json
```

The comparison ignores nft handles and counter values, preserves rule order and
predicates, and exits 1 for differences. It is a structural diff, not a semantic
packet-policy proof. Old daemons remain readable but missing topology information
blocks adoption. Legacy firewall retirement remains a separate explicit opt-in
with rollback; observer deployment alone does not retire anything.

The apply/diff parser exposes every registered host plane. `--plane ghostd`
executes only the daemon layer, without preparing plugins or requiring generated
application configuration. CLI contract tests cover plane-choice parity,
optional inventory targets, ghostd's argument defaults, the printed deployment
command and isolation from unrelated convergence layers.

Ghostd is cross-compiled on the deployment machine with `CGO_ENABLED=0`,
`GOOS=linux` and `GOARCH` determined from the destination's `uname -sm`.
Only the finished ELF binary and service unit are sent to the host. Go is
required locally, never on the destination. Build progress names the target;
Go's normal local cache accelerates subsequent diff/apply runs.

## Boot networking remains independent of ghostd

The generated ifupdown files are the boot fallback, not a cache for ghostd.
Before writing them, ghostd checks the proposed complete include tree from
`/etc/network/interfaces`. The SSH writer performs the same check immediately
before installing files. A missing include, repeated include, duplicate
interface/address-family definition, or removal of a persisted address-family
stanza refuses the write. `source-directory` excludes filenames containing dots,
so it does not load `stack-*.conf`; use an explicit `source` pattern instead.
Includes outside the captured interfaces directory require review.

Existing conflicting definitions are reported with their paths. They are not
deleted automatically: old files can contain IPv6, routes and hooks absent from
the generated draft. Migration must consolidate them without losing the accepted
live behavior. Main-file adoption reuses an existing matching include instead of
adding a duplicate. Ghostd replaces individual files atomically, preserving the
old complete file until the new bytes have been written and synced. This is not
a claim of atomicity across multiple files or a substitute for a reboot test.

## UFW rule translation

Export recognizes UFW user input/output/forward chains, groups duplicate rules and
matching IPv4/IPv6 intent, and writes `firewall-review.md` plus
`firewall-review.json`. Each intent retains its source handles and predicates.
Helper chains are grouped for review, not assumed equivalent based on their names.
Opaque xtables predicates stay unresolved because nft JSON omits their parameters.

Only simple inbound allows present in both IP families contribute zone ports.
Global allows are mapped to observed interfaces in the guarded draft, with an
explicit interface-coverage blocker. Identical interface policies share a zone;
SSH appears once. Output rules never become inbound permissions. Restricted,
denied, limited, or family-specific rules remain review items. In particular,
UFW's matching IPv4/IPv6 OUTPUT policies and simple outbound port allows are now
represented in `firewall.base.output`; helper-chain behavior still requires review.
The candidate stays observation-only until all blockers have been resolved.

Reinterpret a saved observation with the current importer, without contacting the host:

```sh
uv run machines ghostd export node-b --observation output/ghostd/PREVIOUS/observation.json
```

The original capture is preserved; each export creates a new directory.

## Outbound policy

`firewall.base.output` is optional. Omitting it preserves the existing behavior
(no ghostd output hook). An explicit section declares `policy: DROP` or `ACCEPT`,
`established_related` and `loopback` booleans, and an ordered `rules` list of
`{proto: tcp|udp, port: N}` allows. Rules can narrow by `family: ip|ip6`,
`interface`, and `destination` address/CIDR. No input service is implicitly
allowed outbound. Omitted booleans mean false.

The UFW draft explicitly proposes established/related and loopback allowances;
these remain review blockers until helper-chain semantics are verified. It does
not infer unknown conntrack or ICMP parameters from opaque nft xt expressions.

Deploy the new ghostd binary before applying an output policy. The client sends
such policies using the `firewall-output-v1` RPC domain: older daemons reject it,
with no legacy fallback. New daemons normalize it to the existing firewall lease,
so atomic table replacement, confirmation and rollback continue to cover both
input and output. Existing firewall requests remain compatible.

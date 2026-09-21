# Authentication and privilege

ghostd authenticates every RPC caller through the host's own `tailscaled`, using
its `WhoIs` API. There is no Unix-login path, no password, no token to
distribute, and no application-layer TLS — transport encryption comes from
Tailscale, and the listener binds the node's tailnet address alone
(`internal/auth`, `cmd/ghostd/main.go`). Binding a specific address rather than
trusting firewall policy is deliberate: a misconfigured or not-yet-converged
firewall domain still cannot expose the socket off-tailnet.

This replaces granting a service account a broad polkit privilege to manage
firewalling and networking. The privilege level for the work is unchanged — it
has always needed root — but authentication moves to tailnet identity.

## Caller identity

`WhoIs` is asked on every call, including confirmation; nothing is cached across
calls. It yields the caller's login, tags, stable node ID, DNS name and tailnet
addresses. Unknown peers — anyone who is not a recognised tailnet node — are
rejected before authorization is even considered.

Permissions are read from the same `WhoIs` response. A caller cannot supply
permissions in an RPC payload, and permissions are never inferred from the
request body. A `GetState` request cannot carry a deploy grant, and an `Apply`
request cannot assert one.

Three authorization levels exist:

| Level | Method(s) | Requirement |
| --- | --- | --- |
| Read | `GetState`, `GetRegistry`, `GetSuggestions` | Any recognised tailnet peer |
| Mutate | `Apply`, `Confirm`, `ImportLeases`, `ImportObservations`, `RepairIdentity`, `DHCPHandover` | Deployer tag or deploy capability |
| Report | `ReportHost` | Report capability |

## The deploy capability

Authorization for mutations is granted in one of two ways:

- **Node tag.** The caller's node carries the tag named by `--deployer-tag`
  (default `tag:stack-deployer`). This suits dedicated automation nodes.
- **Application capability.** The tailnet policy gives the caller the
  `ghostd.local/cap/deploy` capability, with a body of `{"deploy": true}`, scoped
  to ghostd's destination. This suits a user-owned workstation, and is what lets
  a human keep a personal machine rather than a shared tagged node.

The capability is destination-scoped by the Tailscale policy engine, so it is
granted for ghostd on specific hosts, not globally. Every failure mode is
closed: a missing capability, an explicit `"deploy": false`, or a malformed body
all deny the mutation. Unrelated capabilities do not authorize anything.

`ghostd.local/cap/report` is a separate capability used only by `ReportHost`. Its
body is `{"report": true}`. It never grants deploy permission, and deploy
permission is not required to report — but a deployer may also report, since a
deploy capability or the deployer tag is accepted on that path too. Reporting
additionally requires the caller to have a stable node ID, because the report is
attributed to that node.

## Confirmation is a reachability check

A deployer that has just changed firewall policy may have locked itself out.
`Confirm` therefore runs from a *fresh* connection: the daemon compares the
pending lease's recorded source endpoint against the current caller and rejects a
confirmation that arrives on the same endpoint as the `Apply`. The caller must
close the apply connection, independently prove that the application and
management paths still work, and dial again.

Confirmation is not idempotent, and it is not a proof that every application
works — only that a new connection could be established. Any authorized deployer
can confirm a known pending lease; the daemon does not require the original
caller. Expired, incomplete, unknown and already-completed leases are all
rejected.

## Privilege, and what the validators do not protect

ghostd runs as root, because applying nftables policy and interface configuration
requires it. The domain validators exist to catch mistakes in a resolved target —
they check shapes, additivity, address families and refusals that would strand
the host. They are not a security boundary.

**Treat deployer access as host-administrator access.** Two features make that
concrete:

- The `netconfig` domain writes interface configuration files. On an
  ifupdown-compatible host those files can contain hooks that run as root.
- The legacy `forward` netconfig action executes an existing root-owned script
  (`/etc/stack-forward.sh`).

An attacker who can call `Apply` is therefore not confined by the target schema.
Grant the deploy capability only to identities you would give root on the host.

## Read exposure

`GetState` returns the host's complete nftables ruleset and its interface
configuration. `GetState` with `include_adoption_evidence` additionally returns
fixed read-only adoption evidence, and the DHCP configuration is exposed through
the registry surface. None of this is a secret in the sense of a credential, but
it is a full description of the host's network posture.

Any recognised tailnet peer that can reach the port may read it. Restrict read
access through tailnet policy where that matters — grant the capability to the
deployers who need it, and constrain `ip: ["tcp:7443"]` to the hosts that should
be reachable at all.

## Observation mode

`--observe-only` starts a daemon that reads live state and rejects every mutation
RPC, skips boot-time restore, and refuses to start at all over an existing
confirmed domain or a pending rollback. It exists to capture an unmanaged host's
current configuration before adopting it (see [adoption.md](adoption.md)).

It is **not** a way to stop enforcing policy on a host ghostd already manages.
The daemon refuses that conversion rather than quietly leaving the host
unenforced.

Observation mode does not modify the host's firewall. Installing a daemon on a
host whose firewall already drops inbound tailnet traffic therefore needs that
host's existing firewall to admit TCP 7443 first — observation mode will not open
its own port.

## What ghostd does not provide

- **No audit trail of intent.** Transaction records persist the source peer of an
  apply, which is what makes recovery and diagnosis possible, but ghostd does not
  keep a durable log of who changed what and why.
- **No protection from local root.** Anyone with root on the host can edit the
  store directory, the interface files, or the installed binary. The dead-man's
  switch defends against a *remote* change that was never confirmed; it is not a
  defence against local administration.
- **No substitute for network access control.** DHCP reports and lease records
  attribute addresses to devices. They are evidence supplied by authorised hosts,
  not cryptographic proof of who owns a LAN address, and they do not gate
  network access.

## Tailnet policy example

The deploy grant, with documentation addresses and identities only:

```json
{"grants": [{
  "src": ["deployer@example.com"],
  "dst": ["100.64.0.10"],
  "ip": ["tcp:7443"],
  "app": {"ghostd.local/cap/deploy": [{"deploy": true}]}
}]}
```

Merge this into existing policy; do not replace the policy with this example. Use
the real listener port if it was changed.

A reporting host needs its own capability, granted to the authority it reports
to:

```json
{"grants": [{
  "src": ["node-a"],
  "dst": ["100.64.0.10"],
  "ip": ["tcp:7443"],
  "app": {"ghostd.local/cap/report": [{"report": true}]}
}]}
```

## Additional surfaces

- **`ImportObservations`** (switch evidence) and `RepairIdentity`, `ImportLeases`,
  `DHCPHandover` (including `promote`) are deployer calls. A **warm standby**
  refuses every registry write until promoted, and refuses `ReportHost`.
- **The per-container DNS ACL** (see [dhcp.md](dhcp.md#per-container-dns-acl))
  identifies a container by the resolver listener address it uses. That is a
  property of the network path, not a credential: ghostd cannot verify who holds an
  address, so pair each identity with host firewall policy admitting only that
  container to its own address. A missing or unparsable policy makes the listener
  refuse everything rather than fall back to open access.
- **`mdns-v1`** advertises only what the operator declares, on named interfaces, and
  refuses to advertise over a name another host already owns. Deployer access lets
  a caller advertise any record set on the LAN: treat it like the other domains.
- **The TFTP server** is read-only and confined to its root, but it is
  unauthenticated by nature; serve only files that may be world-readable on the
  LAN.

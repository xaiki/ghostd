# The netconfig domain

The `netconfig` domain persists interface configuration files and executes the
ordered list of commands still needed to reconcile live state with them. It is
the `netconfig` counterpart of the [firewall domain](firewall.md): the client
computes the complete plan, and the daemon validates and executes it.

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

Supply the **complete** target and its replayable actions, including
configuration that is already present on the host. A confirmed target is replayed
at daemon startup, so anything omitted from it is something the daemon will not
restore after a reboot.

## Files

Files may be written below `/etc/network/interfaces.d/`, or to the two forwarding
files:

- `/etc/sysctl.d/99-stack-forward.conf`
- `/etc/sysctl.d/99-stack-no-forward.conf`

Any other path is refused. The two forwarding files accept only an empty string,
`net.ipv4.ip_forward=0\n`, or `net.ipv4.ip_forward=1\n` — nothing else is
permitted in them.

The daemon writes declared files and then executes actions in order. It does
**not** remove files, addresses or interfaces that the target omits, and it does
not reload a network manager. Persisted interface files require an
ifupdown-compatible host setup.

## Actions

Each action is `[kind, ...args]`. The recognised kinds are a closed set:

| Action | Arguments | Meaning |
| --- | --- | --- |
| `default-route` | `dev`, `gateway`, `onlink` \| `offlink` | Install an IPv4 default route |
| `vlan` | `base`, `dev`, `vlan_id` | Create a VLAN device |
| `addr` | `dev`, `address/prefix` | Add an address |
| `sysctl` | `keyval` | Only `net.ipv4.ip_forward=0` or `=1` |
| `forward` | script path | Legacy: `/etc/stack-forward.sh` only |
| `up` | `dev` | Bring a device up |

Every recognised action is additive by construction. No action kind removes an
address or brings an interface down, and `Validate` enforces that as a hard
refusal rather than trusting the caller: a target from a buggy client is rejected
before a lease is armed, not rolled back five minutes later. An unrecognised
action kind is an error, never a silently skipped line.

Idempotency is checked against live state rather than assumed:

- An existing VLAN must match the requested parent and ID.
- An existing address must match the device, address and prefix.
- Default routes are handled conservatively. An existing default route is never
  replaced or removed; the action is satisfied only if the existing route already
  matches exactly, including its flags and metric. Multiple default routes, or
  attributes the daemon does not understand, require explicit migration.
- Two `addr` actions claiming the same bare address on different devices are
  refused outright, rather than the daemon picking a winner.

## Adoption preconditions

```json
"expected_files_sha256": {"/etc/network/interfaces": "<64 hex characters>"}
```

When adopting a host that is already configured, the target can pin the digest of
`/etc/network/interfaces`. The daemon re-reads that file before applying: if it
has changed since the observation the target was built from, the apply is refused
rather than overwriting a configuration that has moved on. The precondition is
only valid for that one path, and a precondition without a matching entry in
`files` is rejected.

## Rollback, and what it does not cover

Recovery restores the contents of every touched file — including restoring a file
that did not exist before — and the previous IPv4 forwarding value.

It does **not** undo additive live link and address changes, and it does not undo
arbitrary effects of the legacy forwarding script. A rollback returns the
configuration files and the forwarding sysctl to their prior state; interfaces
and addresses added by the actions stay until something removes them.

Use the firewall domain for nft policy rather than the legacy `forward` script.

There is no cross-domain atomic transaction. Each domain has its own lease and
its own confirmed state, so a firewall target and a netconfig target applied
together are two independent changes with two independent rollback deadlines.

## Reading state

`GetState` returns the netconfig half as JSON: the persisted
`/etc/network/interfaces.d` file bytes, the live `ip -j addr show` output, and the
current `/proc/sys/net/ipv4/ip_forward` value. That is enough for a client to
compute the next complete target without guessing what is already there.

See [operations.md](operations.md) for the lease, confirmation and recovery
mechanics that both domains share.
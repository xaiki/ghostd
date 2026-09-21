# ghostd as the stack's LAN-presence plane

Status: **plan, not built.** Companion to `docs/arch/samba.md`, which is the first
consumer of it.

This is deliberately **not written as a Samba feature.** SMB needs Time Machine and
printer advertisement; CUPS needs printer browsing; Music Assistant needs player
discovery. Those are three different apps needing the same missing plane, so it
belongs to ghostd and is documented once.

## The gap

Containers live on a podman bridge network. mDNS is multicast on the LAN. Neither
direction crosses that boundary:

- **A containerized app cannot advertise.** Its packets do not leave the bridge,
  and there is no mDNS daemon inside the container — nor will there be, since we
  refuse to install one (`stack_config/nsswitch.py`: *"Deliberately not here:
  installing `libnss-mdns` or `avahi-daemon`"*).
- **A containerized app cannot discover LAN services.** Nothing answers
  `224.0.0.251:5353` inside the bridge, so a player, a printer or a peer is
  invisible.

## The workaround already in the tree, and what it costs

This is not a hypothetical gap. `stack_plugins/container/music_assistant/__init__.py:113`
declares `network_mode="host"`, and the plugin says why in its own words
(`:218`): *"Runs with host networking — upstream requires it for mDNS/UPnP player"*.
`docs/arch/music-assistant.md:13` records the same decision, and `:126` notes the
consequence — LAN players need port 8097, so the plugin has no `ports=` of its own
and the zone needs the port open.

So the cost of the missing bridge is being paid **today**: to obtain mDNS, one app
gives up the container network entirely — no network alias, its ports on the host,
its own firewall entry, and the isolation everything else in the stack keeps.

That is what makes this plane worth building rather than a nice-to-have: it
unblocks SMB and CUPS *and* it lets Music Assistant come back onto the container
network.

## The landmine: retiring avahi breaks the resolver we already have

`ghostd/internal/resolver/resolver.go:146-148` answers `.local` for containers by
shelling out to `getent ahosts`, and the comment says exactly why:

> ghostd is cross-compiled without cgo: getent keeps the host's NSS/Avahi
> behavior instead of Go silently treating `.local` as ordinary unicast DNS.

So the container `.local` path currently **depends on the host's avahi**. And
avahi retirement is not optional for the advertisement half: ghostd's socket rule
is *"No SO_REUSEADDR/SO_REUSEPORT: never share a scope with another allocator"*
(`internal/addressbook/socket_linux.go`), so a bare `:5353` bind fails
`EADDRINUSE` while avahi holds the port.

Therefore: **ghostd must own mDNS queries before avahi is retired**, or `.local`
resolution regresses for every container as a side effect of an unrelated change.
This coupling deserves its own test — retire avahi, and a container can still
resolve a `.local` name — because nothing about "remove a host package" announces
that it can break name resolution.

Also verified: the container resolver listens on the **tailnet address only**
(`cmd/ghostd/main.go:237`, *"container DNS listening on … (tailnet-only)"*). So
containers reach ghostd over the tailnet plane while the advertisement happens on
the LAN plane. That is fine — the unicast hop and the multicast plane are
different things — but it means this capability has consumers on one side and
traffic on the other, which is worth keeping straight when debugging.

## Three shapes for "a container app needs LAN discovery"

| shape | how | cost |
|---|---|---|
| **(a) Host networking** | the app joins the host's network namespace | today's Music Assistant workaround: no container network, no alias, host ports, extra firewall |
| **(b) ghostd as the API** | containers use the unicast resolver ghostd already publishes (`dns.env`/`resolv.conf`) plus a browse/enumerate surface | only works for apps that can be pointed at an explicit resolver — CUPS can be given printers directly, most player libraries cannot |
| **(c) ghostd as a multicast reflector** | re-emit LAN mDNS onto the podman bridge so a container's own mDNS listener sees it, and carry its answers back out | most general: any app that speaks mDNS itself just works, with no host networking |

**Recommendation, revised in light of the ACL below: (c) is the mechanism, (b) is
where the ACL can actually be enforced.** They need the same record knowledge; the
difference is that a query can carry an identity and a reflected multicast packet
cannot.

## The ACL: per-container, by service class

Each container must see only the classes it is allowed to see — printers for the
printing app, players for the music app, and not the rest of the LAN's chatter.
That is a per-container allow-list keyed by service class (`_ipp._tcp`,
`_googlecast._tcp`, `_airplay._tcp`, `_adisk._tcp`, `_smb._tcp`, …), and it should
share the DNS vocabulary rather than being a second permission language.

**What "the DNS ACL" is today: a documented prerequisite, not an implementation.**
grepping ghostd finds no ACL of any kind — no allow-list, no permit, no client
filtering; the only "client" in the resolver is the `dns.Client` that talks to
MagicDNS upstream. What exists is the intent, recorded twice in
`docs/arch/dhcp-dns-identity-plan.md`:

> Per-container DNS ACL identity remains a separate prerequisite; lease names or
> source addresses behind a shared forwarder are not sufficient credentials.
> — `:104`

> … and per-container authenticated DNS ACLs remain explicitly separate work.
> — `:184`

Two consequences follow, and the first kills the obvious shortcut:

1. **The principal cannot be a source address.** The doc states plainly that lease
   names and source addresses behind a shared forwarder are *not* sufficient
   credentials — and podman's own DNS, or ghostd's forwarder, is exactly such a
   shared forwarder, where every container appears to come from the same address.
   So the ACL needs an **authenticated per-container identity**: a credential each
   container presents, which is the "identity" that doc defers.
2. **One identity, two permissions**: what a container may *resolve* (the DNS half)
   and what classes it may *discover* (this half). Built once, both answer from it —
   rather than the reflector growing a private notion of who is allowed what.

### Why this is hard to reconcile with a multicast reflector

A multicast packet cannot carry a per-container identity, and every member of a
bridge receives the same stream. Reflecting a container's allowed classes onto a
**shared** bridge therefore cannot enforce anything: either every container on that
bridge sees the union of everyone's classes, or the reflection target is itself
**per-container scoped**, so the permission is a property of the network rather than
of the packet.

So the ACL requirement picks one of three, and the choice should be made **with**
the DNS ACL rather than beside it, since they share the identity:

- **authenticated unicast browsing** — shape (b) as the real interface, each query
  carrying the container's identity and the answer filtered per class. The only
  shape where enforcement is straightforward; needs the app to cooperate.
- **per-container networks** — shape (c) kept, each container or pod on a network
  whose reflection set is exactly its allowance. Leaves apps unmodified, costs a
  network per permission set.
- **one shared permission** — the whole bridge gets a single class set. Simplest,
  and honest only where every container on it is equally trusted.

## What it costs

Shape surgery on ghostd (there is **no capability registry**; a new domain is a
hand-written cross-language chain). The machinery — the domain wiring, the
privilege situation, the library choice, the wire-versioning discipline and the
reconciler shape — is specified in the daemon's own documentation,
[`ghostd/README.md`'s LAN discovery section](../../ghostd/README.md), so it lives with
the code it describes and does not drift from a copy here.

Two things about cost belong in *this* doc, because they are not ghostd-internal:

- **The ACL identity first, and it is the largest piece.** It is a prerequisite
  shared with the deferred DNS work (`docs/arch/dhcp-dns-identity-plan.md:104`,
  `:184`), where an authenticated per-container identity is explicitly separate
  work. So this plane's critical path runs through something another plan already
  owes — which is an argument for building the identity once, against both
  permissions, rather than letting the advertisement grow its own.
- **Records are captured, not recalled.** The advertisement needs specific record
  sets (`_smb._tcp`, `_device-info._tcp`, `_adisk._tcp`, `_ipp._tcp` plus the
  `_universal` subtype). We take those from a **captured known-good advertisement**
  — browsed once on the LAN and committed as a stripped golden fixture — rather
  than from recollection. `docs/arch/samba.md` records why: a search for the Time
  Machine record keys returned partial evidence, and inventing plausible-looking
  keys is precisely how a Time Capsule never appears in the sidebar.

## Consumers

| consumer | direction | needs |
|---|---|---|
| SMB / Time Machine | advertise | `_adisk._tcp`, `_smb._tcp`, `_device-info._tcp` |
| CUPS | advertise **and** browse | `_ipp._tcp` + `_universal._sub._ipp._tcp`; browsing to find network printers |
| Music Assistant | browse | Chromecast / AirPlay / UPnP player discovery — today via `network_mode="host"` |
| anything later | both | one plane, rather than one bridge per app |

## Decisions this must respect

- `docs/arch/dhcp-dns-identity-plan.md:90` — *"keep `.local` as mDNS discovery"*,
  publishing A/AAAA and scoped PTR only for eligible bindings.
- `docs/arch/access-links.md` — *"mDNS `.local` does not resolve over the tailnet"*,
  no relay. So this plane is **LAN-only**, which is exactly where Time Machine,
  printers and players live.
- The resolver deliberately never rewrites `/etc/resolv.conf` and uses `getent` to
  preserve host NSS behaviour. That last part is the landmine above: it is a
  dependency to replace, not a design to keep.

## Open questions

- **Which of the three ACL shapes.** Authenticated unicast browsing, per-container
  networks, or one shared permission. Note this decides whether a reflector is in
  the design at all: if the ACL must hold per container, reflecting into a shared
  bridge is ruled out, because one stream cannot carry one container's permission.
- **Where the desired record set is declared.** A per-machine
  `advertisement: {managed_by: ghostd}` key in the `firewall:`/`netconfig:`
  convention, or derived from what each plugin renders? Deriving keeps the app
  authoritative; declaring keeps a single reviewable list.
- **Conflict handling.** The LAN may already advertise a name we want — a real
  router, another Time Machine, a printer somebody else manages. What does the
  plane do when it is not the only authority?
- **Whether (a) stays supported** once the ACL shape lands. Almost certainly yes as
  an escape hatch, since upstream may still insist on it.
- **What the container's credential actually is**, and how it is delivered. This is
  the same unknown the DNS ACL defers: a per-container identity that is not a source
  address. Until it exists, per-class enforcement has no principal — so it, not the
  reflector, is the critical path.
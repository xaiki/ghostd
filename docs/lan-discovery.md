# LAN discovery on behalf of containers — design

Build tags: `mdns` (native client, `mdns-v1`) and `coredns` (container resolver,
ACL); the two together give containers native `.local`.

Status: **built, except the multicast reflector — which the design rules out.** The
decisions this document left open are settled in [What was decided and built](#what-was-decided-and-built)
below; the analysis after it is kept because it is why those decisions were made.

## What was decided and built

| Question | Decision | Where |
| --- | --- | --- |
| Retiring avahi breaks `.local` | ghostd owns mDNS **queries** natively: legacy-unicast queries from an ephemeral port, so it never binds UDP 5353. `getent` remains only as a fallback when no interface can send. Lab: no avahi on the host, a third-party responder on the LAN, `.local` still resolves. | `internal/mdns/query.go`, `internal/resolver/resolver.go` |
| Which ACL shape | **Authenticated unicast browsing.** The identity of a query is the resolver *listener* it arrived on, never a source address. Per-container networks and one shared permission were rejected: the first costs a network per permission set, the second is not an ACL. | `internal/resolver/acl.go` |
| Reflector | **Not built, deliberately.** One multicast stream cannot carry one container's permission, so reflecting into a shared bridge would defeat the ACL. An application that can only speak mDNS itself still needs host networking (shape (a) stays as the escape hatch). | — |
| Where the record set is declared | The `mdns-v1` domain: an explicit, reviewable list, riding the ordinary lease, confirmation and rollback. | `internal/mdns/advertise.go`, `internal/rpc/addressbook.go` |
| Conflicts | Before advertising, ghostd **probes** each name; a name another host already owns refuses the apply and leaves the previous set running. Lab: avahi owns "Lobby Printer"; advertising over it is refused. | `internal/mdns/service.go` |
| Records are captured, not recalled | Unchanged. ghostd ships **no** Time Machine record set: supply one captured from a known-good advertisement. | — |

The ACL and the mDNS domain are described for operators in [dhcp.md](dhcp.md#per-container-dns-acl)
and [operations.md](operations.md#mdns-advertisement).

## Analysis (why)

This is deliberately **not written as a feature of one application.** File sharing
needs Time Machine and printer advertisement, printing needs printer browsing, and
media players need discovery. Those are different applications needing the same
missing plane, so it belongs to ghostd and is documented once.

## The gap

Containers live on a Podman bridge network. mDNS is multicast on the LAN. Neither
direction crosses that boundary:

- **A containerised app cannot advertise.** Its packets do not leave the bridge,
  and there is no mDNS daemon inside the container. This project does not install
  one on the host as a workaround either.
- **A containerised app cannot discover LAN services.** Nothing answers
  `224.0.0.251:5353` inside the bridge, so a player, a printer or a peer is
  invisible.

## The workaround already in use, and what it costs

This is not a hypothetical gap. The way to obtain mDNS from a containerised app
today is `network_mode="host"`: the app joins the host's network namespace. The
plugin that does it says why — upstream requires host networking for mDNS/UPnP
discovery.

So the cost of the missing plane is being paid **now**: to obtain mDNS, one
application gives up the container network entirely — no network alias, its ports
exposed on the host, its own firewall entry, and the isolation every other
container keeps.

That is what makes this plane worth building rather than a nice-to-have: it
unblocks file sharing and printing *and* it lets a media application come back
onto the container network.

## The landmine: retiring avahi breaks the resolver we already have

`internal/resolver/resolver.go` answers `.local` for containers by shelling out to
`getent ahosts`, and the comment says exactly why:

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

Also worth keeping straight: the container resolver listens on the **tailnet
address only** (`cmd/ghostd/main.go`). Containers reach ghostd over the tailnet
plane while the advertisement happens on the LAN plane. That is fine — the unicast
hop and the multicast plane are different things — but it means this capability
has consumers on one side and traffic on the other, which matters when debugging.

## Three shapes for "a container app needs LAN discovery"

| Shape | How | Cost |
| --- | --- | --- |
| **(a) Host networking** | The app joins the host's network namespace | Today's workaround: no container network, no alias, host ports, extra firewall |
| **(b) ghostd as the API** | Containers use the unicast resolver ghostd already publishes plus a browse/enumerate surface | Only works for apps that can be pointed at an explicit resolver — printing can be given printers directly, most player libraries cannot |
| **(c) ghostd as a multicast reflector** | Re-emit LAN mDNS onto the Podman bridge so a container's own mDNS listener sees it, and carry its answers back out | Most general: any app that speaks mDNS itself just works, with no host networking |

**Recommendation: (c) is the mechanism, (b) is where the ACL can actually be
enforced.** They need the same record knowledge; the difference is that a query
can carry an identity and a reflected multicast packet cannot.

## The ACL: per-container, by service class

Each container must see only the classes it is allowed to see — printers for the
printing app, players for the music app, and not the rest of the LAN's chatter.
That is a per-container allow-list keyed by service class (`_ipp._tcp`,
`_googlecast._tcp`, `_airplay._tcp`, `_adisk._tcp`, `_smb._tcp`, …), and it should
share the DNS vocabulary rather than being a second permission language.

**What "the DNS ACL" is today: a documented prerequisite, not an implementation.**
There is no ACL of any kind in the tree — no allow-list, no permit, no client
filtering; the only "client" in the resolver is the `dns.Client` that talks to
MagicDNS upstream. What exists is the intent, recorded twice in
[dhcp-dns-identity.md](dhcp-dns-identity.md):

> Per-container DNS ACL identity remains a separate prerequisite; lease names or
> source addresses behind a shared forwarder are not sufficient credentials.

Two consequences follow, and the first kills the obvious shortcut:

1. **The principal cannot be a source address.** Lease names and source addresses
   behind a shared forwarder are explicitly *not* sufficient credentials — and a
   container runtime's own DNS, or ghostd's forwarder, is exactly such a shared
   forwarder, where every container appears to come from the same address. So the
   ACL needs an **authenticated per-container identity**: a credential each
   container presents, which is the "identity" the DHCP design defers.
2. **One identity, two permissions.** What a container may *resolve* (the DNS
   half) and what classes it may *discover* (this half). Built once, both answer
   from it — rather than the reflector growing a private notion of who is allowed
   what.

### Why this is hard to reconcile with a multicast reflector

A multicast packet cannot carry a per-container identity, and every member of a
bridge receives the same stream. Reflecting a container's allowed classes onto a
**shared** bridge therefore cannot enforce anything: either every container on
that bridge sees the union of everyone's classes, or the reflection target is
itself **per-container scoped**, so the permission is a property of the network
rather than of the packet.

So the ACL requirement picks one of three, and the choice should be made **with**
the DNS ACL rather than beside it, since they share the identity:

- **Authenticated unicast browsing** — shape (b) as the real interface, each query
  carrying the container's identity and the answer filtered per class. The only
  shape where enforcement is straightforward; needs the app to cooperate.
- **Per-container networks** — shape (c) kept, each container or pod on a network
  whose reflection set is exactly its allowance. Leaves apps unmodified, costs a
  network per permission set.
- **One shared permission** — the whole bridge gets a single class set. Simplest,
  and honest only where every container on it is equally trusted.

## Implementation shape

There is **no capability registry**; a new domain is a hand-written chain across
several layers. Wiring follows the newest domain (`dhcp-v1`) rather than inventing
a shape:

- `internal/rpc/server.go` — the domain constant, the `Apply` case, `legacyName`,
  the `Confirm` loop, `GetState`, and the server field.
- `internal/state/transaction.go` — the domain allowlist.
- `cmd/ghostd/main.go` — `prepareDomain`, `recoverDomain`, `--revert-domain`.
- `proto/ghoststate.proto` — with regenerated Go.
- `internal/state/lease.go` — the revert timer.

The reconciler imitates `addressbook.Manager.Apply`: desired set in, live listeners
out, close what is no longer wanted. Rollback rides the existing lease and revert
timer rather than adding a second mechanism.

Wire structs parse with `DisallowUnknownFields`, so the daemon must be upgraded
before a new field arrives; use a versioned domain so an older daemon rejects the
request instead of mis-rendering it. DNS-SD is plain DNS and `miekg/dns` is already
a dependency, and the binary is cgo-free, so there is no `libavahi` binding to
reach for.

## What it costs

Two things about cost belong in *this* doc, because they are not
ghostd-internal:

- **The ACL identity first, and it is the largest piece.** It is a prerequisite
  shared with the deferred DNS work, where an authenticated per-container identity
  is explicitly separate work. So this plane's critical path runs through something
  another plan already owes — which is an argument for building the identity once,
  against both permissions, rather than letting the advertisement grow its own.
- **Records are captured, not recalled.** The advertisement needs specific record
  sets (`_smb._tcp`, `_device-info._tcp`, `_adisk._tcp`, `_ipp._tcp` plus the
  `_universal` subtype). Take those from a **captured known-good advertisement** —
  browsed once on the LAN and committed as a stripped golden fixture — rather than
  from recollection. A search for the Time Machine record keys returns partial
  evidence at best, and inventing plausible-looking keys is precisely how an
  advertised volume never appears in the client's sidebar.

## Consumers

| Consumer | Direction | Needs |
| --- | --- | --- |
| File sharing / Time Machine | Advertise | `_adisk._tcp`, `_smb._tcp`, `_device-info._tcp` |
| Printing | Advertise **and** browse | `_ipp._tcp` plus `_universal._sub._ipp._tcp`; browsing to find network printers |
| Media players | Browse | Chromecast, AirPlay and UPnP player discovery — today via host networking |
| Anything later | Both | One plane, rather than one bridge per app |

## Decisions this must respect

- Keep `.local` as mDNS discovery, publishing A/AAAA and scoped PTR records only
  for eligible bindings ([dhcp-dns-identity.md](dhcp-dns-identity.md)).
- mDNS `.local` does not resolve over the tailnet, and there is no relay for it. So
  this plane is **LAN-only** — which is exactly where file sharing, printers and
  players live.
- The resolver deliberately never rewrites `/etc/resolv.conf` and uses `getent` to
  preserve host NSS behaviour. That last part is the landmine above: it is a
  dependency to replace, not a design to keep.

## Open questions (now resolved above)

- **Which of the three ACL shapes.** Authenticated unicast browsing, per-container
  networks, or one shared permission. This decides whether a reflector is in the
  design at all: if the ACL must hold per container, reflecting into a shared bridge
  is ruled out, because one stream cannot carry one container's permission.
- **Where the desired record set is declared.** A per-machine
  `advertisement: {managed_by: ghostd}` key alongside the firewall and netconfig
  targets, or derived from what each application declares? Deriving keeps the app
  authoritative; declaring keeps a single reviewable list.
- **Conflict handling.** The LAN may already advertise a name we want — a real
  router, another Time Machine host, a printer somebody else manages. What does the
  plane do when it is not the only authority?
- **Whether host networking stays supported** once the ACL shape lands. Almost
  certainly yes as an escape hatch, since upstream may still insist on it.
- **What the container's credential actually is, and how it is delivered.** This is
  the same unknown the DNS ACL defers: a per-container identity that is not a source
  address. Until it exists, per-class enforcement has no principal — so it, not the
  reflector, is the critical path.
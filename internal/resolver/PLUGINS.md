# Embedded DNS and DHCP plugins

Both integrations use their upstream plugin registration, configuration and
handler APIs. They do not introduce a separate ghostd plugin interface or load
arbitrary shared libraries at runtime. Plugins are compiled into the binary;
configuration selects and orders their use.

| Responsibility | CoreDNS | CoreDHCP |
| --- | --- | --- |
| Assembly | `resolver/plugins.go`: imports, directives, generated Corefile | `addressbook/plugins.go`: ordered upstream PluginConfig lists |
| Ghostd lease feature | `ghostleases`, registered in `resolver/registry.go` | `ghostleases`, registered in `addressbook/core_plugin.go`, Setup4 and Setup6 |
| Other ghostd feature | `ghostlocal`, registered with CoreDNS | New features register Setup4 and/or Setup6 with CoreDHCP |
| Shared data | `addressbook.Store` and current scope configuration | Same durable store and scope configuration |
| Extension | Import/register plugin, place directive and configure it | Register plugin, pass Before4/After4/Before6/After6 to NewManagerWithPlugins |

The DNS lease handler implements CoreDNS's Handler interface and delegates
unowned names to Next. LAN listeners also use that handler. Lease answers precede
cache so released addresses cannot be served from the recursive cache. An access
policy plugin must precede both lease answers and cache; adding a plugin after
cache cannot enforce access to cached answers.

DHCP Before plugins perform admission checks. The lease plugin constructs the
reply and commits ownership before acknowledging it. Successful replies continue
to After plugins for option decoration or observation. Rejected requests and
no-reply operations stop the chain; a later plugin cannot resurrect them. A
Before plugin may likewise terminate processing through CoreDHCP's stop result.
Do not stack another allocator around ghostleases. After plugins must not change
allocated addresses, client/server identity, or lease lifetimes independently of
the ledger. An After failure does not undo a committed grant; client retries must
use that existing grant. Plugins execute concurrently and must be concurrency-safe.

CoreDHCP extension lists are copied at manager construction and remain fixed for
its lifetime. Scope changes remain independently reloadable. Plugin handlers must
not call Manager.Apply, Close or Config: packet admission holds the configuration
read lock. Use setup-time dependencies or the supplied request/reply instead.

The CoreDHCP server adaptation owns sockets, transport-peer admission, dispatch,
and reply delivery, not allocation or DNS policy. Peer validation remains at the
transport boundary because upstream plugin handlers do not receive the peer.
Persistence and identity joining live in the shared registry so both protocols
observe the same ownership. Router advertisements are a separate ICMPv6 protocol,
not DHCP packets, and are not forced into the DHCP plugin chain.

These extension points do not imply that every planned feature (such as DNS ACLs)
is already implemented, or that the full takeover integration has been validated.

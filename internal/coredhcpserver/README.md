# Embedded CoreDHCP server

Server source from coredhcp/coredhcp commit a0841cb3038f63e3f93e813648cea8641a3bc5c0
(MIT, LICENSE alongside). Config, plugin registry and handler APIs use the pinned
upstream module directly. This copy is limited to its server package so embedding
patches are explicit and diffable against upstream:

- Supplied exclusive sockets preserve bind-before-commit and reject another DHCP authority.
- Admission guards receive the transport peer and hold the scope configuration read lock.
- Both protocol dispatchers allow DECLINE through to the lease plugin.
- Bounded handler concurrency and buffered exit reporting.
- Packet buffers return to the pool after handlers finish, not while options may reference them.
- Non-Linux compile stub for raw Ethernet replies (the managed listener remains Linux-only).

`addressbook/core_plugin.go` is the durable registry plugin. Its configuration uses
CoreDHCP's ordinary ordered `plugins` list, not a second dispatcher.

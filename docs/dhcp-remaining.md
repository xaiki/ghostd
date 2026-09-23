# Remaining DHCP/DNS work

What is left after the cutover, identity, discovery and network-boot work, and what
was verified how. The implemented behaviour is in [dhcp.md](dhcp.md) and the design
rationale in [dhcp-dns-identity.md](dhcp-dns-identity.md).

Read this before trusting the DHCP domain on a network you care about: **no
production or LAN cutover has been performed**; everything below was exercised in
disposable containers.

## Built and verified since the last checkpoint

| Was open | Now | Verified by |
| --- | --- | --- |
| Rollback from an empty original lease file lost new grants | The journal records `activated`; rollback always exports the current ledger once activated | unit; dhcp-lab |
| Rollback after an unimportable snapshot could strand dnsmasq stopped | Rollback of a never-activated takeover restores the untouched legacy authority without re-parsing | unit (malformed, undeclared scope, DHCPv6 temporary) |
| Recovery only ran after normal startup | Boot recovery runs before the DHCP configuration is applied; a pending takeover whose target cannot bind is rolled back | unit; **e2e** (kill mid-window, restart, boot after the deadline) |
| Re-importing our own rollback export collided with the ledger's quarantine | `ImportDocument` recognises the synthetic quarantine identity | unit; dhcp-lab (offer + decline left outstanding, roll back to real dnsmasq, second takeover) |
| Durable interface associations | `RepairIdentity` `persist`/`forget`, applied by allocation, history kept | unit; e2e |
| Observation history | `observation`/`observation-end` events; historical snapshots return only sightings valid at that instant | unit |
| Repair policy consistency | Repair honours `tailnet_node_ids` and refuses names held by other live devices | unit |
| Unmanaged hosts and suggestions | Peer inventory from the authority's tailscaled; `GetSuggestions`, never self-applying, `endpoint` vs weak `hostname` strength | unit; e2e (fake tailscaled reports a peer, reviewer applies the suggestion) |
| Switch evidence | `ImportObservations` | unit; e2e |
| Configuration conversion | `ghostd --convert-dnsmasq`, includes followed, unsupported semantics refused, validator shared with `begin` | unit; e2e (the lab takes over with the converter's own plan) |
| Client-side verification before confirmation | `require_evidence`: renewal of an inherited lease and a fresh grant per scope, from ledger events | unit; e2e (confirm refused, then allowed after real clients) |
| Progress view | `status`: remaining time, retryability, per-scope evidence, what is unverified, history count | unit; e2e |
| Bound expiry work | Expiry reads an end-time index (backfilled on upgrade) | unit |
| DNS revision | The SOA serial advances on zone/alias/scope changes | unit |
| Lease-file replacement | Symlinks refused; mode, cleanup and interrupted replacement tested; rollback waits for the service's own process to hold UDP 67/547 | unit; integration; e2e (real systemd rollback) |
| Recovery journal lifecycle | Finished takeovers archived; `history` action | unit; e2e |
| DHCPv6 durability | Crash after a Reply keeps the grant; no reply grants an unrecorded address | unit |
| Real DHCPv6 Renew/Rebind | ISC `dhclient -6` renews by its own T1 timer and, with Renews dropped, Rebinds at T2 | dhcp-lab |
| Offers and declined addresses across rollback with real dnsmasq | Exported as occupied; neither the decliner nor a stranger is offered them | dhcp-lab |
| Transaction interaction over RPC | Ordinary Apply vs handover, expired Apply recovery | unit (authenticated handlers) |
| Kill at every handover boundary | Simulated kill at stop/read/export/start, then idempotent recovery | unit |
| Production boot path and reboot | The real binary under systemd, container restarted: confirmed firewall, netconfig, handover and mDNS survive; dnsmasq stays masked | **e2e** |
| Per-container DNS ACL | Listener identity, checked before lease answers and cache, per-identity cache, per-identity host grants | unit; integration (loopback aliases); e2e (avahi + python-zeroconf) |
| mDNS without avahi on the host | Native legacy-unicast client | unit; e2e |
| Per-container mDNS relay | Directed rules between named domains (VLANs, the LAN, container bridges) — an endpoint may be a pattern, resolved to the interfaces that exist — composing into a reachability relation with the narrower class set: allowed classes and the hosts they name, allowed queries the other way | unit; e2e (avahi on the LAN, python-zeroconf inside two container-network namespaces, and a second bridge: direction allowed and denied, and a two-hop composition through a pattern endpoint) |
| mDNS translation | A source's advertisements re-advertised on the destination interface at ghostd's address and a pooled port (one pool per interface), DNAT into the container, goodbyes and expiry, terminal at its own rule | unit; e2e (python-zeroconf advertiser inside a container network, avahi/zeroconf client on the LAN: found, resolved to ghostd:port, TCP connection lands in the container, withdrawn on goodbye) |
| LAN advertisement | `mdns-v2` with probing and conflict refusal | unit; e2e (avahi as a competing responder, python-zeroconf as the client, across a reboot) |
| TFTP/PXE | `boot` + `tftp`, converter support | unit; e2e (dnsmasq, then ghostd, serve a boot file to busybox tftp behind the firewall) |
| DHCPv6 prefix delegation | `pd` pool, ledger, attribution, kernel routes | unit; dhcp-lab (`dhclient -6 -P`, route installed and removed) |
| Replication | Warm standby: `--follow`, mirrored ledger/config, fenced manual `promote` | unit (real gRPC between two ledgers) |

Two real defects the labs found are worth remembering as a reason to keep running
them: default-drop input silently ate mDNS responders' unicast replies and TFTP's
ephemeral-port replies (fixed in the firewall renderer), and instance names with
spaces arrive escaped (`\032`), which broke direct instance matching and conflict
detection.

## Since the last checkpoint

| Was open | Now | Verified by |
| --- | --- | --- |
| Container advertisements not visible on the LAN | mDNS NAT: re-advertised at ghostd's address and a pooled port, DNAT into the container | unit; e2e |
| Lookup scans | Indexes over live bindings (client, MAC, name, address); hot paths make no full scan and decode a bounded number of bindings against 20000 historical ones | unit |
| Two-daemon standby | Leader and standby as two systemd services: mirror, refused writes, refused promotion, leader stopped, promotion, clients keep their addresses | e2e (`GHOSTD_E2E_MODE=standby`) |
| Relayed prefix delegation | Scopes behind a relay delegate; route via the relay agent | dhcp-lab (Solicit/Advertise/Request/Reply through a relay, ledger and kernel route) |
| PD in a takeover | `allow_pd`; rollback abandons delegations and records it | unit |
| Reachability before confirmation | Active probes: real DORA (veth on a bridge) with router/DNS/name checks, DNS, TCP | unit; e2e (a takeover confirmed only after the probes pass) |
| Wider dnsmasq conversion | Tags, multi-value DNS, generic options, interface-limited TFTP; boot fields only to clients that ask | unit; e2e |
| Hard failures | SIGKILL at every step of a state save and of the two-file config update; the ledger SIGKILLed 15 times under load with bindings, indexes and event log verified after each; ghostd SIGKILLed five times under client load in the lab | unit; e2e |

## Still open

- **Multi-master allocation and automatic failover.** Excluded by design: two
  authorities that decide independently hand out the same address, and a standby cannot
  tell a dead leader from a partition. What exists is a warm standby with fenced, manual
  promotion (lab-tested as two real daemons). Restarting a demoted leader as a follower
  is an operator step.
- **Probes see the network from the host.** A DORA probe needs a bridge (or another
  host); nothing here can prove a client VLAN you are not on can route. Test that from a
  real client.
- **A real power cut.** Durability across power loss rests on fsync of each state file
  and of every bolt transaction; it is verified by killing the process (SIGKILL), not by
  cutting power or dropping the disk cache.
- **Relay and translation limits.** Rules are per direction and compose; translation
  (a rule with `advertise`) is terminal at its own rule, so a domain that should also
  see a translated service needs its own rule from the source. The NAT maps IPv4
  only, does not conflict-probe the names it re-advertises — instance *or* host
  names, though a name ghostd advertises itself is never taken over — and learns
  from what a source announces, mapping only an address announced on that source's
  own interface. IPv6 reflection is implemented but lab-tested on IPv4 only.
- **DNS ACL identity is a network-path property.** Enforcing that only one container
  can reach its resolver address is host firewall work.
- **General dnsmasq replacement remains a subset.** Ranges that match on tags,
  interfaces or vendor classes, options beyond the named table, and unknown directives
  are refused, not translated.
- **The pool search** for a free address is a linear point-read walk over the pool
  (at most 65536 entries), independent of history; a very full large pool pays for it.
- **A physical LAN, client diversity and a real tailnet** are not exercised: test on a
  VLAN before a production cutover.

## Running the validation

```sh
tests/tags.sh                            # the whole tag matrix, incl. the core-only build
go test -race -tags "tailscale dhcp dnsmasq mdns coredns" ./... && go vet -tags "tailscale dhcp dnsmasq mdns coredns" ./...
GOOS=linux go vet -tags "tailscale dhcp dnsmasq mdns coredns" ./...   # the Linux-only tests compile
tests/integration/run.sh                # privileged suites in a container
tests/dhcp-lab/run.sh                   # takeover, relay, RA, DHCPv6 timers, PD  (~4 min)
tests/e2e/run.sh                        # real daemon under systemd, with a reboot (~3 min)
```

`GHOSTD_LAB_ARCH=amd64` selects the AMD64 image on a matching Podman VM. The labs
need Podman, keep `--network none`, and must never be attached to a real LAN.

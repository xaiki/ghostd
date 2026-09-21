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
| LAN advertisement | `mdns-v1` with probing and conflict refusal | unit; e2e (avahi as a competing responder, python-zeroconf as the client, across a reboot) |
| TFTP/PXE | `boot` + `tftp`, converter support | unit; e2e (dnsmasq, then ghostd, serve a boot file to busybox tftp behind the firewall) |
| DHCPv6 prefix delegation | `pd` pool, ledger, attribution, kernel routes | unit; dhcp-lab (`dhclient -6 -P`, route installed and removed) |
| Replication | Warm standby: `--follow`, mirrored ledger/config, fenced manual `promote` | unit (real gRPC between two ledgers) |

Two real defects the labs found are worth remembering as a reason to keep running
them: default-drop input silently ate mDNS responders' unicast replies and TFTP's
ephemeral-port replies (fixed in the firewall renderer), and instance names with
spaces arrive escaped (`\032`), which broke direct instance matching and conflict
detection.

## Still open

- **Multi-master allocation and automatic failover.** Excluded by design, not
  forgotten: two authorities that decide independently hand out the same address,
  and a standby cannot tell a dead leader from a partition. What exists is a warm
  standby with fenced, manual promotion. Not covered: a lab with two real daemons
  (the standby is tested over real gRPC between two ledgers, not two systemd
  services), and restarting a demoted leader as a follower is an operator step.
- **The mDNS reflector.** Excluded by the ACL design (one multicast stream cannot
  carry one container's permission). An application that can only speak mDNS itself
  still needs host networking.
- **DHCPv6 PD is not part of a dnsmasq takeover**, because dnsmasq's lease file
  cannot carry it; delegations are added with an ordinary apply afterwards. Relayed
  requests route via the relay's recorded peer-address, but that path is
  unit-tested, not lab-tested.
- **DNS ACL identity is a network-path property.** Enforcing that only one
  container can reach its resolver address is host firewall work; ghostd cannot
  verify it. Changing the set of listeners needs a restart.
- **Client verification is evidence of traffic, not of reachability.** It proves the
  ledger saw a renewal and a fresh grant, not that a client can route or resolve.
- **General dnsmasq replacement remains a subset.** Tagged ranges/options,
  interface-limited TFTP, and arbitrary options are refused, not translated.
  dnsmasq only sends boot fields when the client asks for them; ghostd always does.
- **Bound the remaining lookup scans.** Pool scans, `Report` and name-collision
  checks still read all bindings; index them before retained history grows large.
- **Kills inside the state store's own persistence step, and a hard power-off,** are
  not simulated (the container reboot is orderly).
- **Physical LAN broadcast delivery, client diversity and a real tailnet** are not
  exercised: test on a VLAN before a production cutover.

## Running the validation

```sh
tests/tags.sh                            # all feature combinations, incl. the core-only build
go test -race -tags "dhcp dnsmasq mdns coredns" ./... && go vet -tags "dhcp dnsmasq mdns coredns" ./...
GOOS=linux go vet -tags "dhcp dnsmasq mdns coredns" ./...   # the Linux-only tests compile
tests/integration/run.sh                # privileged suites in a container
tests/dhcp-lab/run.sh                   # takeover, relay, RA, DHCPv6 timers, PD  (~4 min)
tests/e2e/run.sh                        # real daemon under systemd, with a reboot (~3 min)
```

`GHOSTD_LAB_ARCH=amd64` selects the AMD64 image on a matching Podman VM. The labs
need Podman, keep `--network none`, and must never be attached to a real LAN.

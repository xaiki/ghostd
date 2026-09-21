# Observe, review, adopt

ghostd does not own policy, so it also does not translate an existing host's
configuration into one. What it does provide is everything needed to do that
translation *with evidence*: an observation mode that reads without changing
anything, a read-only evidence capture, and an offline renderer for reviewing the
rules it would produce. The review itself is where the human judgement goes, and
the review is not optional.

Never switch a host from observation to managed policy before reviewing the
capture.

## 1. Observe

Start the daemon in observation mode on a fresh, unmanaged host:

```sh
sudo /opt/ghostd/ghostd --observe-only --store-dir=/var/lib/ghostd/last-good
```

Or run it under systemd with an `ExecStart` override adding `--observe-only`.

Observation mode reads live state and rejects every mutation RPC. It skips
boot-time restore, and it refuses to start at all over an existing confirmed
domain or a pending rollback — so it cannot be used to quietly stop enforcing
policy on a host ghostd already manages. It also serves no DHCP and reloads no
configuration. It does still run the container resolver on port 53 of the
node's tailnet address, so that port is occupied while the daemon runs.

Observation mode does not modify the host's firewall, so the host's existing
firewall policy must already admit TCP 7443 on its tailnet address. Observation
mode will not open its own port. Build a systemd override that adds
`--observe-only`, rather than editing the shipped unit.

## 2. Capture

Capture the state into a fresh directory per capture, so an earlier capture is
never overwritten:

```sh
mkdir -p observation-1
grpcurl -plaintext -import-path proto -proto ghoststate.proto \
  -d '{"include_adoption_evidence": true}' \
  100.64.0.10:7443 ghostd.HostState/GetState > observation-1/state.json
```

`GetState` is read-only and needs no deployer permission, so a plain
authenticated tailnet peer can do this. The response contains:

| Field | Contents |
| --- | --- |
| `nft_ruleset_json` | The host's complete `nft -j list ruleset` output, verbatim |
| `netconfig_json` | Persisted `/etc/network/interfaces.d` file bytes, live `ip -j addr show`, and `/proc/sys/net/ipv4/ip_forward` |
| `adoption_evidence_json` | Fixed read-only evidence for adoption, described below |
| `dhcp_config_json` | The current DHCP configuration, when the daemon serves one |

Adoption evidence is captured by running a fixed list of read-only commands —
`iptables-save`, `ip6tables-save`, `systemctl show` for `ufw.service`,
`tailscaled.service` and `nftables.service`, and `tailscale debug prefs` with the
output reduced to `NetfilterMode`, `NoSNAT`, `AdvertiseRoutes` and `WantRunning`
— plus reading the `/etc/ufw/*.rules` and `/etc/ufw/ufw.conf` files. Nothing a
caller supplies is ever executed, and authentication material from `tailscale
debug prefs` is never exported. Each command is bounded by a three-second timeout
and a 4 MiB size limit; a command that fails or exceeds the limit is recorded in
the evidence's `errors` map rather than silently omitted.

## 3. Review

Read the capture and resolve, explicitly, every difference between what the host
does now and what ghostd would install. At minimum:

- **Ownership.** Which nft tables or chains does the host already filter with, and
  which daemon or service writes them? ghostd owns only `table inet
  stack_ghostd`, and an `accept` in one base chain cannot override a `drop` in
  another writer's. Decide who owns what before applying anything.
- **Boot ordering.** ghostd leaves other tables alone, but it cannot make someone
  else's firewall reachable. If another manager loads rules at boot, settle the
  ordering with it.
- **Inbound allowances.** Translate the host's actual inbound services into zone
  ports and SSH declarations. Simple allow rules are straightforward; anything
  with extra predicate conditions needs the corresponding rule written explicitly
  or left to the other firewall.
- **Output rules.** Output policy is opt-in and, when omitted, no output filtering
  is installed. Do not infer an output policy from an input one.
- **Forwarding and NAT.** Forwarding defaults to drop apart from explicit
  zone-to-zone declarations and established/related flows. Note what the host
  forwards today, and enable kernel forwarding with the `sysctl` action in the
  netconfig domain if it is needed.
- **Interfaces.** Every interface belongs to exactly one zone, VLANs must match
  their parent and ID, and addresses are treated as additive.

Then build the desired targets. Review the result without touching the host:

```sh
bin/ghostd --render-firewall < firewall.json > firewall.nft
less firewall.nft
sudo nft -c -f firewall.nft   # syntax check only, still no host change
```

Use the same `--port` and `--tailscale-interface` you will run the daemon with,
or the rendered reachability guard will not match what the daemon applies.

### Staged adoption with redirect-only mode

If the host's existing filtering is not ready to be replaced, adopt only the NAT
rules first. A target with `redirect_only: true` and interface-scoped zones
manages the redirect rules in ghostd's table and preserves the host's existing
filtering:

```json
{"redirect_only": true,
 "zones": {"lan": {"interfaces": ["eth0"],
                   "redirects": [{"port": 514, "to_port": 15514, "proto": "udp"}]}}}
```

Send it under the `firewall-redirect-v1` domain so a daemon too old to understand
it rejects the request instead of installing a full filtering policy. Filtering
fields are refused in this mode. This is a legitimate first step: it lets you run
the lease, confirmation and rollback machinery on a live host while changing as
little as possible.

### Adopting an existing interface configuration

The netconfig domain writes files and runs additive actions; it does not remove
what the target omits, and a confirmed target is replayed at startup. So supply
the **complete** file set and action list you want the host to have after
adoption, including configuration that is already there.

To protect against the file moving on between your observation and your apply,
pin its digest. Compute it on the host — the capture reports the
`/etc/network/interfaces.d` files and the two forwarding files, but not the main
`/etc/network/interfaces` file itself:

```sh
sha256sum /etc/network/interfaces
```

A precondition must also name a desired content for that same path, or it is
rejected:

```json
{"expected_files_sha256": {"/etc/network/interfaces": "<64 hex digits from sha256sum>"},
 "files": {
   "/etc/network/interfaces": "source /etc/network/interfaces.d/stack-eth0.conf\n",
   "/etc/network/interfaces.d/stack-eth0.conf": "auto eth0\niface eth0 inet static\n    address 192.0.2.1/24\n"
 },
 "actions": [["addr", "eth0", "192.0.2.1/24"], ["up", "eth0"]]}
```

If `/etc/network/interfaces` changed since the digest was taken, the apply is
refused rather than overwriting a configuration someone else has since edited.
`/etc/network/interfaces` is the only path a precondition may be declared for.

Whatever names you give the files you install under
`/etc/network/interfaces.d/`, make sure the main `/etc/network/interfaces`
actually loads them. `source-directory` skips filenames containing dots, so a
`stack-*.conf` file is not loaded by it — use an explicit `source` pattern.
Conflicting definitions elsewhere in the include tree are not deleted for you:
old files can contain IPv6, routes and hooks that the target does not describe.
Consolidate them yourself without losing behaviour the host currently relies on.

Do not treat the persisted interface files as a cache for ghostd. They are the
boot fallback: the reason the host comes up networked even if ghostd never starts.

## 4. Activate

Once the review is complete and the targets are written:

1. Stop the observation daemon.
2. Start the daemon normally (no `--observe-only`) — this is what enables boot
   restore and mutation RPCs.
3. Apply the firewall target, then confirm it from a fresh connection. Check the
   management path you care about between the two.
4. Apply the netconfig target, then confirm it the same way.
5. Reboot the host when you can, and verify that both the boot fallback and the
   daemon's restore produce the state you reviewed.

## Comparing two captures

Take a new capture into a *new* directory after any change, and compare it
structurally against the previous one. nft JSON carries rule handles and counter
values that change without any semantic difference, so strip those before
diffing:

```sh
jq 'walk(if type=="object" then del(.handle)
        | if has("counter") then .counter = null else . end else . end)' \
  observation-1/state.json > observation-1/normalised.json
# repeat for observation-2, then:
diff -u observation-1/normalised.json observation-2/normalised.json
```

This is a structural diff, not a semantic proof of packet behaviour. It tells you
what the ruleset says, not what the host will do with it. Decide the changes you
want from the review, not from the diff's exit status.

## What observation mode does not give you

- It does not translate any firewall dialect into a ghostd target, and it does not
  offer to merge inventory. That translation is the client's job by design.
- It cannot reconstruct history. A single capture describes the host as it is now;
  nothing before the capture is recoverable from it.
- It is not a packet-level proof that the proposed policy is equivalent. Only a
  real connectivity test on the host can show that.
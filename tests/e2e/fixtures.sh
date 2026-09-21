#!/bin/sh
# Recreated at every boot, the way netconfig would: a LAN bridge that ghostd
# serves DHCP/DNS on, and two client network namespaces plugged into it.
set -eu
ip link add lab0 type bridge 2>/dev/null || true
ip addr replace 10.77.0.1/24 dev lab0
ip link set lab0 up
# Stands in for the tailnet interface; ghostd binds its RPC listener and container
# DNS to this address only, exactly as it would to a real tailscale0.
ip link add tailscale0 type bridge 2>/dev/null || true
ip addr replace 100.64.0.1/32 dev tailscale0
ip link set tailscale0 up
# Stable MACs: a client is the same device after a reboot.
for name in client1 client2; do
	mac="02:00:00:00:00:0${name#client}"
	ip netns list | grep -qw "$name" && continue
	ip netns add "$name"
	ip link add "$name" type veth peer name "${name}p" address "$mac"
	ip link set "$name" master lab0
	ip link set "$name" up
	ip link set "${name}p" netns "$name"
	nsenter --net="/run/netns/$name" -- ip link set lo up
	nsenter --net="/run/netns/$name" -- ip link set "${name}p" up
done

# Extra tailnet-side addresses: one resolver identity per container.
for a in 100.64.0.21 100.64.0.22; do ip addr replace "$a/32" dev tailscale0; done

# A LAN printer with a static address, advertised by avahi (a third-party mDNS
# responder) inside its own namespace.
if ! ip netns list | grep -qw printer; then
	ip netns add printer
	ip link add printer type veth peer name printerp address 02:00:00:00:00:60
	ip link set printer master lab0
	ip link set printer up
	ip link set printerp netns printer
	nsenter --net=/run/netns/printer -- ip link set lo up
	nsenter --net=/run/netns/printer -- ip addr add 10.77.0.60/24 dev printerp
	nsenter --net=/run/netns/printer -- ip link set printerp up
	nsenter --net=/run/netns/printer -- ip route add 224.0.0.0/4 dev printerp
fi

# Two container networks, each a multicast domain of its own with one "container"
# (a namespace with a static address) attached: the per-container mDNS reflector's
# targets. ctr0 will be allowed printers only, ctr1 speakers only.
for n in 0 1; do
	br="ctr$n"; ns="cnt$n"
	ip link add "$br" type bridge 2>/dev/null || true
	ip addr replace "10.9$n.0.1/24" dev "$br"
	ip link set "$br" up
	if ! ip netns list | grep -qw "$ns"; then
		ip netns add "$ns"
		ip link add "$ns" type veth peer name "${ns}p" address "02:00:00:00:09:0$n"
		ip link set "$ns" master "$br"
		ip link set "$ns" up
		ip link set "${ns}p" netns "$ns"
		nsenter --net="/run/netns/$ns" -- ip link set lo up
		nsenter --net="/run/netns/$ns" -- ip addr add "10.9$n.0.10/24" dev "${ns}p"
		nsenter --net="/run/netns/$ns" -- ip link set "${ns}p" up
		nsenter --net="/run/netns/$ns" -- ip route add 224.0.0.0/4 dev "${ns}p"
	fi
done

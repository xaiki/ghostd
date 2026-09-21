#!/bin/sh
# Runs the opt-in privileged Go integration suites (nft, systemd timers,
# netconfig, DHCP listeners) inside a disposable privileged systemd container.
# See docs/operations.md#testing. Never use --network host.
set -eu
cd "$(dirname "$0")/../.."
arch=${GHOSTD_LAB_ARCH:-arm64}
bin=$(mktemp -d "${TMPDIR:-/tmp}/ghostd-int.XXXXXX")
name=ghostd-integration-lab
cleanup() { [ "${GHOSTD_E2E_KEEP:-}" = 1 ] || podman rm -f "$name" >/dev/null 2>&1 || true; rm -rf "$bin"; }
trap cleanup EXIT HUP INT TERM
for pkg in mdns:./internal/mdns resolver:./internal/resolver nft:./internal/nft main:./cmd/ghostd state:./internal/state netconfig:./internal/netconfig addressbook:./internal/addressbook; do
	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -tags "dhcp dnsmasq mdns coredns" -c -o "$bin/${pkg%%:*}.test" "${pkg#*:}"
done
podman build -q -t localhost/ghostd-dhcp-lab -f tests/dhcp-lab/Containerfile tests/dhcp-lab >/dev/null
podman run -d --name "$name" --privileged --systemd=always --network none \
	--volume "$bin:/t:ro" localhost/ghostd-dhcp-lab:latest /lib/systemd/systemd >/dev/null
i=0
until podman exec "$name" systemctl is-system-running 2>/dev/null | grep -Eq 'running|degraded'; do
	i=$((i+1)); [ $i -gt 60 ] && { echo "systemd did not come up" >&2; exit 1; }; sleep 1
done
podman exec "$name" sh -c 'systemctl disable --now dnsmasq.service 2>/dev/null; mkdir -p /etc/network/interfaces.d; echo "source /etc/network/interfaces.d/*" > /etc/network/interfaces'
x() { podman exec "$name" "$@"; }
x unshare -n env GHOSTD_NFT_INTEGRATION=1 /t/nft.test -test.run TestIntegration -test.v
x unshare -n env GHOSTD_NFT_INTEGRATION=1 /t/main.test -test.run TestIntegration -test.v
x env GHOSTD_SYSTEMD_INTEGRATION=1 /t/state.test -test.run TestIntegration -test.v
x unshare -n env GHOSTD_NETCONFIG_INTEGRATION=1 /t/netconfig.test -test.run TestIntegration -test.v
x unshare -n sh -c "ip link set lo up && exec env GHOSTD_DHCP_INTEGRATION=1 /t/addressbook.test -test.run TestLinuxListenerAndPortOwnership -test.v"
x /t/addressbook.test -test.run "TestProcessOwnsUDPPort|TestWriteLeases" -test.v
x unshare -n sh -c "ip link set lo up && exec /t/mdns.test -test.v"
x unshare -n sh -c "ip link set lo up && exec /t/resolver.test -test.run 'TestIdentityListeners|TestEmbedded' -test.v"
echo "integration suites passed"

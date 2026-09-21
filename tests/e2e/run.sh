#!/bin/sh
# End-to-end lab: the real ghostd binary, run by real systemd in a disposable
# container, against a real nft, dnsmasq unit and ISC dhclient clients, with a
# fake tailscaled LocalAPI standing in for the tailnet. The container is
# restarted mid-way to exercise the production boot-restore path.
#
# Never use --network host here; the container has no external network.
set -eu
cd "$(dirname "$0")/../.."
arch=${GHOSTD_LAB_ARCH:-arm64}
case "$arch" in arm64|amd64) ;; *) echo 'GHOSTD_LAB_ARCH must be arm64 or amd64' >&2; exit 2;; esac
bin=$(mktemp -d "${TMPDIR:-/tmp}/ghostd-e2e.XXXXXX")
name=ghostd-e2e-lab
cleanup() {
	if [ "${GHOSTD_E2E_KEEP:-}" != 1 ]; then podman rm -f "$name" >/dev/null 2>&1 || true; fi
	rm -rf "$bin"
}
trap cleanup EXIT HUP INT TERM
for cmd in ghostd:./cmd/ghostd fakets:./tests/e2e/fakets probe:./tests/e2e/probe; do
	GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "$bin/${cmd%%:*}" "${cmd#*:}"
done
cp tests/e2e/fixtures.sh "$bin/"
podman build -q -t localhost/ghostd-dhcp-lab -f tests/dhcp-lab/Containerfile tests/dhcp-lab >/dev/null
podman rm -f "$name" >/dev/null 2>&1 || true
podman run -d --name "$name" --privileged --systemd=always --network none \
	--volume "$bin:/opt/ghostd:ro" localhost/ghostd-dhcp-lab:latest /lib/systemd/systemd >/dev/null

wait_systemd() {
	i=0
	until podman exec "$name" systemctl is-system-running 2>/dev/null | grep -Eq 'running|degraded'; do
		i=$((i+1)); [ $i -gt 60 ] && { echo "systemd did not come up" >&2; exit 1; }
		sleep 1
	done
}
wait_systemd
for u in lab-fixtures.service fakets.service ghostd.service avahi-printer.service; do
	podman cp "tests/e2e/units/$u" "$name:/etc/systemd/system/$u"
done
# A packaged unit lives in the vendor directory, which is what lets systemctl mask it.
podman cp tests/e2e/units/dnsmasq@ghostd-lab.service "$name:/usr/lib/systemd/system/dnsmasq@ghostd-lab.service"
podman cp tests/e2e/dnsmasq-ghostd-lab.conf "$name:/etc/dnsmasq-ghostd-lab.conf"
podman exec "$name" mkdir -p /etc/avahi/services /var/lib/ghostd/last-good
podman cp tests/e2e/avahi/avahi-printer.conf "$name:/etc/avahi/avahi-printer.conf"
podman cp tests/e2e/avahi/ipp.service "$name:/etc/avahi/services/ipp.service"
podman cp tests/e2e/avahi/cast.service "$name:/etc/avahi/services/cast.service"
podman cp tests/e2e/dns-acl.json "$name:/var/lib/ghostd/last-good/dns-acl.json"
podman exec "$name" sh -c 'systemctl disable --now dnsmasq.service avahi-daemon.service avahi-daemon.socket 2>/dev/null; systemctl mask avahi-daemon.service avahi-daemon.socket 2>/dev/null; mkdir -p /var/lib/misc; : > /var/lib/misc/e2e.leases; systemctl daemon-reload; systemctl enable --now lab-fixtures.service fakets.service ghostd.service avahi-printer.service'

run() { podman exec "$name" /opt/ghostd/probe "$1"; }
fail() { podman exec "$name" journalctl -u ghostd.service -n 60 --no-pager >&2 || true; exit 1; }
run pre || fail
run dns || fail
echo; echo "=== rebooting the container (systemd restart, /run cleared)"
podman restart -t 5 "$name" >/dev/null
wait_systemd
run post || fail
run expiry || fail
echo; echo "e2e lab passed"

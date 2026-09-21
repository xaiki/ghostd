#!/bin/sh
# Disposable network only: never use --network host here.
set -eu
cd "$(dirname "$0")/../.."
arch=${GHOSTD_LAB_ARCH:-arm64}
case "$arch" in arm64|amd64) ;; *) echo 'GHOSTD_LAB_ARCH must be arm64 or amd64' >&2; exit 2;; esac
binary=$(mktemp "${TMPDIR:-/tmp}/ghostd-dhcp-lab.XXXXXX")
ghostd_lab_container=""
cleanup() {
 if [ -n "$ghostd_lab_container" ]; then podman rm -f "$ghostd_lab_container" >/dev/null; fi
 rm -f "$binary"
}
trap cleanup EXIT HUP INT TERM
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go test -c ./internal/addressbook -o "$binary"
podman build -t localhost/ghostd-dhcp-lab -f tests/dhcp-lab/Containerfile tests/dhcp-lab
podman run --rm --privileged --network none --env GHOSTD_DHCP_LAB=1 \
 --volume "$binary:/lab/test:ro" localhost/ghostd-dhcp-lab:latest \
 /lab/test -test.run TestDNSmasqTakeoverLab -test.v -test.timeout 8m

# Repeat against a real systemd-managed service (persistent mask/unmask).
ghostd_lab_container=$(podman run -d --privileged --systemd=always --network none \
 --env GHOSTD_DHCP_LAB=1 --env GHOSTD_LAB_SYSTEMD=1 \
 --volume "$binary:/lab/test:ro" localhost/ghostd-dhcp-lab:latest /lib/systemd/systemd)
podman exec "$ghostd_lab_container" /lab/test -test.run TestDNSmasqTakeoverLab -test.v -test.timeout 8m

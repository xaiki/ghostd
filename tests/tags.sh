#!/bin/sh
# Every supported feature combination must build, vet and pass its tests, and
# the default (no tags) build must carry none of the optional dependencies.
# Combinations that violate a dependency must fail to compile.
set -eu
cd "$(dirname "$0")/.."
profiles="
:core only
coredns:container resolver
mdns:mDNS only
coredns mdns:resolver with native .local
dhcp coredns:DHCP + authoritative DNS
dhcp coredns mdns:DHCP + native mDNS
dhcp dnsmasq coredns:DHCP + dnsmasq migration
dhcp dnsmasq mdns coredns:everything
"
echo "$profiles" | while IFS=: read -r tags label; do
	[ -n "$label" ] || continue
	printf '== [%s] %s\n' "$tags" "$label"
	go vet -tags "$tags" ./...
	GOOS=linux go vet -tags "$tags" ./...
	go test -tags "$tags" ./... 2>&1 | grep -v "level=\|ghostd: \|no test files" | grep -v '^ok' || true
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -tags "$tags" -o /dev/null ./cmd/ghostd
done
echo "== dependency isolation of the default build"
if go list -deps ./cmd/ghostd | grep -E 'coredns|coredhcp|insomniacslk|miekg/dns|bbolt|pin/tftp|caddyserver|x/net/ipv[46]'; then
	echo "default build pulls in an optional dependency" >&2; exit 1
fi
echo "== unsupported combinations must not compile"
for tags in dnsmasq dhcp "dnsmasq coredns" "dnsmasq mdns"; do
	if go build -tags "$tags" -o /dev/null ./cmd/ghostd 2>/dev/null; then
		echo "tags [$tags] built but violate a dependency" >&2; exit 1
	fi
done
echo "all feature combinations OK"

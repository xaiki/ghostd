#!/bin/sh
# The feature-tag matrix, exhaustive.
#
# Every combination of the optional build tags must either build, vet and pass
# its tests, or fail to compile because it violates a declared dependency. An
# additive list — the core, then one feature at a time — leaves untested exactly
# the combinations nobody builds: a feature without the dependency it needs, two
# features that were never compiled together, a stub whose build tag no longer
# complements the file it stands in for. That is where build-tag bugs live, and
# such a bug is invisible until somebody builds that combination.
#
# Minutes rather than seconds: 2^6 combinations, each compiled and tested.
# GHOSTD_TAGS_FAST=1 asserts only the build outcomes (seconds, and the half that
# catches tag wiring) and is what to run while iterating; the full run is a
# pre-release gate. GHOSTD_TAGS_ARCH picks the cross-build target (default arm64,
# like the labs).
set -eu
cd "$(dirname "$0")/.."

# The optional tags in play. A new one must be added here: the guard below fails
# on any other tag appearing in a build constraint, so this cannot quietly stop
# being the matrix.
optional="tailscale headscale coredns dhcp dnsmasq mdns"
platform="linux"

known=$(printf '%s' "$optional $platform" | tr ' ' '|')
stray=$(grep -rho '^//go:build .*' --include='*.go' . |
	sed 's|^//go:build ||' | tr '&|()!' '    ' | tr -s ' ' '\n' |
	sed 's/^ *//;s/ *$//' | grep -v '^$' | sort -u | grep -vE "^($known)$" || true)
if [ -n "$stray" ]; then
	echo "tests/tags.sh: build tags missing from the matrix: $stray" >&2
	exit 1
fi

# A combination that violates a dependency must not compile, and everything else
# must. The rules are the dependencies themselves: the DHCP feature serves
# through the authoritative resolver, and the dnsmasq takeover needs the DHCP
# feature it hands over to.
must_not_compile() {
	case " $1 " in
	*" dhcp "*)
		case " $1 " in *" coredns "*) ;; *) return 0 ;; esac
		;;
	esac
	case " $1 " in
	*" dnsmasq "*)
		case " $1 " in *" dhcp "*) ;; *) return 0 ;; esac
		;;
	esac
	return 1
}

combo_of() {
	mask=$1
	out=""
	bit=0
	for t in $optional; do
		[ $(( (mask >> bit) & 1 )) -eq 1 ] && out="$out $t"
		bit=$((bit + 1))
	done
	printf '%s' "$out" | sed 's/^ *//'
}

arch=${GHOSTD_TAGS_ARCH:-arm64}
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ghostd-tags.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

mask=0
total=1
for t in $optional; do total=$((total * 2)); done
built=0
refused=0
while [ "$mask" -lt "$total" ]; do
	combo=$(combo_of "$mask")
	mask=$((mask + 1))
	if must_not_compile "$combo"; then
		refused=$((refused + 1))
		for target in "" "linux"; do
			if [ -n "$target" ]; then
				GOOS=$target CGO_ENABLED=0 go build -tags "$combo" -o /dev/null ./cmd/ghostd 2>"$tmp/err" && {
					printf 'tags=[%s] built on %s, but violates a dependency: %s\n' "$combo" "$target" "$(sed -n 2p "$tmp/err")" >&2
					exit 1
				}
			elif go build -tags "$combo" -o /dev/null ./cmd/ghostd 2>"$tmp/err"; then
				printf 'tags=[%s] built, but violates a dependency: %s\n' "$combo" "$(sed -n 2p "$tmp/err")" >&2
				exit 1
			fi
		done
		printf 'tags=[%s] refused, as its dependency requires\n' "$combo"
		continue
	fi
	built=$((built + 1))
	CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -tags "$combo" -o "$tmp/ghostd" ./cmd/ghostd
	size=$(wc -c < "$tmp/ghostd" | tr -d ' ')
	if [ "${GHOSTD_TAGS_FAST:-0}" = 1 ]; then
		printf 'tags=[%s] OK (%s bytes)\n' "$combo" "$size"
		continue
	fi
	go vet -tags "$combo" ./...
	GOOS=linux GOARCH="$arch" go vet -tags "$combo" ./...
	if ! out=$(go test -tags "$combo" ./... 2>&1); then
		printf '%s\n' "$out" >&2
		printf 'tags=[%s] tests failed\n' "$combo" >&2
		exit 1
	fi
	printf 'tags=[%s] OK (%s bytes)\n' "$combo" "$size"
done

echo "== dependency isolation of the default build"
if go list -deps ./cmd/ghostd | grep -E 'tailscale.com|coredns|coredhcp|insomniacslk|miekg/dns|bbolt|pin/tftp|caddyserver|x/net/ipv[46]'; then
	echo "default build pulls in an optional dependency" >&2; exit 1
fi
printf '== %s combinations: %s built%s, %s refused\n' "$total" "$built" \
	"$([ "${GHOSTD_TAGS_FAST:-0}" = 1 ] && echo '' || echo ' and tested')" "$refused"
echo "all feature combinations OK"
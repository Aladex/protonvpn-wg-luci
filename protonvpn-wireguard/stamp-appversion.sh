#!/bin/sh
# SPDX-License-Identifier: MIT
# Stamp the Proton client version (x-pm-appversion) into api.uc from the
# official Linux client's versions.yml, with the committed constant as the
# fallback. Proton gates sign-ins on this string and the only source of truth
# for the current value is upstream's repository.
#
# This script must NEVER fail a build or ship a garbage value: any problem —
# the file unreachable, its shape changed, the version malformed — leaves the
# committed constant in place, and the log line always says which was used.
#
# Usage: stamp-appversion.sh [--print-upstream] [path-to-api.uc]
#   --print-upstream  print the validated upstream value on stdout and exit
#                     (0 on success, 1 with the reason on stderr otherwise);
#                     the drift-watch workflow uses this so both places share
#                     exactly one parser.
# Test override: PROTONVPN_VERSIONS_YML may point at a local file instead of
# the upstream URL.

set -u

print_only=0
if [ "${1:-}" = "--print-upstream" ]; then
	print_only=1
	shift
fi

here=$(cd "$(dirname "$0")" && pwd)
API_UC="${1:-$here/files/usr/share/ucode/protonvpn/api.uc}"
SRC="${PROTONVPN_VERSIONS_YML:-https://raw.githubusercontent.com/ProtonVPN/proton-vpn-gtk-app/master/versions.yml}"

fallback() {
	if [ "$print_only" = 1 ]; then
		echo "appversion: $1" >&2
		exit 1
	fi
	echo "appversion: keeping committed '$current' ($1)"
	exit 0
}

current=''
if [ "$print_only" = 0 ]; then
	current=$(sed -n "s/^const PM_APPVERSION = '\([^']*\)';.*/\1/p" "$API_UC" 2>/dev/null | head -1)
	[ -n "$current" ] || fallback "no PM_APPVERSION constant readable in $API_UC"
fi

case "$SRC" in
	*://*) body=$(curl -fsSL --connect-timeout 10 --max-time 20 "$SRC" 2>/dev/null) || fallback "fetch of $SRC failed" ;;
	*) body=$(cat "$SRC" 2>/dev/null) || fallback "cannot read $SRC" ;;
esac

# ── Source validation: one rigid shape, everything else falls back ───────
# sed is not a YAML parser and must not try to be one: in real YAML a comment
# needs whitespace before '#', a plain scalar may continue on following
# indented lines, and document markers have an exact shape — every attempt
# to interpret that line-by-line has failed open. So instead of parsing,
# accept exactly one source shape and reject the rest.

# CRLF is the only tolerated place for a CR: strip it from line ends, then
# any remaining control character (VT, FF, a bare CR, other C0 controls,
# DEL) rejects the whole source. Space and tab are the only in-line
# whitespace; genuine upstream content (author names) is UTF-8 and stays.
CR=$(printf '\r')
body=$(printf '%s' "$body" | sed "s/$CR\$//")
clean=$(printf '%s' "$body" | tr -d '\000-\010\013\014\015\016-\037\177')
[ "$clean" = "$body" ] || fallback "control characters in $SRC"

# A document separator is exactly '---' on its own line. Anything merely
# starting with those dashes ('---junk', '----') is not a separator — and
# treating it as one can hide a contradictory version key in the first
# document.
if printf '%s\n' "$body" | grep -E '^---' | grep -qvE '^---$'; then
	fallback "malformed document separator in $SRC"
fi

# The first document — up to the first real separator — describes the
# current release; everything behind a proper separator is history and not
# looked at.
first_doc=$(printf '%s\n' "$body" | awk '/^---$/{exit} {print}')

# Within the first document there must be exactly ONE version key of exactly
# this shape: 'version: X.Y.Z' — a single space after the colon, numeric
# components only, and nothing after the value except an optional comment
# separated by at least one space. A second key (nested, indented or
# contradictory) is ambiguous; any other form of the line is not interpreted.
ver_line_re='^version: [0-9]+\.[0-9]+\.[0-9]+( +#.*)?$'
nkeys=$(printf '%s\n' "$first_doc" | grep -cE '^[[:space:]]*version[[:space:]]*:')
[ "$nkeys" = "1" ] || fallback "expected exactly one 'version' key in the first versions.yml entry, found $nkeys"
nlines=$(printf '%s\n' "$first_doc" | grep -cE "$ver_line_re")
[ "$nlines" = "1" ] || fallback "the version line in $SRC is not exactly 'version: X.Y.Z'"

# The scalar must not continue past its physical line: in real YAML the
# following indented lines (even after blank lines) belong to the value, so
# an indented next content line under the key means the value is not the
# plain X.Y.Z we require.
vno=$(printf '%s\n' "$first_doc" | grep -nE "$ver_line_re" | cut -d: -f1)
cont=$(printf '%s\n' "$first_doc" | tail -n +"$((vno + 1))" | awk 'NF{print; exit}')
if [ -n "$cont" ] && printf '%s' "$cont" | grep -q '^[[:space:]]'; then
	fallback "the version scalar in $SRC continues on a following line"
fi

ver=$(printf '%s\n' "$first_doc" | sed -nE 's/^version: ([0-9]+\.[0-9]+\.[0-9]+)( +#.*)?$/\1/p')
[ -n "$ver" ] || fallback "no version value readable in $SRC"

candidate="linux-vpn-gtk@$ver"
# Last-resort check of the assembled value against the official client's
# format; the parser above should already guarantee this.
printf '%s' "$candidate" | grep -Eq '^linux-vpn-[a-z0-9-]+@[0-9]+\.[0-9]+\.[0-9]+$' \
	|| fallback "upstream value '$candidate' failed format validation"

if [ "$print_only" = 1 ]; then
	printf '%s\n' "$candidate"
	exit 0
fi

if [ "$candidate" = "$current" ]; then
	echo "appversion: committed '$current' already matches upstream $ver"
	exit 0
fi

sed -i "s|^const PM_APPVERSION = '[^']*';|const PM_APPVERSION = '$candidate';|" "$API_UC" \
	|| fallback "could not rewrite $API_UC"
echo "appversion: stamped '$candidate' from upstream versions.yml (was '$current')"
exit 0

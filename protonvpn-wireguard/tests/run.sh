#!/bin/sh
# SPDX-License-Identifier: MIT
# Offline ucode unit/fixture tests for protonvpn-wireguard. No network or
# account. Requires ucode + ucode-mod-fs + ucode-mod-math. 'uci'/'ubus' are
# mocked and forced ahead of the real modules on the search path, so no
# device is needed.
#
# Dev overrides for a locally-built ucode:
#   UCODE=/path/to/ucode          (default: ucode from PATH)
#   UCODE_EXTRA_L="/builddir/*.so" (extra -L pattern, e.g. host-built fs.so/math.so)

here="$(cd "$(dirname "$0")" && pwd)"
lib="$here/../files/usr/share/ucode"
mocks="$here/mocks"
fixture="$here/fixtures/logicals_sample.json"
rpcd="$here/../files/usr/share/rpcd/ucode/protonvpn.uc"
migrate="$here/../files/etc/uci-defaults/90-protonvpn-migrate"
key="$(printf '00000000000000000000000000000001' | base64)"
UCODE="${UCODE:-ucode}"

# Every run gets its own state and scratch directories, and removes them again.
# They used to be fixed paths under /tmp, which meant two suites running at the
# same time — two developers, or a developer next to CI on the same box — wrote
# over each other's status files, locks and rotation state. That produced
# failures in whichever run lost the race, in tests that had nothing to do with
# the code under change; CI greps this output, so such a collision can equally
# well invent a failure or hide a real one.
#
# An explicit PROTONVPN_STATE_DIR / PROTONVPN_RUN_DIR still wins, so a caller
# that wants to inspect the leftovers can pin them and keep them.
own_tmp=''
if [ -z "$PROTONVPN_STATE_DIR" ] || [ -z "$PROTONVPN_RUN_DIR" ]; then
	own_tmp="$(mktemp -d "${TMPDIR:-/tmp}/protonvpn-test.XXXXXX")" || exit 1
	# Remove it however we leave, including Ctrl-C: these are throwaway
	# credentials and status files, and a stale one would be read by the next
	# run as if it were its own.
	trap 'rm -rf "$own_tmp"' EXIT HUP INT TERM
fi

# Relocate the credential state the backend would keep under /etc so the suite
# runs unprivileged and never touches a real session.
PROTONVPN_STATE_DIR="${PROTONVPN_STATE_DIR:-$own_tmp/state}"
mkdir -p "$PROTONVPN_STATE_DIR"
export PROTONVPN_STATE_DIR

# Runtime scratch: status files, locks, rotation state and the server-list
# cache the backend keeps on tmpfs under fixed names (see protonvpn.common
# RUN_DIR). Same relocation, same reason.
PROTONVPN_RUN_DIR="${PROTONVPN_RUN_DIR:-$own_tmp/run}"
mkdir -p "$PROTONVPN_RUN_DIR"
export PROTONVPN_RUN_DIR

# Stub commands that only exist on a router (see stubs/ for what each one does
# and how a test opts into the non-default behaviour). First on PATH, so a test
# can drive a code path that shells out without a device.
PATH="$here/stubs:$PATH"
export PATH

# Routing-table registry: the same relocation, so allocation can be tested
# without writing to the host's /etc/iproute2/rt_tables.
PROTONVPN_RT_TABLES="${PROTONVPN_RT_TABLES:-$PROTONVPN_STATE_DIR/rt_tables}"
export PROTONVPN_RT_TABLES

# odhcpd's init script: an absolute path on a router, so PATH cannot shadow it
# the way it shadows ifup/ifdown. Pointed at a stub that records the calls, so
# a test can assert that a fresh router advertisement was actually asked for.
PROTONVPN_ODHCPD_INIT="${PROTONVPN_ODHCPD_INIT:-$here/stubs/odhcpd-init}"
export PROTONVPN_ODHCPD_INIT

# The readiness budget the router-advertisement wait spends before giving up
# (routing.uc ra_budget_ms). In production it is five seconds, and several
# tests drive a wait all the way to its timeout — at the production value that
# one file took 48 seconds, which is most of the cost of a mutation round.
#
# Shortened here rather than stubbed: this is the real knob, set the way an
# owner with a slow router would set it, so the tests still exercise the real
# code path. The one test that has to prove the PRODUCTION default works end
# to end unsets this again in a child process (helpers/real-budget.uc) — a
# fast suite that no longer tests the timeout would be a worse trade than a
# slow one.
PROTONVPN_RA_SETTLE_MS="${PROTONVPN_RA_SETTLE_MS:-300}"
export PROTONVPN_RA_SETTLE_MS

if ! command -v "$UCODE" >/dev/null 2>&1; then
	echo "ucode not found (set \$UCODE to a built interpreter); skipping" >&2
	exit 2
fi

# The peak-RSS guard in test_cache.uc spawns a fresh child process so the
# number is the child's own VmHWM; it needs the interpreter and the same
# module search path this suite runs with.
export UCODE
PVT_UCODE_L="-L '$mocks/*.uc' -L '$lib/*.uc'"
[ -n "$UCODE_EXTRA_L" ] && PVT_UCODE_L="$PVT_UCODE_L -L '$UCODE_EXTRA_L'"
export PVT_UCODE_L
PVT_MEASURE="$here/measure_peak.uc"
export PVT_MEASURE
# Helpers a test invokes as a child process (see helpers/real-budget.uc).
PVT_HELPERS="$here/helpers"
export PVT_HELPERS
# The tests directory itself, for the test that reads the package sources.
PVT_TESTS="$here"
export PVT_TESTS

status=0
for t in "$here"/test_*.uc; do
	echo "== ${t##*/} =="
	if [ -n "$UCODE_EXTRA_L" ]; then
		"$UCODE" -L "$mocks/*.uc" -L "$lib/*.uc" -L "$UCODE_EXTRA_L" \
			-D fixture="$fixture" -D KEY="$key" -D RPCD="$rpcd" -D MIGRATE="$migrate" \
			-S "$t" || status=1
	else
		"$UCODE" -L "$mocks/*.uc" -L "$lib/*.uc" \
			-D fixture="$fixture" -D KEY="$key" -D RPCD="$rpcd" -D MIGRATE="$migrate" \
			-S "$t" || status=1
	fi
done

[ "$status" = 0 ] && echo "ALL TESTS PASSED" || echo "TESTS FAILED"
exit "$status"

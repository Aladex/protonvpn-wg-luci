#!/bin/sh
# SPDX-License-Identifier: MIT
# Parser regression tests for stamp-appversion.sh. The stamper must accept
# exactly ONE rigid source shape — a first document holding a single
# 'version: X.Y.Z' line — and fall back to the committed constant for
# everything else. sed is not a YAML parser: these cases are inputs where a
# real YAML parse disagrees with naive line extraction (collected from two
# review rounds), plus the genuine upstream shape that must keep stamping.
# Offline: PROTONVPN_VERSIONS_YML points the script at generated sources.
# Run directly or from CI (build.yml 'static' job).

set -u

here=$(cd "$(dirname "$0")" && pwd)
STAMP="$here/../stamp-appversion.sh"
API_UC="$here/../files/usr/share/ucode/protonvpn/api.uc"

ok=0
failed=0
tmp=$(mktemp -d "${TMPDIR:-/tmp}/protonvpn-stamp-test.XXXXXX") || exit 1
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

# Dates inside generated sources come from the current time with offsets,
# never hard-coded: a static date that is 'in the future' today silently
# becomes 'in the past' later and can flip test branches. These particular
# fields are opaque to the stamper's whitelist, but the fixtures must stay
# honest upstream lookalikes anyway.
now=$(date -u +%s)
t0=$(date -u -d "@$now" '+%Y/%m/%d %H:%M')
t1=$(date -u -d "@$((now - 9 * 86400))" '+%Y/%m/%d %H:%M')
t2=$(date -u -d "@$((now - 671 * 86400))" '+%Y/%m/%d %H:%M')

# The genuine upstream shape, generated rather than stored: extra keys, a
# description list, a non-ASCII author name, and history documents behind
# proper separators, one with indented list items — the shapes the real
# versions.yml shows today.
cat > "$tmp/genuine.yml" <<EOF
version: 4.18.2
time: $t0
author: Axel Langenskiold
email: axel.langenskiold@proton.ch
description:
- "i18n(weekly-mr): Upgrade translations from crowdin (58d09466). (L10n bot)"
- "feat: Free tier users can connect to fastest free global and country servers, and change servers randomly (behind feature flag) (Richard Paterson)"
---
version: 4.18.1
time: $t1
author: Pep Llaneras
email: josep.llaneras@proton.ch
description:
- "i18n(weekly-mr): Upgrade translations from crowdin (c6610.5a)"
- "chore: Bump devtools. (Axel Langenskiold)"
---
version: 4.7.3
time: $t2
author: Alexandru Cheltuitor
email: alexandru.cheltuitor@proton.ch
urgency: medium
stability: unstable
description:
  - Fix bug when opening the application after hibernation (Alexandru Cheltuitor).
  - Re-wrote success rate metrics for connection monitoring (Pep Llaneras)
  - Show 'Connecting to VPN from <location>' text while connecting (Elena Švilpė)
---
EOF

report() { # <cond> <label>
	if [ "$1" = 0 ]; then
		ok=$((ok + 1)); printf 'ok   %s\n' "$2"
	else
		failed=$((failed + 1)); printf 'FAIL %s\n' "$2"
	fi
}

# What a run leaves behind: the stamping exit status, the constant in the
# api.uc copy, and what --print-upstream says. Stamping must always exit 0 —
# a package build may never fail over this — and both modes must agree on a
# value or on a refusal.
run_case() { # <content-as-printf-%b>
	printf '%b' "$1" > "$tmp/src.yml"
	cp "$API_UC" "$tmp/t.uc"
	stamp_out=$(PROTONVPN_VERSIONS_YML="$tmp/src.yml" sh "$STAMP" "$tmp/t.uc" 2>&1)
	stamp_rc=$?
	left=$(sed -n "s/^const PM_APPVERSION = '\([^']*\)';.*/\1/p" "$tmp/t.uc" | head -1)
	print_out=$(PROTONVPN_VERSIONS_YML="$tmp/src.yml" sh "$STAMP" --print-upstream 2>/dev/null)
	print_rc=$?
}

# A rejected source: stamping exits 0 and leaves the constant untouched,
# --print-upstream refuses (exit 1, no value).
expect_fallback() { # <label> <content>
	run_case "$2"
	[ "$stamp_rc" = 0 ] && [ "$left" = "linux-vpn-gtk@4.18.2" ] && [ "$print_rc" = 1 ] && [ -z "$print_out" ]
	report $? "$1"
}

# An accepted source: stamping exits 0 and rewrites the constant,
# --print-upstream prints the same candidate.
expect_stamp() { # <label> <content> <expected-version>
	run_case "$2"
	[ "$stamp_rc" = 0 ] && [ "$left" = "linux-vpn-gtk@$3" ] && [ "$print_rc" = 0 ] && [ "$print_out" = "linux-vpn-gtk@$3" ]
	report $? "$1"
}

# ── rejected: a real YAML parse disagrees with naive extraction ──────────

expect_fallback 'comment without whitespace before # is part of the value' \
	'version: 9.9.9#beta\n'
expect_fallback 'a scalar continuation line is part of the value' \
	'version: 9.9.9\n  beta\n'
expect_fallback 'a continuation line after a blank line still continues the scalar' \
	'version: 9.9.9\n\n  beta\n'
expect_fallback 'a line starting with --- is not a document separator' \
	'version: 9.9.9\n---junk\nversion: 8.8.8\n'
expect_fallback 'a malformed marker after the version line rejects the source' \
	"version: 9.9.9\n---junk\ntime: $t0\n"
expect_fallback 'VT is not whitespace' \
	'version:\0139.9.9\n'
expect_fallback 'FF is not whitespace' \
	'version: 9.9.9\014\n'
expect_fallback 'a control character anywhere rejects the source' \
	'version: 9.9.9\n\013\n'
expect_fallback 'a control character inside the comment rejects the source' \
	'version: 9.9.9 # rel\013ease\n'
expect_fallback 'a suffix on the scalar rejects it' \
	'version: 9.9.9 beta\n'
expect_fallback 'a pre-release suffix on the scalar rejects it' \
	'version: 4.0.0b2\n'
expect_fallback 'a missing mapping separator rejects the key' \
	'version:9.9.9\n'
expect_fallback 'a tab after the colon is not the accepted shape' \
	'version:\t9.9.9\n'
expect_fallback 'duplicate version keys are ambiguous' \
	'version: 9.9.9\nversion: 8.8.8\n'
expect_fallback 'a nested version key is ambiguous' \
	'version: 9.9.9\nnested:\n  version: 8.8.8\n'
expect_fallback 'a quoted scalar is not the accepted shape' \
	'version: "9.9.9"\n'
expect_fallback 'trailing whitespace without a comment is not the accepted shape' \
	'version: 9.9.9 \n'
expect_fallback 'an empty source has no version' \
	''
expect_fallback 'a bare CR that is not part of CRLF rejects the source' \
	'version: 9.9.9\rjunk\n'

# ── accepted: the one rigid shape ────────────────────────────────────────

expect_stamp 'a plain version line stamps' \
	'version: 9.9.9\n' '9.9.9'
expect_stamp 'an inline comment after whitespace is allowed' \
	'version: 9.9.9  # weekly release\n' '9.9.9'
expect_stamp 'CRLF line endings are normalized' \
	"version: 9.9.9\r\ntime: $t0\r\n" '9.9.9'
expect_stamp 'history documents behind a proper separator are ignored' \
	"version: 9.9.9\ntime: $t0\n---\nversion: 4.18.2\n" '9.9.9'

# The genuine upstream shape must stamp. The copy starts one version
# behind, the situation the stamper exists for.
sed "s/linux-vpn-gtk@4.18.2/linux-vpn-gtk@4.18.1/" "$API_UC" > "$tmp/t.uc"
stamp_out=$(PROTONVPN_VERSIONS_YML="$tmp/genuine.yml" sh "$STAMP" "$tmp/t.uc" 2>&1)
stamp_rc=$?
left=$(sed -n "s/^const PM_APPVERSION = '\([^']*\)';.*/\1/p" "$tmp/t.uc" | head -1)
print_out=$(PROTONVPN_VERSIONS_YML="$tmp/genuine.yml" sh "$STAMP" --print-upstream 2>/dev/null)
print_rc=$?
[ "$stamp_rc" = 0 ] && [ "$left" = "linux-vpn-gtk@4.18.2" ] && [ "$print_rc" = 0 ] && [ "$print_out" = "linux-vpn-gtk@4.18.2" ]
report $? 'the genuine upstream file shape stamps'

echo "stamp parser tests: $ok ok, $failed failed"
[ "$failed" = 0 ]

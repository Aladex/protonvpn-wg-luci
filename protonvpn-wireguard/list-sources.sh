#!/bin/sh
# SPDX-License-Identifier: MIT
# The package's source files, by kind, for the CI syntax checks.
#
#   list-sources.sh shell   -> every shell script, for `sh -n`
#   list-sources.sh ucode   -> every ucode source the package ships, for `ucode -c`
#
# Run from the repository root; paths are printed relative to it, one per line.
#
# ── Why this is a script and not two shell snippets in build.yml ─────────
#
# Because it would otherwise be the same rule written twice, and this package
# has now been bitten three times by a second definition that agrees today and
# drifts later. The two CI steps ask this file; this file is the only place
# that knows what a shell script or a ucode source is.
#
# ── Why the sets are derived, and why derivation alone is not enough ─────
#
# A hand-maintained list of entry points goes stale silently: the compile-check
# list had lost three of six ucode programs before anyone noticed. So the sets
# are derived from the files themselves.
#
# But a derived set narrows silently too, which is the same defect wearing a
# different hat. The first version of this matched only a first line containing
# `/bin/sh`, so `#!/usr/bin/env sh` and `#!/bin/ash` matched nothing at all —
# and because the files that DID match kept the "is it empty?" guard green, the
# step reported success while covering less than it claimed. Widening the
# pattern fixes today's gap and leaves the failure mode intact for the next
# shebang form nobody thought of.
#
# So every set is checked against a FLOOR that is stated independently of the
# predicate that derives it. A file in the floor that the predicate missed is
# reported BY NAME and fails the run. The floors:
#
#   shell  — everything shipped under etc/init.d or etc/uci-defaults, plus every
#            *.sh in the tree. OpenWrt executes the contents of those two
#            directories with sh, so membership IS the claim "this is a shell
#            script"; .sh is the extension this repository gives its tooling.
#
#   ucode  — everything shipped under usr/bin or ending in .uc.
#
# Both read the PAYLOAD TREES — protonvpn-wireguard/files, luci-app-protonvpn/
# root and luci-app-protonvpn/htdocs — and not the Makefiles.
#
# That is deliberate, and it is the second thing this file got wrong. The floor
# used to come from a sed pattern over $(INSTALL_*) lines, which is a second
# implementation of Make: it saw only same-line calls with a './' source, so a
# line continuation, a variable-sourced install or a CP-generated one fell out
# of the floor AND out of the unknown-category check together. A floor that
# fails in the same direction as the predicate it checks is not a floor. And it
# could never have seen luci-app-protonvpn at all, which ships through luci.mk
# by convention with no install lines to read.
#
# A payload tree needs no parser: every file under it is installed because it
# is there. Membership, not syntax.
#
# The one installed path with no source file is lib/upgrade/keep.d/protonvpn,
# which the package Makefile generates with `echo`. There is nothing to
# syntax-check about a one-line generated file, so it is simply not in any
# tree and not in any floor.
#
# Every payload file must fall into a known category (see `classify`), so a
# file of some new kind fails the run instead of slipping past both predicates.

set -e

pkg=protonvpn-wireguard
[ -d "$pkg" ] || { echo "run me from the repository root" >&2; exit 1; }

# This repository's own source. node_modules is a dependency tree, not ours,
# and lives at the root rather than inside either package.
roots="protonvpn-wireguard luci-app-protonvpn"

# The payload trees: a file is installed because it sits in one of these.
# protonvpn-wireguard/files is copied by that package's Makefile; root/ and
# htdocs/ are copied by luci.mk, which is why neither has install lines to
# read. Listing the directories is the whole manifest.
payload() {
	find $roots -type f \
		\( -path '*/files/*' -o -path '*/root/*' -o -path '*/htdocs/*' \) \
		-not -path '*/.git/*' | sort
}

die() { echo "$*" >&2; exit 1; }

# The command a shebang names, reduced to a bare name:
#   "#!/bin/sh"                -> sh
#   "#!/bin/sh /etc/rc.common" -> sh      (the init scripts' form)
#   "#!/usr/bin/env sh"        -> sh      (env indirection)
#   "#!/usr/bin/ucode -S"      -> ucode
# A file with no shebang prints nothing. Reading the interpreter instead of
# pattern-matching the whole line is what lets an unusual but valid path be
# recognised rather than silently skipped.
interp() {
	head -1 "$1" 2>/dev/null | awk '
		/^#!/ {
			sub(/^#![ \t]*/, "")
			n = $1
			if (n ~ /(^|\/)env$/)
				n = $2
			sub(/.*\//, "", n)
			print n
		}'
}

# ── the derived sets ────────────────────────────────────────────────────

derive_shell() {
	find $roots -type f -not -path '*/.git/*' | sort | while read -r f; do
		case "$(interp "$f")" in
			sh|ash|dash|bash|ksh) echo "$f" ;;
		esac
	done
}

derive_ucode() {
	payload | while read -r f; do
		case "$f" in
			*.uc) echo "$f"; continue ;;
		esac
		if [ "$(interp "$f")" = ucode ]; then
			echo "$f"
		fi
	done
}

# ── the floors ──────────────────────────────────────────────────────────

floor_shell() {
	payload | while read -r f; do
		case "$f" in
			*/etc/init.d/*|*/etc/uci-defaults/*) echo "$f" ;;
		esac
	done
	find $roots -type f -name '*.sh' -not -path '*/.git/*'
}

floor_ucode() {
	payload | while read -r f; do
		case "$f" in
			*/usr/bin/*|*.uc) echo "$f" ;;
		esac
	done
}

# Every shipped file has to be something some step knows how to check. A file
# that matches no category is not "not our kind of file", it is a category
# nobody has thought about yet — so it stops the run and says so, rather than
# being quietly covered by no step at all.
classify() {
	payload | while read -r f; do
		case "$f" in
			*/etc/config/*)       continue ;;   # uci configuration, not code
			*/etc/init.d/*)       continue ;;   # floor_shell, `sh -n`
			*/etc/uci-defaults/*) continue ;;   # floor_shell, `sh -n`
			*/usr/bin/*|*.uc)     continue ;;   # floor_ucode, `ucode -c`
			*.json)               continue ;;   # the "Validate all JSON" step
			*.js)                 continue ;;   # eslint
			*.LICENSE)            continue ;;   # a bundled dependency's licence
		esac
		echo "$f"
	done
}

# ── checking a derived set against its floor ────────────────────────────

# Fails naming every floor member the predicate did not produce. `sort` and
# `comm` do the comparison so the message lists all of them at once: finding
# out about a second missing file only after fixing the first is how a widening
# turns into three rounds.
check() {
	kind=$1; derived=$2; floor=$3
	n=$(printf '%s\n' "$derived" | grep -c . || true)
	[ "$n" -gt 0 ] || die "$kind: the search matched nothing - the predicate is wrong"

	tmp=${TMPDIR:-/tmp}/list-sources.$$
	printf '%s\n' "$floor"   | sort -u > "$tmp.floor"
	printf '%s\n' "$derived" | sort -u > "$tmp.derived"
	missing=$(comm -23 "$tmp.floor" "$tmp.derived")
	rm -f "$tmp.floor" "$tmp.derived"
	if [ -n "$missing" ]; then
		echo "$kind: these files must be checked and the predicate missed them:" >&2
		printf '  %s\n' $missing >&2
		die "$kind: the predicate has narrowed - widen it, do not shrink the floor"
	fi
}

case "$1" in
	shell)
		set=$(derive_shell)
		check shell "$set" "$(floor_shell)"
		printf '%s\n' "$set"
		;;
	ucode)
		set=$(derive_ucode)
		check ucode "$set" "$(floor_ucode)"
		unknown=$(classify)
		if [ -n "$unknown" ]; then
			echo "these shipped files match no known category:" >&2
			printf '  %s\n' $unknown >&2
			die "say what they are in list-sources.sh, or they ship unchecked"
		fi
		printf '%s\n' "$set"
		;;
	*)
		die "usage: $0 shell|ucode"
		;;
esac

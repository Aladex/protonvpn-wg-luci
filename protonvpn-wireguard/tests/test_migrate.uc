#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// The uci-defaults migration script, driven offline. The real `uci` binary is
// not available in the test environment (and must not touch the host's
// /etc/config anyway), so the script runs against a stand-in `uci` written
// here that keeps a flat key=value database, plus PROTONVPN_CONFIG_DIR to
// relocate the config file the script creates.

'use strict';

import { readfile, writefile, unlink, mkdir, chmod } from 'fs';
const _cmn = require('protonvpn.common');

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

const statedir = getenv('PROTONVPN_STATE_DIR') || '/tmp/protonvpn-test-state';
const workdir = statedir + '/migrate';
const bindir = workdir + '/bin';
const confdir = workdir + '/config';
const db = workdir + '/uci.db';
const script = MIGRATE;      // supplied by run.sh

mkdir(workdir);
mkdir(bindir);
mkdir(confdir);

// A stand-in for the uci CLI: `get`, `set`, `delete`, `show`, `changes` and
// `commit` over one key=value file, which is all the migration uses.
writefile(bindir + '/uci',
'#!/bin/sh\n' +
'db="$FAKE_UCI_DB"\n' +
'[ -f "$db" ] || : > "$db"\n' +
'[ "$1" = "-q" ] && shift\n' +
'cmd="$1"; shift\n' +
'esc() { printf %s "$1" | sed "s/[.[\\\\*^$]/\\\\\\\\&/g"; }\n' +
'case "$cmd" in\n' +
'get)\n' +
'\tv="$(sed -n "s/^$(esc "$1")=//p" "$db")"\n' +
'\t[ -n "$v" ] || exit 1\n' +
'\techo "$v" ;;\n' +
'set)\n' +
'\tkey="${1%%=*}"; val="${1#*=}"\n' +
'\tsed -i "/^$(esc "$key")=/d" "$db"\n' +
'\techo "$key=$val" >> "$db" ;;\n' +
'delete)\n' +
'\tsed -i "/^$(esc "$1")=/d" "$db" ;;\n' +
'show)\n' +
'\tgrep "^$(esc "$1")\\." "$db" || true ;;\n' +
'changes)\n' +
'\t: ;;\n' +
'commit)\n' +
'\t: ;;\n' +
'*)\n' +
'\texit 1 ;;\n' +
'esac\n' +
'exit 0\n');
chmod(bindir + '/uci', 0o755);

// Run the migration once against the given starting database.
function migrate(lines) {
	writefile(db, lines);
	let r = _cmn.run([ 'env', 'PATH=' + bindir + ':' + (getenv('PATH') || '/bin:/usr/bin'),
		'FAKE_UCI_DB=' + db, 'PROTONVPN_CONFIG_DIR=' + confdir,
		'sh', script ]);
	let out = {};
	for (let line in split(readfile(db) || '', '\n')) {
		let i = index(line, '=');
		if (i > 0)
			out[substr(line, 0, i)] = substr(line, i + 1);
	}
	out['.code'] = r.code;
	return out;
}

// ── a config from before the option existed ──────────────────────────────
{
	let s = migrate('protonvpn.main=instance\nprotonvpn.main.block_ipv6=1\n');
	eq('the script succeeds', s['.code'], 0);
	eq('block_ipv6=1 becomes ipv6_mode=block', s['protonvpn.main.ipv6_mode'], 'block');
	ok('and the old key is removed', s['protonvpn.main.block_ipv6'] == null);
	eq('the schema version is bumped', s['protonvpn.main.config_version'], '2');
}

// block_ipv6='0' meant "leave IPv6 alone", which is the new 'off' — NOT the
// new default. Mapping it to 'block' would start blocking traffic on a router
// that deliberately had IPv6 running.
{
	let s = migrate('protonvpn.main=instance\nprotonvpn.main.block_ipv6=0\n');
	eq('block_ipv6=0 becomes ipv6_mode=off', s['protonvpn.main.ipv6_mode'], 'off');
	ok('and the old key is removed', s['protonvpn.main.block_ipv6'] == null);
}

// ── every instance is migrated, not just 'main' ──────────────────────────
{
	let s = migrate('protonvpn.main=instance\nprotonvpn.main.block_ipv6=1\n' +
		'protonvpn.media=instance\nprotonvpn.media.block_ipv6=0\n' +
		'protonvpn.globals=globals\n');
	eq('main is migrated', s['protonvpn.main.ipv6_mode'], 'block');
	eq('and so is a second instance', s['protonvpn.media.ipv6_mode'], 'off');
	ok('the globals section is left alone', s['protonvpn.globals.ipv6_mode'] == null);
}

// ── nothing to convert ───────────────────────────────────────────────────
{
	let s = migrate('protonvpn.main=instance\n');
	ok('a config without the old key gets no ipv6_mode', s['protonvpn.main.ipv6_mode'] == null);
	eq('but is still stamped', s['protonvpn.main.config_version'], '2');
}

// ── idempotence: running twice must not undo the second run's settings ───
{
	let s = migrate('protonvpn.main=instance\nprotonvpn.main.block_ipv6=1\n');
	// Second pass over the already-migrated database, with the user having
	// since chosen 'auto'. A migration that re-fires would push it back to
	// 'block' and silently turn IPv6 off again.
	writefile(db, 'protonvpn.main=instance\nprotonvpn.main.config_version=2\n' +
		'protonvpn.main.ipv6_mode=auto\n');
	let again = migrate('protonvpn.main=instance\nprotonvpn.main.config_version=2\n' +
		'protonvpn.main.ipv6_mode=auto\n');
	eq('a migrated config is left alone', again['protonvpn.main.ipv6_mode'], 'auto');
	eq('and keeps its version', again['protonvpn.main.config_version'], '2');
}

// An explicit ipv6_mode always wins over the boolean it replaced, even when
// the version stamp says the migration has not run yet.
{
	let s = migrate('protonvpn.main=instance\nprotonvpn.main.block_ipv6=1\n' +
		'protonvpn.main.ipv6_mode=auto\n');
	eq('an existing ipv6_mode is not overwritten', s['protonvpn.main.ipv6_mode'], 'auto');
	ok('but the stale boolean is still cleaned up', s['protonvpn.main.block_ipv6'] == null);
}

unlink(db);
unlink(bindir + '/uci');
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL MIGRATION TESTS PASSED');
exit(fails ? 1 : 0);

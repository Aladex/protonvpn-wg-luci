#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// The uci-defaults migration script, driven offline. The real `uci` binary is
// not available in the test environment (and must not touch the host's
// /etc/config anyway), so the script runs against a stand-in `uci` written
// here that keeps a flat key=value database, plus PROTONVPN_CONFIG_DIR to
// relocate the config file the script creates.
//
// `protonvpn-instance-owners` gets a stand-in too, but of a different kind: a
// wrapper that runs the REAL shipped script through the interpreter with the
// module search path an installed package gets for free. The migration asks
// that program which interface each instance owns, and the whole point is
// that the answer comes from the backend reading its own config — so the
// wrapper must not be allowed to answer in its place. The config it reads is
// the mock cursor's, seeded from PROTONVPN_MOCK_UCI below.

'use strict';

import { readfile, writefile, unlink, mkdir, chmod } from 'fs';
import { cursor } from 'uci';
const _cmn = require('protonvpn.common');

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

const statedir = getenv('PROTONVPN_STATE_DIR') || '/tmp/protonvpn-test-state';
const workdir = statedir + '/migrate';
const bindir = workdir + '/bin';
const confdir = workdir + '/config';
const db = workdir + '/uci.db';
// The same config again, in the shape the ucode uci mock seeds itself from —
// the migration asks the backend to read it, and the backend reads through a
// cursor, not through the CLI.
const mockdb = workdir + '/uci.json';
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
'\tsed -i "/^$(esc "$1")=/d;/^$(esc "$1")\\./d" "$db"\n' +
// Real uci renumbers the anonymous sections that follow a deleted one, so
// `network.@rule6[5]` becomes `[4]` the moment `[4]` goes. A migration that
// walks indices forward while deleting therefore skips sections and deletes
// ones it never looked at; the stand-in has to model the renumbering or that
// bug passes the suite.
'\tcase "$1" in *".@"*"["*"]")\n' +
'\t\tcfg="${1%%.@*}"; rest="${1#*.@}"\n' +
'\t\ttyp="${rest%%[*}"; idx="${rest#*[}"; idx="${idx%]}"\n' +
'\t\tmax="$(sed -n "s/^$(esc "$cfg")\\.@$typ\\[\\([0-9]*\\)\\].*/\\1/p" "$db" | sort -n | tail -1)"\n' +
'\t\tn=$((idx + 1))\n' +
'\t\twhile [ -n "$max" ] && [ "$n" -le "$max" ]; do\n' +
'\t\t\tsed -i "s/^$(esc "$cfg")\\.@$typ\\[$n\\]/$cfg.@$typ[$((n - 1))]/" "$db"\n' +
'\t\t\tn=$((n + 1))\n' +
'\t\tdone ;;\n' +
'\tesac ;;\n' +
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

// The shipped ownership program, run through the built interpreter with the
// -L flags the dev build needs to find /usr/share/ucode/protonvpn. On a router
// it is on PATH and those modules are on the default search path, so `owners`
// there is this same script with neither wrapper nor flags.
const owners_bin = bindir + '/protonvpn-instance-owners';
const owners_src = replace(script, /etc\/uci-defaults\/[^\/]+$/,
	'usr/bin/protonvpn-instance-owners');
const owners_real = '#!/bin/sh\nexec ' + (getenv('UCODE') || 'ucode') + ' ' +
	(getenv('PVT_UCODE_L') || '') + ' -S ' + owners_src + ' "$@"\n';
writefile(owners_bin, owners_real);
chmod(owners_bin, 0o755);

// The ucode cursor's view of the `protonvpn` config, derived from the SAME
// flat database the `uci` CLI stand-in reads — one fixture, both sides, so a
// test cannot accidentally describe two different routers.
//
// `over` replaces individual options with values the flat format cannot
// carry, and that is the whole point of it: on a real router `uci get` and the
// ucode cursor do not always hand back the same thing. A value with a newline
// in it prints as two lines through the CLI and arrives whole at the cursor; a
// one-item list prints as a bare word and arrives as an array. Those are the
// cases where a shell-marshalled answer and the runtime's own answer part
// company, so the fixture has to be able to state them.
function mock_config(lines, over) {
	let cfg = {};
	for (let line in split(lines, '\n')) {
		let m = match(line, /^protonvpn\.([^.=]+)=(.*)$/);
		if (m) {
			cfg[m[1]] = { '.type': m[2], '.name': m[1] };
			continue;
		}
		m = match(line, /^protonvpn\.([^.=]+)\.([^=]+)=(.*)$/);
		if (m && cfg[m[1]])
			cfg[m[1]][m[2]] = m[3];
	}
	for (let sec in (over || {}))
		if (cfg[sec])
			for (let k in over[sec])
				cfg[sec][k] = over[sec][k];
	return { protonvpn: cfg };
}

// Run the migration once against the given starting database.
function migrate(lines, over) {
	writefile(db, lines);
	writefile(mockdb, sprintf('%J', mock_config(lines, over)));
	let r = _cmn.run([ 'env', 'PATH=' + bindir + ':' + (getenv('PATH') || '/bin:/usr/bin'),
		'FAKE_UCI_DB=' + db, 'PROTONVPN_CONFIG_DIR=' + confdir,
		'PROTONVPN_MOCK_UCI=' + mockdb,
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
	eq('the schema version is bumped', s['protonvpn.main.config_version'], '3');
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
	eq('but is still stamped', s['protonvpn.main.config_version'], '3');
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
	eq('and keeps its version', again['protonvpn.main.config_version'], '3');
}

// An explicit ipv6_mode always wins over the boolean it replaced, even when
// the version stamp says the migration has not run yet.
{
	let s = migrate('protonvpn.main=instance\nprotonvpn.main.block_ipv6=1\n' +
		'protonvpn.main.ipv6_mode=auto\n');
	eq('an existing ipv6_mode is not overwritten', s['protonvpn.main.ipv6_mode'], 'auto');
	ok('but the stale boolean is still cleaned up', s['protonvpn.main.block_ipv6'] == null);
}

// ── v3: netifd rules left behind by an instance that is no longer there ──
//
// Until the fix in protonvpn.routing, switching an instance off in LuCI kept
// its IPv6 prohibit: a persistent `rule6 in lan prohibit priority 21000`
// stamped with an interface that no longer existed. Nothing reconciles an
// instance that is disabled, so that rule stayed across reboots and refused
// every IPv6 packet from the LAN before the kernel reached the ISP default
// route. The router this was found on had to be cleared by hand. The fix
// stops new ones appearing; this step clears the ones already out there.
//
// The judgement is ownership, not shape: a stamped rule whose
// `protonvpn_iface` names no instance's interface has no owner left to
// reconcile it, so it goes. Anything else is left exactly alone.

// A netifd rule section in the flat stand-in database.
function rule(cfgtype, idx, opts) {
	let out = 'network.@' + cfgtype + '[' + idx + ']=' + cfgtype + '\n';
	for (let k in opts)
		out += 'network.@' + cfgtype + '[' + idx + '].' + k + '=' + opts[k] + '\n';
	return out;
}
// Every key still under network.@<type>[<idx>], so a half-deleted section
// (the type line gone, the options left) is visible rather than passing.
function sect(s, cfgtype, idx) {
	let pre = 'network.@' + cfgtype + '[' + idx + ']', out = [];
	for (let k in s)
		if (k == pre || substr(k, 0, length(pre) + 1) == (pre + '.'))
			push(out, k);
	sort(out);
	return out;
}

{
	// The owner's router, reproduced: instance 'main' on pv_home is alive,
	// 'ournet' was deleted, and its prohibit is still sitting there.
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		'protonvpn.main.config_version=2\n' +
		rule('rule6', 0, { 'in': 'lan', lookup: '101', priority: '20000',
			protonvpn_managed: '1', protonvpn_role: 'steer_v6_lookup',
			protonvpn_iface: 'pv_home' }) +
		rule('rule6', 1, { 'in': 'lan', action: 'prohibit', priority: '21000',
			protonvpn_managed: '1', protonvpn_role: 'steer_v6',
			protonvpn_iface: 'pv_ournet' }));
	eq('v3: the orphaned prohibit is gone, options and all',
		sect(s, 'rule6', 1), []);
	eq('v3: the live instance keeps its rule',
		s['network.@rule6[0].protonvpn_iface'], 'pv_home');
	eq('v3: and the schema version is bumped', s['protonvpn.main.config_version'], '3');
}

{
	// The IPv4 half is stamped the same way and orphans the same way; a
	// migration that only knew about rule6 would leave a kill switch behind.
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		rule('rule', 0, { 'in': 'lan', action: 'prohibit', priority: '21000',
			protonvpn_managed: '1', protonvpn_role: 'steer_ks',
			protonvpn_iface: 'pv_gone' }));
	eq('v3: an orphaned IPv4 rule goes too', sect(s, 'rule', 0), []);
}

{
	// Not ours: no stamp, same shape. Removing it would delete a rule the user
	// wrote, which is the one thing this module never does.
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit', priority: '21000' }));
	eq('v3: an unstamped rule of the same shape is left alone',
		s['network.@rule6[0].priority'], '21000');

	// Named after a dead interface but NOT stamped. The stamp is the module's
	// only claim of ownership — "only stamped objects are ever modified or
	// removed" is what lets this package be trusted with a user's network
	// config — so the name alone is not enough to take a section away.
	s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_iface: 'pv_gone' }));
	eq('v3: an unstamped rule is not ours to delete, whatever it names',
		s['network.@rule6[0].protonvpn_iface'], 'pv_gone');

	// Stamped but with no interface recorded: there is nothing to judge
	// ownership by, and guessing would risk deleting a live rule.
	s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1' }));
	eq('v3: a stamped rule naming no interface is left alone',
		s['network.@rule6[0].protonvpn_managed'], '1');
}

{
	// An instance with no `interface` option owns the default name. Reading
	// the option alone would declare every such install orphaned and delete
	// the rules of a working tunnel.
	let s = migrate('protonvpn.main=instance\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'protonvpn' }));
	eq('v3: the default interface name counts as a live owner',
		s['network.@rule6[0].protonvpn_iface'], 'protonvpn');
}

{
	// A second instance is an owner too, disabled or not: `enabled=0` is a
	// state the enforcement now reconciles, not a reason to reach in here.
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		'protonvpn.media=instance\nprotonvpn.media.interface=pv_media\n' +
		'protonvpn.media.enabled=0\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'pv_media' }));
	eq('v3: a disabled instance still owns its rules',
		s['network.@rule6[0].protonvpn_iface'], 'pv_media');
}

{
	// Several orphans at once. uci renumbers the anonymous sections after a
	// delete, so walking indices forward while deleting skips one and then
	// deletes a section that was never examined — here it would leave an
	// orphan standing and take the live rule with it.
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'pv_a' }) +
		rule('rule6', 1, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'pv_b' }) +
		rule('rule6', 2, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'pv_c' }) +
		rule('rule6', 3, { 'in': 'lan', lookup: '101',
			protonvpn_managed: '1', protonvpn_iface: 'pv_home' }));
	eq('v3: every orphan goes', [ ...sect(s, 'rule6', 1), ...sect(s, 'rule6', 2),
		...sect(s, 'rule6', 3) ], []);
	eq('v3: and the one live rule is the only survivor',
		s['network.@rule6[0].protonvpn_iface'], 'pv_home');
}

{
	// Idempotence, and the step never fires again: a rule created after the
	// migration belongs to whatever is running now, and re-running must not
	// reach for it.
	let s = migrate('protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		'protonvpn.main.config_version=3\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'pv_stale' }));
	eq('v3: an already-migrated config is not swept again',
		s['network.@rule6[0].protonvpn_iface'], 'pv_stale');
	eq('v3: and keeps its version', s['protonvpn.main.config_version'], '3');
}

{
	// A config with no network rules at all must still bump cleanly rather
	// than trip over an empty listing.
	let s = migrate('protonvpn.main=instance\n');
	eq('v3: nothing to sweep is not an error', s['.code'], 0);
	eq('v3: the version is bumped anyway', s['protonvpn.main.config_version'], '3');
}

// ── v3: whose interface is it — the backend's answer, not a shell copy ───
//
// Every stamped object carries the NORMALIZED interface name: load_settings()
// runs the raw option through validate_interface and falls back to the
// default when it is rejected. The migration decides what is an orphan by
// that name, so if it derived the name itself the two would be one edit to
// validate_interface away from disagreeing — and on the day they disagreed,
// a still-enabled instance would have every stamped rule swept, the IPv6
// prohibit this whole change exists to get right included. A migration that
// ships to close a leak must not be able to open one.
//
// So the migration asks protonvpn.common, and these checks ask the same
// module, and then require the two to agree. They are not a list of names
// anybody has to keep current: move a name across validate_interface and the
// expectation moves with it, because both sides are computed, not written
// down.

// What the backend itself calls this instance's interface — the authority
// every stamped object is tagged with, and the one the migration has to match.
function owned_interface(raw) {
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance' } } };
	if (raw != null)
		global.MOCK_UCI.protonvpn.main.interface = raw;
	return _cmn.load_settings(cursor(), 'main').interface;
}

// Raw option values on both sides of validate_interface today. `null` is the
// option being absent, which is its own path through load_settings.
const RAW_IFACES = [ null, 'protonvpn', 'pv_home', 'a', 'A1_b2', 'abcdefghijklmno',
	'bad-name', 'dot.name', 'has space', 'abcdefghijklmnop', 'né', 'pv/home' ];

for (let raw in RAW_IFACES) {
	let owned = owned_interface(raw);
	let cfg = 'protonvpn.main=instance\nprotonvpn.main.enabled=1\n' +
		((raw != null) ? ('protonvpn.main.interface=' + raw + '\n') : '');
	let shown = sprintf('%J', raw);

	// The live instance's own guard, stamped the way the enforcement stamps it.
	let s = migrate(cfg +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit', priority: '21000',
			protonvpn_managed: '1', protonvpn_role: 'steer_v6',
			protonvpn_iface: owned }));
	eq('v3: interface ' + shown + ' keeps the leak guard of its live instance',
		s['network.@rule6[0].protonvpn_iface'], owned);

	// And the other direction, so the agreement is not bought by keeping
	// everything: a name the backend does NOT own is still an orphan. Only
	// meaningful where normalization actually moved the name.
	if (raw != null && raw != owned) {
		let s2 = migrate(cfg +
			rule('rule6', 0, { 'in': 'lan', action: 'prohibit', priority: '21000',
				protonvpn_managed: '1', protonvpn_role: 'steer_v6',
				protonvpn_iface: raw }));
		eq('v3: interface ' + shown + ' does not make the raw name an owner',
			sect(s2, 'rule6', 0), []);
	}
}

{
	// The reviewer's case, spelled out on its own: an enabled instance whose
	// interface option validate_interface rejects. Its rules are stamped
	// 'protonvpn', and a shell copy that read the raw option would call every
	// one of them an orphan.
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.enabled=1\n' +
		'protonvpn.main.interface=bad-name\n' +
		rule('rule6', 0, { 'in': 'lan', lookup: '101', priority: '20000',
			protonvpn_managed: '1', protonvpn_role: 'steer_v6_lookup',
			protonvpn_iface: 'protonvpn' }) +
		rule('rule6', 1, { 'in': 'lan', action: 'prohibit', priority: '21000',
			protonvpn_managed: '1', protonvpn_role: 'steer_v6',
			protonvpn_iface: 'protonvpn' }) +
		rule('rule', 0, { 'in': 'lan', lookup: '101', priority: '20000',
			protonvpn_managed: '1', protonvpn_role: 'steer_lookup',
			protonvpn_iface: 'protonvpn' }));
	eq('v3: a rejected interface name keeps the v6 lookup',
		s['network.@rule6[0].protonvpn_iface'], 'protonvpn');
	eq('v3: a rejected interface name keeps the v6 prohibit',
		s['network.@rule6[1].protonvpn_iface'], 'protonvpn');
	eq('v3: a rejected interface name keeps the IPv4 rule',
		s['network.@rule[0].protonvpn_iface'], 'protonvpn');
}

{
	// The sweep must not run on a guess. If the interpreter is missing, or the
	// module will not load, the answer is not "no instance owns anything" —
	// that reading deletes every stamped rule on the router. The step is
	// skipped and the stamp left alone, so the next boot tries again.
	let saved = readfile(owners_bin);
	writefile(owners_bin, '#!/bin/sh\nexit 1\n');
	chmod(owners_bin, 0o755);
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'pv_gone' }));
	eq('v3: an unanswerable ownership question deletes nothing',
		s['network.@rule6[0].protonvpn_iface'], 'pv_gone');
	ok('v3: and the step is left un-stamped so it runs again',
		s['protonvpn.main.config_version'] != '3');
	writefile(owners_bin, saved);
	chmod(owners_bin, 0o755);
}

// ── v3: the question must reach the backend unflattened ─────────────────
//
// Round 2 stopped the migration from having its own COPY of the ownership
// rule. That is only half the guarantee: a single definition answering a
// question that arrived mangled gives a single wrong answer. The values here
// are ones where `uci get` on the command line and the ucode cursor genuinely
// disagree about what is stored, so any transport that serializes the option
// through the shell re-introduces the round-2 defect from the other end —
// with the same consequence, a live instance's IPv6 prohibit swept as an
// orphan.
//
// The fix is for nothing to be serialized: the helper reads the config
// itself, through the same cursor the runtime uses.
{
	// UCI permits a newline inside a value. The cursor hands the whole string
	// to validate_interface, which refuses it, so the instance owns the
	// default name and its objects are stamped 'protonvpn'. Anything that
	// splits the CLI's output on newlines sees 'pv_home' instead.
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.enabled=1\n' +
		'protonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit', priority: '21000',
			protonvpn_managed: '1', protonvpn_role: 'steer_v6',
			protonvpn_iface: 'protonvpn' }),
		{ main: { interface: 'pv_home\njunk' } });
	eq('v3: a newline inside the interface value does not orphan the live guard',
		s['network.@rule6[0].protonvpn_iface'], 'protonvpn');

	// ...and the name the split would have produced is not an owner either.
	let s2 = migrate(
		'protonvpn.main=instance\nprotonvpn.main.enabled=1\n' +
		'protonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'pv_home' }),
		{ main: { interface: 'pv_home\njunk' } });
	eq('v3: and the first line of that value owns nothing',
		sect(s2, 'rule6', 0), []);
}

{
	// A one-item list. `uci get` prints the bare word; the cursor returns an
	// array, which validate_interface refuses because it is not a string — so
	// again the instance owns the default name.
	let s = migrate(
		'protonvpn.main=instance\nprotonvpn.main.enabled=1\n' +
		'protonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit', priority: '21000',
			protonvpn_managed: '1', protonvpn_role: 'steer_v6',
			protonvpn_iface: 'protonvpn' }),
		{ main: { interface: [ 'pv_home' ] } });
	eq('v3: a one-item list does not orphan the live guard',
		s['network.@rule6[0].protonvpn_iface'], 'protonvpn');

	let s2 = migrate(
		'protonvpn.main=instance\nprotonvpn.main.enabled=1\n' +
		'protonvpn.main.interface=pv_home\n' +
		rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
			protonvpn_managed: '1', protonvpn_iface: 'pv_home' }),
		{ main: { interface: [ 'pv_home' ] } });
	eq('v3: and the list item owns nothing',
		sect(s2, 'rule6', 0), []);
}

// ── v3: the answer is trusted only when it is clean AND complete ────────
//
// The sweep deletes things, so "I could not find out who owns these" and "no
// one owns these" must never be the same answer. A non-empty reply is not
// enough on its own: a helper can fail after printing, print half its
// instances, or have something else land on its stdout.

// Replace the ownership program on the script's PATH for one run.
function with_owners(body, fn) {
	writefile(owners_bin, body);
	chmod(owners_bin, 0o755);
	let r = fn();
	writefile(owners_bin, owners_real);
	chmod(owners_bin, 0o755);
	return r;
}

// One live instance, one rule belonging to nobody. When the answer is
// trustworthy the rule goes; in every case below it must not.
const SWEEP_CFG = 'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n';
const SWEEP_RULE = { 'in': 'lan', action: 'prohibit',
	protonvpn_managed: '1', protonvpn_iface: 'pv_gone' };

function sweep_run() {
	return migrate(SWEEP_CFG + rule('rule6', 0, SWEEP_RULE));
}

{
	// A helper that fails AFTER printing something plausible. Reading only the
	// text and ignoring the status is how a partial run gets trusted.
	let s = with_owners('#!/bin/sh\necho pv_home\nexit 1\n', sweep_run);
	eq('v3: a helper that prints an answer and then fails is not believed',
		s['network.@rule6[0].protonvpn_iface'], 'pv_gone');
	ok('v3: and the step stays un-stamped after a failed helper',
		s['protonvpn.main.config_version'] != '3');
}

{
	// Fewer answers than instances: the run stopped part way, and the
	// instances it never reached would have their objects swept.
	let s = with_owners('#!/bin/sh\necho pv_home\n',
		function() {
			return migrate(
				'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
				'protonvpn.media=instance\nprotonvpn.media.interface=pv_media\n' +
				rule('rule6', 0, SWEEP_RULE));
		});
	eq('v3: fewer answers than instances is not a complete answer',
		s['network.@rule6[0].protonvpn_iface'], 'pv_gone');
	ok('v3: and that leaves the step un-stamped too',
		s['protonvpn.main.config_version'] != '3');
}

{
	// More lines than instances: something other than the answer reached
	// stdout, so the list cannot be read as the set of owners.
	let s = with_owners('#!/bin/sh\necho pv_home\necho pv_gone\n', sweep_run);
	eq('v3: an extra line on stdout is not a new owner',
		s['network.@rule6[0].protonvpn_iface'], 'pv_gone');
	ok('v3: and the step stays un-stamped',
		s['protonvpn.main.config_version'] != '3');
}

{
	// Output that is not a name at all. A helper that exits 0 having printed a
	// diagnostic — a loader warning, a deprecation notice — has still not told
	// anyone who owns anything. Counting lines rather than NAMES makes that
	// one answer for one instance, and the sweep then runs with a list whose
	// only member is a sentence: every stamped object on the router is an
	// orphan by that list, which is the worst outcome this step can have.
	let s = with_owners('#!/bin/sh\necho "warning: could not open the config"\n',
		sweep_run);
	eq('v3: a diagnostic is not an owner',
		s['network.@rule6[0].protonvpn_iface'], 'pv_gone');
	ok('v3: and a run that produced no name leaves the step un-stamped',
		s['protonvpn.main.config_version'] != '3');

	// A diagnostic ALONGSIDE the real answer is refused too, and that is a
	// deliberate tightening: it used to be filtered out by matching each line
	// against the name rule, which meant this script held a second copy of
	// that rule, agreeing with validate_interface today and drifting silently
	// the day the validator widened. The frame replaces it. Nothing but the
	// helper writes to this stdout — its warnings go to stderr, which the
	// caller discards — so an extra line means something is wrong with the
	// run, and skipping is the answer that deletes nothing.
	let s2 = with_owners('#!/bin/sh\necho "warning: deprecated"\necho pv_home\n' +
		'echo "# owners 1"\n', sweep_run);
	eq('v3: an extra line breaks the frame even beside a complete answer',
		s2['network.@rule6[0].protonvpn_iface'], 'pv_gone');
	ok('v3: and that leaves the step un-stamped',
		s2['protonvpn.main.config_version'] != '3');

	// A frame that claims more than it delivered: the run stopped after the
	// names it did print, and the ones it never reached would be swept.
	let s3 = with_owners('#!/bin/sh\necho pv_home\necho "# owners 2"\n', sweep_run);
	eq('v3: a frame claiming more names than it delivered is not believed',
		s3['network.@rule6[0].protonvpn_iface'], 'pv_gone');

	// A sentinel that is not last: something was written after the answer.
	let s4 = with_owners('#!/bin/sh\necho pv_home\necho "# owners 1"\necho oops\n',
		sweep_run);
	eq('v3: output after the frame is not believed either',
		s4['network.@rule6[0].protonvpn_iface'], 'pv_gone');

	// The sentinel in the wrong place. Looking for it ANYWHERE rather than
	// requiring it last still lines the counts up here, and `sed '$d'` then
	// strips a NAME instead of the sentinel: the list would carry the
	// sentinel text as if it were an owner, and the instance whose name was
	// stripped would have its objects swept.
	let s6 = with_owners('#!/bin/sh\necho "# owners 2"\necho pv_home\necho pv_media\n',
		function() {
			return migrate(
				'protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
				'protonvpn.media=instance\nprotonvpn.media.interface=pv_media\n' +
				rule('rule6', 0, { 'in': 'lan', action: 'prohibit',
					protonvpn_managed: '1', protonvpn_iface: 'pv_media' }));
		});
	eq('v3: a frame that is not last does not sweep pv_media as an orphan',
		s6['network.@rule6[0].protonvpn_iface'], 'pv_media');
	ok('v3: and leaves the step un-stamped',
		s6['protonvpn.main.config_version'] != '3');

	// And a frame with no sentinel at all — the shape every pre-frame helper
	// would have produced.
	let s5 = with_owners('#!/bin/sh\necho pv_home\n', sweep_run);
	eq('v3: an unframed answer is not believed',
		s5['network.@rule6[0].protonvpn_iface'], 'pv_gone');
}

{
	// The producer's half of the contract. The migration verifies a frame; the
	// helper has to emit one, and nothing else asserts that it does.
	migrate('protonvpn.main=instance\nprotonvpn.main.interface=pv_home\n' +
		'protonvpn.media=instance\nprotonvpn.media.interface=pv_media\n');
	let r = _cmn.run([ 'env', 'PROTONVPN_MOCK_UCI=' + mockdb, owners_bin ]);
	eq('the owners helper succeeds', r.code, 0);
	eq('and frames its answer: the names, then the count',
		r.stdout, 'pv_home\npv_media\n# owners 2\n');
}

{
	// The control: the real helper, one instance, one answer — the sweep runs.
	let s = sweep_run();
	eq('v3: a clean and complete answer does let the sweep run',
		sect(s, 'rule6', 0), []);
	eq('v3: and stamps the step', s['protonvpn.main.config_version'], '3');
}

unlink(db);
unlink(mockdb);
unlink(bindir + '/uci');
unlink(owners_bin);
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL MIGRATION TESTS PASSED');
exit(fails ? 1 : 0);

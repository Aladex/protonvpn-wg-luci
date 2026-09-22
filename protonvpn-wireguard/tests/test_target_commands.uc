#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Every external command this package shells out to, against what the TARGET
// actually has.
//
// Why this file exists: round 3 bounded a ubus probe with `timeout N ubus …`
// and the suite went green, because the development machine has GNU timeout.
// Stock OpenWrt does not — not as a binary, not as a busybox applet, and the
// package declares no coreutils-timeout dependency. So on the router the
// probe failed to start, the readiness wait was skipped, and the ten-minute
// switchover the whole feature exists to remove came straight back, silently.
//
// That is the same shape as the stubbed-away timing test one level up: the
// suite stayed green while the property stopped holding, because the thing
// the test relied on exists here and not there. A stub, or a command, that is
// present on the dev machine and absent on the target is a false pass.
//
// So the target's command set is written down, with the reason each entry is
// expected to be there, and the sources are scanned against it. Adding a
// command means adding a line here and saying why the router has it — which
// is the question nobody asked about `timeout`.
//
// Run: part of tests/run.sh.

'use strict';

import { readfile, lsdir, stat, unlink } from 'fs';

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }

const HERE = getenv('PVT_TESTS') || '.';
const SRC = [
	'/../files/usr/share/ucode/protonvpn/api.uc',
	'/../files/usr/share/ucode/protonvpn/apply.uc',
	'/../files/usr/share/ucode/protonvpn/cache.uc',
	'/../files/usr/share/ucode/protonvpn/common.uc',
	'/../files/usr/share/ucode/protonvpn/rotate.uc',
	'/../files/usr/share/ucode/protonvpn/routing.uc',
	'/../files/usr/share/ucode/protonvpn/select.uc',
	'/../files/usr/share/ucode/protonvpn/service.uc',
	'/../files/usr/share/ucode/protonvpn/status.uc',
	'/../files/usr/share/rpcd/ucode/protonvpn.uc'
];

// ── The target's command set ─────────────────────────────────────────────
//
// Each entry says WHY the command is on a stock OpenWrt image. "declared"
// means the package Makefile lists the package that ships it, which is the
// only kind of guarantee this repository can give by itself.
const ALLOWED = {
	// Core system, present on every OpenWrt: ubusd is part of the base and
	// the CLI ships beside it.
	ubus: { by: 'base', why: 'base system (ubus, pulled in by rpcd)' },
	// netifd's own scripts, /sbin/ifup and /sbin/ifdown, base system.
	ifup: { by: 'base', why: 'base system (netifd)' },
	ifdown: { by: 'base', why: 'base system (netifd)' },
	// busybox provides the shell and these applets on every image.
	sh: { by: 'busybox', why: 'busybox' },
	sleep: { by: 'busybox', why: 'busybox' },
	echo: { by: 'builtin', why: 'shell builtin' },
	// Packages this package must declare, or it can land on a router that
	// cannot run it. `pkg` is checked against the Makefile below — that check
	// is the generalisation of the `timeout` defect, which was precisely a
	// command with no package behind it.
	wg: { by: 'depends', pkg: 'wireguard-tools', why: 'wireguard-tools' },
	curl: { by: 'depends', pkg: 'curl', why: 'curl' },
	// MEASURED on the owner's router, which is why this is no longer marked
	// unverified: /usr/bin/ip is present, and busybox on that build has NO ip
	// applet. OpenWrt disables it by default because netifd uses libnl, so
	// "busybox usually has it" is false and the package has to say it needs
	// one. `ip` is the virtual that ip-tiny and ip-full both provide.
	ip: { by: 'depends', pkg: 'ip', why: 'ip-tiny/ip-full via the `ip` virtual' },
	// Shipped by this package itself.
	'/usr/bin/protonvpn-apply': { by: 'self', why: 'shipped by this package' },
	'/usr/bin/protonvpn-cache-update': { by: 'self', why: 'shipped by this package' },
	// Init scripts of packages on any image that has the feature at all: if
	// odhcpd is absent there are no router advertisements to reload, and if
	// the firewall is absent there are no rules to apply. Both degrade to a
	// failed run() rather than to a wrong result, so neither is a dependency.
	'/etc/init.d/odhcpd': { by: 'optional', why: 'odhcpd; absent means nothing to reload' },
	'/etc/init.d/firewall': { by: 'optional', why: 'firewall; absent means nothing to reload' }
};
// Commands that must NOT appear, with the reason, so a regression names
// itself instead of just failing a set membership.
const FORBIDDEN = {
	timeout: 'not on stock OpenWrt: no binary, no busybox applet, and this ' +
		'package declares no coreutils-timeout. Use `ubus -t <secs>` for a ' +
		'bounded ubus call; it needs nothing installed.'
};

// ── What the sources actually invoke ─────────────────────────────────────
//
// argv[0] of every run([...]), plus every absolute path literal that looks
// like a program, plus the command-shaped words inside `sh -c` payloads
// (start of the string, or after a pipe/&&/;).
//
// The limit, stated rather than hidden: this reads string literals, so a
// command assembled at runtime from a variable is invisible to it. There are
// none today, and the shape of run([ 'name', ... ]) is what the package uses
// everywhere.
function commands_in(src) {
	let found = {};
	for (let m in match(src, /run\(\s*\[\s*'([^']+)'/g))
		found[m[1]] = true;
	// Any absolute path literal; the ones that name a program are picked out
	// afterwards, because ucode's regex dialect does not take a group of
	// alternative directory prefixes here.
	for (let m in match(src, /'(\/[A-Za-z0-9._\/-]+)'/g)) {
		let path = m[1];
		for (let dir in [ '/usr/bin/', '/usr/sbin/', '/sbin/', '/bin/', '/etc/init.d/' ])
			if (index(path, dir) == 0)
				found[path] = true;
	}
	// Inside an `sh -c` payload: the first word, and anything just after a
	// pipe. Only the literal that follows `'sh', '-c',` is read — scanning
	// every string in the file matches the first word of every log message.
	// Payloads are built by concatenation and the leading piece is the one
	// that carries the command, which is the shape this package uses.
	for (let m in match(src, /'sh',\s*'-c',\s*'([^']*)'/g)) {
		let lit = m[1];
		let head = match(lit, /^\s*([a-z][a-z0-9_-]*)\s/);
		if (head)
			found[head[1]] = true;
		for (let c in match(lit, /\|\s*([a-z][a-z0-9_-]*)\s/g))
			found[c[1]] = true;
	}
	return found;
}

let used = {};
for (let rel in SRC) {
	let txt = readfile(HERE + rel);
	if (txt == null)
		continue;
	for (let c in commands_in(txt))
		used[c] = (used[c] || 0) + 1;
}

ok('scan: the sources were readable and do call out to programs',
	length(used) > 0);

// ── The checks ───────────────────────────────────────────────────────────

let unlisted = [];
for (let c in used)
	if (!exists(ALLOWED, c))
		push(unlisted, c);
sort(unlisted);
ok('commands: everything the package runs is on the target\'s list' +
	(length(unlisted) ? ' — unlisted: ' + join(', ', unlisted) : ''),
	length(unlisted) == 0);

for (let c in FORBIDDEN)
	ok('commands: ' + c + ' is not used — ' + FORBIDDEN[c], !exists(used, c));

// A command that comes from a package must have that package declared, or the
// package can be installed on a router that cannot run it. This is the general
// form of the `timeout` defect: not "the dev machine has it" but "nothing says
// the target must".
let mk = readfile(HERE + '/../Makefile') || '';
let at = index(mk, 'DEPENDS:=');
let deps = (at >= 0) ? substr(mk, at) : '';
let undeclared = [];
for (let c in ALLOWED) {
	let e = ALLOWED[c];
	if (e.by != 'depends')
		continue;
	if (index(deps, '+' + e.pkg + ' ') < 0 && index(deps, '+' + e.pkg + '\n') < 0 &&
	    index(deps, '+' + e.pkg + ' \\') < 0)
		push(undeclared, c + ' (needs +' + e.pkg + ')');
}
sort(undeclared);
ok('depends: every command from a package is declared in the Makefile' +
	(length(undeclared) ? ' — undeclared: ' + join(', ', undeclared) : ''),
	length(undeclared) == 0);

// And nothing is left marked as unverified: an entry this repository cannot
// stand behind is a question, not a manifest line.
let unverified = [];
for (let c in ALLOWED)
	if (index(ALLOWED[c].why, 'NOT verified') >= 0)
		push(unverified, c);
ok('commands: no entry is still marked unverified' +
	(length(unverified) ? ' — ' + join(', ', unverified) : ''),
	length(unverified) == 0);

// A stub is the dev machine's version of "this command exists". One for a
// command the target does not have is exactly how the timeout defect would
// have been papered over instead of found.
// A stub for a command reached by absolute path cannot be named after it,
// because PATH does not shadow an absolute path — those are relocated through
// an environment variable instead, and the stub file is named for the thing
// it stands in for.
const STUB_ALIAS = { 'odhcpd-init': '/etc/init.d/odhcpd' };

let stubs = lsdir(HERE + '/stubs') || [];
let stray = [];
for (let s in stubs) {
	let stands_for = exists(STUB_ALIAS, s) ? STUB_ALIAS[s] : s;
	if (!exists(ALLOWED, stands_for))
		push(stray, s);
}
sort(stray);
ok('stubs: every stub stands for a command the target has' +
	(length(stray) ? ' — stray: ' + join(', ', stray) : ''),
	length(stray) == 0);

// The bound on a ubus call has to come from ubus itself, and from EVERY call:
// a wedged ubusd on an unbounded one hangs the apply, the rpcd request behind
// it and the page in front of that, with nothing on the path to stop it.
let unbounded = [];
for (let rel in SRC) {
	let txt = readfile(HERE + rel);
	if (txt == null)
		continue;
	for (let m in match(txt, /run\(\s*\[\s*'ubus',\s*'([^']*)'/g))
		if (m[1] != '-t')
			push(unbounded, rel + ": ubus '" + m[1] + "'");
}
ok('probe: every ubus call bounds itself with -t' +
	(length(unbounded) ? ' — unbounded: ' + join(', ', unbounded) : ''),
	length(unbounded) == 0);

// `ip` is declared (DEPENDS), so on a correctly built image it is there. But a
// package can be force-installed onto an image without it, or `ip` removed
// later, and every call site turned "not installed" into an ordinary negative
// answer: no IPv6 default route, no WAN MTU, no pinned routes to mirror, no
// WAN default to restore. Each of those is a plausible answer, so the failure
// was invisible — the same shape as the `timeout` defect this file was written
// for. Every `ip` call goes through run_ip(), which says so once.
let bare_ip = [];
for (let rel in SRC) {
	let txt = readfile(HERE + rel);
	if (txt == null)
		continue;
	for (let m in match(txt, /run\(\s*\[\s*'ip',\s*'([^']*)'/g))
		push(bare_ip, rel + ": ip '" + m[1] + "'");
}
ok('degrade: no call site runs `ip` through bare run()' +
	(length(bare_ip) ? ' — bare: ' + join(', ', bare_ip) : ''),
	length(bare_ip) == 0);

// And the message that reaches the user has to be actionable and singular.
// Read from the child's real stderr, not from a stubbed logger: what ships is
// what a user reads in the system log.
let uc = getenv('UCODE') || 'ucode';
let libs = getenv('PVT_UCODE_L') || '';
let out = HERE + '/.missing-ip.err';
let cmd = 'PATH=' + HERE + '/stubs ' + uc + ' ' + libs + ' -S ' +
	getenv('PVT_HELPERS') + '/missing-ip.uc >/dev/null 2>' + out;
system([ '/bin/sh', '-c', cmd ]);
let said = [];
for (let l in split(readfile(out) || '', '\n'))
	if (match(l, /`ip`|iproute|ip-tiny|ip-full/))
		push(said, l);
unlink(out);
ok('degrade: a missing `ip` is reported exactly once, not once per call — said ' +
	length(said) + ' time(s)', length(said) == 1);
ok('degrade: the report names what to install' +
	(length(said) ? ': ' + said[0] : ''),
	length(said) == 1 && match(said[0], /ip-tiny|ip-full/));

printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL TARGET COMMAND TESTS PASSED');
exit(fails ? 1 : 0);

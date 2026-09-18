#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Tests for the client-version gate: the stamped x-pm-appversion value, its
// uci override, and the messages for the codes the gate produces — 2028
// ("app no longer supported") and 8002 surfacing during sign-in, before any
// two-factor code was submitted. Run via tests/run.sh.

'use strict';

import { open, unlink } from 'fs';

let ok = true;
function check(label, cond) {
	if (!cond) {
		ok = false;
		printf('FAIL %s\n', label);
	} else {
		printf('ok   %s\n', label);
	}
}

let api = require('protonvpn.api');

// ── PM_APPVERSION: format and pinned value ───────────────────────────────
// The official Linux client stamps 'linux-vpn-<type>@<version>'; the old
// type-less 'linux-vpn@…' is what Proton stopped accepting.
check('PM_APPVERSION uses the linux-vpn-<type>@<version> format',
	match(api.PM_APPVERSION, /^linux-vpn-[a-z0-9-]+@[0-9]+\.[0-9]+\.[0-9]+$/) != null);
// Pinned to the current official Linux client (versions.yml at the root of
// ProtonVPN/proton-vpn-gtk-app). The scheduled CI watch opens an issue when
// upstream moves; bump this together with the constant.
check('PM_APPVERSION is the current official client',
	api.PM_APPVERSION == 'linux-vpn-gtk@4.18.2');

// ── api_error(): the version-gate codes ──────────────────────────────────
function res(http, proton_code, err) {
	let d = {};
	if (proton_code != null)
		d.Code = proton_code;
	if (err != null)
		d.Error = err;
	return { code: http, data: d, raw: '' };
}

let e2028 = api.api_error(res(422, 2028, 'This version of the app is no longer supported'));
check('Code 2028 names the rejected client version',
	index(e2028, '2028') >= 0 && match(e2028, /client version/i) != null);
check('Code 2028 points at the uci override', index(e2028, 'app_version') >= 0);
// Config-file option syntax has no '=': 'option name value', matching the
// watcher issue text.
check('Code 2028 shows valid option syntax',
	index(e2028, "option app_version 'linux-vpn-gtk@") >= 0);

// 8002 is overloaded: after a submitted TOTP it means a wrong code, but the
// version gate also answers 8002 during sign-in, before any code exists.
let e_totp = api.api_error(res(422, 8002), 'totp');
check('8002 after a submitted code is a wrong-code message',
	index(e_totp, 'Wrong or already-used two-factor code') >= 0);
let e_gate = api.api_error(res(422, 8002));
check('8002 before any code is not called a wrong code',
	index(e_gate, 'Wrong or already-used') < 0);
check('8002 before any code points at the client version',
	match(e_gate, /version/i) != null);
check('Code 5003 still means the version gate',
	index(api.api_error(res(422, 5003)), '5003') >= 0);

// ── the uci override ─────────────────────────────────────────────────────
function seed_uci(appver) {
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', '.name': 'main' } } };
	if (appver != null)
		global.MOCK_UCI.protonvpn.main.app_version = appver;
}

if (type(api.app_version) != 'function') {
	ok = false;
	printf('FAIL app_version is exported\n');
} else {
	seed_uci(null);
	check('app_version() defaults to the stamped constant',
		api.app_version() == api.PM_APPVERSION);
	seed_uci('linux-vpn-gtk@9.9.9');
	check('a valid uci override wins', api.app_version() == 'linux-vpn-gtk@9.9.9');
	seed_uci('garbage');
	check('garbage falls back to the constant', api.app_version() == api.PM_APPVERSION);
	seed_uci('linux-vpn@4.9.0');
	check('the old type-less format is rejected', api.app_version() == api.PM_APPVERSION);
	seed_uci('linux-vpn-gtk@4.18');
	check('an incomplete version is rejected', api.app_version() == api.PM_APPVERSION);
	// In ucode ^ and $ match LINE boundaries, so an anchored regex alone
	// accepts a multiline value when any single line has the right shape —
	// and the value is concatenated into the quoted curl config, where extra
	// lines inject curl options. Every one of these must fall back.
	seed_uci('linux-vpn-gtk@9.9.9\n');
	check('a trailing newline is rejected', api.app_version() == api.PM_APPVERSION);
	seed_uci('linux-vpn-gtk@9.9.9\nheader = "Injected: yes"');
	check('curl config injection via a second line is rejected',
		api.app_version() == api.PM_APPVERSION);
	seed_uci('junk\nlinux-vpn-gtk@9.9.9');
	check('a valid line after an invalid one is rejected',
		api.app_version() == api.PM_APPVERSION);
	seed_uci('linux-vpn-gtk@9.9.9\njunk');
	check('a valid line before an invalid one is rejected',
		api.app_version() == api.PM_APPVERSION);
	seed_uci('linux-vpn-gtk@9.9.9\r\n');
	check('a CR/LF line ending is rejected', api.app_version() == api.PM_APPVERSION);
	seed_uci('xxlinux-vpn-gtk@9.9.9');
	check('junk prefixed to a valid string is rejected',
		api.app_version() == api.PM_APPVERSION);
	seed_uci('linux-vpn-gtk@9.9.9-beta');
	check('junk suffixed to a valid string is rejected',
		api.app_version() == api.PM_APPVERSION);
	// The shared options live in the globals section when one exists.
	global.MOCK_UCI.protonvpn.globals =
		{ '.type': 'globals', '.name': 'globals', app_version: 'linux-vpn-gtk@8.8.8' };
	check('the globals section carries the override',
		api.app_version() == 'linux-vpn-gtk@8.8.8');

	// auth_headers() stamps the effective version on every authenticated call.
	api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: time() + 1800, session_expires_at: time() + 86400,
		scope: 'vpn', twofa: false });
	let hdrs = api.auth_headers();
	check('auth_headers sends the overridden version',
		hdrs != null && index(join('|', hdrs), 'x-pm-appversion: linux-vpn-gtk@8.8.8') >= 0);
}

// ── the wiring: which caller has a submitted code ────────────────────────
// api_call() ends in curl; tests/stubs/curl answers from
// $PROTONVPN_RUN_DIR/curl-response (first line the HTTP code, rest the body).
let resp = getenv('PROTONVPN_RUN_DIR') + '/curl-response';
function stub_response(code, obj) {
	let f = open(resp, 'w');
	f.write('' + code + '\n' + sprintf('%J', obj) + '\n');
	f.close();
}

api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
	access_expires_at: time() + 1800, session_expires_at: time() + 86400,
	scope: 'vpn', twofa: true });

stub_response(422, { Code: 8002, Error: 'Invalid or already used two factor code' });
let t = api.totp_submit('123456');
check('totp_submit reports 8002 as a wrong code',
	index(t.error || '', 'Wrong or already-used two-factor code') >= 0);

stub_response(422, { Code: 8002, Error: 'Invalid or already used two factor code' });
let af = api.auth_finish({ username: 'u', srp_session: 's',
	client_ephemeral: 'e', client_proof: 'p' });
check('auth_finish does not blame 2FA before a code was submitted',
	index(af.error || '', 'Wrong or already-used') < 0);
check('auth_finish points at the client version on 8002',
	match(af.error || '', /version/i) != null);

stub_response(422, { Code: 2028, Error: 'This version of the app is no longer supported' });
let ai = api.auth_info('user@example.com');
check('auth_info explains Code 2028 and the override',
	index(ai.error || '', '2028') >= 0 && index(ai.error || '', 'app_version') >= 0);

unlink(resp);
api.session_store(null);

exit(ok ? 0 : 1);

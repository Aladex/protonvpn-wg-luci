#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Tests for the client-version gate (the stamped x-pm-appversion value and
// its uci override), for what a failed API call tells the user, and for what
// it leaves in syslog. Run via tests/run.sh.

'use strict';

import { open, unlink, readfile } from 'fs';

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

// ── api_error(): Proton's own message, verbatim ──────────────────────────
// Every error response from Proton carries a ready, human-readable `Error`
// string. Replacing it with a guess cost a forum user three days of changing
// client versions while Proton was telling them their account had been
// temporarily locked. So: show the `Error` as Proton wrote it, with the code
// and the HTTP status, and append our own wording only where it is certainly
// correct — never instead of Proton's.
function res(http, proton_code, err) {
	let d = {};
	if (proton_code != null)
		d.Code = proton_code;
	if (err != null)
		d.Error = err;
	return { code: http, data: d, raw: '' };
}

// The texts below are what the live API answered when the codes were
// measured; they are fixtures, not assertions about Proton's wording.
const LOCKOUT = 'Our systems detected unusual activity targeting your ' +
	'account. To protect you from potential compromise, we have temporarily ' +
	'limited access to it.';
const BADCREDS = 'Incorrect login credentials. Please try again.';
const NOSUCHUSER = 'This username does not exist. Please try again.';
const OLDAPP = 'This version of the app is no longer supported.';
const CAPTCHA = 'Human verification required.';

let e2028 = api.api_error(res(422, 2028, LOCKOUT));
check('Code 2028 shows the lockout text Proton sent, verbatim',
	index(e2028, LOCKOUT) >= 0);
check('Code 2028 carries the code and the HTTP status',
	index(e2028, '2028') >= 0 && index(e2028, '422') >= 0);
// The old message told a locked-out user to update the package. It was wrong
// and it is what sent them version-hunting for three days.
check('Code 2028 invents no client-version problem',
	match(e2028, /version/i) == null && index(e2028, 'app_version') < 0);

let e8002 = api.api_error(res(422, 8002, BADCREDS));
check('Code 8002 shows the credentials text Proton sent, verbatim',
	index(e8002, BADCREDS) >= 0);
check('Code 8002 carries the code and the HTTP status',
	index(e8002, '8002') >= 0 && index(e8002, '422') >= 0);
check('Code 8002 invents no client-version problem',
	match(e8002, /version/i) == null);
check('Code 8002 invents no two-factor problem',
	match(e8002, /two-factor|2fa/i) == null);

// 8002 is also what an unknown username gets. Proton distinguishes the two in
// the text, so the text has to survive to the user.
let e8002u = api.api_error(res(422, 8002, NOSUCHUSER));
check('the same code with another Error says what Proton actually said',
	index(e8002u, NOSUCHUSER) >= 0 && index(e8002u, BADCREDS) < 0);

// 5003 is the real version gate, so here the hint is certainly correct — but
// it is appended, not substituted.
let e5003 = api.api_error(res(422, 5003, OLDAPP));
check('Code 5003 shows Proton\'s text verbatim', index(e5003, OLDAPP) >= 0);
check('Code 5003 carries the code and the HTTP status',
	index(e5003, '5003') >= 0 && index(e5003, '422') >= 0);
// Config-file option syntax has no '=': 'option name value'.
check('Code 5003 appends the uci override hint',
	index(e5003, "option app_version 'linux-vpn-gtk@") >= 0);

let e9001 = api.api_error(res(422, 9001, CAPTCHA));
check('Code 9001 shows Proton\'s text verbatim', index(e9001, CAPTCHA) >= 0);
check('Code 9001 appends the wait-rather-than-retry hint',
	match(e9001, /wait/i) != null);

let eunknown = api.api_error(res(429, 2001, 'Too many recent requests.'));
check('an unrecognised code is shown exactly as Proton wrote it',
	index(eunknown, 'Too many recent requests.') >= 0 &&
	index(eunknown, '2001') >= 0 && index(eunknown, '429') >= 0);

let ebare = api.api_error({ code: 503, data: { Code: 2000 }, raw: '' });
check('a response with no Error text still carries the code and the status',
	index(ebare, '2000') >= 0 && index(ebare, '503') >= 0);
check('a response with no body at all still carries the status',
	index(api.api_error({ code: 502, data: null, raw: '' }), '502') >= 0);
check('a transport failure is passed through unchanged',
	api.api_error({ code: 0, data: null, raw: '', error: 'failed to start curl' }) ==
		'failed to start curl');

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

// ── the wiring: the callers relay Proton, they do not rewrite it ─────────
// api_call() ends in curl; tests/stubs/curl answers from
// $PROTONVPN_RUN_DIR/curl-response (first line the HTTP code, rest the body).
let resp = getenv('PROTONVPN_RUN_DIR') + '/curl-response';
function stub_response(code, obj) {
	let f = open(resp, 'w');
	f.write('' + code + '\n' + sprintf('%J', obj) + '\n');
	f.close();
}

const ACCESS = 'ACCESS-TOKEN-SECRET';
const REFRESH = 'REFRESH-TOKEN-SECRET';
function seed_session() {
	api.session_store({ uid: 'UID-SECRET', access_token: ACCESS,
		refresh_token: REFRESH, access_expires_at: time() + 1800,
		session_expires_at: time() + 86400, scope: 'vpn', twofa: true });
}
seed_session();

const WRONGCODE = 'Invalid or already used two factor code';
stub_response(422, { Code: 8002, Error: WRONGCODE });
let t = api.totp_submit('123456');
check('totp_submit relays the two-factor message Proton sent',
	index(t.error || '', WRONGCODE) >= 0);
check('totp_submit substitutes no wording of its own',
	index(t.error || '', 'Wrong or already-used') < 0);

stub_response(422, { Code: 8002, Error: BADCREDS });
let af = api.auth_finish({ username: 'u', srp_session: 's',
	client_ephemeral: 'e', client_proof: 'p' });
check('auth_finish relays the credentials message Proton sent',
	index(af.error || '', BADCREDS) >= 0);
check('auth_finish no longer blames the client version on 8002',
	match(af.error || '', /version/i) == null);

stub_response(422, { Code: 2028, Error: LOCKOUT });
let ai = api.auth_info('user@example.com');
check('auth_info relays the lockout instead of a version guess',
	index(ai.error || '', LOCKOUT) >= 0 && index(ai.error || '', 'app_version') < 0);

// ── failed sign-ins reach syslog ─────────────────────────────────────────
// The user who reported this had an empty `logread -e protonvpn` after
// repeated failed sign-ins, so the only evidence was a photograph of a red
// line in a browser. Each failed sign-in call now leaves one line — endpoint,
// HTTP status, Proton's code, Proton's message — and nothing else: no
// username, no password proof, no SRP material, no tokens.
let logged = [];
let real_warn = warn;
global.warn = function (m) { push(logged, '' + m); };

stub_response(422, { Code: 8002, Error: BADCREDS });
logged = [];
api.auth_info('user@example.com');
let line = join('\n', logged);
check('a failed /auth/info leaves a line in the log', length(logged) > 0);
check('the /auth/info log line names the endpoint', index(line, '/auth/info') >= 0);
check('the /auth/info log line carries the HTTP status', index(line, '422') >= 0);
check('the /auth/info log line carries Proton\'s code', index(line, '8002') >= 0);
check('the /auth/info log line carries Proton\'s message', index(line, BADCREDS) >= 0);
check('the /auth/info log line never carries the username',
	index(line, 'user@example.com') < 0);

stub_response(422, { Code: 2028, Error: LOCKOUT });
logged = [];
api.auth_finish({ username: 'user@example.com', srp_session: 'SRP-SESSION-SECRET',
	client_ephemeral: 'EPHEMERAL-SECRET', client_proof: 'PROOF-SECRET' });
line = join('\n', logged);
check('a failed /auth leaves a line in the log', length(logged) > 0);
check('the /auth log line names the endpoint and the code',
	index(line, '/auth') >= 0 && index(line, '2028') >= 0);
check('the /auth log line carries Proton\'s message', index(line, LOCKOUT) >= 0);
check('the /auth log line never carries the username or the SRP material',
	index(line, 'user@example.com') < 0 && index(line, 'SRP-SESSION-SECRET') < 0 &&
	index(line, 'EPHEMERAL-SECRET') < 0 && index(line, 'PROOF-SECRET') < 0);

seed_session();
stub_response(422, { Code: 8002, Error: WRONGCODE });
logged = [];
api.totp_submit('123456');
line = join('\n', logged);
check('a failed two-factor step leaves a line in the log', length(logged) > 0);
check('the two-factor log line names the endpoint and the code',
	index(line, '/auth/2fa') >= 0 && index(line, '8002') >= 0);
check('the two-factor log line carries Proton\'s message',
	index(line, WRONGCODE) >= 0);
check('the two-factor log line never carries the code the user typed',
	index(line, '123456') < 0);
check('the two-factor log line never carries the session tokens',
	index(line, ACCESS) < 0 && index(line, REFRESH) < 0);

function long_tail() {
	let s = '';
	for (let i = 0; i < 400; i++)
		s += 'x';
	return s;
}

// Proton's Error is remote text on its way into syslog. A newline in it would
// forge a second 'protonvpn:' line that a reader — or a log parser — would
// take for ours, and an unbounded one would push everything else out of a
// logread window. Neither goes through.
seed_session();
stub_response(422, { Code: 8002,
	Error: 'bad\nprotonvpn: rotated main to XX#1\nand ' + long_tail() });
logged = [];
api.auth_info('user@example.com');
line = join('\n', logged);
check('a failure leaves exactly one log line', length(logged) == 1);
check('a newline in Proton\'s message cannot forge a second line',
	index(line, '\nprotonvpn: rotated') < 0);
check('an overlong message is cut rather than flooding the log',
	length(line) < 400);
check('the beginning of the message still survives the cut',
	index(line, 'bad') >= 0 && index(line, '8002') >= 0);

// A successful call must stay quiet: a log line per API call would bury the
// failures this section exists to surface.
seed_session();
stub_response(200, { Code: 1000, Scope: 'full' });
logged = [];
api.totp_submit('123456');
check('a successful call logs no failure',
	match(join('\n', logged), /failed/i) == null);

global.warn = real_warn;
unlink(resp);
// ── the curl config is line-oriented, so what goes into it must be one line ──
//
// api_call() builds curl's --config by string concatenation:
//     header = "x-pm-uid: <uid>"
//     header = "Authorization: Bearer <token>"
// curl reads that file one OPTION PER LINE and the value is a quoted field.
// The uid and the access token are opaque strings taken verbatim out of
// Proton's JSON and stored, so nothing about them is this package's to
// invent — but a newline in one is a second curl option, and a double quote
// closes the field and lets the rest of the value be read as options. Either
// turns a credential into control of the request, so both are refused before
// the request is built rather than trusted because of where they came from.
//
// This is the same defect as the two blockers of this round: the guard has to
// be on the PATH the value travels, not merely somewhere in the file.
{
	const cfgfile = getenv('PROTONVPN_RUN_DIR') + '/curl-config';
	const poison = [
		{ what: 'a newline in the uid',
		  sess: { uid: 'u\noutput = /tmp/pv-pwned', access_token: 'a' } },
		{ what: 'a newline in the access token',
		  sess: { uid: 'u', access_token: 'a\noutput = /tmp/pv-pwned' } },
		{ what: 'a quote in the uid',
		  sess: { uid: 'u"\noutput = /tmp/pv-pwned', access_token: 'a' } },
		{ what: 'a quote in the access token',
		  sess: { uid: 'u', access_token: 'a"\noutput = /tmp/pv-pwned' } },
		// Not a literal newline: the two characters backslash and n, which
		// curl's config parser unescapes INTO one. See test_curlconfig.uc,
		// where real curl is asked what it does with these.
		{ what: 'an escaped newline in the uid',
		  sess: { uid: 'u\\noutput = /tmp/pv-pwned', access_token: 'a' } },
		{ what: 'an escaped newline in the access token',
		  sess: { uid: 'u', access_token: 'a\\noutput = /tmp/pv-pwned' } },
		{ what: 'a trailing backslash in the uid',
		  sess: { uid: 'u\\', access_token: 'a' } },
		{ what: 'a NUL in the access token',
		  sess: { uid: 'u', access_token: 'a' + chr(0) + 'output = /tmp/pv-pwned' } }
	];
	for (let p in poison) {
		unlink(cfgfile);
		api.session_store({ uid: p.sess.uid, access_token: p.sess.access_token,
			refresh_token: 'r', access_expires_at: time() + 1800,
			session_expires_at: time() + 86400, scope: 'vpn', twofa: false });
		// A session whose credentials cannot travel safely is not a usable
		// session: the user is asked to sign in again, which is recoverable.
		check(p.what + ' makes the session unusable', api.session_load() == null);
		check(p.what + ' produces no auth headers', api.auth_headers() == null);

		// ...and the sink refuses independently, so a future caller that
		// builds a request some other way cannot reintroduce it.
		stub_response(200, { Code: 1000 });
		api.api_call({ url: 'https://api.protonvpn.ch/tests',
			uid: p.sess.uid, token: p.sess.access_token });
		let cfg = readfile(cfgfile) || '';
		check(p.what + ' never reaches the curl config',
			index(cfg, 'output = /tmp/pv-pwned') < 0);
	}
	unlink(cfgfile);
	unlink(resp);

	// The ordinary case still works: a clean session is sent, and the headers
	// really are in that config — otherwise the checks above would pass by
	// the config being empty.
	seed_session();
	stub_response(200, { Code: 1000 });
	api.api_call({ url: 'https://api.protonvpn.ch/tests',
		uid: 'UID-SECRET', token: ACCESS });
	let good = readfile(cfgfile) || '';
	check('a clean uid is sent', index(good, 'x-pm-uid: UID-SECRET') >= 0);
	check('and so is a clean token', index(good, 'Bearer ' + ACCESS) >= 0);
	unlink(cfgfile);
	unlink(resp);
}

api.session_store(null);

exit(ok ? 0 : 1);

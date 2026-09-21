#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// safe_header_value() against the parser it exists to protect — REAL curl,
// not our idea of curl.
//
// api_call() builds curl's --config by concatenation:
//     header = "x-pm-uid: <uid>"
//     header = "Authorization: Bearer <token>"
// and the uid and access token are opaque strings taken verbatim out of
// Proton's JSON. safe_header_value() decides what may be interpolated there.
//
// It used to reject literal CR, LF and double quote and accept BACKSLASH,
// which is a hole, because curl UNESCAPES inside a quoted value. A token
// holding the two characters backslash and n satisfied every part of that
// predicate and left curl as a real line feed, ending the header and starting
// whatever came next as another one. That is a header the caller never asked
// to send, on an authenticated request, and curl reports success.
//
// The lesson of how it survived a review and a mutation run is in how these
// tests are written: a test that restates the predicate ("we reject a quote,
// so a quote is rejected") cannot find a character we never thought of. So
// every case below ASKS CURL what it does with the value and requires
// safe_header_value() to agree — the predicate is checked against the parser,
// which is the only thing that can tell us we guessed the alphabet wrong.
//
// Run: part of tests/run.sh. Skips, loudly, where a real curl is not
// available — the suite otherwise shadows curl with tests/stubs/curl, and a
// silent pass here would mean "the parser was never consulted".

'use strict';

import { readfile, writefile, unlink, mkdir, rmdir, lsdir, stat } from 'fs';
const _cmn = require('protonvpn.common');

const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }
function skip(l) { printf('skip %s\n', l); }

// The REAL curl, not tests/stubs/curl. run.sh puts the stubs first on PATH so
// that nothing in this suite can reach the network; this one probe needs the
// actual binary, so it is found by walking PATH and skipping the stub.
function real_curl() {
	let stubs = null;
	for (let d in split(getenv('PATH') || '', ':'))
		if (match(d, /tests\/stubs$/))
			stubs = d;
	for (let d in split(getenv('PATH') || '', ':')) {
		if (d == '' || d == stubs)
			continue;
		let p = d + '/curl';
		let st = stat(p);
		if (st && st.type == 'file')
			return p;
	}
	return null;
}

const CURL = real_curl();

// Remove a directory and whatever is in it. The probe deliberately produces
// files with line feeds and tabs in their names, so this cannot be a glob.
function wipe(dir) {
	for (let e in (lsdir(dir) || []))
		unlink(dir + '/' + e);
	rmdir(dir);
}

// What curl's --config parser makes of `v` when it appears inside a quoted
// value.
//
// The parsed value is handed to curl as an OUTPUT FILENAME, so whatever bytes
// the parser produced are readable straight off the directory entry — no
// server, no guessing, curl's own parser doing the work. Returns the string
// curl produced, or null when the config did not parse into a usable request
// at all (which is itself a way of not being left alone).
function parsed_by_curl(v) {
	let dir = RUN + '/curlcfg';
	wipe(dir);
	mkdir(dir);
	writefile(dir + '/cfg',
		'output = "' + dir + '/' + v + '"\nurl = "file:///dev/null"\n');
	_cmn.run([ CURL, '-s', '--config', dir + '/cfg' ]);
	let got = lsdir(dir) || [];
	let out = null;
	for (let e in got)
		if (e != 'cfg')
			out = e;
	wipe(dir);
	return out;
}

// The candidates. Each is a value someone could find in a session file — by a
// hand edit, or because the API returned it — paired with nothing but itself:
// what it MEANS is curl's to say, and the loop below asks.
//
// Deliberately not a list of "things we reject". It is a list of things worth
// asking about, and the assertion is agreement, so a character whose handling
// we guessed wrong shows up as a disagreement rather than as a passing test.
const CANDIDATES = [
	'AAA',                  // an ordinary credential
	'A-b_9=',               // the punctuation Proton's tokens really use
	'A\\nB',                // backslash + n: the hole this round closes
	'A\\rB',                // backslash + r
	'A\\tB',                // backslash + t
	'A\\\\B',               // an escaped backslash
	'A\\qB',                // an UNKNOWN escape: curl swallows the backslash
	'AB\\',                 // a trailing backslash, against the closing quote
	'A\\"B'                 // an escaped quote
];

if (!CURL) {
	skip('no real curl on PATH; the parser was not consulted');
} else {
	for (let v in CANDIDATES) {
		let got = parsed_by_curl(v);
		// "Safe" is not a property of the character, it is a property of the
		// round trip: curl handed on exactly what it was given.
		let intact = (got == v);
		let shown = sprintf('%J', v);
		eq('curl agrees with safe_header_value about ' + shown,
			_cmn.safe_header_value(v), intact);
		// ...and say what curl actually did, so a failure reads as a fact
		// about the parser rather than as a bare mismatch.
		if (!intact)
			printf('     (curl turned %J into %J)\n', v, got);
	}

	// NUL is its own case: it cannot appear in a filename, and curl does not
	// mangle the value so much as stop reading. The rest of the config —
	// including, in api_call, the Authorization header and the request body —
	// is silently dropped.
	{
		let dir = RUN + '/curlcfg';
		wipe(dir);
		mkdir(dir);
		writefile(dir + '/cfg',
			'output = "' + dir + '/nul' + chr(0) + 'probe"\n' +
			'url = "file:///dev/null"\n');
		let r = _cmn.run([ CURL, '-s', '--config', dir + '/cfg' ]);
		// curl stops reading at the NUL, so the `url` line below it is never
		// seen and the request has no URL at all. In api_call that same cut
		// would drop the Authorization header, or the body, without a word.
		ok('a NUL makes curl abandon the rest of the config', r.code != 0);
		ok('and nothing is written', length(lsdir(dir) || []) == 1);
		wipe(dir);
	}
	ok('safe_header_value refuses NUL', _cmn.safe_header_value('A' + chr(0) + 'B') == false);
}

// ── the same thing, on the wire ──────────────────────────────────────────
//
// The parser probe above is the mechanism; this is the consequence, observed
// end to end: real curl, a real socket, and the bytes that actually leave.
// Needs ucode's socket module, which the offline build may not carry — the
// package does not depend on it, so this skips rather than fails.
{
	let sock = null;
	try {
		sock = require('socket');
	} catch (e) {
		sock = null;
	}
	if (!CURL || !sock || type(sock.listen) != 'function') {
		skip('no socket module or no real curl; the wire was not observed');
	} else {
		// A fixed high port, retried a little: the suite runs one file at a
		// time, so nothing here races itself.
		let srv = null, port = 0;
		for (let p = 18973; p < 18993 && !srv; p++) {
			srv = sock.listen('127.0.0.1', p, { socktype: 'stream', reuseaddr: true });
			if (srv)
				port = p;
		}
		if (!srv) {
			skip('could not bind a loopback port; the wire was not observed');
		} else {
			let dir = RUN + '/curlwire';
			wipe(dir);
			mkdir(dir);
			// Exactly the line api_call() builds, with the value a predicate
			// that allows backslash would have let through.
			const POISON = 'AAA\\nX-Injected: yes';
			writefile(dir + '/cfg',
				'header = "x-pm-uid: ' + POISON + '"\n' +
				'url = "http://127.0.0.1:' + port + '/probe"\n');
			// curl has to run while this process waits for the connection, so
			// it is started detached and its output discarded.
			_cmn.run([ 'sh', '-c', CURL + ' -s --config ' + dir + '/cfg' +
				' -o /dev/null >/dev/null 2>&1 &' ]);
			// poll() BEFORE accept(), and the reason is not tidiness: accept()
			// blocks for ever and does not honour a receive timeout (measured),
			// so a curl that fails to start would hang the whole suite rather
			// than fail it. Ten seconds is far beyond a loopback connect.
			let ready = sock.poll(10000, srv);
			let c = (ready && length(ready)) ? srv.accept() : null;
			let raw = c ? (c.recv(8192) || '') : '';
			if (c) {
				c.send("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
				c.close();
			}
			srv.close();
			wipe(dir);

			ok('curl connected at all', c != null);
			ok('the request really carried the uid header',
				index(raw, 'x-pm-uid: AAA') >= 0);
			// The point of the whole round: two ordinary characters in a
			// stored credential become a header nobody asked to send.
			ok('and backslash-n in the value became a header of its own',
				index(raw, 'X-Injected: yes') >= 0);
			// ...which is precisely why the predicate has to refuse it.
			ok('so safe_header_value refuses that value',
				_cmn.safe_header_value(POISON) == false);
		}
	}
}

// ── the cases the predicate already handled stay closed ──────────────────
//
// Kept because widening the guard for backslash must not narrow it elsewhere.
ok('a literal line feed is still refused', _cmn.safe_header_value('A\nB') == false);
ok('a literal carriage return is still refused', _cmn.safe_header_value('A\rB') == false);
ok('a literal double quote is still refused', _cmn.safe_header_value('A"B') == false);
ok('an ordinary credential is still allowed', _cmn.safe_header_value('AbC123-_=') == true);
ok('a non-string is not a credential', _cmn.safe_header_value([ 'AbC' ]) == false);

printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL CURL CONFIG TESTS PASSED');
exit(fails ? 1 : 0);

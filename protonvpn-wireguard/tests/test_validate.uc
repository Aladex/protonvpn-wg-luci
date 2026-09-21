#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// The anchored validators in protonvpn.common against multiline input.
//
// Why this suite exists: ucode compiles regexes with REG_NEWLINE, so `^` and
// `$` match LINE boundaries, not string boundaries. Every validator in
// common.uc is written as an anchored shape test, and an anchored test alone
// says "SOME line of this value has the right shape" — so a value with a
// newline in it is accepted whole, and what comes back is the whole value,
// not the line that matched.
//
// api.uc's app_version() has guarded against exactly this on its own since a
// multiline override could inject options into the curl config it is
// concatenated into. The same trap is in the validators the rest of the
// backend is built on, and two of them end up somewhere just as unforgiving:
//
//   * validate_interface names the interface every stamped routing and
//     firewall object is tagged with. A name that is two lines is two
//     different answers to "who owns this" depending on who is asking, which
//     is how a live instance's IPv6 prohibit gets swept as an orphan.
//   * validate_routing_table names the table written into /etc/iproute2/
//     rt_tables, a line-oriented file, where a second line is a second table.
//
// Run: part of tests/run.sh.

'use strict';

const _cmn = require('protonvpn.common');

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

// Every anchored validator, with a value whose FIRST line is well-formed and
// whose second line is not. Each must refuse the value outright rather than
// hand back a string that is still two lines.
//
// The list is the validators themselves, so adding one anchored validator
// without the single-line guard shows up here as a missing entry rather than
// as nothing at all.
const ANCHORED = [
	{ name: 'validate_interface',     fn: _cmn.validate_interface,     good: 'pv_home' },
	{ name: 'validate_instance',      fn: _cmn.validate_instance,      good: 'media' },
	{ name: 'validate_routing_table', fn: _cmn.validate_routing_table, good: 'pvtable' },
	{ name: 'validate_hostname',      fn: _cmn.validate_hostname,      good: 'api.protonvpn.ch' },
	{ name: 'validate_location_code', fn: _cmn.validate_location_code, good: 'DE-BER' },
	{ name: 'validate_country_code',  fn: _cmn.validate_country_code,  good: 'DE' },
	{ name: 'validate_time',          fn: _cmn.validate_time,          good: '03:30' }
];

for (let v in ANCHORED) {
	// The good value on its own still passes: the guard must not cost the
	// validator its job.
	ok(v.name + ' still accepts a well-formed value', v.fn(v.good) != null);

	// A well-formed first line followed by anything at all.
	eq(v.name + ' refuses a value with a newline after it',
		v.fn(v.good + '\njunk'), null);
	// ...and a trailing newline, which is what a value read from a
	// line-oriented source arrives with.
	eq(v.name + ' refuses a trailing newline', v.fn(v.good + '\n'), null);
	// ...and a well-formed line that is not the first.
	eq(v.name + ' refuses a value with a newline before it',
		v.fn('junk\n' + v.good), null);
	// CR is refused too. Characterization rather than a new guarantee: no
	// character class here admits CR, so the shape test already rejects it
	// and one_line()'s CR clause changes nothing for these validators. Worth
	// pinning because a widened character class would silently make it reachable.
	eq(v.name + ' refuses a carriage return', v.fn(v.good + '\rjunk'), null);
}

// ── what that means for the one the migration turns on ───────────────────
//
// instance_interface() is the single definition of the name an instance owns.
// A multiline option is not a name, so the instance owns the default — the
// same answer it gives for every other value validate_interface refuses. The
// alternative is an interface name with a newline in it being stamped onto
// objects and handed to ifup.
eq('a multiline interface option owns the default name',
	_cmn.instance_interface('pv_home\njunk'), 'protonvpn');
eq('so does one with a trailing newline',
	_cmn.instance_interface('pv_home\n'), 'protonvpn');
eq('and a well-formed one still owns itself',
	_cmn.instance_interface('pv_home'), 'pv_home');

// A non-string is not a name either. uci hands back an ARRAY for a list
// option, and `list interface 'pv_home'` is a perfectly ordinary thing to
// find in a config someone edited by hand.
eq('a list-valued interface option owns the default name',
	_cmn.instance_interface([ 'pv_home' ]), 'protonvpn');
eq('and an empty list does too', _cmn.instance_interface([]), 'protonvpn');

// ── the guard has to be on the PATH, not merely in the file ─────────────
//
// Three rounds have now gone to the same shape of defect: a validator exists,
// is correct, and is not called by the code the value actually travels
// through. A definition nothing invokes protects nothing, so these check the
// values at the point the rest of the backend reads them — load_settings()
// and the feature-bit tests — rather than the validators in isolation.

import { cursor } from 'uci';

function settings(opts) {
	let sec = { '.type': 'instance', '.name': 'main' };
	for (let k in opts)
		sec[k] = opts[k];
	global.MOCK_UCI = { protonvpn: { main: sec } };
	return _cmn.load_settings(cursor(), 'main');
}

// routing_table names the table written into /etc/iproute2/rt_tables, one
// line per table. Read raw, a multiline value is a second table entry there.
eq('a multiline routing_table does not survive load_settings',
	settings({ routing_table: 'pv_a\n200\tevil' }).routing_table, '');
eq('nor does a numeric-looking one with a second line',
	settings({ routing_table: '101\n200\tevil' }).routing_table, '');
eq('nor one that is merely the wrong shape',
	settings({ routing_table: 'has space' }).routing_table, '');
eq('a well-formed table name is kept',
	settings({ routing_table: 'pv_home' }).routing_table, 'pv_home');
eq('and an absent one stays empty',
	settings({}).routing_table, '');

// The feature stamp decides whether IPv6 is routed into a gateway at all.
// Both readers document themselves as failing closed — "a missing or
// unparsable stamp deliberately reads as no IPv6", because the alternative is
// a v6 default route into a gateway that drops it. Under REG_NEWLINE the
// anchored `^[0-9]+$` matches a LINE, so a stamp whose FIRST line happens to
// carry the bit passed, and the black hole those comments exist to prevent
// was reachable through a malformed stamp.
function capable(stamp) {
	global.MOCK_UCI = { network: { pv_media: { '.type': 'interface',
		proto: 'wireguard', protonvpn_features: stamp } } };
	return _cmn.iface_ipv6_capable(cursor(), 'pv_media');
}
// 28 = IPv6|Streaming|P2P, the usual combination on a v6-capable gateway.
ok('a plain stamp with the bit still reads as capable', capable('28') == true);
ok('a plain stamp without it still reads as not capable', capable('12') == false);
ok('a stamp with the bit on its first line is not trusted',
	capable('28\njunk') == false);
ok('nor one with the bit on a later line', capable('junk\n28') == false);
ok('nor one with a trailing newline', capable('28\n') == false);

ok('a relay whose features carry the bit on one line is not trusted',
	_cmn.relay_ipv6_capable({ features: '28\njunk' }) == false);
ok('a relay with a plain string of digits still is',
	_cmn.relay_ipv6_capable({ features: '28' }) == true);
ok('and an integer one still is', _cmn.relay_ipv6_capable({ features: 28 }) == true);

// The external-IP probe reads an HTTP response from a third party, so its
// shape test is the only thing standing between that response and the page.
// Anchored, it accepted anything after a newline as long as the first line
// looked like an address. Nothing line-oriented is downstream — the value
// travels as JSON and the page renders it as text — so this was never an
// injection; it was a validator that did not do what it says, on the one
// input in this package an outsider controls.
ok('a plain address is still an address', _cmn.one_line('1.2.3.4') == true);
ok('an address with something after it is not',
	_cmn.one_line('1.2.3.4\n<script>alert(1)</script>') == false);

// ── the curl config is line-oriented; what goes in it must be one line ──
//
// safe_header_value is the sink's rule, not the value's: uid and access token
// are opaque strings from Proton and this package has no business deciding
// what they look like, only what they must not contain to travel safely
// through a file read one option per line with values in quoted fields.
ok('an ordinary credential is safe to send',
	_cmn.safe_header_value('AbC123-_=') == true);
ok('one carrying a newline is not',
	_cmn.safe_header_value('AbC123\noutput = /tmp/pwned') == false);
ok('one carrying a double quote is not either',
	_cmn.safe_header_value('AbC123"') == false);
ok('nor a carriage return', _cmn.safe_header_value('AbC123\rx') == false);
ok('and a non-string is not a credential at all',
	_cmn.safe_header_value([ 'AbC123' ]) == false);

// A backslash is refused because curl UNESCAPES inside the quoted field: the
// two characters backslash and n leave curl as a real line feed, ending the
// header and starting whatever followed as another one. A NUL is refused
// because curl stops reading the config there and silently drops the rest.
//
// These are a BACKSTOP, and knowingly a restatement of the predicate — which
// is the kind of test that let this hole through a whole round of review. The
// real check is in test_curlconfig.uc, where the same values are put to real
// curl and the predicate is required to agree with what the parser does. This
// copy exists only so an environment with no curl binary is not left with the
// predicate unasserted altogether.
ok('a backslash is refused', _cmn.safe_header_value('AbC\\nx') == false);
ok('and a lone one too', _cmn.safe_header_value('AbC\\') == false);
ok('and a NUL', _cmn.safe_header_value('AbC' + chr(0) + 'x') == false);

printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL VALIDATOR TESTS PASSED');
exit(fails ? 1 : 0);

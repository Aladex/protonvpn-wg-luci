#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// The mocks stand in for libuci and ubusd, so anywhere they are more
// permissive than the real thing they do not simplify the system under test,
// they diverge from it — and the suite then proves things about a router that
// does not exist. One such divergence (`set` creating a section libuci refuses
// to create) cost a full round on a defect that cannot occur on hardware.
//
// Every expectation below was measured on the device (ImmortalWrt 24.10.3,
// ucode's own uci module against a scratch config dir), and is written here so
// the next person to find the mock inconvenient has to argue with a failing
// test rather than with a comment. Where the mock deliberately does NOT model
// libuci, that is asserted too, so the exception stays visible and bounded.

'use strict';

import { cursor } from 'uci';
import { connect } from 'ubus';

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

function seed() {
	global.MOCK_UCI = { demo: {
		alpha: { '.type': 'interface', proto: 'static', ipaddr: '10.0.0.1' },
		beta: { '.type': 'interface', proto: 'dhcp' }
	} };
	return cursor();
}

// ── get ──────────────────────────────────────────────────────────────────
{
	let c = seed();
	eq('get: a missing config is null', c.get('nosuch', 'alpha'), null);
	eq('get: a missing section is null', c.get('demo', 'ghost'), null);
	eq('get: a missing option is null', c.get('demo', 'alpha', 'nope'), null);
	eq('get: two arguments answer the section TYPE', c.get('demo', 'alpha'), 'interface');
	eq('get: three answer the option', c.get('demo', 'alpha', 'proto'), 'static');
	// libuci has no empty option: `option x ''` reads back as null, so a
	// caller cannot tell "set to nothing" from "not set" and must not try.
	c.set('demo', 'alpha', 'blank', '');
	eq('get: an option set to the empty string reads back as null',
		c.get('demo', 'alpha', 'blank'), null);
	ok('get: even though it was stored', global.MOCK_UCI.demo.alpha.blank === '');
}

// ── set ──────────────────────────────────────────────────────────────────
// The one this file exists for.
{
	let c = seed();
	eq('set: an option on a missing section fails',
		c.set('demo', 'ghost', 'opt', '1'), null);
	eq('set: and says why', c.error(), 'Entry not found');
	ok('set: and creates NOTHING — no placeholder for the next run to read',
		global.MOCK_UCI.demo.ghost == null);
	eq('set: an option on a real section succeeds',
		c.set('demo', 'alpha', 'extra', '1'), true);
	eq('set: and clears the last error', c.error(), null);
	eq('set: the value is there', c.get('demo', 'alpha', 'extra'), '1');
	// Three arguments name a TYPE, and that form does create the section —
	// this is how a caller is meant to bring one into being.
	eq('set: three arguments create the section', c.set('demo', 'fresh', 'interface'), true);
	eq('set: with the type it was given', c.get('demo', 'fresh'), 'interface');
	eq('set: and can retype one that exists', c.set('demo', 'beta', 'device'), true);
	eq('set: retyped', c.get('demo', 'beta'), 'device');
	eq('set: an option on the section just created now works',
		c.set('demo', 'fresh', 'proto', 'static'), true);
}

// ── delete ───────────────────────────────────────────────────────────────
{
	let c = seed();
	eq('delete: a missing section fails', c.delete('demo', 'ghost'), null);
	eq('delete: and says why', c.error(), 'Entry not found');
	eq('delete: a missing option fails', c.delete('demo', 'alpha', 'nope'), null);
	eq('delete: and says why', c.error(), 'Entry not found');
	eq('delete: an option that is there succeeds',
		c.delete('demo', 'alpha', 'ipaddr'), true);
	ok('delete: and it is gone', global.MOCK_UCI.demo.alpha.ipaddr == null);
	eq('delete: a section that is there succeeds', c.delete('demo', 'beta'), true);
	ok('delete: and it is gone', global.MOCK_UCI.demo.beta == null);
}

// ── add ──────────────────────────────────────────────────────────────────
// libuci hands back an opaque name for an ANONYMOUS section (cfg0692bd), not
// a readable one derived from the type. A test that expects 'rule_0' is
// describing a mock, not a router.
{
	let c = seed();
	let n = c.add('demo', 'rule');
	ok('add: the name is opaque, not <type>_<n>', n != 'rule_0' && index(n, 'cfg') == 0);
	ok('add: the section is anonymous', global.MOCK_UCI.demo[n]['.anonymous'] == true);
	eq('add: with the type it was given', c.get('demo', n), 'rule');
	eq('add: and options can be written to the name it returned',
		c.set('demo', n, 'name', 'x'), true);
	let m = c.add('demo', 'rule');
	ok('add: a second one gets its own name', m != n);
	ok('add: a seeded section is NOT anonymous',
		global.MOCK_UCI.demo.alpha['.anonymous'] == null);
}

// ── foreach ──────────────────────────────────────────────────────────────
{
	let c = seed();
	eq('foreach: a missing config answers null, not false',
		c.foreach('nosuch', 'interface', function() {}), null);
	let names = [];
	eq('foreach: otherwise it answers true',
		c.foreach('demo', 'interface', function(s) { push(names, s['.name']); }), true);
	eq('foreach: it visited both', names, [ 'alpha', 'beta' ]);
	// The section a callback is handed carries libuci's own keys as well as
	// the options.
	let keys = null;
	c.foreach('demo', 'interface', function(s) {
		if (keys == null) {
			keys = [];
			for (let k in s)
				if (substr(k, 0, 1) == '.')
					push(keys, k);
		}
	});
	eq('foreach: the section carries the keys libuci supplies', keys,
		[ '.anonymous', '.type', '.name', '.index' ]);
	let seen = 0;
	eq('foreach: returning false still answers true',
		c.foreach('demo', 'interface', function() { seen++; return false; }), true);
	eq('foreach: but stops the walk', seen, 1);
	// `.index` counts every section in the config, not only the matching ones.
	global.MOCK_UCI.demo.gamma = { '.type': 'rule' };
	global.MOCK_UCI.demo.delta = { '.type': 'interface' };
	let idx = [];
	c.foreach('demo', 'interface', function(s) { push(idx, s['.index']); });
	eq('foreach: .index is the position in the whole config', idx, [ 0, 1, 3 ]);
}

// ── error ────────────────────────────────────────────────────────────────
{
	let c = seed();
	c.delete('demo', 'ghost');
	eq('error: reports the last failure', c.error(), 'Entry not found');
	c.get('demo', 'alpha');
	eq('error: and a later success clears it', c.error(), null);
}

// ── the exceptions, asserted so they stay bounded ────────────────────────
// These are places the mock knowingly does NOT follow libuci. Pinning them
// here keeps each one a decision someone made rather than a surprise; the
// reasoning is in mocks/uci.uc.
{
	let c = seed();
	// libuci: every operation on a config file that does not exist fails.
	// Here the container is created on demand, because the four configs this
	// package touches are shipped by packages and cannot be absent.
	eq('exception: a write to an unseeded config creates it',
		c.set('brandnew', 's', 'interface'), true);
	eq('exception: committing an unseeded config succeeds', c.commit('nothere'), true);
	// libuci returns an object keyed by config, holding the pending tuples,
	// and does not clear them on commit. Nothing reads this.
	eq('exception: changes() is an empty list', c.changes(), []);
	// libuci addresses anonymous sections as @type[n] in get/set/delete.
	let n = c.add('demo', 'rule');
	eq('exception: @type[n] addressing is not implemented',
		c.get('demo', '@rule[0]'), null);
	ok('exception: the section is reachable by the name add() returned',
		c.get('demo', n) == 'rule');
}

// ── ubus ─────────────────────────────────────────────────────────────────
{
	global.MOCK_UBUS = { 'thing~status': { up: true } };
	global.MOCK_UBUS_OPEN = 0;
	let u = connect();
	eq('ubus: an open connection is counted', global.MOCK_UBUS_OPEN, 1);
	eq('ubus: a seeded method answers', u.call('thing', 'status', {}), { up: true });
	eq('ubus: and leaves no error', u.error(), null);
	eq('ubus: an unseeded method is null', u.call('thing', 'nope', {}), null);
	eq('ubus: and says why', u.error(), 'Method not found');
	eq('ubus: disconnecting answers true', u.disconnect(), true);
	eq('ubus: and releases the count', global.MOCK_UBUS_OPEN, 0);
	eq('ubus: a second close answers null rather than throwing', u.disconnect(), null);
	eq('ubus: and does not double-release the count', global.MOCK_UBUS_OPEN, 0);
	// A call on a closed connection never reaches ubusd. The mock used to
	// answer one, which hid the very misuse the count above exists to catch.
	eq('ubus: a call after close fails', u.call('thing', 'status', {}), null);
	eq('ubus: and says the connection is closed', u.error(),
		'Connection failed: Connection is closed');

	// Deliberately NOT modelled, pinned so it stays a decision: ubusd tells an
	// unknown object from an unknown method and this mock cannot, being keyed
	// by object~method. Nothing in the product reads the text.
	global.MOCK_UBUS_OPEN = 0;
	let v = connect();
	v.call('no.such.object', 'status', {});
	eq('exception: an unknown object reports the unknown-method error',
		v.error(), 'Method not found');
	v.disconnect();
}

global.MOCK_UCI = {};
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL MOCK TESTS PASSED');
exit(fails ? 1 : 0);

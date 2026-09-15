// SPDX-License-Identifier: MIT
// Minimal in-memory 'uci' module mock for offline ucode tests. Mirrors the real
// ucode uci cursor API used by the backend. Seed and inspect via global.MOCK_UCI:
//   global.MOCK_UCI = { network: { protonvpn: { '.type':'interface', proto:'wireguard' } } };
//
// ── Fidelity ─────────────────────────────────────────────────────────────
// This mock stands in for libuci, so where it is more permissive than libuci
// it does not simplify the system under test, it DIVERGES from it — and a
// divergence invents failures the product cannot have. One already did: `set`
// used to create a section that did not exist, so a routing stamp written for
// a deleted interface brought a bare section into being, the next reconcile
// read that back as proof of an interface, and a whole round went to a defect
// that cannot occur on hardware. Measured on the device (ImmortalWrt 24.10.3,
// ucode's own uci module against a scratch config dir):
//
//   set('demo', 'ghost', 'opt', '1')  -> null, error() "Entry not found",
//                                        and NOTHING is created
//   set('demo', 'fresh', 'interface') -> true  (3-arg DOES create a section)
//   delete('demo', 'ghost')           -> null, error() "Entry not found"
//   delete('demo','alpha','missing')  -> null, error() "Entry not found"
//   add('demo', 'rule')               -> "cfg0692bd": an ANONYMOUS section,
//                                        '.anonymous': true, not "rule_0"
//   foreach('nosuch', t, cb)          -> null   (not false)
//   foreach section keys              -> '.anonymous', '.type', '.name',
//                                        '.index', then the options
//   error()                           -> the LAST operation's error; a later
//                                        successful call clears it
//   get of an option set to ''        -> null: libuci has no empty option
//
// So: tests must not rely on `set` conjuring sections, and must declare every
// section they then write to. Please do not make this mock convenient again —
// measure against the device first (the probe is a scratch config dir plus
// `cursor('/tmp/dir')`, no router state involved).
//
// Known remaining divergences, deliberately not modelled — see the round-17
// report for the reasoning and the measured blast radius of each:
//   * a MISSING CONFIG FILE. libuci answers "Entry not found" for every
//     operation on one; here the config container is created on demand. Every
//     config this package touches (network, firewall, dhcp, protonvpn) is
//     shipped by a package and cannot be absent on a working install, so
//     requiring each test to seed all four would model an impossible state.
//     Section existence, which is reachable, IS enforced.
//   * `changes()` returns an empty array. libuci returns an object keyed by
//     config, holding [op, section, option, value] tuples, and — a real quirk
//     — does not clear them on `commit`. Nothing in the product or the suite
//     reads it.
//   * `@type[n]` addressing of anonymous sections works in libuci's get/set/
//     delete and is not implemented here. The product never uses it, but
//     `uci show` prints that syntax, so a test copied from a router would not
//     work.
//   * iteration order is this object's insertion order; libuci's is the order
//     the file lists sections in. The two coincide closely enough that
//     test_ipv6's net_first() uses insertion order to exercise both orderings
//     of a shared device on purpose.

'use strict';

function store() {
	if (!global.MOCK_UCI)
		global.MOCK_UCI = {};
	return global.MOCK_UCI;
}

// Names for sections created by add(). libuci derives them from a hash of the
// file, so they are opaque and stable; a counter is opaque and stable too, and
// keeps a failing test reproducible.
let anon_seq = 0;

export function cursor() {
	let s = store();
	let err = null;
	// Every operation ends in one of these two, so error() reports the last
	// one rather than the last failure ever seen — which is what libuci does.
	let fail = function() {
		err = 'Entry not found';
		return null;
	};
	let done = function(v) {
		err = null;
		return v;
	};
	// The view of a section libuci hands out: its own keys first, then the
	// options. `.index` is the position within the whole config and only
	// foreach supplies it.
	let view = function(sec, name, index) {
		let out = { '.anonymous': (sec['.anonymous'] == true), '.type': sec['.type'],
			'.name': name };
		if (index != null)
			out['.index'] = index;
		for (let k in sec)
			if (k != '.type' && k != '.name' && k != '.anonymous')
				out[k] = sec[k];
		return out;
	};
	return {
		get: function(c, sec, opt) {
			let section = s[c] ? s[c][sec] : null;
			if (!section)
				return done(null);
			if (opt == null)
				return done(section['.type']);
			// libuci has no empty option: `option x ''` reads back as null,
			// so a caller cannot tell "set to nothing" from "not set".
			let v = section[opt];
			return done((v === '') ? null : v);
		},
		get_all: function(c, sec) {
			if (!s[c])
				return done(null);
			if (sec == null)
				return done(s[c]);
			return done(s[c][sec] ? view(s[c][sec], sec) : null);
		},
		get_first: function(c, t, opt) {
			if (!s[c])
				return done(null);
			for (let name in s[c])
				if (s[c][name]['.type'] == t)
					return done((opt != null) ? s[c][name][opt] : name);
			return done(null);
		},
		foreach: function(c, t, cb) {
			if (!s[c])
				return fail();
			let i = 0;
			for (let name in s[c]) {
				let section = s[c][name];
				if (t == null || section['.type'] == t) {
					if (cb(view(section, name, i)) === false)
						break;
				}
				i++;
			}
			return done(true);
		},
		add: function(c, t) {
			if (!s[c])
				s[c] = {};
			let name = sprintf('cfg%04x92bd', ++anon_seq);
			s[c][name] = { '.type': t, '.name': name, '.anonymous': true };
			return done(name);
		},
		// 4-arg: set an option on an EXISTING section. 3-arg (val == null):
		// create the section, or change the type of one already there.
		set: function(c, sec, a, b) {
			if (!s[c])
				s[c] = {};
			if (b == null) {
				if (!s[c][sec])
					s[c][sec] = { '.type': a, '.name': sec };
				else
					s[c][sec]['.type'] = a;
				return done(true);
			}
			// The divergence this mock was fixed for: libuci creates nothing
			// here, so neither does this.
			if (!s[c][sec])
				return fail();
			s[c][sec][a] = b;
			return done(true);
		},
		delete: function(c, sec, opt) {
			if (!s[c] || !s[c][sec])
				return fail();
			if (opt != null) {
				if (s[c][sec][opt] == null)
					return fail();
				delete s[c][sec][opt];
			} else {
				delete s[c][sec];
			}
			return done(true);
		},
		list_append: function(c, sec, opt, val) {
			if (!s[c] || !s[c][sec])
				return fail();
			let cur = s[c][sec][opt];
			if (type(cur) != 'array')
				cur = (cur != null) ? [cur] : [];
			push(cur, val);
			s[c][sec][opt] = cur;
			return done(true);
		},
		save: function() { return done(true); },
		commit: function() { return done(true); },
		changes: function() { return done([]); },
		revert: function() { return done(true); },
		error: function() { return err; }
	};
}

#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// The `require_ipv6` option: "I want IPv6, so only consider gateways that
// have it". Where test_ipv6.uc pins down what adaptive IPv6 does once a
// gateway has been chosen, this file pins down which gateways may be chosen
// at all — and, just as importantly, that an unsatisfiable requirement stops
// the connection instead of quietly settling for a gateway without IPv6.
//
// Every selection path funnels through protonvpn.select, so the tests drive
// the three real entry points (apply, rotate, and the rotate() the watchdog
// calls) rather than the shared helper alone: a filter honoured in one place
// and forgotten in another is exactly the bug worth catching.
//
// Uses the mock 'uci'/'ubus' modules; globals `KEY` and `fixture` come from
// run.sh.

'use strict';

const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';
const STATE = getenv('PROTONVPN_STATE_DIR') || '/tmp/protonvpn-test-state';

import { unlink, mkdir, writefile, readfile } from 'fs';
import { cursor } from 'uci';

const _cmn = require('protonvpn.common');
const load_settings = _cmn.load_settings,
      relay_ipv6_capable = _cmn.relay_ipv6_capable,
      require_ipv6_active = _cmn.require_ipv6_active;
const _cache = require('protonvpn.cache');
const _select = require('protonvpn.select');
const selection_candidates = _select.selection_candidates,
      selection_report = _select.selection_report;
const _api = require('protonvpn.api');
const _apply = require('protonvpn.apply');

// Off-device `ifup` always fails, so a connect could never report success and
// the branches after it would never run — which would make every "it refused
// to connect" assertion below pass for the wrong reason. Two seams are needed
// because the two paths reach connect_one differently:
//
//  - apply() calls its own module-local connect_one, so it is driven with the
//    tests/stubs/ifup marker, i.e. a real connect that really succeeds;
//  - protonvpn.rotate captures _apply.connect_one at require time, so it is
//    replaced here BEFORE that require — the seam test_ipv6 and test_instances
//    already use. (The marker alone does not help it: rotation's verify step
//    shells out to `wg`, which is also absent.)
const IFUP_OK = STATE + '/ifup-ok';
writefile(IFUP_OK, '');

const real_connect_one = _apply.connect_one;
_apply.connect_one = function(uci, iface, relay, s) {
	_apply.write_relay(uci, iface, relay, s);
	uci.commit('network');
	return true;
};
const _rotate = require('protonvpn.rotate');
const plan_candidates = _rotate.plan_candidates,
      rotate = _rotate.rotate;
const _service = require('protonvpn.service');
const watchdog_result_update = _service.watchdog_result_update;
const _routing = require('protonvpn.routing');
const ipv6_state = _routing.ipv6_state;

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

// Features as Proton really sends them: 28 = IPv6|Streaming|P2P, 12 = the
// same server without the bit, 1 = Secure Core, 2 = Tor.
const F_V6 = 28;
const F_NO_V6 = 12;

// The sorted logical names of a candidate list. Selection is a SET question,
// so the tests assert the whole membership rather than a count: a length
// check passes just as happily when the filter keeps the wrong two servers.
function names(list) {
	let out = [];
	for (let r in list)
		push(out, r.name);
	sort(out);
	return out;
}

// ── Fixture cache ────────────────────────────────────────────────────────
// nl: a mixed city — the interesting case, since the requirement has to
//     narrow rather than empty it.
// de: standard gateways, none with the bit — the "you picked somewhere real
//     that cannot serve you" case the refusal exists for.
// ch/fr: Secure Core and Tor, neither of which ever carries bit 16.

function mkrelay(name, host, ip, over) {
	let r = { name: name, hostname: host, ip_address: ip, public_key: KEY,
		location: 'nl-amsterdam', country_code: 'nl', city_code: 'nl-amsterdam',
		city: 'Amsterdam', port: 51820, load: 42, score: 2.9, features: F_V6,
		tier: 2, secure_core: false, tor: false, active: true };
	for (let k in over)
		r[k] = over[k];
	return r;
}

// Overrides placing a relay in Warsaw; `f` defaults to a gateway with the bit.
function mkpl(f) {
	return { features: (f == null) ? F_V6 : f, location: 'pl-warsaw',
		country_code: 'pl', city_code: 'pl-warsaw', city: 'Warsaw' };
}

function mkcache() {
	return { countries: [
		{ code: 'nl', name: 'NL', gateway_count: 3, cities: [
			{ code: 'nl-amsterdam', name: 'Amsterdam', country: 'NL',
				country_code: 'nl', gateway_count: 3, relays: [
					mkrelay('NL#1', 'node-nl-01.protonvpn.net', '1.2.3.4'),
					mkrelay('NL#2', 'node-nl-02.protonvpn.net', '5.6.7.8',
						{ features: F_NO_V6 }),
					mkrelay('NL#3', 'node-nl-03.protonvpn.net', '9.10.11.12')
				] }
		] },
		{ code: 'de', name: 'DE', gateway_count: 2, cities: [
			{ code: 'de-berlin', name: 'Berlin', country: 'DE',
				country_code: 'de', gateway_count: 2, relays: [
					mkrelay('DE#1', 'node-de-01.protonvpn.net', '20.0.0.1',
						{ features: F_NO_V6, location: 'de-berlin',
							country_code: 'de', city_code: 'de-berlin', city: 'Berlin' }),
					mkrelay('DE#2', 'node-de-02.protonvpn.net', '20.0.0.2',
						{ features: F_NO_V6, location: 'de-berlin',
							country_code: 'de', city_code: 'de-berlin', city: 'Berlin' })
				] }
		] },
		// pl: two eligible gateways among seven. Used by the loop tests: with
		// the filter working only PL#1/PL#7 can ever come up, so GREEN is
		// deterministic; without it the chance of five straight draws missing
		// all five ineligible ones is (2/7)^5, about one in 1500 — so RED is
		// a real failure rather than a coin toss.
		{ code: 'pl', name: 'PL', gateway_count: 7, cities: [
			{ code: 'pl-warsaw', name: 'Warsaw', country: 'PL',
				country_code: 'pl', gateway_count: 7, relays: [
					mkrelay('PL#1', 'node-pl-01.protonvpn.net', '50.0.0.1', mkpl()),
					mkrelay('PL#2', 'node-pl-02.protonvpn.net', '50.0.0.2', mkpl(F_NO_V6)),
					mkrelay('PL#3', 'node-pl-03.protonvpn.net', '50.0.0.3', mkpl(F_NO_V6)),
					mkrelay('PL#4', 'node-pl-04.protonvpn.net', '50.0.0.4', mkpl(F_NO_V6)),
					mkrelay('PL#5', 'node-pl-05.protonvpn.net', '50.0.0.5', mkpl(F_NO_V6)),
					mkrelay('PL#6', 'node-pl-06.protonvpn.net', '50.0.0.6', mkpl(F_NO_V6)),
					mkrelay('PL#7', 'node-pl-07.protonvpn.net', '50.0.0.7', mkpl())
				] }
		] },
		{ code: 'ch', name: 'CH', gateway_count: 1, cities: [
			{ code: 'ch-zurich', name: 'Zurich', country: 'CH',
				country_code: 'ch', gateway_count: 1, relays: [
					mkrelay('CH-SC#1', 'ch-sc-01.protonvpn.net', '30.0.0.1',
						{ features: 1, secure_core: true, location: 'ch-zurich',
							country_code: 'ch', city_code: 'ch-zurich', city: 'Zurich' })
				] }
		] },
		{ code: 'fr', name: 'FR', gateway_count: 1, cities: [
			{ code: 'fr-paris', name: 'Paris', country: 'FR',
				country_code: 'fr', gateway_count: 1, relays: [
					mkrelay('FR#1-TOR', 'fr-13-tor.protonvpn.net', '40.0.0.1',
						{ features: 2, tor: true, location: 'fr-paris',
							country_code: 'fr', city_code: 'fr-paris', city: 'Paris' })
				] }
		] }
	], stats: { countries: 5, cities: 5, gateways: 14, servers_seen: 14 } };
}

const cache = mkcache();

// The same cache on disk, in the envelope protonvpn.cache writes, for the
// apply()/rotate() flows that read it themselves.
let cdir = RUN + '/pv6req_' + time();
mkdir(cdir);
_cmn.atomic_write(cdir + '/protonvpn_servers_cache.json', sprintf('%J', {
	...cache, cached_at: time(), schema_version: _cmn.CACHE_SCHEMA_VERSION,
	cache_info: { created: _cmn.iso_ts(), expires_at: _cmn.iso_ts(time() + 86400) }
}));

// Settings as load_settings produces them, for the pure selection helpers.
function sel(over) {
	let base = { name: 'main', interface: 'protonvpn', locations: [ 'nl' ],
		hop_mode: 'standard', ipv6_mode: 'auto', require_ipv6: true,
		country_code: '', city_code: '', max_retries: 10,
		// Steered routing with a table of its own: the one shape in which
		// ipv6_mode 'auto' actually hands IPv6 to clients, and therefore the
		// only one in which requiring it can be satisfied.
		auto_routing: false, source_networks: [ 'guest' ], routing_table: '101' };
	for (let k in over)
		base[k] = over[k];
	return base;
}

// A configured, logged-in instance whose apply()/rotate() can run to the
// selection step. `opts` go straight into the protonvpn instance section.
function device(opts) {
	let inst = { '.type': 'instance', interface: 'protonvpn', cache_dir: cdir,
		enabled: '1', hop_mode: 'standard', ipv6_mode: 'auto',
		// Same reason as sel(): steered, with a routing table, so 'auto' can
		// deliver IPv6 and the requirement is live.
		auto_routing: '0', source_network: [ 'guest' ], routing_table: '101' };
	for (let k in opts)
		inst[k] = opts[k];
	global.MOCK_UCI = {
		protonvpn: { main: inst },
		network: { protonvpn: { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, vpn_type: 'protonvpn' } },
		firewall: {}
	};
	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: time() + 1800, session_expires_at: time() + 86400,
		scope: 'vpn', twofa: false });
	_apply.record_cert_state('main', { serial: '1', expires_at: time() + 86400,
		refresh_at: time() + 43200, created_at: time() });
	unlink(RUN + '/protonvpn_rotate.lock');
	return cursor();
}

// The interfaces the backend actually asked netifd to take down, in order
// (tests/stubs/ifdown records them). The peer vanishing from the uci mock only
// says the configuration changed; this is the one thing that says the tunnel
// really went down, which is half of what "took the tunnel down" has to mean.
function ifdowns() {
	let raw = readfile(STATE + '/ifdown.log');
	if (!raw)
		return [];
	let out = [];
	for (let line in split(trim(raw), '\n'))
		if (line != '')
			push(out, line);
	return out;
}

function cleanup() {
	unlink(STATE + '/session.json');
	unlink(STATE + '/certificate.json');
	unlink(RUN + '/protonvpn_rotate.lock');
	unlink(STATE + '/ifdown.log');
}

// ── 1. the option and when it applies ────────────────────────────────────
{
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance',
		interface: 'protonvpn' } } };
	let uci = cursor();
	eq('require_ipv6 is off by default', load_settings(uci).require_ipv6, false);
	global.MOCK_UCI.protonvpn.main.require_ipv6 = '1';
	eq('require_ipv6 is read from the config', load_settings(uci).require_ipv6, true);
	// Anything that is not the literal '1' is off, like every other boolean
	// the backend reads.
	global.MOCK_UCI.protonvpn.main.require_ipv6 = 'yes';
	eq('a non-1 value is off', load_settings(uci).require_ipv6, false);

	// The raw option survives a hop mode that cannot honour it, so flipping
	// out and back does not silently forget what the user asked for.
	global.MOCK_UCI.protonvpn.main.require_ipv6 = '1';
	global.MOCK_UCI.protonvpn.main.hop_mode = 'secure_core';
	global.MOCK_UCI.protonvpn.main.ipv6_mode = 'auto';
	eq('the stored option survives secure_core', load_settings(uci).require_ipv6, true);
}

// ── 2. require_ipv6_active: the availability rule, in one place ──────────
// Only under ipv6_mode 'auto' (the one mode where the bit changes what
// happens to a client) and hop_mode 'standard' (bit 16 is set on 0 of 122
// Secure Core and 0 of 7 Tor logicals, so the others can only ever be empty).
{
	ok('auto + standard: the requirement applies',
		require_ipv6_active(sel()) == true);
	ok('block: nothing is routed either way, so it does not apply',
		require_ipv6_active(sel({ ipv6_mode: 'block' })) == false);
	ok('off: the app does not touch IPv6, so it does not apply',
		require_ipv6_active(sel({ ipv6_mode: 'off' })) == false);
	ok('secure_core has no IPv6 gateways, so it does not apply',
		require_ipv6_active(sel({ hop_mode: 'secure_core' })) == false);
	ok('tor has no IPv6 gateways, so it does not apply',
		require_ipv6_active(sel({ hop_mode: 'tor' })) == false);
	ok('the option off means it never applies',
		require_ipv6_active(sel({ require_ipv6: false })) == false);
	ok('no settings at all is not a crash', require_ipv6_active(null) == false);
}

// ── 2b. it must also be inactive where adaptive IPv6 cannot route at all ──
// 'auto' only gives clients IPv6 through the per-network policy rules that
// steered routing creates (protonvpn.routing steering_configured). Where
// those do not exist the mode is inert, so requiring IPv6 could only ever
// refuse an otherwise usable VPN over an option that changes nothing — the
// same "costs servers, buys nothing" the ipv6_mode guard already avoids.
// Reachable by hand: /etc/config/protonvpn is edited directly all the time.
{
	ok('auto_routing routes everything and never routes IPv6, so it does not apply',
		require_ipv6_active(sel({ auto_routing: true })) == false);
	ok('with no steered network there is nothing to attach IPv6 to',
		require_ipv6_active(sel({ source_networks: [] })) == false);
	ok('steering without a routing table is not steering yet',
		require_ipv6_active(sel({ routing_table: '' })) == false);

	// And the consequence that matters: such an instance keeps its whole
	// fleet rather than being refused over an option that cannot apply.
	eq('an auto_routing instance is selected unfiltered',
		names(selection_candidates(cache, sel({ auto_routing: true }))),
		[ 'NL#1', 'NL#2', 'NL#3' ]);
	let rep = selection_report(cache, sel({ auto_routing: true, locations: [ 'de' ] }));
	eq('and a set with no IPv6 gateway is still usable there',
		names(rep.list), [ 'DE#1', 'DE#2' ]);
	eq('with nothing blamed on IPv6', rep.ipv6_filtered, false);
}

// ── 3. relay_ipv6_capable: unknown resolves to "no" ──────────────────────
{
	ok('bit 16 set is capable', relay_ipv6_capable({ features: F_V6 }) == true);
	ok('bit 16 clear is not', relay_ipv6_capable({ features: F_NO_V6 }) == false);
	// A relay out of a cache written before `features` was kept must not be
	// read as capable: guessing the other way hands the user a black hole.
	ok('a relay without features is not capable', relay_ipv6_capable({}) == false);
	ok('a non-relay is not capable', relay_ipv6_capable(null) == false);
	ok('a numeric string still decodes',
		relay_ipv6_capable({ features: '' + F_V6 }) == true);
	ok('garbage is not capable', relay_ipv6_capable({ features: 'lots' }) == false);
}

// ── 4. selection narrows to the bit-16 gateways ──────────────────────────
{
	eq('off: every standard gateway in the set',
		names(selection_candidates(cache, sel({ require_ipv6: false }))),
		[ 'NL#1', 'NL#2', 'NL#3' ]);
	eq('on: only the gateways that forward IPv6',
		names(selection_candidates(cache, sel())),
		[ 'NL#1', 'NL#3' ]);

	// The report has to keep the pre-filter count, or an empty result cannot
	// be explained: "you picked nowhere" and "you picked somewhere with no
	// IPv6 gateway" need different answers.
	let rep = selection_report(cache, sel());
	eq('the report counts what geography alone matched', rep.matched, 3);
	eq('and says the IPv6 filter was applied', rep.ipv6_filtered, true);
	let off = selection_report(cache, sel({ require_ipv6: false }));
	eq('with the option off nothing is filtered', off.ipv6_filtered, false);
	eq('and matched equals the list', off.matched, length(off.list));

	// Two countries, one of them without a single eligible gateway: the good
	// one must still be offered rather than the whole set being refused.
	eq('a mixed location set keeps what qualifies',
		names(selection_candidates(cache, sel({ locations: [ 'nl', 'de' ] }))),
		[ 'NL#1', 'NL#3' ]);
}

// ── 5. an unsatisfiable set selects nothing, and says why ────────────────
{
	let rep = selection_report(cache, sel({ locations: [ 'de' ] }));
	eq('no eligible gateway means no candidates', names(rep.list), [ ]);
	eq('but the locations did match servers', rep.matched, 2);
	eq('and the IPv6 filter is what emptied it', rep.ipv6_filtered, true);

	// An empty result that IPv6 did not cause must not be blamed on IPv6.
	let nowhere = selection_report(cache, sel({ locations: [ 'is' ] }));
	eq('an unknown location matches nothing', names(nowhere.list), [ ]);
	eq('and nothing matched before the filter either', nowhere.matched, 0);
}

// ── 6. the modes where the requirement must NOT narrow anything ──────────
// Leaving the filter on here would hand the user an empty list in a mode
// where the bit simply does not occur.
{
	eq('secure_core is selected unfiltered',
		names(selection_candidates(cache, sel({ locations: [ 'ch' ],
			hop_mode: 'secure_core' }))), [ 'CH-SC#1' ]);
	eq('tor is selected unfiltered',
		names(selection_candidates(cache, sel({ locations: [ 'fr' ],
			hop_mode: 'tor' }))), [ 'FR#1-TOR' ]);
	eq('ipv6_mode block leaves selection alone',
		names(selection_candidates(cache, sel({ ipv6_mode: 'block' }))),
		[ 'NL#1', 'NL#2', 'NL#3' ]);
	eq('ipv6_mode off leaves selection alone',
		names(selection_candidates(cache, sel({ ipv6_mode: 'off' }))),
		[ 'NL#1', 'NL#2', 'NL#3' ]);
}

// ── 7. apply(): refuse rather than downgrade ─────────────────────────────
{
	let uci = device({ require_ipv6: '1', locations: [ 'de' ] });
	let r = _apply.apply(uci);
	eq('apply refuses when no gateway in the set forwards IPv6', r.state, 'failure');
	eq('and flags the reason for the UI', r.ipv6_required, true);
	ok('and says so in words',
		index(r.error || '', 'no IPv6 gateways in the selected locations') == 0);
	eq('and no peer was written', global.MOCK_UCI.network.peer0, null);

	// The generic "nothing matched" message stays generic: blaming IPv6 for
	// an empty location set would send the user to fix the wrong thing.
	uci = device({ require_ipv6: '1', locations: [ 'is' ] });
	let r2 = _apply.apply(uci);
	eq('an empty location set is not blamed on IPv6', r2.ipv6_required, null);
	eq('and keeps the generic message', r2.error,
		'no matching server found for the current selection');

	// With the requirement off the very same set connects.
	uci = device({ require_ipv6: '0', locations: [ 'de' ] });
	let r3 = _apply.apply(uci);
	eq('with the option off the same set is usable', r3.state, 'success');
	ok('and it landed on a gateway without IPv6',
		r3.gateway == 'node-de-01.protonvpn.net' || r3.gateway == 'node-de-02.protonvpn.net');
	cleanup();
}

// ── 8. apply() only ever lands on an eligible gateway ────────────────────
// The mixed city is the case a "filter the displayed list" implementation
// would get wrong: the picker looks right and the backend still rolls NL#2.
{
	let landed = {}, connected = 0;
	for (let i = 0; i < 5; i++) {
		let uci = device({ require_ipv6: '1', locations: [ 'pl' ] });
		let r = _apply.apply(uci);
		if (r.state == 'success')
			connected++;
		landed[r.gateway || '?'] = true;
	}
	eq('every apply connected', connected, 5);
	// Named individually so a failure says which gateway leaked through.
	for (let bad in [ 'node-pl-02', 'node-pl-03', 'node-pl-04', 'node-pl-05',
			'node-pl-06' ])
		eq('apply never chose ' + bad + ' (no IPv6)',
			landed[bad + '.protonvpn.net'], null);
	ok('and it did connect to an eligible gateway',
		landed['node-pl-01.protonvpn.net'] || landed['node-pl-07.protonvpn.net']);
	cleanup();
}

// ── 9. a pinned server without the bit is refused ────────────────────────
// Refused, not warned about: a pin is still a connect, and connecting anyway
// is the silent downgrade the whole option exists to prevent. Pinning already
// disables rotation, so "leave it alone" would strand the instance on a
// gateway without IPv6 indefinitely, with the checkbox still ticked.
{
	let uci = device({ require_ipv6: '1', locations: [ 'nl' ],
		fixed_server: 'NL#2' });
	let r = _apply.apply(uci);
	eq('a pin without IPv6 is refused', r.state, 'failure');
	eq('and flagged', r.ipv6_required, true);
	ok('and the message names both ways out',
		index(r.error || '', 'unpin') >= 0 && index(r.error || '', 'requirement') >= 0);
	eq('and nothing was connected', global.MOCK_UCI.network.peer0, null);

	// A pin that does carry the bit is honoured exactly as before.
	uci = device({ require_ipv6: '1', locations: [ 'nl' ], fixed_server: 'NL#1' });
	let r2 = _apply.apply(uci);
	eq('a pin with IPv6 still connects', r2.state, 'success');
	eq('to the pinned gateway', r2.gateway, 'node-nl-01.protonvpn.net');

	// And with the requirement off, the same pin the first case refused works.
	uci = device({ require_ipv6: '0', locations: [ 'nl' ], fixed_server: 'NL#2' });
	let r3 = _apply.apply(uci);
	eq('without the requirement the same pin is fine', r3.state, 'success');
	eq('and connects to it', r3.gateway, 'node-nl-02.protonvpn.net');
	cleanup();
}

// ── 10. rotation honours the requirement ─────────────────────────────────
{
	// The planner is what rotation draws from, so it must already be narrowed.
	eq('the rotation plan only holds eligible gateways',
		names(plan_candidates(cache, sel(), null, 10)), [ 'NL#1', 'NL#3' ]);
	eq('excluding the current one leaves the other eligible gateway',
		names(plan_candidates(cache, sel(), 'NL#1', 10)), [ 'NL#3' ]);
	// Without the requirement the same exclusion leaves the ineligible one in.
	eq('with the option off the plan keeps everything else',
		names(plan_candidates(cache, sel({ require_ipv6: false }), 'NL#1', 10)),
		[ 'NL#2', 'NL#3' ]);
}

// ── 11. rotate() never moves onto a gateway without the bit ──────────────
{
	let landed = {}, rotated = 0;
	for (let i = 0; i < 5; i++) {
		let uci = device({ require_ipv6: '1', locations: [ 'pl' ] });
		// Currently on the other eligible gateway, so PL#7 is the only server
		// rotation may move to once the requirement is honoured.
		global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
			interface: 'protonvpn', public_key: KEY, endpoint_host: '50.0.0.1',
			endpoint_port: '51820', protonvpn_gateway: 'PL#1' };
		let r = rotate(uci);
		if (r.ok) {
			rotated++;
			landed[r.server] = true;
		}
	}
	eq('every rotation moved', rotated, 5);
	for (let bad in [ 'PL#2', 'PL#3', 'PL#4', 'PL#5', 'PL#6' ])
		eq('rotation never landed on ' + bad + ' (no IPv6)', landed[bad], null);
	eq('it can only have gone to the one eligible alternative',
		landed['PL#7'], true);
	cleanup();
}

// ── 12. rotate() refuses an unsatisfiable set instead of no-opping ───────
// Reported before the current gateway is excluded: afterwards an empty plan
// is indistinguishable from "nothing else to move to", and rotation would
// report a routine no-op while the instance can in fact never satisfy the
// requirement it was given.
{
	let uci = device({ require_ipv6: '1', locations: [ 'de' ] });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '20.0.0.1',
		endpoint_port: '51820', protonvpn_gateway: 'DE#1' };
	let r = rotate(uci);
	ok('rotation reports the unsatisfiable requirement',
		index(r.error || '', 'no IPv6 gateways in the selected locations') == 0);
	eq('and flags it', r.ipv6_required, true);
	ok('and does not call it a routine skip', r.skipped == null);
	// This used to assert the peer was LEFT in place, which encoded the defect
	// as intended behaviour: refusing to choose a gateway without IPv6 while
	// still running one is the worst of both worlds. See section 16.
	eq('and did not leave the instance on the non-compliant peer',
		global.MOCK_UCI.network.peer0, null);
	eq('and says the tunnel went down', r.tunnel_down, true);
	eq('and the interface was actually brought down', ifdowns(), [ 'protonvpn' ]);
	cleanup();
}

// ── 13. the watchdog inherits all of it ──────────────────────────────────
// The watchdog's recovery IS rotate(), so it cannot connect to a gateway the
// requirement excludes. What is specific to the watchdog is the aftermath: a
// refusal has to count as a failed recovery so the cooldown backs off,
// instead of being retried every WATCHDOG_COOLDOWN_BASE seconds forever.
{
	let uci = device({ require_ipv6: '1', locations: [ 'de' ], watchdog: '1' });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '20.0.0.1',
		endpoint_port: '51820', protonvpn_gateway: 'DE#1' };
	// Exactly the call service.uc makes for a recovery.
	let res = rotate(null, 'main');
	ok('watchdog recovery refuses the same way',
		index(res.error || '', 'no IPv6 gateways in the selected locations') == 0);
	eq('a refused recovery counts as a failure', watchdog_result_update(res, 0), 1);
	eq('so the cooldown keeps backing off', watchdog_result_update(res, 3), 4);
	// Losing the lock is still not a failure — the requirement must not have
	// turned that exemption off.
	eq('a lost lock is still not a failure',
		watchdog_result_update({ skipped: true,
			reason: 'rotation already running' }, 2), 2);

	// A recovery that CAN be satisfied still succeeds and stays on eligible
	// gateways, so the refusal is not just "the watchdog never works now".
	uci = device({ require_ipv6: '1', locations: [ 'nl' ], watchdog: '1' });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '1.2.3.4',
		endpoint_port: '51820', protonvpn_gateway: 'NL#1' };
	let good = rotate(null, 'main');
	eq('a satisfiable recovery still rotates', good.ok, true);
	eq('onto the eligible gateway', good.server, 'NL#3');
	eq('and is not counted as a failure', watchdog_result_update(good, 2), 2);
	cleanup();
}

// ── 16. a tunnel already up is not exempt from the refusal ───────────────
// The sequence that motivates all of this: connected to a gateway without the
// bit, the user turns the requirement on, and nothing eligible can be reached.
// Declining to CHOOSE such a gateway while continuing to RUN one tells the
// user the requirement failed and carries them on a gateway that violates it.
// So the peer goes with the refusal — and the assertions below check the
// resulting STATE (peer gone, stamp gone, interface down), not just the
// message, because a correct-looking error over a live violating tunnel is
// exactly the bug this section exists to catch.
//
// Nothing leaks as a result: under ipv6_mode 'auto' the priority-21000
// prohibit is installed whether the tunnel is up or down, so IPv6 on the
// steered networks still stops at the router (test_ipv6 section 4 pins that
// rule down). IPv4 falls back to the main table unless the kill switch is on,
// which is the posture every other tunnel failure already leaves.
{
	// (a) apply, nothing eligible in the set.
	let uci = device({ require_ipv6: '1', locations: [ 'de' ] });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '20.0.0.1',
		endpoint_port: '51820', protonvpn_gateway: 'DE#1' };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_NO_V6;
	let r = _apply.apply(uci);
	eq('apply still refuses', r.state, 'failure');
	eq('and still flags IPv6 as the reason', r.ipv6_required, true);
	eq('the non-compliant peer is gone', global.MOCK_UCI.network.peer0, null);
	eq('the feature stamp is gone',
		global.MOCK_UCI.network.protonvpn.protonvpn_features, null);
	eq('and the result says the tunnel went down', r.tunnel_down, true);
	eq('and the interface was actually brought down', ifdowns(), [ 'protonvpn' ]);
	ok('and the reason is the IPv6 one, not a generic failure',
		index(r.error || '', 'IPv6') >= 0);
	cleanup();

	// (b) apply, a pinned server that does not forward IPv6 while a
	//     non-compliant tunnel is already up.
	uci = device({ require_ipv6: '1', locations: [ 'nl' ], fixed_server: 'NL#2' });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '5.6.7.8',
		endpoint_port: '51820', protonvpn_gateway: 'NL#2' };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_NO_V6;
	let rp = _apply.apply(uci);
	eq('a pin without IPv6 is still refused', rp.state, 'failure');
	eq('the peer it was running on is gone', global.MOCK_UCI.network.peer0, null);
	eq('and the tunnel went down', rp.tunnel_down, true);
	eq('and the interface with it', ifdowns(), [ 'protonvpn' ]);
	cleanup();

	// (c) A tunnel that DOES satisfy the requirement is left alone. The apply
	//     failed, but the running state is compliant, and tearing it down
	//     would be gratuitous.
	uci = device({ require_ipv6: '1', locations: [ 'de' ] });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '1.2.3.4',
		endpoint_port: '51820', protonvpn_gateway: 'NL#1' };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_V6;
	let rc = _apply.apply(uci);
	eq('the refusal still stands', rc.state, 'failure');
	ok('but a compliant tunnel is kept', global.MOCK_UCI.network.peer0 != null);
	eq('and nothing claims to have gone down', rc.tunnel_down, null);
	eq('and the interface was left up', ifdowns(), [ ]);
	cleanup();

	// (d) With the requirement off, the same non-compliant tunnel survives:
	//     the teardown belongs to the requirement, not to every failure.
	uci = device({ require_ipv6: '0', locations: [ 'is' ] });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '20.0.0.1',
		endpoint_port: '51820', protonvpn_gateway: 'DE#1' };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_NO_V6;
	let ro = _apply.apply(uci);
	eq('the apply fails for its own reason', ro.state, 'failure');
	ok('and the tunnel is left exactly as it was',
		global.MOCK_UCI.network.peer0 != null);
	cleanup();
}

// ── 17. a rollback must not reinstate a non-compliant peer ───────────────
// The candidate loop is filtered, so everything it tried was eligible — but
// the peer it rolls BACK to predates the requirement and need not be. Putting
// it back (and explicitly bringing it up) would reinstate precisely the
// violation section 16 removes, by a different door.
{
	// Every eligible candidate fails to hand shake: ifup is made to fail so
	// connect_one reports nothing came up, which is what drives the rollback.
	unlink(IFUP_OK);
	let uci = device({ require_ipv6: '1', locations: [ 'nl' ] });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '20.0.0.1',
		endpoint_port: '51820', protonvpn_gateway: 'DE#1',
		protonvpn_features: '' + F_NO_V6 };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_NO_V6;
	let r = _apply.apply(uci);
	eq('the apply failed', r.state, 'failure');
	eq('the non-compliant peer was not restored',
		global.MOCK_UCI.network.peer0, null);
	eq('and the tunnel went down instead', r.tunnel_down, true);
	eq('and the interface was actually brought down', ifdowns(), [ 'protonvpn' ]);
	ok('with the IPv6 requirement named as the reason',
		index(r.error || '', 'IPv6') >= 0);
	cleanup();

	// The same rollback with a COMPLIANT saved peer restores it as before:
	// this must not become "every failed apply tears the tunnel down".
	uci = device({ require_ipv6: '1', locations: [ 'nl' ] });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '1.2.3.4',
		endpoint_port: '51820', protonvpn_gateway: 'NL#1',
		protonvpn_features: '' + F_V6 };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_V6;
	let rc = _apply.apply(uci);
	eq('the apply still failed', rc.state, 'failure');
	eq('but the compliant peer was restored', rc.restored, true);
	eq('to the gateway it was on',
		global.MOCK_UCI.network.peer0.protonvpn_gateway, 'NL#1');
	eq('and nothing was torn down', rc.tunnel_down, null);
	cleanup();
	writefile(IFUP_OK, '');
}

// ── 18. the refusal has to REACH the browser, not merely be set ─────────
// The page never calls apply() directly: it spawns the detached worker and
// polls apply_status. The reason therefore has to survive run_apply's status
// record, the JSON round trip through the status file and the rpcd method —
// three boundaries, each able to drop a field quietly. A field the backend
// never delivers is how the 0.5.0 IPv6 badge died (it was read in the view and
// never put in trim_relay), so these assert what comes back OUT of the ubus
// method the browser calls, not what apply() put in.
{
	unlink(_cmn.APPLY_LOCK_FILE);
	unlink(_cmn.APPLY_STATUS_FILE);
	// Kill switch off: the instance whose second half of the situation is that
	// its networks are now on the bare WAN.
	let uci = device({ require_ipv6: '1', locations: [ 'de' ], killswitch: '0' });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '20.0.0.1',
		endpoint_port: '51820', protonvpn_gateway: 'DE#1' };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_NO_V6;

	_apply.run_apply('main');

	// Exactly the call the browser makes.
	let rpcd = loadfile(RPCD)();
	let st = rpcd.protonvpn.apply_status.call({ args: {} });
	eq('the worker recorded a finished apply', st.state, 'failed');
	let r = st.result || {};
	eq('the result survived the status record', r.state, 'failure');
	eq('the IPv6 flag arrives at the ubus boundary', r.ipv6_required, true);
	eq('and so does the teardown flag', r.tunnel_down, true);
	// waitForApply() resolves st.result and handleConnect() renders res.error
	// verbatim, so this string is literally what the user reads.
	ok('the reason that reaches the UI names IPv6',
		index(r.error || '', 'IPv6') >= 0);
	ok('and says the tunnel was taken down',
		index(r.error || '', 'taken down') >= 0);
	ok('and, with the kill switch off, that the networks are on the provider',
		index(r.error || '', 'provider') >= 0);
	ok('a caller reading only the top-level error still gets it',
		st.error != null && index(st.error, 'IPv6') >= 0);
	unlink(_cmn.APPLY_STATUS_FILE);
	cleanup();
}

// ── 18b. the same refusal with the kill switch ON tells the other truth ──
// The two halves are one situation, so the note must track the actual setting
// rather than always warning about an exposure that is not happening.
{
	unlink(_cmn.APPLY_LOCK_FILE);
	unlink(_cmn.APPLY_STATUS_FILE);
	let uci = device({ require_ipv6: '1', locations: [ 'de' ], killswitch: '1' });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '20.0.0.1',
		endpoint_port: '51820', protonvpn_gateway: 'DE#1' };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_NO_V6;

	_apply.run_apply('main');
	let rpcd = loadfile(RPCD)();
	let r = (rpcd.protonvpn.apply_status.call({ args: {} }) || {}).result || {};
	ok('it still names IPv6 as the reason', index(r.error || '', 'IPv6') >= 0);
	ok('and says the kill switch is holding the networks',
		index(r.error || '', 'kill switch') >= 0);
	ok('and does NOT claim they are on the provider',
		index(r.error || '', 'provider') < 0);
	unlink(_cmn.APPLY_STATUS_FILE);
	cleanup();
}

// ── 19. a page reload has to explain the dead tunnel too ─────────────────
// handleConnect() only fires on a click. Someone who reloads the page after
// the teardown reads the status band instead, and 'gateway_no_ipv6' renders
// there as "this server does not forward it" — about a server that is not
// connected, with no hint that their own requirement took the tunnel down.
// Under an active requirement the backend never connects to a gateway without
// the bit, so that reason cannot be the true one; the true one is that no
// eligible gateway was reachable.
{
	global.MOCK_UCI = { network: { protonvpn: { '.type': 'interface' } } };
	let uci = cursor();
	let s = { name: 'main', interface: 'protonvpn', ipv6_mode: 'auto',
		hop_mode: 'standard', require_ipv6: true, enabled: true,
		source_networks: [ 'media' ], auto_routing: false, routing_table: '101' };
	let st = ipv6_state(uci, s, 'steered', false);
	eq('a required-but-unavailable IPv6 says so', st.reason, 'ipv6_required_unavailable');
	ok('and is not active', st.active == false);

	// Without the requirement the existing reason is still the right one: the
	// gateway really is what lacks IPv6, and the next rotation may fix it.
	s.require_ipv6 = false;
	eq('without the requirement it is still the gateway',
		ipv6_state(uci, s, 'steered', false).reason, 'gateway_no_ipv6');

	// And a capable gateway is unaffected either way.
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_V6;
	s.require_ipv6 = true;
	eq('a capable gateway is not blamed on the requirement',
		ipv6_state(uci, s, 'steered', true).reason, null);
}

// ── 20. status has to say WHICH way the requirement went unmet ──────────
// One reason for two situations gives one of them the wrong advice. "No
// eligible gateway here" wants wider locations; "the eligible gateways could
// not be reached" wants another attempt — those gateways do forward IPv6, so
// telling the user to widen the locations or drop the requirement has them
// undo the one setting that was not the problem. The cause is recorded at the
// refusal because afterwards there is no peer to inspect and answering it
// again would mean re-reading the server cache on a path the UI polls.
{
	global.MOCK_UCI = { network: { protonvpn: { '.type': 'interface' } } };
	let uci = cursor();
	eq('no stamp means no recorded cause',
		_cmn.iface_ipv6_unmet(uci, 'protonvpn'), null);
	for (let c in [ 'no_gateway', 'unreachable', 'pinned' ]) {
		global.MOCK_UCI.network.protonvpn.protonvpn_ipv6_unmet = c;
		eq('the ' + c + ' cause is read back', _cmn.iface_ipv6_unmet(uci, 'protonvpn'), c);
	}
	// An unknown value must not be passed through to the UI as if it were a
	// cause it knows how to word.
	global.MOCK_UCI.network.protonvpn.protonvpn_ipv6_unmet = 'something else';
	eq('an unknown cause reads as none',
		_cmn.iface_ipv6_unmet(uci, 'protonvpn'), null);

	// And it reaches the status object, which is the only thing a page reload
	// or a background rotation has to work from.
	let s = { name: 'main', interface: 'protonvpn', ipv6_mode: 'auto',
		hop_mode: 'standard', require_ipv6: true, enabled: true,
		source_networks: [ 'media' ], auto_routing: false, routing_table: '101' };
	global.MOCK_UCI.network.protonvpn.protonvpn_ipv6_unmet = 'unreachable';
	let st = ipv6_state(uci, s, 'steered', false);
	eq('status reports the reason', st.reason, 'ipv6_required_unavailable');
	eq('and which way it went unmet', st.required_cause, 'unreachable');

	// With the requirement off the stamp is stale by definition: the gateway
	// really is what lacks IPv6, and the cause must not be offered.
	s.require_ipv6 = false;
	let off = ipv6_state(uci, s, 'steered', false);
	eq('without the requirement the gateway is the reason', off.reason, 'gateway_no_ipv6');
	eq('and no cause is offered', off.required_cause, null);
}

// ── 21. each refusal records its own cause, and a connect clears it ──────
{
	// (a) nothing eligible in the selected locations.
	let uci = device({ require_ipv6: '1', locations: [ 'de' ] });
	_apply.apply(uci);
	eq('an empty eligible set records no_gateway',
		global.MOCK_UCI.network.protonvpn.protonvpn_ipv6_unmet, 'no_gateway');
	cleanup();

	// (b) a pinned server that does not forward IPv6 — not a location problem,
	//     and saying it is would send the user to change the wrong thing.
	uci = device({ require_ipv6: '1', locations: [ 'nl' ], fixed_server: 'NL#2' });
	_apply.apply(uci);
	eq('a pinned server without IPv6 records pinned',
		global.MOCK_UCI.network.protonvpn.protonvpn_ipv6_unmet, 'pinned');
	cleanup();

	// (c) eligible gateways existed and none could be reached: ifup fails, so
	//     every filtered candidate fails to come up and the rollback runs.
	unlink(IFUP_OK);
	uci = device({ require_ipv6: '1', locations: [ 'nl' ] });
	global.MOCK_UCI.network.peer0 = { '.type': 'wireguard_protonvpn',
		interface: 'protonvpn', public_key: KEY, endpoint_host: '20.0.0.1',
		endpoint_port: '51820', protonvpn_gateway: 'DE#1',
		protonvpn_features: '' + F_NO_V6 };
	global.MOCK_UCI.network.protonvpn.protonvpn_features = '' + F_NO_V6;
	_apply.apply(uci);
	eq('unreachable eligible gateways record unreachable',
		global.MOCK_UCI.network.protonvpn.protonvpn_ipv6_unmet, 'unreachable');
	cleanup();
	writefile(IFUP_OK, '');

	// (d) A connect clears it. A cause outliving the refusal would have the
	//     band explain a refusal that is no longer happening.
	uci = device({ require_ipv6: '1', locations: [ 'nl' ] });
	global.MOCK_UCI.network.protonvpn.protonvpn_ipv6_unmet = 'no_gateway';
	let ok_res = _apply.apply(uci);
	eq('the connect succeeded', ok_res.state, 'success');
	eq('and the stale cause is gone',
		global.MOCK_UCI.network.protonvpn.protonvpn_ipv6_unmet, null);
	cleanup();
}

// ── 14. the status object reports the requirement ────────────────────────
// Two fields, because they genuinely differ: under secure_core the option is
// set and does nothing, and a status that showed only one of them would
// either hide the setting or overstate it.
{
	global.MOCK_UCI = { network: { protonvpn: { '.type': 'interface',
		protonvpn_features: '' + F_V6 } } };
	let uci = cursor();
	let base = { name: 'main', interface: 'protonvpn', ipv6_mode: 'auto',
		hop_mode: 'standard', require_ipv6: true, enabled: true,
		source_networks: [ 'media' ], auto_routing: false, routing_table: '101' };
	let st = ipv6_state(uci, base, 'steered', true);
	eq('status reports the requirement', st.require_ipv6, true);
	eq('and that it is binding', st.require_ipv6_active, true);

	base.hop_mode = 'secure_core';
	let sc = ipv6_state(uci, base, 'steered', true);
	eq('under secure_core the option is still reported', sc.require_ipv6, true);
	eq('but reported as not binding', sc.require_ipv6_active, false);

	base.hop_mode = 'standard';
	base.auto_routing = true;
	let ar = ipv6_state(uci, base, 'auto', true);
	eq('under auto_routing the option is still reported', ar.require_ipv6, true);
	eq('but reported as not binding either', ar.require_ipv6_active, false);
	eq('and the state agrees about why IPv6 is not routed', ar.reason, 'auto_routing');

	base.auto_routing = false;
	base.require_ipv6 = false;
	let no = ipv6_state(uci, base, 'steered', true);
	eq('an unset option reports false', no.require_ipv6, false);
	eq('and is not binding', no.require_ipv6_active, false);
}

// ── 15. the cache hands the UI what it needs to render the choice ────────
{
	// The page decides the per-server IPv6 badge and, with the requirement on,
	// which gateways it may offer at all. Both read bit 16 off the trimmed
	// relay, so the bitmask has to survive the trim.
	let t = _cache.trim_relay(cache.countries[0].cities[0].relays[0]);
	eq('trim_relay carries the Features bitmask', t.features, F_V6);
	ok('so the UI can decide from it', relay_ipv6_capable(t) == true);
	eq('and the public key never leaves the cache', t.public_key, null);

	// "N of M", not a yes/no: a city where 1 of 3 gateways carries the bit is
	// a different offer from one where all 3 do, and a boolean calls both yes.
	let tree = _cache.locations_tree(cache);
	let by = {};
	for (let c in tree)
		by[c.code] = c;
	eq('a mixed country counts its eligible gateways', by.nl.ipv6_count, 2);
	eq('against the standard total', by.nl.standard_count, 3);
	eq('the city carries the same pair', by.nl.cities[0].ipv6_count, 2);
	eq('a country with none says zero', by.de.ipv6_count, 0);
	ok('but is still listed, so the refusal is explicable',
		by.de.gateway_count == 2);
	// Secure Core and Tor logicals never carry the bit; counting them as
	// eligible would promise IPv6 in modes that cannot deliver it.
	eq('secure core counts no IPv6 gateways', by.ch.ipv6_count, 0);
	eq('tor counts no IPv6 gateways', by.fr.ipv6_count, 0);
}

_apply.connect_one = real_connect_one;
unlink(IFUP_OK);
cleanup();

printf('%s\n', fails ? 'SOME IPV6 REQUIREMENT TESTS FAILED' : 'ALL IPV6 REQUIREMENT TESTS PASSED');
exit(fails ? 1 : 0);

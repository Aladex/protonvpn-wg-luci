#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Adaptive IPv6: ProtonVPN forwards IPv6 only on the gateways that carry bit
// 16 of the logical Features bitmask, so every decision here hangs off the
// `protonvpn_features` stamp write_relay leaves on the interface. These tests
// pin down that the lookup rule appears ONLY with the bit, that the prohibit
// rule never disappears while the mode is not 'off', and that the ULA
// addressing written onto networks the module does not own is given back.
// Uses the mock 'uci'/'ubus' modules; globals `KEY` and `fixture` come from
// run.sh.

'use strict';

// Runtime scratch dir of THIS run (tests/run.sh gives each run its own, so
// two suites can execute concurrently); never the shared /tmp.
const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';

import { unlink, mkdir, rmdir, writefile } from 'fs';
import { cursor } from 'uci';

const _cmn = require('protonvpn.common');
const _api = require('protonvpn.api');
const _apply = require('protonvpn.apply');

// Marker that lets tests/stubs/ifup report success, so a connect can be driven
// to completion off-device. Created and removed by the tests that need it.
const IFUP_OK = (getenv('PROTONVPN_STATE_DIR') || '/tmp/protonvpn-test-state') + '/ifup-ok';

// Rotation has to be able to redo the IPv6 decision after it moves the peer,
// but off-device `ifup` always fails, so connect_one never reports success and
// the reconciliation branch would never run. Replace it through the module
// namespace BEFORE protonvpn.rotate captures it — the same seam test_instances
// uses to stub the API out of rpcd.
const real_connect_one = _apply.connect_one;
_apply.connect_one = function(uci, iface, relay, s) {
	_apply.write_relay(uci, iface, relay, s);
	uci.commit('network');
	return true;
};
const _rotate = require('protonvpn.rotate');

const _routing = require('protonvpn.routing');
const enforce_routing = _routing.enforce,
      detect_routing = _routing.detect,
      reconcile_ipv6 = _routing.reconcile_ipv6,
      ipv6_state = _routing.ipv6_state;

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

// Features values as Proton really sends them: 28 = IPv6|Streaming|P2P is the
// most common combination on a v6-capable gateway, 12 = Streaming|P2P is the
// same server without the bit.
const F_V6 = 28;
const F_NO_V6 = 12;

// ── Fixtures ─────────────────────────────────────────────────────────────

// Settings for a steered instance ('media' leaves through pv_media).
function ssteer(over) {
	let base = { name: 'main', interface: 'pv_media', routing_table: '101',
		auto_routing: false, killswitch: false, ipv6_mode: 'block',
		vpn_dns: 'off', source_networks: [ 'media' ], enabled: true };
	for (let k in over)
		base[k] = over[k];
	return base;
}

// A router with one steered network ('media'), one spare ('guest') and the
// usual lan/wan zones. `features` is the stamp write_relay would have left.
function mkall(features) {
	let iface = { '.type': 'interface', proto: 'wireguard', private_key: KEY };
	if (features != null)
		iface.protonvpn_features = '' + features;
	return { network: {
		globals: { '.type': 'globals', ula_prefix: 'fd7a:1b2c:3d4e::/48' },
		pv_media: iface,
		peer_m: { '.type': 'wireguard_pv_media', interface: 'pv_media',
			endpoint_host: '138.199.7.129' },
		media: { '.type': 'interface', proto: 'static', ipaddr: '10.9.1.1',
			netmask: '255.255.255.0', device: 'br-media' },
		// A guest-style bridge with IPv6 turned off at the device level, the
		// state a network is in when IPv6 was never used on it.
		dev_media: { '.type': 'device', name: 'br-media', type: 'bridge', ipv6: '0' },
		guest: { '.type': 'interface', proto: 'static', ipaddr: '10.9.2.1/24' }
	}, firewall: {
		zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] },
		zmedia: { '.type': 'zone', name: 'media', network: [ 'media' ] }
	}, dhcp: {
		// The state a network is in when IPv6 was never used on it — which is
		// what the old block-IPv6 policy left behind, and the configuration
		// this feature has to work on.
		media: { '.type': 'dhcp', interface: 'media', ra: 'disabled', dhcpv6: 'disabled' },
		guest: { '.type': 'dhcp', interface: 'guest', ra: 'disabled', dhcpv6: 'disabled' }
	} };
}

// The COMBINED IPv6 state of one network: the opening, the ULA addressing and
// the announcement. Asserting only one of them is how a network left
// advertising an IPv6 default route it could not use stayed invisible — the
// three have to appear and disappear together, so tests check them together.
function v6_state(net) {
	let n = global.MOCK_UCI.network[net] || {};
	let ra = null;
	for (let k in (global.MOCK_UCI.dhcp || {}))
		if (global.MOCK_UCI.dhcp[k].interface == net)
			ra = global.MOCK_UCI.dhcp[k].ra;
	let nd = 0;
	for (let k in (global.MOCK_UCI.firewall || {})) {
		let sec = global.MOCK_UCI.firewall[k];
		if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
		    sec.protonvpn_role == 'icmpv6_nd')
			nd++;
	}
	return { nd: nd, ip6assign: n.ip6assign, ip6class: n.ip6class,
		delegate: n.delegate, ra: ra };
}

// Move network section `name` to the front of the table. uci.foreach walks
// sections in the order the config file lists them, and the mock walks the
// object in insertion order — so the order a fixture adds its networks in IS
// the ordering under test. Several of these tests turn on which co-tenant of a
// shared device comes first, and a fixture that only ever produces the benign
// order is a test that cannot fail.
function net_first(name) {
	let old = global.MOCK_UCI.network, fresh = {};
	fresh[name] = old[name];
	for (let k in old)
		if (k != name)
			fresh[k] = old[k];
	global.MOCK_UCI.network = fresh;
}

// Stamped rule6 sections of one role.
function rules6(role, iface) {
	let out = [];
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'rule6' && sec.protonvpn_managed == '1' &&
		    sec.protonvpn_role == role && sec.protonvpn_iface == iface)
			push(out, sec);
	}
	return out;
}

// ── 1. the option itself ─────────────────────────────────────────────────
{
	eq('ipv6_mode accepts block', _cmn.validate_ipv6_mode('block'), 'block');
	eq('ipv6_mode accepts auto', _cmn.validate_ipv6_mode('auto'), 'auto');
	eq('ipv6_mode accepts off', _cmn.validate_ipv6_mode('off'), 'off');
	eq('ipv6_mode refuses anything else', _cmn.validate_ipv6_mode('1'), null);

	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn' } } };
	let uci = cursor();
	eq('ipv6_mode defaults to block', _cmn.load_settings(uci).ipv6_mode, 'block');
	global.MOCK_UCI.protonvpn.main.ipv6_mode = 'auto';
	eq('ipv6_mode is read from the config', _cmn.load_settings(uci).ipv6_mode, 'auto');
	// Garbage must not silently become 'auto'; the safe side is a block.
	global.MOCK_UCI.protonvpn.main.ipv6_mode = 'yes please';
	eq('an invalid ipv6_mode falls back to block', _cmn.load_settings(uci).ipv6_mode, 'block');
	// The boolean this option replaced is gone: one source of truth.
	global.MOCK_UCI.protonvpn.main.ipv6_mode = null;
	global.MOCK_UCI.protonvpn.main.block_ipv6 = '0';
	eq('the legacy block_ipv6 no longer steers anything',
		_cmn.load_settings(uci).ipv6_mode, 'block');
	eq('and is not carried in the settings', _cmn.load_settings(uci).block_ipv6, null);
}

// ── 2. the feature stamp ─────────────────────────────────────────────────
{
	global.MOCK_UCI = { network: { pv_media: { '.type': 'interface' } } };
	let uci = cursor();
	ok('no stamp means no IPv6', _cmn.iface_ipv6_capable(uci, 'pv_media') == false);
	global.MOCK_UCI.network.pv_media.protonvpn_features = '' + F_NO_V6;
	ok('a gateway without bit 16 has no IPv6', _cmn.iface_ipv6_capable(uci, 'pv_media') == false);
	global.MOCK_UCI.network.pv_media.protonvpn_features = '' + F_V6;
	ok('a gateway with bit 16 has IPv6', _cmn.iface_ipv6_capable(uci, 'pv_media') == true);
	// Garbage is not a number, and "unknown" must resolve to the safe side.
	global.MOCK_UCI.network.pv_media.protonvpn_features = 'lots';
	ok('an unparsable stamp means no IPv6', _cmn.iface_ipv6_capable(uci, 'pv_media') == false);
}

// ── 3. write_relay stamps the bitmask ────────────────────────────────────
{
	global.MOCK_UCI = {
		protonvpn: { main: { '.type': 'instance', interface: 'pv_media' } },
		network: { pv_media: { '.type': 'interface', proto: 'wireguard', private_key: KEY } }
	};
	let uci = cursor();
	let s = _cmn.load_settings(uci);
	_apply.write_relay(uci, 'pv_media', { name: 'NL#1', hostname: 'n1', ip_address: '1.2.3.4',
		public_key: KEY, features: F_V6, country_code: 'nl', city_code: 'nl-amsterdam' }, s);
	eq('write_relay stamps the raw Features bitmask',
		global.MOCK_UCI.network.pv_media.protonvpn_features, '' + F_V6);

	// A relay from a cache written before features were kept must not be read
	// as "IPv6 capable" — the stamp has to say 0, not vanish.
	_apply.write_relay(uci, 'pv_media', { name: 'NL#2', hostname: 'n2', ip_address: '1.2.3.5',
		public_key: KEY, country_code: 'nl', city_code: 'nl-amsterdam' }, s);
	eq('a relay without features stamps zero',
		global.MOCK_UCI.network.pv_media.protonvpn_features, '0');
	ok('and zero is not IPv6 capable', _cmn.iface_ipv6_capable(uci, 'pv_media') == false);

	// The stamp describes the peer's gateway, so a rollback has to take it
	// back with the peer — otherwise the IPv6 decision keeps pointing at a
	// gateway that is no longer connected.
	_apply.write_relay(uci, 'pv_media', { name: 'NL#3', hostname: 'n3', ip_address: '1.2.3.6',
		public_key: KEY, features: F_V6, country_code: 'nl', city_code: 'nl-amsterdam' }, s);
	let saved = _apply.current_peer(uci, 'pv_media');
	eq('current_peer snapshots the features stamp', saved.features, '' + F_V6);
	_apply.write_relay(uci, 'pv_media', { name: 'NL#4', hostname: 'n4', ip_address: '1.2.3.7',
		public_key: KEY, features: F_NO_V6, country_code: 'nl', city_code: 'nl-amsterdam' }, s);
	_apply.restore_peer(uci, 'pv_media', saved);
	eq('restore_peer puts the features stamp back',
		global.MOCK_UCI.network.pv_media.protonvpn_features, '' + F_V6);
}

// ── 4. auto + the bit: lookup AND prohibit ───────────────────────────────
// The prohibit at 21000 is the v6 kill switch: it sits below the lookup but
// above `main`, so a down tunnel stops there instead of leaking to the ISP
// default route. It must never be traded away for the lookup.
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));

	let look = rules6('steer_v6_lookup', 'pv_media');
	let stop = rules6('steer_v6', 'pv_media');
	eq('auto+bit: one lookup rule for the steered network', length(look), 1);
	eq('auto+bit: the lookup targets the instance table', look[0] ? look[0].lookup : null, '101');
	eq('auto+bit: on the steered network', look[0] ? look[0]['in'] : null, 'media');
	eq('auto+bit: at priority 20000', look[0] ? look[0].priority : null, '20000');
	eq('auto+bit: the prohibit rule is still there', length(stop), 1);
	eq('auto+bit: prohibit sits below the lookup', stop[0] ? stop[0].priority : null, '21000');
	eq('auto+bit: and really prohibits', stop[0] ? stop[0].action : null, 'prohibit');

	// Two runs in a row must not create a second pair.
	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('auto+bit: idempotent', res.changed_network || res.changed_firewall, false);
}

// ── 5. auto without the bit, and auto without a stamp ────────────────────
{
	global.MOCK_UCI = mkall(F_NO_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('auto+no bit: no lookup rule', length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('auto+no bit: the prohibit rule is there', length(rules6('steer_v6', 'pv_media')), 1);

	// An interface written by a version that did not stamp the bitmask: the
	// unknown must resolve to "no IPv6", never to a black hole.
	global.MOCK_UCI = mkall(null);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('auto+no stamp: no lookup rule', length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('auto+no stamp: the prohibit rule is there', length(rules6('steer_v6', 'pv_media')), 1);
}

// ── 6. block and off keep the behaviour they always had ──────────────────
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('block: never a lookup rule, bit or no bit', length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('block: the prohibit rule is there', length(rules6('steer_v6', 'pv_media')), 1);
	ok('block: detection reports the v6 block', detect_routing(uci, ssteer({ ipv6_mode: 'block' }), false).ipv6_block);

	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ ipv6_mode: 'off' }));
	eq('off: no lookup rule', length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('off: no prohibit rule either', length(rules6('steer_v6', 'pv_media')), 0);
	ok('off: detection reports no v6 block', !detect_routing(uci, ssteer({ ipv6_mode: 'off' }), false).ipv6_block);

	// Switching from auto back to off has to take the rules away again.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	pristine = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'off' }));
	eq('off after auto: lookup removed', length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('off after auto: prohibit removed', length(rules6('steer_v6', 'pv_media')), 0);
}

// ── 7. auto_routing wins: the adaptive scheme is steered-only ────────────
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let s = ssteer({ ipv6_mode: 'auto', auto_routing: true, source_networks: [] });
	enforce_routing(uci, s);
	eq('auto_routing: no steered lookup rule', length(rules6('steer_v6_lookup', 'pv_media')), 0);
	let det = detect_routing(uci, s, false);
	eq('auto_routing: mode is auto', det.mode, 'auto');
	ok('auto_routing: the firewall IPv6 block is installed, exactly as in block mode',
		det.ipv6_block);
	eq('auto_routing: and the status says why', ipv6_state(uci, s, det.mode).reason, 'auto_routing');

	// Even with source networks still listed in the config, auto_routing wins
	// and there is no steering to hang either rule on — the firewall's IPv6
	// block does that job in this mode.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', auto_routing: true }));
	eq('auto_routing: no steered lookup even with networks listed',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('auto_routing: and no steered prohibit either',
		length(rules6('steer_v6', 'pv_media')), 0);

	// Steering without the routing table it needs is not steering: nothing is
	// created, and a prohibit here would block IPv6 on a network that is not
	// going through the tunnel at all.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto', routing_table: '' }));
	eq('no table: no lookup rule', length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('no table: and no prohibit on a network we do not steer',
		length(rules6('steer_v6', 'pv_media')), 0);
	ok('no table: the user is told why', length(res.notes) > 0);
}

// ── 8. ULA addressing on the steered networks ────────────────────────────
// The client must not hold an ISP GUA next to the tunnel: Happy Eyeballs would
// prefer it and IPv6 would leave through the WAN. These are sections the
// module does not own, so the previous values are recorded and given back.
{
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.ip6assign = '60';   // a value the user set
	let uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);

	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let media = global.MOCK_UCI.network.media;
	eq('ula: ip6assign is a /64', media.ip6assign, '64');
	eq('ula: the prefix comes from the router ULA', media.ip6class, 'local');
	eq('ula: the ISP delegation is not passed on', media.delegate, '0');
	eq('ula: the edit is stamped with its owner', media.protonvpn_managed_v6, 'pv_media');
	eq('ula: the user value is recorded', media.protonvpn_saved_ip6assign, '60');
	ok('ula: an option that had no value records none', media.protonvpn_saved_ip6class == null);
	eq('ula: an untouched network stays untouched', global.MOCK_UCI.network.guest.ip6assign, null);

	// The zone the module owns NATs it, because Proton hands out one fixed
	// /128 and there is no prefix to delegate.
	let masq6 = null;
	for (let k in global.MOCK_UCI.firewall) {
		let z = global.MOCK_UCI.firewall[k];
		if (z['.type'] == 'zone' && z.protonvpn_managed == '1' && z.protonvpn_iface == 'pv_media')
			masq6 = z.masq6;
	}
	eq('ula: the managed zone masquerades IPv6', masq6, '1');

	// A zone stamped by a version that predates NAT6 has to pick it up on the
	// next apply, or an upgraded router would route IPv6 into a zone that
	// cannot translate it and every steered client would send an unroutable
	// ULA source address down the tunnel.
	let zname = null;
	for (let k in global.MOCK_UCI.firewall) {
		let z = global.MOCK_UCI.firewall[k];
		if (z['.type'] == 'zone' && z.protonvpn_managed == '1' && z.protonvpn_iface == 'pv_media')
			zname = k;
	}
	delete global.MOCK_UCI.firewall[zname].masq6;
	let again = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('ula: an older managed zone gains NAT6 on the next apply',
		global.MOCK_UCI.firewall[zname].masq6, '1');
	ok('ula: and the firewall is reloaded for it', again.changed_firewall == true);

	// Turning auto off gives the section back exactly as it was.
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('ula: the user value is restored', global.MOCK_UCI.network.media.ip6assign, '60');
	ok('ula: what had no value is removed again', global.MOCK_UCI.network.media.ip6class == null);
	ok('ula: and so is the delegate we wrote', global.MOCK_UCI.network.media.delegate == null);
	ok('ula: the stamp is gone', global.MOCK_UCI.network.media.protonvpn_managed_v6 == null);
	ok('ula: and the record with it', global.MOCK_UCI.network.media.protonvpn_saved_ip6assign == null);

	// Disabling the instance gives the addressing back — those sections are
	// the user's. The v6 prohibit is NOT part of that: see section 12.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	ok('ula: a disabled instance gives the addressing back',
		global.MOCK_UCI.network.media.ip6assign == null &&
		global.MOCK_UCI.network.media.ip6class == null &&
		global.MOCK_UCI.network.media.delegate == null);
	ok('ula: and takes its stamp with it',
		global.MOCK_UCI.network.media.protonvpn_managed_v6 == null);

	// A value the user changed AFTER us is theirs, not ours to put back.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	global.MOCK_UCI.network.media.ip6assign = '60';
	enforce_routing(uci, ssteer({ ipv6_mode: 'off' }));
	eq('ula: a user edit after ours survives teardown',
		global.MOCK_UCI.network.media.ip6assign, '60');
}

// ── 9. rotation reconciles the rules against the new gateway ─────────────
// rotate() writes the peer itself and never ran the routing enforcement, so
// rotating from a bit-16 gateway onto one without the bit used to leave the
// lookup rule in place — a black hole for every steered client.
{
	let cdir = RUN + '/pvtest6_' + time();
	mkdir(cdir);
	let cpath = cdir + '/protonvpn_servers_cache.json';
	let mkrelay = function(name, ip, features) {
		return { name: name, hostname: name + '.protonvpn.net', ip_address: ip,
			public_key: KEY, location: 'nl-amsterdam', country_code: 'nl',
			city_code: 'nl-amsterdam', port: 51820, load: 10, score: 1,
			features: features, tier: 2, secure_core: false, tor: false, active: true };
	};
	let write_cache = function(features) {
		_cmn.atomic_write(cpath, sprintf('%J', {
			countries: [ { code: 'nl', name: 'NL', gateway_count: 1, cities: [
				{ code: 'nl-amsterdam', name: 'Amsterdam', country: 'NL', country_code: 'nl',
					gateway_count: 1, relays: [ mkrelay('NL#9', '9.9.9.9', features) ] } ] } ],
			stats: { countries: 1, cities: 1, gateways: 1, servers_seen: 1 },
			cached_at: time(), schema_version: _cmn.CACHE_SCHEMA_VERSION,
			cache_info: { created: _cmn.iso_ts(), expires_at: _cmn.iso_ts(time() + 86400) }
		}));
	};

	let setup = function(features) {
		global.MOCK_UCI = mkall(features);
		global.MOCK_UCI.protonvpn = { main: { '.type': 'instance', interface: 'pv_media',
			country_code: 'nl', city_code: '', cache_dir: cdir, enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] } };
		global.MOCK_UCI.network.peer_m.protonvpn_gateway = 'NL#1';
		return cursor();
	};

	// Start on a gateway WITH IPv6 and rotate onto one WITHOUT.
	unlink(RUN + '/protonvpn_rotate.lock');
	let uci = setup(F_V6);
	enforce_routing(uci, _cmn.load_settings(uci));
	eq('rotation: the lookup rule exists before rotating',
		length(rules6('steer_v6_lookup', 'pv_media')), 1);
	write_cache(F_NO_V6);
	let r = _rotate.rotate(cursor());
	eq('rotation: moved to the other gateway', r.server, 'NL#9');
	eq('rotation: the new gateway has no IPv6', global.MOCK_UCI.network.pv_media.protonvpn_features, '' + F_NO_V6);
	eq('rotation: the lookup rule is withdrawn',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('rotation: the prohibit rule stays, so nothing leaks',
		length(rules6('steer_v6', 'pv_media')), 1);

	// And the other way round: onto a gateway that does forward IPv6.
	unlink(RUN + '/protonvpn_rotate.lock');
	uci = setup(F_NO_V6);
	enforce_routing(uci, _cmn.load_settings(uci));
	eq('rotation: no lookup rule on a no-bit gateway',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	write_cache(F_V6);
	r = _rotate.rotate(cursor());
	eq('rotation: moved to the v6 gateway', r.server, 'NL#9');
	eq('rotation: the lookup rule appears', length(rules6('steer_v6_lookup', 'pv_media')), 1);
	eq('rotation: and the prohibit is still below it',
		length(rules6('steer_v6', 'pv_media')), 1);

	// The narrow piece rotation uses, driven directly: only the stamp moves.
	uci = setup(F_V6);
	enforce_routing(uci, _cmn.load_settings(uci));
	global.MOCK_UCI.network.pv_media.protonvpn_features = '' + F_NO_V6;
	ok('reconcile_ipv6 reports the change', reconcile_ipv6(uci, _cmn.load_settings(uci)) == true);
	eq('reconcile_ipv6 withdrew the lookup', length(rules6('steer_v6_lookup', 'pv_media')), 0);
	ok('reconcile_ipv6 is idempotent', reconcile_ipv6(uci, _cmn.load_settings(uci)) == false);
	eq('reconcile_ipv6 left the prohibit alone', length(rules6('steer_v6', 'pv_media')), 1);
	eq('reconcile_ipv6 left the ULA addressing alone',
		global.MOCK_UCI.network.media.ip6assign, '64');

	unlink(RUN + '/protonvpn_rotate.lock');
	unlink(cpath);
	rmdir(cdir);
}

// ── 10. what the status card says, and why ───────────────────────────────
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let s = ssteer({ ipv6_mode: 'auto' });
	enforce_routing(uci, s);
	let st = ipv6_state(uci, s, null);
	ok('status: IPv6 is active', st.active == true);
	eq('status: with no reason to give', st.reason, null);
	eq('status: and the mode is reported', st.mode, 'auto');
	ok('status: the gateway capability is reported', st.gateway_ipv6 == true);

	global.MOCK_UCI.network.pv_media.protonvpn_features = '' + F_NO_V6;
	st = ipv6_state(uci, ssteer({ ipv6_mode: 'auto' }), null);
	ok('status: no bit, not active', st.active == false);
	eq('status: because the gateway has no IPv6', st.reason, 'gateway_no_ipv6');

	eq('status: block says so', ipv6_state(uci, ssteer({ ipv6_mode: 'block' }), null).reason, 'mode_block');
	eq('status: off says so', ipv6_state(uci, ssteer({ ipv6_mode: 'off' }), null).reason, 'mode_off');
	eq('status: a disabled instance says so',
		ipv6_state(uci, ssteer({ ipv6_mode: 'auto', enabled: false }), null).reason, 'disabled');
	eq('status: no steered network says so',
		ipv6_state(uci, ssteer({ ipv6_mode: 'auto', source_networks: [] }), null).reason, 'not_steered');

	// The runtime status object carries it, so the UI has one place to read.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.protonvpn = { main: { '.type': 'instance', interface: 'pv_media',
		enabled: '1', routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] } };
	uci = cursor();
	let full = require('protonvpn.status').status(uci, 'main');
	ok('status: the report carries an ipv6 block', type(full.ipv6) == 'object');
	eq('status: with the mode', full.ipv6.mode, 'auto');
	ok('status: and the gateway capability', full.ipv6.gateway_ipv6 == true);
}

// ── 11. a SUCCESSFUL apply reconciles against the gateway it landed on ───
// enforce_routing runs at the TOP of apply, before a peer is written, so it
// can only judge the gateway being left behind. connect_one then stamps the
// new one and every success path returns. Without a reconciliation after the
// connect, applying from a bit-16 gateway onto one without the bit leaves the
// priority-20000 lookup installed and black-holes IPv6 for every steered
// client — precisely what the adaptive mode exists to prevent.
{
	let cdir = RUN + '/pvtest6a_' + time();
	mkdir(cdir);
	let cpath = cdir + '/protonvpn_servers_cache.json';

	// bring_up() shells out to `ifup`, which cannot work off-device; the stub
	// on PATH succeeds only while this marker exists (see tests/stubs/ifup).
	// Without it apply can never reach a success return at all.
	writefile(IFUP_OK, '');

	// ensure_keypair registers a certificate on first use — stub the call so
	// the test needs no account, exactly as test_rotate does.
	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: time() + 1800, session_expires_at: time() + 86400,
		scope: 'vpn', twofa: false });
	let real_create = _api.certificate_create;
	_api.certificate_create = function(pubkey, mode, days) {
		return { ok: true, serial: '1', mode: mode,
			expires_at: time() + 365 * 86400, refresh_at: time() + 300 * 86400 };
	};

	let write_cache = function(name, features) {
		_cmn.atomic_write(cpath, sprintf('%J', {
			countries: [ { code: 'nl', name: 'NL', gateway_count: 1, cities: [
				{ code: 'nl-amsterdam', name: 'Amsterdam', country: 'NL', country_code: 'nl',
					gateway_count: 1, relays: [ {
						name: name, hostname: name + '.protonvpn.net', ip_address: '9.9.9.9',
						public_key: KEY, location: 'nl-amsterdam', country_code: 'nl',
						city_code: 'nl-amsterdam', port: 51820, load: 10, score: 1,
						features: features, tier: 2, secure_core: false, tor: false,
						active: true } ] } ] } ],
			stats: { countries: 1, cities: 1, gateways: 1, servers_seen: 1 },
			cached_at: time(), schema_version: _cmn.CACHE_SCHEMA_VERSION,
			cache_info: { created: _cmn.iso_ts(), expires_at: _cmn.iso_ts(time() + 86400) }
		}));
	};

	let setup = function(stamp, fixed) {
		global.MOCK_UCI = mkall(stamp);
		global.MOCK_UCI.network.pv_media.private_key = KEY;
		global.MOCK_UCI.protonvpn = { main: { '.type': 'instance', interface: 'pv_media',
			country_code: 'nl', city_code: '', cache_dir: cdir, enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ],
			verify_timeout: '2' } };
		if (fixed)
			global.MOCK_UCI.protonvpn.main.fixed_server = fixed;
		let uci = cursor();
		// The state the router is in before the apply: rules reconciled against
		// the gateway currently stamped on the interface.
		enforce_routing(uci, _cmn.load_settings(uci));
		return uci;
	};

	// bit-16 gateway -> no-bit gateway, over the pinned-server success path.
	write_cache('NL#41', F_NO_V6);
	let uci = setup(F_V6, 'NL#41');
	eq('apply: the lookup rule is installed before the apply',
		length(rules6('steer_v6_lookup', 'pv_media')), 1);
	let r = _apply.apply(uci, 'main');
	eq('apply: the pinned server connected', r.state, 'success');
	eq('apply: the new gateway stamp is on the interface',
		global.MOCK_UCI.network.pv_media.protonvpn_features, '' + F_NO_V6);
	eq('apply: the lookup rule is withdrawn for a gateway without IPv6',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('apply: and the prohibit still guards the steered network',
		length(rules6('steer_v6', 'pv_media')), 1);

	// no-bit gateway -> bit-16 gateway, over the candidate-loop success path
	// (a second return statement, and it used to skip the reconcile too).
	write_cache('NL#42', F_V6);
	uci = setup(F_NO_V6, null);
	eq('apply: no lookup rule before the apply',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	r = _apply.apply(uci, 'main');
	eq('apply: a candidate connected', r.state, 'success');
	eq('apply: the new gateway stamp is on the interface',
		global.MOCK_UCI.network.pv_media.protonvpn_features, '' + F_V6);
	eq('apply: the lookup rule appears for a gateway that forwards IPv6',
		length(rules6('steer_v6_lookup', 'pv_media')), 1);
	eq('apply: with the prohibit below it',
		length(rules6('steer_v6', 'pv_media')), 1);

	// A total failure: every candidate is written to the interface before
	// bring_up is even tried, so a failed apply with nothing to roll back to
	// leaves the interface stamped with a gateway this router never reached.
	// Acting on that stamp would install a lookup for a server that is not
	// connected, so the stamp has to go — no stamp means no IPv6.
	unlink(IFUP_OK);
	write_cache('NL#43', F_V6);
	uci = setup(F_V6, null);
	delete global.MOCK_UCI.network.peer_m;          // nothing to roll back to
	uci = cursor();
	eq('apply: a lookup is up before the failing apply',
		length(rules6('steer_v6_lookup', 'pv_media')), 1);
	r = _apply.apply(uci, 'main');
	eq('apply: a total failure is reported as one', r.state, 'failure');
	ok('apply: the unreachable gateway leaves no stamp behind',
		global.MOCK_UCI.network.pv_media.protonvpn_features == null);
	eq('apply: and no lookup rule survives for a server that never came up',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('apply: the prohibit is still there after a failed apply',
		length(rules6('steer_v6', 'pv_media')), 1);

	// A pinned server is never rolled back — the user asked for that one and
	// the next attempt should retry it — so the peer on the interface IS the
	// pinned gateway even when it fails to come up, and the rules have to
	// describe it. Pinning a gateway without IPv6 must withdraw the lookup
	// whether or not the interface managed to come up.
	write_cache('NL#45', F_NO_V6);
	uci = setup(F_V6, 'NL#45');
	eq('apply: the old gateway lookup is up before pinning',
		length(rules6('steer_v6_lookup', 'pv_media')), 1);
	r = _apply.apply(uci, 'main');
	ok('apply: the pinned server did not come up', r.state != 'success');
	eq('apply: the pinned gateway is on the interface anyway',
		global.MOCK_UCI.network.pv_media.protonvpn_features, '' + F_NO_V6);
	eq('apply: and its lack of IPv6 withdrew the lookup',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('apply: with the prohibit untouched',
		length(rules6('steer_v6', 'pv_media')), 1);

	// With a working peer to roll back to, the rules must describe THAT
	// gateway again — not the candidate that just failed.
	write_cache('NL#44', F_NO_V6);
	uci = setup(F_V6, null);
	eq('apply: the lookup is up for the gateway in use', length(rules6('steer_v6_lookup', 'pv_media')), 1);
	r = _apply.apply(uci, 'main');
	eq('apply: the failed candidate is rolled back', r.restored, true);
	eq('apply: the working gateway stamp is back',
		global.MOCK_UCI.network.pv_media.protonvpn_features, '' + F_V6);
	eq('apply: and its lookup rule with it', length(rules6('steer_v6_lookup', 'pv_media')), 1);

	_api.certificate_create = real_create;
	unlink(IFUP_OK);
	unlink(_api.SESSION_FILE);
	unlink((getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn') + '/certificate.json');
	unlink(cpath);
	rmdir(cdir);
}

// ── 12. the prohibit is a kill switch, so it outlives the instance ───────
// Removing it when the instance goes down is a leak: the steered clients still
// have IPv6, the lookup is gone, and the next rule they meet is `main` — where
// the ISP default route lives. 'off' is how a user says "stop guarding IPv6";
// a disabled instance is not 'off'.
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('disabled: lookup and prohibit are both up while enabled',
		length(rules6('steer_v6_lookup', 'pv_media')) + length(rules6('steer_v6', 'pv_media')), 2);

	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	eq('disabled: the lookup goes, nothing routes into a dead tunnel',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('disabled: the prohibit stays, so IPv6 cannot reach the ISP route',
		length(rules6('steer_v6', 'pv_media')), 1);
	let stop = rules6('steer_v6', 'pv_media');
	eq('disabled: and it is still the priority-21000 prohibit',
		stop[0] ? (stop[0].priority + '/' + stop[0].action) : null, '21000/prohibit');

	// Same for a disabled instance in plain 'block' mode.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'block', enabled: false }));
	eq('disabled: block keeps its prohibit too',
		length(rules6('steer_v6', 'pv_media')), 1);

	// 'off' is the one mode that really does take it away, disabled or not.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'off', enabled: false }));
	eq('disabled: off removes the prohibit, because that is what off means',
		length(rules6('steer_v6', 'pv_media')), 0);

	// Dropping the steering removes it as well: the rule names a network this
	// instance no longer has anything to do with.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [] }));
	eq('un-steering restores the pristine config', sprintf('%J', global.MOCK_UCI), pristine);

	// The real user action behind "disabled" is Disconnect, which is a
	// separate entry point into the same enforcement.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.protonvpn = { main: { '.type': 'instance', interface: 'pv_media',
		enabled: '1', routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] } };
	uci = cursor();
	enforce_routing(uci, _cmn.load_settings(uci));
	_apply.disconnect(uci, 'main');
	eq('disconnect: the lookup is withdrawn',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('disconnect: the prohibit survives the disconnect',
		length(rules6('steer_v6', 'pv_media')), 1);
}

// ── 13. a tunnel that is not there is not a reason to unguard IPv6 ───────
// There is no code path that reacts to the link going down — the rules are
// static netifd config — so what has to hold is that everything which CAN
// re-run the enforcement while the tunnel is gone keeps the prohibit.
{
	// The gateway stamp is gone (an interface rewritten by an older version,
	// or never applied): unknown capability resolves to no lookup, and the
	// guard stays.
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	delete global.MOCK_UCI.network.pv_media.protonvpn_features;
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('tunnel gone: no lookup without a known gateway',
		length(rules6('steer_v6_lookup', 'pv_media')), 0);
	eq('tunnel gone: the prohibit stays', length(rules6('steer_v6', 'pv_media')), 1);

	// The peer section itself is gone (tunnel torn down by hand).
	delete global.MOCK_UCI.network.peer_m;
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('peer gone: the prohibit still stands', length(rules6('steer_v6', 'pv_media')), 1);
}

// ── 14. two instances over one network: no tug of war on the addressing ──
// Nothing in the backend stops two instances from listing the same source
// network, and the ULA stamp records a single owner. Releasing ours must not
// pull the addressing out from under an instance that is still using it.
{
	let other = function(over) {
		let base = ssteer(over);
		base.interface = 'pv_guest';
		base.routing_table = '102';
		return base;
	};
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
		private_key: KEY, protonvpn_features: '' + F_V6 };
	// Both instances exist in the config, so the backend can see the overlap.
	global.MOCK_UCI.protonvpn = {
		main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
		guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
			routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
	};
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('overlap: the first instance owns the addressing',
		global.MOCK_UCI.network.media.protonvpn_managed_v6, 'pv_media');
	enforce_routing(uci, other({ ipv6_mode: 'auto' }));
	eq('overlap: the second does not steal the record',
		global.MOCK_UCI.network.media.protonvpn_managed_v6, 'pv_media');

	// Disabling the owner while the other is still enabled and still steering
	// that network: the addressing has to stay, and the record moves across so
	// the survivor can give it back later.
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	eq('overlap: the ULA survives the owner being disabled',
		global.MOCK_UCI.network.media.ip6assign, '64');
	eq('overlap: and the record is handed to the instance still using it',
		global.MOCK_UCI.network.media.protonvpn_managed_v6, 'pv_guest');

	// Once the survivor lets go too, the section goes back to the user.
	global.MOCK_UCI.protonvpn.main.enabled = '0';
	uci = cursor();
	enforce_routing(uci, other({ ipv6_mode: 'auto', enabled: false }));
	ok('overlap: the last one out restores the addressing',
		global.MOCK_UCI.network.media.ip6assign == null &&
		global.MOCK_UCI.network.media.protonvpn_managed_v6 == null);
}

// ── 15. status does not claim IPv6 is working on a dead tunnel ───────────
{
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.protonvpn = { main: { '.type': 'instance', interface: 'pv_media',
		enabled: '1', routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] } };
	let uci = cursor();
	enforce_routing(uci, _cmn.load_settings(uci));

	// netifd says the interface is down: the rules are still installed, but
	// nothing is going through the tunnel, and the card must not say it is.
	global.MOCK_UBUS = { 'network.interface.pv_media~status': { up: false } };
	let st = require('protonvpn.status').status(uci, 'main');
	eq('status: a down interface is not carrying IPv6', st.ipv6.active, false);
	eq('status: and says the tunnel is the reason', st.ipv6.reason, 'tunnel_down');
	eq('status: while still reporting the gateway can do IPv6', st.ipv6.gateway_ipv6, true);

	// The configuration-only answer is unchanged for callers with no runtime
	// view (enforce/rotate never have one).
	let s = _cmn.load_settings(uci);
	ok('status: told the tunnel is up, it is active', ipv6_state(uci, s, null, true).active == true);
	ok('status: asked without a runtime view, it answers from the config',
		ipv6_state(uci, s, null).active == true);
	global.MOCK_UBUS = null;
}

// ── 16. the ULA has to actually reach the clients ────────────────────────
// Setting ip6assign/ip6class on the interface allocates a prefix; it does not
// announce one. On a network where IPv6 was never used — `ra 'disabled'`,
// which is exactly what the old block-IPv6 policy encouraged — the client ends
// up with no IPv6 address at all and the whole adaptive mode does nothing
// visible. Not dangerous (clients stay on IPv4), but not working either.
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);

	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let d = global.MOCK_UCI.dhcp.media;
	eq('ra: router advertisements are switched on', d.ra, 'server');
	// The A flag on the prefix information option is what makes a client
	// build an address for itself (odhcpd router.c: ra_slaac gates
	// ND_OPT_PI_FLAG_AUTO).
	eq('ra: with SLAAC, which is what gives the client its address', d.ra_slaac, '1');
	// Without this the router advertises a lifetime of 0 and is not a default
	// router: odhcpd only counts a ULA as a usable prefix when ra_default is
	// set, so the client would get an address it cannot route with.
	eq('ra: and a default route, which a ULA-only prefix does not get for free',
		d.ra_default, '1');
	eq('ra: the section is stamped with its owner', d.protonvpn_managed_v6, 'pv_media');
	eq('ra: the previous value is recorded', d.protonvpn_saved_ra, 'disabled');
	ok('ra: an option that had no value records none', d.protonvpn_saved_ra_slaac == null);
	// DHCPv6 is deliberately not touched: SLAAC supplies the address and the
	// RA supplies the route, so stateful assignment buys nothing here.
	ok('ra: DHCPv6 is left exactly as the user had it',
		d.dhcpv6 == 'disabled' && d.protonvpn_saved_dhcpv6 == null);
	ok('ra: the caller is told to reload odhcpd', res.changed_dhcp == true);
	eq('ra: a network this instance does not steer is untouched',
		global.MOCK_UCI.dhcp.guest.ra, 'disabled');

	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	ok('ra: a second run changes nothing',
		res.changed_dhcp == false && res.changed_network == false);

	// Leaving 'auto' gives the section back: the prefix is gone, so announcing
	// it would be a lie.
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('ra: teardown puts the user value back', global.MOCK_UCI.dhcp.media.ra, 'disabled');
	ok('ra: and removes what never had one',
		global.MOCK_UCI.dhcp.media.ra_slaac == null &&
		global.MOCK_UCI.dhcp.media.ra_default == null);
	ok('ra: and the stamp with it', global.MOCK_UCI.dhcp.media.protonvpn_managed_v6 == null);

	// A full release has to leave the whole config byte for byte as found.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	pristine = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [] }));
	eq('ra: un-steering restores the pristine config including dhcp',
		sprintf('%J', global.MOCK_UCI), pristine);

	// Disabling the instance is the same release.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	eq('ra: a disabled instance stops announcing', global.MOCK_UCI.dhcp.media.ra, 'disabled');

	// A value the user changed after us is theirs, exactly as on the network
	// section: we only undo what is still ours.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	global.MOCK_UCI.dhcp.media.ra = 'relay';
	global.MOCK_UCI.dhcp.media.ra_default = '2';
	enforce_routing(uci, ssteer({ ipv6_mode: 'off' }));
	eq('ra: a user edit after ours survives teardown', global.MOCK_UCI.dhcp.media.ra, 'relay');
	eq('ra: and so does a changed ra_default', global.MOCK_UCI.dhcp.media.ra_default, '2');

	// A steered network with no dhcp section at all cannot be announced to.
	// Saying so is the whole point: silently doing nothing is the bug.
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.dhcp.media;
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let said = false;
	for (let n in res.notes)
		if (index(n, 'media') >= 0 && index(n, 'dhcp') >= 0)
			said = true;
	ok('ra: a network without a dhcp section is reported, not ignored', said);
	eq('ra: and the addressing is still applied', global.MOCK_UCI.network.media.ip6assign, '64');

	// Without a ULA prefix on the router there is nothing for ip6class 'local'
	// to draw from, so the client gets no address however the RA is set up.
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.network.globals;
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	said = false;
	for (let n in res.notes)
		if (index(n, 'ULA') >= 0)
			said = true;
	ok('ra: a router with no ULA prefix is reported', said);
}

// ── 17. only an instance that really steers can inherit the addressing ───
// The successor test used to read the options — enabled, ipv6_mode, table,
// source_network — without asking whether that instance steers ANYTHING. An
// instance with auto_routing on, or with a hand-built routing scheme, does
// not, however its source_network list reads, so handing the record to it
// strands the addressing on a section nobody maintains any more.
{
	let mk2 = function(over_guest) {
		global.MOCK_UCI = mkall(F_V6);
		global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, protonvpn_features: '' + F_V6 };
		global.MOCK_UCI.protonvpn = {
			main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
				routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
			guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
				routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
		};
		for (let k in over_guest)
			global.MOCK_UCI.protonvpn.guest[k] = over_guest[k];
		return cursor();
	};
	let settings_of = function(uci, n) { return _cmn.load_settings(uci, n); };

	// The other instance routes everything instead of steering: its stale
	// source_network entry must not make it an heir.
	let uci = mk2({ auto_routing: '1' });
	enforce_routing(uci, settings_of(uci, 'main'));
	eq('heir: the owner claimed the addressing',
		global.MOCK_UCI.network.media.protonvpn_managed_v6, 'pv_media');
	global.MOCK_UCI.protonvpn.main.enabled = '0';
	uci = cursor();
	enforce_routing(uci, settings_of(uci, 'main'));
	ok('heir: an auto_routing instance does not inherit',
		global.MOCK_UCI.network.media.protonvpn_managed_v6 == null);
	ok('heir: so the addressing goes back to the user',
		global.MOCK_UCI.network.media.ip6assign == null);
	eq('heir: and so does the announcement', global.MOCK_UCI.dhcp.media.ra, 'disabled');

	// Same for an instance whose routing the user has taken over by hand.
	uci = mk2({});
	enforce_routing(uci, settings_of(uci, 'main'));
	global.MOCK_UCI.network.ownroute = { '.type': 'route', interface: 'pv_guest',
		target: '0.0.0.0/0' };
	global.MOCK_UCI.protonvpn.main.enabled = '0';
	uci = cursor();
	enforce_routing(uci, settings_of(uci, 'main'));
	ok('heir: an instance in manual routing does not inherit',
		global.MOCK_UCI.network.media.protonvpn_managed_v6 == null);
	ok('heir: and its addressing is restored too',
		global.MOCK_UCI.network.media.ip6assign == null);

	// The control: an instance that really does steer that network still
	// inherits, so the round-2 fix is not undone by the tightening.
	uci = mk2({});
	enforce_routing(uci, settings_of(uci, 'main'));
	global.MOCK_UCI.protonvpn.main.enabled = '0';
	uci = cursor();
	enforce_routing(uci, settings_of(uci, 'main'));
	eq('heir: a genuinely steering instance still inherits',
		global.MOCK_UCI.network.media.protonvpn_managed_v6, 'pv_guest');
	eq('heir: and the announcement stays up for its clients',
		global.MOCK_UCI.dhcp.media.ra, 'server');
}

// ── 18. the dhcp claim is owned in its own right ─────────────────────────
// Both halves used to hang off the network section: the dhcp side was only
// ever looked at while walking a network section that still existed and was
// ours. A network section is a thing the user can delete, and a dhcp section
// is a thing the user can add, so neither assumption holds.
{
	// A claimed network section deleted underneath us. The prefix it allocated
	// is gone, so announcing one is a promise nothing can keep — and the stamp
	// left on the dhcp section means nobody will ever give the user's settings
	// back either.
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('orphan: the dhcp section starts out claimed',
		global.MOCK_UCI.dhcp.media.protonvpn_managed_v6, 'pv_media');

	delete global.MOCK_UCI.network.media;
	uci = cursor();
	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('orphan: a dhcp section whose network is gone stops announcing',
		global.MOCK_UCI.dhcp.media.ra, 'disabled');
	ok('orphan: and the options we added are removed',
		global.MOCK_UCI.dhcp.media.ra_slaac == null &&
		global.MOCK_UCI.dhcp.media.ra_default == null);
	ok('orphan: the stamp is released, so nothing is left owning it',
		global.MOCK_UCI.dhcp.media.protonvpn_managed_v6 == null);
	ok('orphan: and the record with it',
		global.MOCK_UCI.dhcp.media.protonvpn_saved_ra == null);
	ok('orphan: the caller is told to reload odhcpd', res.changed_dhcp == true);

	// A dhcp section that did not exist when the owner claimed the network.
	// Only the OTHER instance sharing that network is reconciled afterwards —
	// it must still pick the announcement up, because the dhcp section is
	// unowned and the settings it needs are the same either way.
	let other = function(over) {
		let b = ssteer(over);
		b.interface = 'pv_guest';
		b.routing_table = '102';
		return b;
	};
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.dhcp.media;            // none at claim time
	global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
		private_key: KEY, protonvpn_features: '' + F_V6 };
	global.MOCK_UCI.protonvpn = {
		main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
		guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
			routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
	};
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('late dhcp: the owner holds the network section',
		global.MOCK_UCI.network.media.protonvpn_managed_v6, 'pv_media');

	global.MOCK_UCI.dhcp.media = { '.type': 'dhcp', interface: 'media',
		ra: 'disabled', dhcpv6: 'disabled' };
	uci = cursor();
	res = enforce_routing(uci, other({ ipv6_mode: 'auto' }));
	eq('late dhcp: the non-owner still switches the announcement on',
		global.MOCK_UCI.dhcp.media.ra, 'server');
	eq('late dhcp: with SLAAC', global.MOCK_UCI.dhcp.media.ra_slaac, '1');
	eq('late dhcp: and a default route', global.MOCK_UCI.dhcp.media.ra_default, '1');
	eq('late dhcp: stamped by whoever actually claimed it',
		global.MOCK_UCI.dhcp.media.protonvpn_managed_v6, 'pv_guest');
	eq('late dhcp: recording what was there', global.MOCK_UCI.dhcp.media.protonvpn_saved_ra, 'disabled');
	ok('late dhcp: and the caller reloads odhcpd', res.changed_dhcp == true);

	// The network section stays with its own owner — the two claims are
	// independent, and neither may quietly take the other's record.
	eq('late dhcp: the network record is untouched',
		global.MOCK_UCI.network.media.protonvpn_managed_v6, 'pv_media');

	// When the non-owner lets go, the other instance is still steering that
	// network — so the announcement must stay up for ITS clients and the
	// record move across, exactly as the network side already behaves.
	enforce_routing(uci, other({ ipv6_mode: 'auto', source_networks: [] }));
	eq('late dhcp: still announcing for the instance that still steers it',
		global.MOCK_UCI.dhcp.media.ra, 'server');
	eq('late dhcp: and the record is handed to that instance',
		global.MOCK_UCI.dhcp.media.protonvpn_managed_v6, 'pv_media');
}

// ── 19. the prefix has to be allowed onto the device at all ──────────────
// Measured on the router this feature targets: with `option ipv6 '0'` on the
// bridge's `config device` section the kernel carries disable_ipv6=1, so netifd
// computes the prefix assignment, fails to add the address and reports an empty
// `local-address` — every option below it is set correctly and the client still
// has no IPv6. It is the device-level twin of `ra 'disabled'`, and a network
// where IPv6 was never used has both.
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);

	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let d = global.MOCK_UCI.network.dev_media;
	eq('device: IPv6 is allowed onto the bridge', d.ipv6, '1');
	eq('device: the section is stamped with its owner', d.protonvpn_managed_v6, 'pv_media');
	eq('device: the previous value is recorded', d.protonvpn_saved_ipv6, '0');
	ok('device: the caller is told to reload netifd', res.changed_network == true);

	// Idempotent, like every other claim.
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	ok('device: a second run changes nothing', res.changed_network == false);

	// Leaving auto hands the device section back exactly as found: the user
	// turned IPv6 off there and only borrowed it to us.
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('device: teardown puts the user value back',
		global.MOCK_UCI.network.dev_media.ipv6, '0');
	ok('device: and takes its stamp with it',
		global.MOCK_UCI.network.dev_media.protonvpn_managed_v6 == null);
	ok('device: and the record',
		global.MOCK_UCI.network.dev_media.protonvpn_saved_ipv6 == null);

	// A full release is byte-for-byte.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	pristine = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [] }));
	eq('device: un-steering restores the pristine config',
		sprintf('%J', global.MOCK_UCI), pristine);

	// A value the user changed after us is theirs.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	global.MOCK_UCI.network.dev_media.ipv6 = '0';   // user turned it off again
	enforce_routing(uci, ssteer({ ipv6_mode: 'off' }));
	eq('device: a user edit after ours survives teardown',
		global.MOCK_UCI.network.dev_media.ipv6, '0');

	// A network with no device section at all needs nothing: netifd leaves
	// IPv6 enabled by default, so there is nothing to switch on and nothing
	// to say about it.
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.network.dev_media;
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('device: no device section is not an error',
		length(rules6('steer_v6_lookup', 'pv_media')), 1);
	let quiet = true;
	for (let n in res.notes)
		if (index(n, 'device') >= 0)
			quiet = false;
	ok('device: and nothing is reported about it', quiet);

	// Shared network: the device claim follows the same hand-over as the rest,
	// or disabling one instance would switch IPv6 off under another's clients.
	let other = function(over) {
		let b = ssteer(over);
		b.interface = 'pv_guest';
		b.routing_table = '102';
		return b;
	};
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
		private_key: KEY, protonvpn_features: '' + F_V6 };
	global.MOCK_UCI.protonvpn = {
		main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
		guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
			routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
	};
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	eq('device: IPv6 stays on for the instance still steering the network',
		global.MOCK_UCI.network.dev_media.ipv6, '1');
	eq('device: and the record moves across',
		global.MOCK_UCI.network.dev_media.protonvpn_managed_v6, 'pv_guest');
}

// ── 20. the steered network needs a /64 of its own ───────────────────────
// netifd hands sub-prefixes out of the router's ULA sequentially from 0, so a
// steered network and `lan` both land on <ula>::/64. Measured on a live
// router: br-lan.1 held fd19:8aa7:61d4::/64 at metric 256 and br-guest the
// same /64 at metric 1024, so the return route for a NAT6'd client's reply
// resolved to br-lan.1 and the client never saw it — the tunnel round trip was
// symmetric and complete, and the last hop went to the wrong bridge. Pinning a
// sub-prefix per steered network is what keeps the reply on the right one.
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);

	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let hint = global.MOCK_UCI.network.media.ip6hint;
	ok('hint: the steered network gets a sub-prefix of its own', hint != null && hint != '');
	// Four hex digits, so at least 0x1000 — above anything netifd's own
	// sequential allocation hands to a network without a hint.
	ok('hint: out of netifd sequential range, so it cannot collide with lan',
		hint != null && match(hint, /^[1-9a-f][0-9a-f]{3}$/) != null);

	// Stable: the same network must not move to another prefix on every apply,
	// or every client would be re-addressed each time. Pinned as an exact
	// mapping rather than "equal to last run", because two runs inside the
	// same second would agree even if the value depended on the clock.
	let again = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('hint: it does not move on the next run', global.MOCK_UCI.network.media.ip6hint, hint);
	ok('hint: and nothing is reported as changed', again.changed_network == false);
	eq('hint: the name -> sub-prefix mapping is fixed', _routing.v6_hint('media'), 'b444');
	eq('hint: and differs per name', _routing.v6_hint('guest'), 'b048');

	// Two steered networks must not be given the same one.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.guest.device = 'br-guest';
	global.MOCK_UCI.network.dev_guest = { '.type': 'device', name: 'br-guest', ipv6: '0' };
	global.MOCK_UCI.dhcp.guest.interface = 'guest';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'media', 'guest' ] }));
	ok('hint: two steered networks get different sub-prefixes',
		global.MOCK_UCI.network.media.ip6hint != global.MOCK_UCI.network.guest.ip6hint);

	// It is the user's section, so the previous value comes back.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.ip6hint = '5';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('hint: a user value is recorded', global.MOCK_UCI.network.media.protonvpn_saved_ip6hint, '5');
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('hint: and restored on teardown', global.MOCK_UCI.network.media.ip6hint, '5');

	// Full release is byte-for-byte.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	pristine = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [] }));
	eq('hint: un-steering restores the pristine config',
		sprintf('%J', global.MOCK_UCI), pristine);
}

// ── 21. the in-tunnel address, and migrating off the published one ───────
// Proton publishes 2a07:b944::2:2 and answers to fd54:20a4:d33b:b10c:0:2:0:2.
// An instance applied before this was known carries the published one, so a
// re-apply has to move it across rather than leave a tunnel that can send and
// never receive.
{
	global.MOCK_UCI = {
		protonvpn: { main: { '.type': 'instance', interface: 'pv_media' } },
		network: { pv_media: { '.type': 'interface', proto: 'wireguard', private_key: KEY,
			// what an older version left behind
			addresses: [ '10.2.0.2/32', '2a07:b944::2:2/128' ] } }
	};
	let uci = cursor();
	let s = _cmn.load_settings(uci);
	_apply.write_relay(uci, 'pv_media', { name: 'NL#1', hostname: 'n1', ip_address: '1.2.3.4',
		public_key: KEY, features: F_V6, country_code: 'nl', city_code: 'nl-amsterdam' }, s);
	eq('address: a re-apply migrates the interface to the working address',
		global.MOCK_UCI.network.pv_media.addresses,
		[ '10.2.0.2/32', 'fd54:20a4:d33b:b10c:0:2:0:2/128' ]);
	let carried = false;
	for (let a in global.MOCK_UCI.network.pv_media.addresses)
		if (index(a, '2a07:b944') >= 0)
			carried = true;
	ok('address: and does not leave the published one behind', carried == false);
}

// ── 22. neighbour discovery on the steered zone ──────────────────────────
// A guest-style zone rejects everything it does not name, and neighbour
// discovery is not named: measured on a live router, the zone's input chain
// allowed DHCP and DNS and then jumped to reject, so a client's neighbour
// advertisement never reached the router, the neighbour entry stayed FAILED
// and no reply could be delivered to any client on that network. IPv6 cannot
// work there at all until that is open, so the mode that asks for IPv6 opens
// exactly that and nothing else.
{
	let nd_rules = function() {
		let out = [];
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				push(out, sec);
		}
		return out;
	};

	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);

	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let nd = nd_rules();
	eq('nd: one rule for the steered network zone', length(nd), 1);
	eq('nd: on the zone that holds the steered network', nd[0] ? nd[0].src : null, 'media');
	eq('nd: IPv6 only', nd[0] ? nd[0].family : null, 'ipv6');
	eq('nd: ICMP only', nd[0] ? nd[0].proto : null, 'icmp');
	eq('nd: and accepted', nd[0] ? nd[0].target : null, 'ACCEPT');
	// Exactly the three types neighbour discovery needs from a client, and no
	// more: echo, MLD and the rest stay closed.
	eq('nd: only the neighbour-discovery types', nd[0] ? nd[0].icmp_type : null,
		[ 'router-solicitation', 'neighbour-solicitation', 'neighbour-advertisement' ]);
	ok('nd: the caller reloads the firewall', res.changed_firewall == true);

	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	ok('nd: a second run changes nothing', res.changed_firewall == false);

	// Only under auto: in block or off nothing on that network may use IPv6,
	// so opening neighbour discovery would be opening it for nothing.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	let before = v6_state('media');
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('nd: block leaves the network exactly as it was', v6_state('media'), before);
	enforce_routing(uci, ssteer({ ipv6_mode: 'off' }));
	eq('nd: and so does off', v6_state('media'), before);

	// Leaving auto closes it again.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	pristine = sprintf('%J', global.MOCK_UCI);
	before = v6_state('media');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('nd: leaving auto takes the whole of it away again',
		v6_state('media'), before);

	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [] }));
	eq('nd: un-steering restores the pristine config',
		sprintf('%J', global.MOCK_UCI), pristine);

	// A steered network in a different zone gets its own rule.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.firewall.zguest = { '.type': 'zone', name: 'guest', network: [ 'guest' ] };
	global.MOCK_UCI.network.guest.device = 'br-guest';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'media', 'guest' ] }));
	eq('nd: one rule per zone', length(nd_rules()), 2);
}

// ── 23. the one thing here that OPENS something ──────────────────────────
// The neighbour-discovery rule is the only ACCEPT this module writes, so its
// blast radius is pinned down twice over: what may receive it, and that it
// cannot outlive the mode that asked for it.
{
	let nd_rules = function() {
		let out = [];
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				push(out, sec);
		}
		return out;
	};

	// ── never on the uplink ──────────────────────────────────────────────
	// Nothing stops a user putting `wan` in source_network, and the zone of
	// the steered network was fed straight to the rule — which would publish
	// an IPv6 ICMP ACCEPT facing the internet. Neighbour discovery belongs on
	// the networks the tunnel serves and nowhere else.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.wan = { '.type': 'interface', proto: 'dhcp', device: 'eth1' };
	let uci = cursor();
	let before = v6_state('wan');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'wan' ] }));
	eq('uplink: steering the uplink configures nothing at all',
		v6_state('wan'), before);

	// The same for an uplink that is not in a zone called wan: it is the
	// protocol that gives it away, and a dialer is never LAN-side.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.dsl = { '.type': 'interface', proto: 'pppoe', device: 'dsl0' };
	global.MOCK_UCI.firewall.zdsl = { '.type': 'zone', name: 'dsl', network: [ 'dsl' ] };
	uci = cursor();
	before = v6_state('dsl');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'dsl' ] }));
	eq('uplink: a dialer network gets nothing either', v6_state('dsl'), before);

	// A static network someone has put in the WAN zone is still the uplink
	// side. The protocol test alone would wave it through, which is why the
	// zone is checked independently.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.dmz = { '.type': 'interface', proto: 'static', ipaddr: '10.9.3.1/24' };
	global.MOCK_UCI.firewall.zwan.network = [ 'wan', 'dmz' ];
	uci = cursor();
	before = v6_state('dmz');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'dmz' ] }));
	eq('uplink: a static network in the WAN zone is still not LAN-side',
		v6_state('dmz'), before);

	// A mixed set still serves the LAN-side half, and only that half.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.wan = { '.type': 'interface', proto: 'dhcp', device: 'eth1' };
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'media', 'wan' ] }));
	let nd = nd_rules();
	eq('uplink: the LAN-side network still gets its rule', length(nd), 1);
	eq('uplink: and it is not the uplink zone', nd[0] ? nd[0].src : null, 'media');

	// The predicate on its own, so the rule that decides this is inspectable
	// against a real router's config and not only through enforce().
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.wan = { '.type': 'interface', proto: 'dhcp', device: 'eth1' };
	global.MOCK_UCI.network.dsl = { '.type': 'interface', proto: 'pppoe', device: 'dsl0' };
	uci = cursor();
	ok('lan-side: a static LAN network qualifies', _routing.is_lan_side(uci, 'media') == true);
	ok('lan-side: a dhcp uplink does not', _routing.is_lan_side(uci, 'wan') == false);
	ok('lan-side: nor a dialer', _routing.is_lan_side(uci, 'dsl') == false);
	// An unknown protocol is not assumed safe: this decides an ACCEPT.
	global.MOCK_UCI.network.exotic = { '.type': 'interface', proto: 'somethingnew' };
	ok('lan-side: an unknown protocol is refused, not assumed',
		_routing.is_lan_side(uci, 'exotic') == false);
	// A network in no firewall zone has no `src` to write the rule on, but the
	// predicate says no in its own right rather than leaving that to the
	// caller noticing.
	// It has a device, so the zone is what refuses it — without one the test
	// passed on the missing device and said nothing about zones at all.
	global.MOCK_UCI.network.orphan = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.9.1/24', device: 'br-orphan' };
	ok('lan-side: a network in no zone is refused outright',
		_routing.is_lan_side(cursor(), 'orphan') == false);
	uci = cursor();
	let orphan_before = v6_state('orphan');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'orphan' ] }));
	eq('lan-side: and nothing at all is configured on it',
		v6_state('orphan'), orphan_before);

	// ── it cannot outlive the mode that asked for it ─────────────────────
	// Teardown used to sit inside the managed-zone branch, so an instance
	// whose interface had been taken out of its zone skipped it entirely: the
	// user switches to 'block', believes IPv6 is shut, and a stamped ACCEPT
	// they cannot see is still installed. Releasing it must not depend on
	// managed routing still being in one piece, exactly as the prohibit's
	// invariants do not.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	before = v6_state('media');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('outlive: the rule is there to begin with', length(nd_rules()), 1);
	// Take the VPN interface out of its managed zone; the zone keeps its name,
	// so the enforcement cannot simply recreate it.
	for (let k in global.MOCK_UCI.firewall) {
		let z = global.MOCK_UCI.firewall[k];
		if (z['.type'] == 'zone' && z.protonvpn_iface == 'pv_media')
			z.network = [];
	}
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('outlive: switching to block leaves nothing of it behind',
		v6_state('media'), before);

	// Same for 'off', and for an instance switched off entirely.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	for (let k in global.MOCK_UCI.firewall) {
		let z = global.MOCK_UCI.firewall[k];
		if (z['.type'] == 'zone' && z.protonvpn_iface == 'pv_media')
			z.network = [];
	}
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'off' }));
	eq('outlive: off leaves nothing either', v6_state('media'), before);

	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	for (let k in global.MOCK_UCI.firewall) {
		let z = global.MOCK_UCI.firewall[k];
		if (z['.type'] == 'zone' && z.protonvpn_iface == 'pv_media')
			z.network = [];
	}
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	eq('outlive: nor does a disabled instance', v6_state('media'), before);
}

// ── 24. more than one uplink, and a tunnel that is no longer there ───────
// The LAN-side test asked whether a network sat in THE wan zone, singular. A
// dual-WAN or DSL-plus-LTE-failover router has two, and a static network in
// the second one passed every test and got the ACCEPT. Nothing on a
// single-uplink test bench can show this, which is exactly why it is pinned
// here.
{
	let nd_rules = function() {
		let out = [];
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				push(out, sec);
		}
		return out;
	};
	// A second uplink zone that masquerades, holding a plain static network
	// with no gateway of its own: the protocol test passes it, and only the
	// zone being an uplink disqualifies it.
	let with_second_uplink = function() {
		let m = mkall(F_V6);
		m.network.lte = { '.type': 'interface', proto: 'static', ipaddr: '10.64.0.2/24' };
		m.firewall.zlte = { '.type': 'zone', name: 'lte', masq: '1', network: [ 'lte' ] };
		return m;
	};

	global.MOCK_UCI = with_second_uplink();
	let uci = cursor();
	let before = v6_state('lte');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'lte' ] }));
	eq('dual-wan: the second masquerading uplink gets nothing',
		v6_state('lte'), before);

	// And a routed uplink that does not masquerade at all, given away by the
	// default gateway on the network itself.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.wan2 = { '.type': 'interface', proto: 'static',
		ipaddr: '192.0.2.2/30', gateway: '192.0.2.1' };
	global.MOCK_UCI.firewall.zwan2 = { '.type': 'zone', name: 'uplink2', network: [ 'wan2' ] };
	uci = cursor();
	before = v6_state('wan2');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'wan2' ] }));
	eq('dual-wan: a routed uplink carrying a gateway gets nothing',
		v6_state('wan2'), before);

	// This one asserted the opposite before the rule was bound to a device: a
	// static network sharing a zone with a dialer used to be refused, because
	// the opening covered the whole zone. Now it is served and the uplink
	// cannot reach it, which is the point of the change — so the assertion is
	// that the rule names the sibling's device and not the dialer's.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.dsl = { '.type': 'interface', proto: 'pppoe', device: 'dsl0' };
	global.MOCK_UCI.network.dmz = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.4.1/24', device: 'br-dmz' };
	global.MOCK_UCI.firewall.zedge = { '.type': 'zone', name: 'edge', network: [ 'dsl', 'dmz' ] };
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'dmz' ] }));
	let edge = nd_rules();
	eq('dual-wan: the static network sharing a zone with a dialer is served',
		length(edge), 1);
	eq('dual-wan: scoped to its own device, so the dialer cannot use it',
		edge[0] ? edge[0].device : null, 'br-dmz');

	// But a LAN zone that also carries the user's own WireGuard tunnel is
	// still a LAN zone. Seen on a real router, where the lan zone lists
	// 'lan' and 'wg0': a tunnel is not a way out to the internet, and
	// treating "anything not static" as an uplink quietly stopped serving
	// the main LAN.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.wg0 = { '.type': 'interface', proto: 'wireguard' };
	global.MOCK_UCI.network.lan = { '.type': 'interface', proto: 'static',
		ipaddr: '192.168.1.1/24', device: 'br-lan' };
	global.MOCK_UCI.firewall.zlan.network = [ 'lan', 'wg0' ];
	uci = cursor();
	ok('dual-wan: a LAN carrying a user tunnel in its zone stays serviceable',
		_routing.is_lan_side(uci, 'lan') == true);

	// The LAN-side network alongside two uplinks still works — the point is to
	// disqualify uplinks, not to stop serving the networks the tunnel exists
	// for.
	global.MOCK_UCI = with_second_uplink();
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'media', 'lte' ] }));
	let nd = nd_rules();
	eq('dual-wan: the LAN-side network is still served', length(nd), 1);
	eq('dual-wan: and only it', nd[0] ? nd[0].src : null, 'media');

	// The predicate directly, so the shape of "uplink" is inspectable.
	global.MOCK_UCI = with_second_uplink();
	uci = cursor();
	ok('uplink zones: the conventional one is an uplink', _routing.zone_is_uplink(uci, 'zwan') == true);
	ok('uplink zones: and so is the second one', _routing.zone_is_uplink(uci, 'zlte') == true);
	ok('uplink zones: a LAN zone is not', _routing.zone_is_uplink(uci, 'zmedia') == false);

	// ── the rule must not outlive the interface it serves ────────────────
	// Deleting the VPN interface section while the instance stays enabled and
	// steering left the ACCEPT installed. Smaller blast radius than the uplink
	// case — a normal apply recreates the interface — but an opening should
	// exist only while the thing it serves does.
	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	before = v6_state('media');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('gone: the rule is there while the interface is', length(nd_rules()), 1);
	delete global.MOCK_UCI.network.pv_media;
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('gone: deleting the interface section takes all of it with it',
		v6_state('media'), before);
}

// ── 25. a default route declared in its own section ──────────────────────
// Third round on the same question, so the shape changed rather than the
// symptom: a network is now admitted on POSITIVE evidence and refused
// otherwise, instead of being admitted because no known sign of being an
// uplink was spotted. These cases are the ones that shape has to get right.
{
	let nd_rules = function() {
		let out = [];
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				push(out, sec);
		}
		return out;
	};
	// A plain static network, no inline gateway, in a zone that neither
	// masquerades nor is called wan — and a `config route` that makes it the
	// way out. Nothing about the network or the zone says "uplink"; only the
	// route section does.
	let routed = function(rt) {
		let m = mkall(F_V6);
		// It has a device of its own, so the default route below is what
		// disqualifies it and not the absence of something to bind to.
		m.network.routed = { '.type': 'interface', proto: 'static',
			ipaddr: '198.51.100.2/24', device: 'br-routed' };
		m.firewall.zrouted = { '.type': 'zone', name: 'edge', network: [ 'routed' ] };
		m.network.defroute = rt;
		return m;
	};

	global.MOCK_UCI = routed({ '.type': 'route', interface: 'routed',
		target: '0.0.0.0/0', gateway: '198.51.100.1' });
	let uci = cursor();
	let before = v6_state('routed');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'routed' ] }));
	eq('routed: a default route in its own section makes it an uplink',
		v6_state('routed'), before);

	// The separate target+netmask spelling of the same thing.
	global.MOCK_UCI = routed({ '.type': 'route', interface: 'routed',
		target: '0.0.0.0', netmask: '0.0.0.0', gateway: '198.51.100.1' });
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'routed' ] }));
	eq('routed: and so does the target-plus-netmask spelling',
		v6_state('routed'), before);

	// And the IPv6 one, which is the family this feature actually routes.
	global.MOCK_UCI = routed({ '.type': 'route6', interface: 'routed',
		target: '::/0', gateway: 'fe80::1' });
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'routed' ] }));
	eq('routed: a ::/0 route6 counts too', v6_state('routed'), before);

	// Transitive: a perfectly ordinary LAN network sharing a zone with that
	// uplink is not eligible either, because the rule is written on the ZONE.
	global.MOCK_UCI = routed({ '.type': 'route', interface: 'routed',
		target: '0.0.0.0/0', gateway: '198.51.100.1' });
	global.MOCK_UCI.network.office = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.5.1/24', device: 'br-office' };
	global.MOCK_UCI.firewall.zrouted.network = [ 'routed', 'office' ];
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'office' ] }));
	let off = nd_rules();
	eq('routed: a LAN network sharing that zone is served on its own device',
		length(off), 1);
	eq('routed: and the routed uplink is not in the match',
		off[0] ? off[0].device : null, 'br-office');

	// The other direction matters just as much: an ordinary subnet route must
	// NOT disqualify anything, or the feature stops working on real routers
	// that simply have static routes.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.subnetroute = { '.type': 'route', interface: 'media',
		target: '10.50.0.0/16', gateway: '10.9.1.254' };
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('routed: an ordinary subnet route disqualifies nothing', length(nd_rules()), 1);

	// A sibling running a protocol this module has never heard of used to
	// close the whole zone, because it might obtain a default route by itself
	// and the opening was zone-wide. It no longer has to: the opening names
	// the steered network's device, and the stranger cannot reach it.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.mystery = { '.type': 'interface', proto: 'somethingnew' };
	global.MOCK_UCI.firewall.zmedia.network = [ 'media', 'mystery' ];
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let mys = nd_rules();
	eq('routed: an unrecognised sibling no longer costs the steered network',
		length(mys), 1);
	eq('routed: because the opening names one device only',
		mys[0] ? mys[0].device : null, 'br-media');

	// But a WireGuard link sharing the zone is still fine — a tunnel that
	// terminates on this router is not a way out, and a real router's lan zone
	// carries one.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.wg0 = { '.type': 'interface', proto: 'wireguard' };
	global.MOCK_UCI.firewall.zmedia.network = [ 'media', 'wg0' ];
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('routed: a tunnel terminating here does not close the zone',
		length(nd_rules()), 1);

	// ...and even when that tunnel IS the way out, the steered network keeps
	// its own device-scoped opening; the tunnel simply is not in the match.
	global.MOCK_UCI.network.wgdef = { '.type': 'route', interface: 'wg0',
		target: '0.0.0.0/0' };
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let wgd = nd_rules();
	eq('routed: a tunnel carrying the default route no longer closes the zone',
		length(wgd), 1);
	eq('routed: the opening still names only the steered device',
		wgd[0] ? wgd[0].device : null, 'br-media');

	// Two steered networks in the SAME zone get one opening each, keyed by
	// device: the zone alone can no longer identify a rule, so reconciling on
	// the zone would collapse them into one and leave a network unserved.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.guest.device = 'br-guest';
	global.MOCK_UCI.firewall.zmedia.network = [ 'media', 'guest' ];
	uci = cursor();
	// Added one at a time, which is how a user actually does it — and the case
	// where an existing rule for the same zone must not be mistaken for this
	// network's own.
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'media' ] }));
	eq('device: the first steered network gets its opening', length(nd_rules()), 1);
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'media', 'guest' ] }));
	let both = nd_rules();
	eq('device: two networks sharing a zone get one opening each', length(both), 2);
	let devs = {};
	for (let r in both)
		devs[r.device] = true;
	ok('device: one per device, not one per zone',
		devs['br-media'] == true && devs['br-guest'] == true);

	// And dropping one of them takes its opening with it. This is where the
	// zone stops being enough to identify a rule: both openings carry the same
	// src, so reconciling on the zone alone would see the survivor and keep
	// the stale one installed.
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'media' ] }));
	let left = nd_rules();
	eq('device: un-steering one of them removes exactly its opening', length(left), 1);
	eq('device: and the one that remains is the right one',
		left[0] ? left[0].device : null, 'br-media');

	// There is only one list now — what may RECEIVE the rule — because nothing
	// is asked about a zone's other members any more. A tunnel is still not
	// eligible itself: the opening exists so clients on a bridge can do
	// neighbour discovery, and a point-to-point tunnel has no such clients.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.wgnet = { '.type': 'interface', proto: 'wireguard' };
	global.MOCK_UCI.firewall.zwg = { '.type': 'zone', name: 'wgzone', network: [ 'wgnet' ] };
	uci = cursor();
	ok('routed: a tunnel is not itself eligible for the rule',
		_routing.is_lan_side(uci, 'wgnet') == false);
	before = v6_state('wgnet');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [ 'wgnet' ] }));
	eq('routed: so steering a tunnel configures nothing', v6_state('wgnet'), before);
}

// ── 26. the rule is bound to a device, not to a zone ─────────────────────
// Four rounds of this defect shared one root: the ACCEPT was written on a
// ZONE, and a zone holds arbitrary networks, so each fix had to prove that no
// member of it was an uplink — correct every time, complete never. fw4 lets a
// rule carry a `device`, which scopes the match to one interface
// (`iifname "br-guest" icmpv6 type nd-...`, verified on the router), so a
// sibling in the same zone cannot reach the opening whatever it is. The
// transitivity, and with it the whole class, is gone.
{
	let nd_rules = function() {
		let out = [];
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				push(out, sec);
		}
		return out;
	};

	// The rule names the steered network's own device, so what else shares the
	// zone stops mattering.
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let nd = nd_rules();
	eq('device: the rule is bound to the steered network device',
		nd[0] ? nd[0].device : null, 'br-media');
	eq('device: and still carries the zone that selects the chain',
		nd[0] ? nd[0].src : null, 'media');

	// A WireGuard sibling that really is an uplink — peer with
	// route_allowed_ips and a default allowed_ips. Its static sibling is still
	// served, because the opening is scoped to the sibling's own device and
	// the tunnel cannot use it.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.wgup = { '.type': 'interface', proto: 'wireguard' };
	global.MOCK_UCI.network.wgpeer = { '.type': 'wireguard_wgup', interface: 'wgup',
		route_allowed_ips: '1', allowed_ips: [ '0.0.0.0/0', '::/0' ] };
	global.MOCK_UCI.firewall.zmedia.network = [ 'media', 'wgup' ];
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	nd = nd_rules();
	eq('wg-sibling: the steered network is still served', length(nd), 1);
	eq('wg-sibling: and the opening names only its device',
		nd[0] ? nd[0].device : null, 'br-media');

	// A network listed in a LAN zone AND in the WAN zone. Only the first zone
	// used to be inspected, so being in wan as well went unnoticed.
	// Listed in the LAN zone FIRST, so a scan that stops at the first match
	// sees only that one and never reaches the WAN membership.
	global.MOCK_UCI = mkall(F_V6);
	// A real LAN network, so the LAN zone is genuinely router-side and the
	// only thing under test is the second membership.
	global.MOCK_UCI.network.lan = { '.type': 'interface', proto: 'static',
		ipaddr: '192.168.1.1/24', device: 'br-lan' };
	global.MOCK_UCI.network.wan = { '.type': 'interface', proto: 'static',
		ipaddr: '203.0.113.2/24', device: 'eth1' };
	global.MOCK_UCI.firewall.zlan.network = [ 'lan', 'media' ];
	global.MOCK_UCI.firewall.zwan.network = [ 'wan', 'media' ];
	uci = cursor();
	let before = v6_state('media');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('dual-zone: being in the WAN zone as well disqualifies it',
		v6_state('media'), before);

	// `proto none` says "this router does not configure it", which is absence
	// of information, not evidence of being router-side — the exact mistake
	// the inversion was meant to remove. An unmanaged uplink whose default
	// route is installed at runtime looks exactly like this.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.proto = 'none';
	uci = cursor();
	before = v6_state('media');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('proto-none: unknown configuration is not positive evidence',
		v6_state('media'), before);

	// And with no way to tell which device the network sits on, there is
	// nothing to bind the rule to, so nothing is opened.
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.network.media.device;
	uci = cursor();
	before = v6_state('media');
	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('no-device: without a device to scope it, nothing is configured',
		v6_state('media'), before);
	let said = false;
	for (let n in res.notes)
		if (index(n, 'media') >= 0 && index(n, 'device') >= 0)
			said = true;
	ok('no-device: and the reason is reported', said);
}

// ── 27. a device can be shared too, and the decision comes first ─────────
{
	let nd_rules = function() {
		let out = [];
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				push(out, sec);
		}
		return out;
	};

	// Binding to the device moved the transitivity rather than removing it: a
	// second logical network can sit on the same bridge. An alias interface
	// with a gateway of its own makes br-media a way out, and the opening
	// matches the device, so it would cover the alias too.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.edge_alias = { '.type': 'interface', proto: 'static',
		device: 'br-media', ipaddr: '198.51.100.2/24', gateway: '198.51.100.1' };
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('shared-device: an alias with a gateway makes the whole device a way out',
		v6_state('media'),
		{ nd: 0, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });

	// The same alias without the gateway is harmless and must not cost the
	// steered network its IPv6 — the test is about being a way out, not about
	// sharing a device.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.plain_alias = { '.type': 'interface', proto: 'static',
		device: 'br-media', ipaddr: '10.9.7.1/24' };
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('shared-device: a harmless alias costs nothing', v6_state('media'),
		{ nd: 1, ip6assign: '64', ip6class: 'local', delegate: '0', ra: 'server' });

	// Ordering: a network that will not get the opening must not be given the
	// addressing and the announcement either. Configuring first and declining
	// afterwards left clients with an address and an advertised default route
	// they could not use — worse than not configuring at all, because it looks
	// like it works.
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.network.media.device;
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('ordering: a network with no device is left entirely alone',
		v6_state('media'),
		{ nd: 0, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });

	// Same for every other reason a network can be declined.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.proto = 'none';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('ordering: nor is one declined for its protocol', v6_state('media'),
		{ nd: 0, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });

	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.gateway = '10.9.1.254';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('ordering: nor one that is itself a way out', v6_state('media'),
		{ nd: 0, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });

	// Legacy bridge: `option type bridge` with member ifnames. netifd names the
	// L3 device after the interface, and the members carry no address, so
	// binding to them would match nothing.
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.network.media.device;
	global.MOCK_UCI.network.media.type = 'bridge';
	global.MOCK_UCI.network.media.ifname = 'eth0.1 eth0.2';
	global.MOCK_UCI.network.dev_media.name = 'br-media';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let nd = nd_rules();
	eq('legacy-bridge: bound to the L3 bridge, not to a member',
		nd[0] ? nd[0].device : null, 'br-media');
	eq('legacy-bridge: and the network is fully configured', v6_state('media'),
		{ nd: 1, ip6assign: '64', ip6class: 'local', delegate: '0', ra: 'server' });

	// Several member ifnames without `type bridge` name no single L3 device,
	// so there is nothing to bind to and nothing is configured.
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.network.media.device;
	global.MOCK_UCI.network.media.ifname = 'eth0.1 eth0.2';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('legacy-bridge: ambiguous members configure nothing', v6_state('media'),
		{ nd: 0, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });
}

// ── 28. a device name can be a reference to another interface ────────────
// netifd lets `option device` hold a REFERENCE instead of a device name:
// `@edge` means "whatever L3 device interface `edge` ends up using" (device.c
// hands a leading `@` to device_alias_get(), and interface.c points that alias
// at the referenced interface's l3_dev on IFEV_UP). Read literally, `@edge`
// looked like a device nothing else sat on — so an alias through an uplink was
// admitted, and the opening written for it said `iifname "@edge"`, which
// matches nothing: the network advertised IPv6 whose neighbour discovery could
// never work. `@` is the only such prefix; a name with a dot is a VLAN device,
// which is a real device name.
{
	let nd_rules = function() {
		let out = [];
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				push(out, sec);
		}
		return out;
	};
	let noted = function(res, net, word) {
		for (let n in res.notes)
			if (index(n, 'network ' + net + ' ') >= 0 && index(n, word) >= 0)
				return true;
		return false;
	};
	// The state a declined network is left in: nothing opened, nothing
	// addressed, nothing announced.
	const CLOSED = { nd: 0, ip6assign: null, ip6class: null, delegate: null,
		ra: 'disabled' };
	const OPEN = { nd: 1, ip6assign: '64', ip6class: 'local', delegate: '0',
		ra: 'server' };

	// A reference straight at an uplink. The parent dials out, so the device
	// the steered network actually sits on is the way out itself.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@edge';
	global.MOCK_UCI.network.edge = { '.type': 'interface', proto: 'dhcp',
		device: 'eth1' };
	let uci = cursor();
	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a reference at an uplink parent is declined', v6_state('media'), CLOSED);
	ok('alias: and the note names the parent that made it one',
		noted(res, 'media', 'edge'));

	// A reference at a plain LAN bridge resolves to that bridge, and the
	// opening has to name the bridge — `iifname "@base"` matches no packet.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@base';
	global.MOCK_UCI.network.base = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.1/24', device: 'br-base' };
	global.MOCK_UCI.network.dev_media.name = 'br-base';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a reference at a LAN bridge is served', v6_state('media'), OPEN);
	eq('alias: and the opening names the device, not the reference',
		nd_rules()[0] ? nd_rules()[0].device : null, 'br-base');
	// The device section is found through the reference too, or the kernel
	// would still refuse an address on a bridge left with `ipv6 0`.
	eq('alias: the bridge behind the reference is allowed IPv6',
		global.MOCK_UCI.network.dev_media.ipv6, '1');
	eq('alias: and the section is stamped with its owner',
		global.MOCK_UCI.network.dev_media.protonvpn_managed_v6, 'pv_media');
	// And handed back when the instance stops steering it, which needs the
	// held section matched back to the network through the reference as well.
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', source_networks: [] }));
	eq('alias: and given back on teardown',
		global.MOCK_UCI.network.dev_media.ipv6, '0');
	ok('alias: taking the stamp with it',
		global.MOCK_UCI.network.dev_media.protonvpn_managed_v6 == null);

	// ...and handed to a SURVIVOR rather than released when another instance
	// is still steering the same network. This is the one place where failing
	// to match the held section back to its network is not merely undone by
	// the next claim: the section would be switched off under the other
	// instance's clients until that instance next ran.
	let other = function(over) {
		let b = ssteer(over);
		b.interface = 'pv_guest';
		b.routing_table = '102';
		return b;
	};
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@base';
	global.MOCK_UCI.network.base = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.1/24', device: 'br-base' };
	global.MOCK_UCI.network.dev_media.name = 'br-base';
	global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
		private_key: KEY, protonvpn_features: '' + F_V6 };
	global.MOCK_UCI.protonvpn = {
		main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
		guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
			routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
	};
	// The parent BEFORE the network that references it, which is how a user
	// writes it: the bridge exists first and the alias is added later. This
	// fixture listed it the other way round, so the hand-over below always met
	// the steered network first and the ordering that breaks it never arose.
	net_first('base');
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, other({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	eq('alias: the bridge behind a reference stays on for the survivor',
		global.MOCK_UCI.network.dev_media.ipv6, '1');
	eq('alias: and the record moves across',
		global.MOCK_UCI.network.dev_media.protonvpn_managed_v6, 'pv_guest');
	eq('alias: and the survivor keeps the whole of its IPv6', v6_state('media'),
		{ nd: 1, ip6assign: '64', ip6class: 'local', delegate: '0', ra: 'server' });
	eq('alias: while the parent itself was never configured', v6_state('base'),
		{ nd: 1, ip6assign: null, ip6class: null, delegate: null, ra: null });

	// A chain: the reference may point at an interface that is itself a
	// reference. Every hop resolves to the same device at the end.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@mid';
	global.MOCK_UCI.network.mid = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.1/24', device: '@base' };
	global.MOCK_UCI.network.base = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.2/24', device: 'br-base' };
	global.MOCK_UCI.network.dev_media.name = 'br-base';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a chain of references resolves to the far end', v6_state('media'), OPEN);
	eq('alias: and the opening names that device',
		nd_rules()[0] ? nd_rules()[0].device : null, 'br-base');

	// A way out ANYWHERE on the chain disqualifies the network: the hops all
	// sit on the same device, so an alias cannot launder the uplink it passes
	// through.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@mid';
	global.MOCK_UCI.network.mid = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.1/24', device: '@base', gateway: '10.9.8.254' };
	global.MOCK_UCI.network.base = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.2/24', device: 'br-base' };
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a way out in the middle of the chain disqualifies it',
		v6_state('media'), CLOSED);
	ok('alias: and the note names the hop that is one', noted(res, 'media', 'mid'));

	// A hop that is a way out is still named when the chain breaks AFTER it:
	// there is no device left to report co-tenants of, and "it is bound to
	// @ghost" would hide the uplink the reference actually went through.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@mid';
	global.MOCK_UCI.network.mid = { '.type': 'interface', proto: 'dhcp',
		device: '@ghost' };
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a broken chain through an uplink is declined', v6_state('media'), CLOSED);
	ok('alias: and the uplink is the reason given, not the broken reference',
		noted(res, 'media', 'proto dhcp'));

	// Self-reference. netifd would leave the alias pointing at nothing; the
	// walk has to notice and stop rather than follow it round for ever.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@media';
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a self-reference is declined', v6_state('media'), CLOSED);
	ok('alias: and says so', noted(res, 'media', '@media'));
	eq('alias: and writes no opening at all', length(nd_rules()), 0);

	// A cycle of two, which a plain "have I seen the name I started from"
	// check would miss if it only compared against the steered network.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@a';
	global.MOCK_UCI.network.a = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.1/24', device: '@b' };
	global.MOCK_UCI.network.b = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.2/24', device: '@a' };
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a cycle that does not include the steered network is declined',
		v6_state('media'), CLOSED);
	eq('alias: and no opening is written for it', length(nd_rules()), 0);

	// A reference at an interface that does not exist resolves to nothing, so
	// there is no device to bind to and nothing may be configured.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@ghost';
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a reference to no interface is declined', v6_state('media'), CLOSED);
	ok('alias: and the reason is reported', noted(res, 'media', '@ghost'));

	// A bare `@` names no interface either.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a bare @ is declined', v6_state('media'), CLOSED);

	// A reference at a `config device` section rather than an interface is not
	// a netifd alias: the alias table is keyed by INTERFACE name.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@dev_media';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a reference at a device section is not an interface reference',
		v6_state('media'), CLOSED);

	// A dot is not a reference: `eth0.1` is a VLAN device netifd creates, and
	// a real device name.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = 'eth0.1';
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a VLAN device is a name, not a reference', v6_state('media'), OPEN);
	eq('alias: and is bound to as it stands',
		nd_rules()[0] ? nd_rules()[0].device : null, 'eth0.1');

	// A sibling that reaches the shared device through a reference is still a
	// sibling: reading it literally hid it from the device it really sits on.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.side = { '.type': 'interface', proto: 'static',
		device: '@media', ipaddr: '198.51.100.2/24', gateway: '198.51.100.1' };
	uci = cursor();
	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('alias: a sibling reaching the device by reference still counts',
		v6_state('media'), CLOSED);
	ok('alias: and is named', noted(res, 'media', 'side'));
}

// ── 29. handing a shared device on picks a co-tenant that wants it ───────
// The device section is the one thing here not keyed by network: a `config
// device` records no network of its own, so releasing it asks "which network
// sits on this device" — and that question was answered with the FIRST one
// found. A bridge has as many logical networks as the user cares to put on it,
// only some of which any instance steers, so the first one was routinely the
// wrong one to ask about: the hand-over looked for an instance still steering
// a network nobody steers, found none, and gave the bridge back. The user
// turned one VPN instance off and IPv6 stopped on another they never touched.
{
	let nd_devs = function() {
		let out = {};
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				out[sec.src] = sec.device;
		}
		return out;
	};
	let other = function(over) {
		let b = ssteer(over);
		b.interface = 'pv_guest';
		b.routing_table = '102';
		return b;
	};
	// Two instances, both steering `media`, and a plain `base` network sharing
	// the bridge. `which` puts one of the two co-tenants first, so the same
	// case can be run in both orderings.
	let shared_net = function(which) {
		global.MOCK_UCI = mkall(F_V6);
		global.MOCK_UCI.network.media.device = '@base';
		global.MOCK_UCI.network.base = { '.type': 'interface', proto: 'static',
			ipaddr: '10.9.8.1/24', device: 'br-base' };
		global.MOCK_UCI.network.dev_media.name = 'br-base';
		global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, protonvpn_features: '' + F_V6 };
		global.MOCK_UCI.protonvpn = {
			main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
				routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
			guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
				routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
		};
		net_first(which);
		let uci = cursor();
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
		enforce_routing(uci, other({ ipv6_mode: 'auto' }));
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	};

	const OPEN = { nd: 1, ip6assign: '64', ip6class: 'local', delegate: '0',
		ra: 'server' };
	// `base` is never steered, so nothing of its own is ever written on it.
	// The nd count is the suite-wide one; the opening it counts belongs to
	// `media`, and nd_devs() below says which device it names.
	const UNTOUCHED = { nd: 1, ip6assign: null, ip6class: null, delegate: null,
		ra: null };

	for (let first in [ 'base', 'media' ]) {
		shared_net(first);
		eq('handover/' + first + ': the survivor keeps the whole of its IPv6',
			v6_state('media'), OPEN);
		eq('handover/' + first + ': the co-tenant is still left alone',
			v6_state('base'), UNTOUCHED);
		eq('handover/' + first + ': the bridge is still allowed IPv6',
			global.MOCK_UCI.network.dev_media.ipv6, '1');
		eq('handover/' + first + ': and the record went to the instance still running',
			global.MOCK_UCI.network.dev_media.protonvpn_managed_v6, 'pv_guest');
		eq('handover/' + first + ': the opening left behind is the survivor own',
			nd_devs(), { media: 'br-base' });
	}

	// The stronger shape: the survivor steers a DIFFERENT network on the same
	// bridge. No ordering makes this work by accident — asking about one
	// co-tenant can only ever find the instance steering THAT one, and here
	// the two instances steer different networks.
	let shared_dev = function(which) {
		global.MOCK_UCI = mkall(F_V6);
		global.MOCK_UCI.network.media.device = 'br-base';
		global.MOCK_UCI.network.sibling = { '.type': 'interface', proto: 'static',
			ipaddr: '10.9.8.1/24', device: 'br-base' };
		global.MOCK_UCI.network.dev_media.name = 'br-base';
		global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, protonvpn_features: '' + F_V6 };
		global.MOCK_UCI.firewall.zsib = { '.type': 'zone', name: 'sib',
			network: [ 'sibling' ] };
		global.MOCK_UCI.dhcp.sibling = { '.type': 'dhcp', interface: 'sibling',
			ra: 'disabled', dhcpv6: 'disabled' };
		global.MOCK_UCI.protonvpn = {
			main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
				routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
			guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
				routing_table: '102', ipv6_mode: 'auto', source_network: [ 'sibling' ] }
		};
		net_first(which);
		let uci = cursor();
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
		enforce_routing(uci, other({ ipv6_mode: 'auto', source_networks: [ 'sibling' ] }));
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	};

	for (let first in [ 'media', 'sibling' ]) {
		shared_dev(first);
		eq('handover-sibling/' + first + ': the survivor network keeps its IPv6',
			v6_state('sibling'),
			{ nd: 1, ip6assign: '64', ip6class: 'local', delegate: '0', ra: 'server' });
		eq('handover-sibling/' + first + ': the bridge is still allowed IPv6',
			global.MOCK_UCI.network.dev_media.ipv6, '1');
		eq('handover-sibling/' + first + ': and the record went to the survivor',
			global.MOCK_UCI.network.dev_media.protonvpn_managed_v6, 'pv_guest');
		eq('handover-sibling/' + first + ': the network the disabled instance held is given back',
			v6_state('media'),
			{ nd: 1, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });
		eq('handover-sibling/' + first + ': and only the survivor opening is left',
			nd_devs(), { sib: 'br-base' });
	}

	// The other half of the same question: an instance that is STILL steering
	// a network on the bridge keeps it. Asking only the first co-tenant gets
	// this wrong in the same ordering — `base` is not steered, so the section
	// looks unwanted and is handed to the other instance while its real holder
	// is still running.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = '@base';
	global.MOCK_UCI.network.base = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.1/24', device: 'br-base' };
	global.MOCK_UCI.network.dev_media.name = 'br-base';
	global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
		private_key: KEY, protonvpn_features: '' + F_V6 };
	global.MOCK_UCI.protonvpn = {
		main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
		guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
			routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
	};
	net_first('base');
	let u2 = cursor();
	enforce_routing(u2, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(u2, other({ ipv6_mode: 'auto' }));
	enforce_routing(u2, ssteer({ ipv6_mode: 'auto' }));
	eq('handover: an instance still steering the bridge does not give it away',
		global.MOCK_UCI.network.dev_media.protonvpn_managed_v6, 'pv_media');
	// Two openings, one per instance: each reconciles only its own stamped
	// rules, so both hold an identical one and each takes its own away again.
	eq('handover: and nothing about the network moved either', v6_state('media'),
		{ nd: 2, ip6assign: '64', ip6class: 'local', delegate: '0', ra: 'server' });

	// The hand-over must still be a hand-over and not a refusal to let go:
	// with nobody left steering anything on the bridge, it goes back exactly
	// as it was.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.media.device = 'br-base';
	global.MOCK_UCI.network.sibling = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.8.1/24', device: 'br-base' };
	global.MOCK_UCI.network.dev_media.name = 'br-base';
	global.MOCK_UCI.protonvpn = {
		main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] }
	};
	net_first('sibling');
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('handover: the only instance holds the bridge',
		global.MOCK_UCI.network.dev_media.protonvpn_managed_v6, 'pv_media');
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
	eq('handover: with no survivor the bridge is given back',
		global.MOCK_UCI.network.dev_media.ipv6, '0');
	ok('handover: and the stamp goes with it',
		global.MOCK_UCI.network.dev_media.protonvpn_managed_v6 == null);
	eq('handover: and so does everything on the network',
		v6_state('media'),
		{ nd: 0, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });
}

// ── 30. an heir passes the same test as an owner ─────────────────────────
// The hand-over asked only whether another instance was switched on, in auto
// mode and steering the network — never whether it could actually be given
// IPv6. So a network that had just become ineligible was not given back: its
// ULA, its announcement and the bridge's `ipv6` were handed to a peer that
// would have refused to configure them itself, and the stamp said that peer
// was looking after them. That is the half-configured state round 12 removed
// — a network advertising IPv6 it cannot use — coming back through
// inheritance. Claims were inherited; the scrutiny that justified them was
// not.
{
	let stamps = function() {
		return {
			net: global.MOCK_UCI.network.media.protonvpn_managed_v6,
			dev: global.MOCK_UCI.network.dev_media.protonvpn_managed_v6,
			dhcp: global.MOCK_UCI.dhcp.media.protonvpn_managed_v6
		};
	};
	let other = function(over) {
		let b = ssteer(over);
		b.interface = 'pv_guest';
		b.routing_table = '102';
		return b;
	};
	// Two auto instances steering `media`, the first holding the claims. Then
	// a second logical network on the same bridge gains a default route, which
	// makes the whole device a way out and `media` ineligible for everyone.
	// `which` decides whether the alias is listed before or after `media`.
	let went_ineligible = function(which) {
		global.MOCK_UCI = mkall(F_V6);
		global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, protonvpn_features: '' + F_V6 };
		global.MOCK_UCI.protonvpn = {
			main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
				routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
			guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
				routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
		};
		let uci = cursor();
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
		enforce_routing(uci, other({ ipv6_mode: 'auto' }));
		// Both are serving it at this point, and the owner holds the claims.
		global.MOCK_UCI.network.edge_alias = { '.type': 'interface', proto: 'static',
			device: 'br-media', ipaddr: '198.51.100.2/24', gateway: '198.51.100.1' };
		net_first(which);
		return cursor();
	};

	// Everything given back, in both config orderings. The nd count is the
	// suite-wide one: the owner takes ITS opening away here and the peer's own
	// stays until the peer runs, which is the next step.
	const GIVEN_BACK = { nd: 1, ip6assign: null, ip6class: null, delegate: null,
		ra: 'disabled' };
	// The alias never had any of this written on it and must not acquire it.
	const ALIAS_CLEAN = { nd: 1, ip6assign: null, ip6class: null, delegate: null,
		ra: null };

	for (let first in [ 'media', 'edge_alias' ]) {
		let uci = went_ineligible(first);
		// Sanity: the owner really did hold all three before the change, or
		// the assertions below would pass on a fixture that never claimed
		// anything.
		eq('heir/' + first + ': the owner held the claims to begin with', stamps(),
			{ net: 'pv_media', dev: 'pv_media', dhcp: 'pv_media' });

		enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
		eq('heir/' + first + ': the network is given back, not handed on',
			v6_state('media'), GIVEN_BACK);
		eq('heir/' + first + ': and the alias got nothing', v6_state('edge_alias'),
			ALIAS_CLEAN);
		eq('heir/' + first + ': the bridge is closed again',
			global.MOCK_UCI.network.dev_media.ipv6, '0');
		eq('heir/' + first + ': and no stamp is left anywhere', stamps(),
			{ net: null, dev: null, dhcp: null });
		eq('heir/' + first + ': the user values came back',
			global.MOCK_UCI.network.dev_media.protonvpn_saved_ipv6, null);

		// The peer must not take them back either. It is ineligible for the
		// same reason the owner was, so its own run has nothing to claim.
		enforce_routing(uci, other({ ipv6_mode: 'auto' }));
		eq('heir/' + first + ': the peer does not take the claims back',
			v6_state('media'),
			{ nd: 0, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });
		eq('heir/' + first + ': nor stamps anything', stamps(),
			{ net: null, dev: null, dhcp: null });
		eq('heir/' + first + ': and the bridge stays closed',
			global.MOCK_UCI.network.dev_media.ipv6, '0');
	}

	// An heir whose own interface section is gone is no heir either: the
	// opening and the addressing exist to serve clients reaching a tunnel, and
	// the owner's want list already refuses a network when its own interface
	// has been deleted. The successor search has to refuse it for the same
	// reason, or deleting a tunnel and then disabling the other instance would
	// leave the addressing stamped to an interface that does not exist and
	// nothing would ever give it back.
	for (let first in [ 'media', 'pv_guest' ]) {
		global.MOCK_UCI = mkall(F_V6);
		global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, protonvpn_features: '' + F_V6 };
		global.MOCK_UCI.protonvpn = {
			main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
				routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
			guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
				routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
		};
		net_first(first);
		let uci = cursor();
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
		enforce_routing(uci, other({ ipv6_mode: 'auto' }));
		delete global.MOCK_UCI.network.pv_guest;
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
		eq('heir-gone/' + first + ': a peer with no interface section inherits nothing',
			v6_state('media'),
			{ nd: 1, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });
		eq('heir-gone/' + first + ': and nothing is left stamped to it', stamps(),
			{ net: null, dev: null, dhcp: null });
	}
}

// ── 31. a section bearing the name is not a WireGuard interface ──────────
// All of this exists to serve clients reaching a tunnel, so it is refused
// when the tunnel's own interface is not there. That was asked as "is there a
// section with this name", which answers a different question: a `config
// device` of that name passes, a leftover static interface passes, and — in
// the mock, whose `set` creates a section real uci refuses to create — so does
// the routing stamp this module writes one step later, which makes the test
// self-confirming on the second run. The condition is now what actually makes
// the section a WireGuard interface.
{
	let nd_rules = function() {
		let out = [];
		for (let k in global.MOCK_UCI.firewall) {
			let sec = global.MOCK_UCI.firewall[k];
			if (sec['.type'] == 'rule' && sec.protonvpn_managed == '1' &&
			    sec.protonvpn_role == 'icmpv6_nd')
				push(out, sec);
		}
		return out;
	};
	let stamps = function() {
		return {
			net: global.MOCK_UCI.network.media.protonvpn_managed_v6,
			dev: global.MOCK_UCI.network.dev_media.protonvpn_managed_v6,
			dhcp: global.MOCK_UCI.dhcp.media.protonvpn_managed_v6
		};
	};
	const CLOSED = { nd: 0, ip6assign: null, ip6class: null, delegate: null,
		ra: 'disabled' };
	const OPEN = { nd: 1, ip6assign: '64', ip6class: 'local', delegate: '0',
		ra: 'server' };
	const NO_STAMPS = { net: null, dev: null, dhcp: null };

	// The reviewer's probe. The first reconcile after the interface goes gives
	// everything back — and writes the routing stamp for an interface that is
	// no longer there. The SECOND reconcile used to read that back as proof of
	// an interface and configure the lot again: a ULA, a router advertisement
	// and a neighbour-discovery opening for a tunnel that does not exist.
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('twopass: configured while the interface is there', v6_state('media'), OPEN);
	delete global.MOCK_UCI.network.pv_media;
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('twopass: the first reconcile gives it all back', v6_state('media'), CLOSED);
	eq('twopass: and leaves no stamp', stamps(), NO_STAMPS);
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('twopass: and the second reconcile configures nothing',
		v6_state('media'), CLOSED);
	eq('twopass: no opening either', length(nd_rules()), 0);
	eq('twopass: and still no stamp', stamps(), NO_STAMPS);
	// A third, because "the state after one run" is exactly what the condition
	// was reading: whatever a run leaves behind must not become the evidence
	// the next one admits.
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('twopass: nor any run after that', v6_state('media'), CLOSED);

	// The same two passes on an instance whose interface was never created —
	// the state a configured-but-never-applied instance is in.
	global.MOCK_UCI = mkall(F_V6);
	delete global.MOCK_UCI.network.pv_media;
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('never-applied: an instance with no interface configures nothing',
		v6_state('media'), CLOSED);
	eq('never-applied: and opens nothing', length(nd_rules()), 0);

	// And the part that needs no stamp at all to go wrong: a section of that
	// name which is not a WireGuard interface. This is the condition being
	// judged on what it means rather than on what it leaves behind, so it
	// holds whatever any previous run did or did not write.
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.pv_media = { '.type': 'interface', proto: 'static',
		ipaddr: '10.9.9.1/24' };
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('not-wireguard: a static interface of that name is not the tunnel',
		v6_state('media'), CLOSED);

	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.pv_media = { '.type': 'device', name: 'pv_media',
		type: 'bridge' };
	uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('not-wireguard: nor is a device section of that name',
		v6_state('media'), CLOSED);

	// An heir is judged by the same condition, so a peer whose interface is
	// only a name cannot inherit the claims either. Round 15 made the heir
	// take the owner's test; this is that test being the right one.
	let other = function(over) {
		let b = ssteer(over);
		b.interface = 'pv_guest';
		b.routing_table = '102';
		return b;
	};
	for (let shape in [ 'static', 'stamp' ]) {
		global.MOCK_UCI = mkall(F_V6);
		global.MOCK_UCI.network.pv_guest = { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, protonvpn_features: '' + F_V6 };
		global.MOCK_UCI.protonvpn = {
			main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
				routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
			guest: { '.type': 'instance', interface: 'pv_guest', enabled: '1',
				routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
		};
		uci = cursor();
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
		enforce_routing(uci, other({ ipv6_mode: 'auto' }));
		// The peer's tunnel stops being a tunnel: either replaced by an
		// unrelated section of the same name, or reduced to the routing stamp
		// a reconcile of its own would leave.
		global.MOCK_UCI.network.pv_guest = (shape == 'static')
			? { '.type': 'interface', proto: 'static', ipaddr: '10.9.9.1/24' }
			: { '.type': 'unknown', protonvpn_managed_routing: '1' };
		uci = cursor();
		enforce_routing(uci, ssteer({ ipv6_mode: 'auto', enabled: false }));
		eq('heir-name/' + shape + ': a peer that is only a name inherits nothing',
			v6_state('media'),
			{ nd: 1, ip6assign: null, ip6class: null, delegate: null, ra: 'disabled' });
		eq('heir-name/' + shape + ': and nothing is left stamped to it', stamps(),
			NO_STAMPS);
	}
}

_apply.connect_one = real_connect_one;
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL IPV6 TESTS PASSED');
exit(fails ? 1 : 0);

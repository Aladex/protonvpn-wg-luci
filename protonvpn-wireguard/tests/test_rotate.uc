#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Offline tests for the rotation worker, the transactional apply and the
// routing enforcement. Uses the mock 'uci'/'ubus' modules (forced ahead on
// the module search path). Globals `fixture` and `KEY` are supplied by
// run.sh.

'use strict';

import { unlink, mkdir, rmdir } from 'fs';
import { cursor } from 'uci';
const _cmn = require('protonvpn.common');
const load_settings = _cmn.load_settings;
const _api = require('protonvpn.api');
const _apply = require('protonvpn.apply');
const read_cert_state = _apply.read_cert_state;
const write_relay = _apply.write_relay,
      current_peer = _apply.current_peer,
      restore_peer = _apply.restore_peer,
      verify_handshake = _apply.verify_handshake,
      ensure_keypair = _apply.ensure_keypair,
      apply = _apply.apply;
const _rotate = require('protonvpn.rotate');
const shuffle = _rotate.shuffle,
      current_key = _rotate.current_key,
      plan_candidates = _rotate.plan_candidates,
      rotate = _rotate.rotate;
const _routing = require('protonvpn.routing');
const detect_routing = _routing.detect,
      enforce_routing = _routing.enforce,
      recommend_mtu = _routing.recommend_mtu;
// Runtime scratch dir of THIS run (see tests/run.sh); never the shared /tmp.
const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';


let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

// ── Inline normalized cache (the shape protonvpn.cache produces) ──────────

function mkrelay(name, hostname, ip, over) {
	let r = { name: name, hostname: hostname, ip_address: ip, public_key: KEY,
		location: 'nl-amsterdam', country_code: 'nl', city_code: 'nl-amsterdam',
		port: 51820, load: 42, score: 2.9, features: 12, tier: 2,
		secure_core: false, tor: false, active: true };
	for (let k in over)
		r[k] = over[k];
	return r;
}

let cache = {
	countries: [
		{ code: 'nl', name: 'NL', gateway_count: 3, cities: [
			{ code: 'nl-amsterdam', name: 'Amsterdam', country: 'NL', country_code: 'nl',
				gateway_count: 3, relays: [
					mkrelay('NL#1', 'node-nl-01.protonvpn.net', '1.2.3.4'),
					mkrelay('NL#2', 'node-nl-02.protonvpn.net', '5.6.7.8'),
					mkrelay('NL#3', 'node-nl-03.protonvpn.net', '9.10.11.12')
				] }
		] },
		{ code: 'ch', name: 'CH', gateway_count: 1, cities: [
			{ code: 'ch-zurich', name: 'Zurich', country: 'CH', country_code: 'ch',
				gateway_count: 1, relays: [
					mkrelay('CH#1', 'ch-zurich-01.protonvpn.net', '2.3.4.5',
						{ location: 'ch-zurich', country_code: 'ch',
							city_code: 'ch-zurich', features: 1, secure_core: true })
				] }
		] },
		{ code: 'fr', name: 'FR', gateway_count: 1, cities: [
			{ code: 'fr-paris', name: 'Paris', country: 'FR', country_code: 'fr',
				gateway_count: 1, relays: [
					mkrelay('FR#1-TOR', 'fr-13-tor.protonvpn.net', '3.4.5.6',
						{ location: 'fr-paris', country_code: 'fr',
							city_code: 'fr-paris', features: 2, tor: true })
				] }
		] }
	],
	stats: { countries: 3, cities: 3, gateways: 5, servers_seen: 5 }
};

// A cache file on disk for the rotate() flow, in the envelope
// protonvpn.cache writes (schema_version + cached_at + cache_info).
let cdir = RUN + '/pvtest_' + time();
mkdir(cdir);
let cpath = cdir + '/protonvpn_servers_cache.json';
_cmn.atomic_write(cpath, sprintf('%J', {
	...cache,
	cached_at: time(),
	schema_version: _cmn.CACHE_SCHEMA_VERSION,
	cache_info: { created: _cmn.iso_ts(), expires_at: _cmn.iso_ts(time() + 86400) }
}));

// ── 1. shuffle (pure) ─────────────────────────────────────────────────────
{
	let arr = [ 1, 2, 3, 4, 5 ];
	let sh = shuffle(arr);
	eq('shuffle preserves length', length(sh), 5);
	let sum = 0;
	for (let x in sh) sum += x;
	eq('shuffle preserves members', sum, 15);
	eq('shuffle does not mutate input', length(arr), 5);
}

// ── 2. current_key (pure): stamped gateway wins, endpoint_host is the
//       fallback so an unstamped peer is still excluded ────────────────────
{
	eq('current_key prefers gateway', current_key({ gateway: 'g', endpoint_host: 'e' }), 'g');
	eq('current_key falls back to endpoint_host', current_key({ endpoint_host: 'e' }), 'e');
	eq('current_key null when neither', current_key({}), null);
	eq('current_key null when no peer', current_key(null), null);
}

// ── 3. plan_candidates (pure): excludes the current gateway, respects
//       max_retries, filters by hop mode via select ────────────────────────
{
	let s_nl = { country_code: 'nl', city_code: '', hop_mode: 'standard', locations: [], max_retries: 10 };
	eq('plan includes all matches without exclusion', length(plan_candidates(cache, s_nl, null, 10)), 3);
	let plan = plan_candidates(cache, s_nl, 'node-nl-01.protonvpn.net', 10);
	eq('plan excludes current gateway', length(plan), 2);
	let has_current = false;
	for (let r in plan)
		if (r.hostname == 'node-nl-01.protonvpn.net')
			has_current = true;
	eq('plan never contains the current gateway', has_current, false);
	eq('plan excludes via endpoint_host key',
		length(plan_candidates(cache, s_nl, current_key({ endpoint_host: 'node-nl-01.protonvpn.net' }), 10)), 2);
	eq('plan respects max_retries cap', length(plan_candidates(cache, s_nl, null, 2)), 2);
	eq('plan excluding the only match is empty',
		length(plan_candidates(cache, { ...s_nl, country_code: 'ch', hop_mode: 'secure_core' }, 'ch-zurich-01.protonvpn.net', 10)), 0);

	// Hop modes select exactly their kind through the Features-decoded flags.
	let s_sc = { country_code: 'ch', city_code: '', hop_mode: 'secure_core', locations: [], max_retries: 10 };
	let sc = plan_candidates(cache, s_sc, null, 10);
	eq('secure_core plan selects the secure-core relay', length(sc) == 1 && sc[0].hostname == 'ch-zurich-01.protonvpn.net', true);
	let s_tor = { country_code: 'fr', city_code: '', hop_mode: 'tor', locations: [], max_retries: 10 };
	let tor = plan_candidates(cache, s_tor, null, 10);
	eq('tor plan selects the tor relay', length(tor) == 1 && tor[0].hostname == 'fr-13-tor.protonvpn.net', true);
	eq('standard mode never picks secure-core/tor relays',
		length(plan_candidates(cache, { ...s_nl, country_code: 'ch' }, null, 10)), 0);

	// Location sets: the union wins over the legacy country/city selection.
	let s_set = { country_code: 'fr', city_code: '', hop_mode: 'standard', locations: [ 'nl' ], max_retries: 10 };
	eq('plan draws from the location set', length(plan_candidates(cache, s_set, null, 10)), 3);
	eq('plan over the set excludes the gateway',
		length(plan_candidates(cache, s_set, 'node-nl-02.protonvpn.net', 1)), 1);
}

// ── 4. rotation state persistence: the daemon's attempt clock survives a
//       restart, record() merges without clobbering, per-instance isolation ─
{
	unlink(RUN + '/protonvpn_rotate_state.json');
	eq('last_attempt 0 when no state', _rotate.last_attempt_ts(), 0);
	_rotate.mark_attempt(1000);
	eq('last_attempt persisted', _rotate.last_attempt_ts(), 1000);
	_rotate.record({ last_success: 2000, server: 'NL#1' });
	eq('record keeps last_attempt', _rotate.last_attempt_ts(), 1000);
	eq('record merged last_success', _rotate.read_state().last_success, 2000);
	_rotate.mark_attempt(3000);
	eq('mark_attempt keeps last_success', _rotate.read_state().last_success, 2000);
	unlink(RUN + '/protonvpn_rotate_state.json');

	unlink(RUN + '/protonvpn_rotate_state_media.json');
	_rotate.mark_attempt(1000);
	_rotate.mark_attempt(2000, 'media');
	eq('main rotate state isolated', _rotate.last_attempt_ts(), 1000);
	eq('media rotate state isolated', _rotate.last_attempt_ts('media'), 2000);
	unlink(RUN + '/protonvpn_rotate_state.json');
	unlink(RUN + '/protonvpn_rotate_state_media.json');
}

// ── 5. write_relay: Proton peer/address/stamp values ─────────────────────
{
	global.MOCK_UCI = {
		protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
			country_code: 'nl', city_code: '', cache_dir: cdir } },
		network: { protonvpn: { '.type': 'interface', proto: 'wireguard',
			private_key: KEY, vpn_type: 'protonvpn' } }
	};
	let uci = cursor();
	let relay = mkrelay('NL#85', 'node-nl-47.protonvpn.net', '138.199.7.129', { location: 'nl-amsterdam' });
	write_relay(uci, 'protonvpn', relay, load_settings(uci));

	let net = global.MOCK_UCI.network;
	let peerkey = null;
	for (let k in net)
		if (index(net[k]['.type'], 'wireguard_') == 0)
			peerkey = k;
	ok('write_relay created a peer section', peerkey != null);
	let peer = net[peerkey];
	eq('peer public_key is the server X25519PublicKey', peer.public_key, KEY);
	eq('peer endpoint_host is the EntryIP', peer.endpoint_host, '138.199.7.129');
	eq('peer endpoint_port is 51820', peer.endpoint_port, '51820');
	eq('peer keepalive', peer.persistent_keepalive, '25');
	eq('peer allowed_ips is full-tunnel v4+v6', peer.allowed_ips, [ '0.0.0.0/0', '::/0' ]);
	// The stamp is the logical name the user sees and pins, not the per-server
	// domain, so status and the picker speak the same identity.
	eq('peer stamped with the logical server name', peer.protonvpn_gateway, 'NL#85');
	eq('iface addresses are the fixed Proton pair',
		net.protonvpn.addresses, [ '10.2.0.2/32', 'fd54:20a4:d33b:b10c:0:2:0:2/128' ]);
	eq('iface vpn_type', net.protonvpn.vpn_type, 'protonvpn');
	eq('iface city stamp', net.protonvpn.protonvpn_city_code, 'nl-amsterdam');
	eq('iface country stamp', net.protonvpn.protonvpn_country_code, 'nl');
	ok('iface last-applied stamp', net.protonvpn.protonvpn_last_applied != null);

	// current_peer/restore_peer round-trip.
	let saved = current_peer(uci, 'protonvpn');
	eq('current_peer snapshots the gateway', saved.gateway, 'NL#85');
	eq('current_peer snapshots the endpoint', saved.endpoint_host, '138.199.7.129');
	write_relay(uci, 'protonvpn', mkrelay('NL#86', 'node-nl-48.protonvpn.net', '138.199.7.130'), load_settings(uci));
	restore_peer(uci, 'protonvpn', saved);
	let back = current_peer(uci, 'protonvpn');
	eq('restore_peer brings the gateway back', back.gateway, 'NL#85');
	eq('restore_peer brings the endpoint back', back.endpoint_host, '138.199.7.129');
}

// ── 6. ensure_keypair/apply without a session fail as 'not logged in' ─────
{
	global.MOCK_UCI = {
		protonvpn: { main: { '.type': 'instance', interface: 'protonvpn', cache_dir: cdir } },
		network: { protonvpn: { '.type': 'interface', proto: 'wireguard' } }
	};
	let uci = cursor();
	// No session in the (relocated) state dir, so keypair generation must
	// stop before touching openssl or the API.
	unlink((getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn') + '/session.json');
	eq('ensure_keypair needs a session', ensure_keypair(uci).error, 'not logged in');
	eq('apply needs a session', apply(uci).error, 'not logged in');
	ok('no key was persisted', global.MOCK_UCI.network.protonvpn.private_key == null);
}

// ── 6b. ensure_keypair on the SUCCESS path ───────────────────────────────
// The failure-only test above stops at 'not logged in', so nothing ever ran
// the branch that persists the key and records the certificate. That branch
// is exactly where a missing import would blow up, so drive it end to end
// with a stubbed registration call.
{
	let statedir = getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn';
	global.MOCK_UCI = {
		protonvpn: { main: { '.type': 'instance', interface: 'protonvpn', cache_dir: cdir } },
		network: {}
	};
	let uci = cursor();

	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: time() + 1800, session_expires_at: time() + 86400,
		scope: 'vpn', twofa: false });

	// Stub the registration so the test needs no network and no real account.
	let seen_pem = null;
	let real_create = _api.certificate_create;
	_api.certificate_create = function(pubkey, mode, days) {
		seen_pem = pubkey;
		return { ok: true, serial: '123', mode: mode,
			expires_at: time() + 365 * 86400, refresh_at: time() + 300 * 86400 };
	};

	let r = ensure_keypair(uci, 'main');
	_api.certificate_create = real_create;

	eq('ensure_keypair succeeds with a session', r.error, null);
	ok('ensure_keypair reports ok', r.ok == true);
	ok('a WireGuard private key was persisted',
		_cmn.validate_wg_key(uci.get('network', 'protonvpn', 'private_key')) != null);
	ok('the API received a PEM public key, not a raw wg key',
		seen_pem != null && index(seen_pem, '-----BEGIN PUBLIC KEY-----') == 0);
	ok('the registered key is Ed25519 (SPKI OID 1.3.101.112)',
		index(seen_pem, 'MCowBQYDK2Vw') >= 0);

	let cs = read_cert_state('main');
	ok('certificate metadata was recorded', cs != null);
	eq('serial stored', cs ? cs.serial : null, '123');
	ok('refresh_at stored (Proton tells us when to renew)', cs && cs.refresh_at > 0);

	// A second call must take the fast path and not re-register.
	let calls = 0;
	_api.certificate_create = function() { calls++; return { ok: true, serial: 'x' }; };
	ensure_keypair(uci, 'main');
	_api.certificate_create = real_create;
	eq('an existing keypair is not re-registered', calls, 0);

	unlink(statedir + '/session.json');
	unlink(statedir + '/certificate.json');
}

// ── 6c. rotation refuses to run on an instance that cannot possibly connect ─
// Without these guards a rotation would try max_retries servers at
// verify_timeout seconds each and only then give up with a vague error.
{
	let statedir = getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn';
	unlink(statedir + '/certificate.json');
	global.MOCK_UCI = {
		protonvpn: { main: { '.type': 'instance', interface: 'protonvpn', cache_dir: cdir } },
		network: { protonvpn: { '.type': 'interface', proto: 'wireguard' } }
	};
	let r = rotate(cursor());
	ok('rotation skips an instance with no keypair', r.skipped == true);
	ok('and says why', index(r.reason || '', 'keypair') >= 0);

	// With a key but an expired certificate, every candidate would reject us.
	global.MOCK_UCI.network.protonvpn.private_key = KEY;
	_apply.record_cert_state('main', { serial: '1', expires_at: time() - 10,
		refresh_at: 0, created_at: time() - 100 });
	let r2 = rotate(cursor());
	ok('rotation reports an expired certificate', r2.certificate_expired == true);
	ok('and does not pretend it merely failed', index(r2.error || '', 'expired') >= 0);

	// A valid certificate lets it get as far as needing the server list.
	_apply.record_cert_state('main', { serial: '1', expires_at: time() + 86400,
		refresh_at: 0, created_at: time() });
	let r3 = rotate(cursor());
	ok('a valid certificate passes the guard', r3.certificate_expired == null);
	unlink(statedir + '/certificate.json');

	// Deleting an instance must not leave its certificate metadata behind.
	_apply.record_cert_state('other', { serial: '9', expires_at: time() + 100 });
	_apply.record_cert_state('main', { serial: '8', expires_at: time() + 100 });
	_apply.forget_cert_state('main');
	ok('forget_cert_state drops just that instance', _apply.read_cert_state('main') == null);
	ok('and keeps the others', _apply.read_cert_state('other') != null);
	unlink(statedir + '/certificate.json');
}

// ── 7. verify_handshake off-device: wg cannot run, so the check passes
//       through instead of blocking the apply logic ────────────────────────
{
	ok('verify_handshake passes off-device', verify_handshake('protonvpn', 1) == true);
}

// ── 8. rotate(): every candidate fails off-device (ifup fails), so the
//       previous peer must be restored untouched ───────────────────────────
{
	unlink(RUN + '/protonvpn_rotate.lock');
	global.MOCK_UCI = {
		protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
			country_code: 'nl', city_code: '', cache_dir: cdir, enabled: '1' } },
		network: {
			protonvpn: { '.type': 'interface', proto: 'wireguard',
				private_key: KEY, vpn_type: 'protonvpn' },
			peer0: { '.type': 'wireguard_protonvpn', interface: 'protonvpn',
				public_key: KEY, endpoint_host: '1.2.3.4', endpoint_port: '51820',
				protonvpn_gateway: 'node-nl-01.protonvpn.net' }
		}
	};
	let uci = cursor();
	let res = rotate(uci);
	ok('rotate reports total failure', res.error != null);
	eq('rotate restored the previous peer', res.restored, true);
	let peer = global.MOCK_UCI.network.peer0;
	eq('peer gateway rolled back', peer.protonvpn_gateway, 'node-nl-01.protonvpn.net');
	eq('peer endpoint rolled back', peer.endpoint_host, '1.2.3.4');
	eq('peer port rolled back', peer.endpoint_port, '51820');
	eq('peer pubkey rolled back', peer.public_key, KEY);

	// A pinned fixed server skips rotation entirely.
	global.MOCK_UCI.protonvpn.main.fixed_server = 'NL#2';
	eq('rotate skips a pinned server', rotate(cursor()).reason, 'fixed server configured');
	delete global.MOCK_UCI.protonvpn.main.fixed_server;
	unlink(RUN + '/protonvpn_rotate.lock');
}

// ── 9. routing detection: none vs manual vs steered vs auto ──────────────
{
	let mks = function(over) {
		let base = { interface: 'protonvpn', routing_table: '', auto_routing: false,
			killswitch: false, ipv6_mode: 'block', vpn_dns: 'off' };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	let mknet = function() {
		return {
			protonvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
			peer: { '.type': 'wireguard_protonvpn', interface: 'protonvpn',
				endpoint_host: '138.199.7.129' }
		};
	};
	let mkfw = function() {
		return {
			zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
			zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] }
		};
	};

	// A bare custom routing table is NOT manual on its own — only user routes
	// or rules make it manual, so the table can be used for steered mode.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	let uci = cursor();
	eq('routing: bare table is not manual', detect_routing(uci, mks({ routing_table: '101' }), false).mode, 'none');

	// A user route living in the instance's table (not referencing the iface)
	// still forces manual — that is a real hand-built policy scheme.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.tblroute = { '.type': 'route', interface: 'lan', target: '10.0.0.0/8', table: '101' };
	uci = cursor();
	eq('routing: route in the table forces manual', detect_routing(uci, mks({ routing_table: '101' }), false).mode, 'manual');

	// A user route referencing the interface means manual mode, and enforce()
	// must not change a single byte even with every toggle on.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	global.MOCK_UCI.network.myroute = { '.type': 'route', interface: 'protonvpn', target: '0.0.0.0/0' };
	uci = cursor();
	eq('routing: manual via user route', detect_routing(uci, mks({ auto_routing: true }), false).mode, 'manual');
	let before = sprintf('%J', global.MOCK_UCI);
	let res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true, vpn_dns: 'standard' }));
	eq('routing: manual scheme untouched', sprintf('%J', global.MOCK_UCI), before);
	eq('routing: manual reports no changes', res.changed_network || res.changed_firewall, false);

	// Fresh install with automatic routing: zone, forwarding, default route,
	// kill switch and IPv6 block appear; everything stamped.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	uci = cursor();
	let pristine = sprintf('%J', global.MOCK_UCI);
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true }));
	ok('routing: auto changed firewall', res.changed_firewall);
	ok('routing: auto changed network', res.changed_network);
	let det = detect_routing(uci, mks({ auto_routing: true }), false);
	eq('routing: auto mode', det.mode, 'auto');
	eq('routing: zone created', det.zone, 'protonvpn');
	ok('routing: zone is stamped', det.zone_managed);
	ok('routing: default route set', det.route_allowed_ips);
	ok('routing: kill switch installed', det.killswitch);
	ok('routing: ipv6 block installed', det.ipv6_block);

	// Idempotent: a second run changes nothing.
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true }));
	eq('routing: idempotent', res.changed_network || res.changed_firewall, false);

	// Turning a single toggle off removes exactly that object.
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: false }));
	ok('routing: kill switch removed', !detect_routing(uci, mks({ auto_routing: true }), false).killswitch);
	ok('routing: ipv6 block survives the ks toggle', detect_routing(uci, mks({ auto_routing: true }), false).ipv6_block);
	res = enforce_routing(uci, mks({ auto_routing: true, ipv6_mode: 'off' }));
	ok('routing: ipv6 block removed', !detect_routing(uci, mks({ auto_routing: true }), false).ipv6_block);
	res = enforce_routing(uci, mks({ auto_routing: true }));

	// Turning automatic mode off restores the pristine configuration.
	res = enforce_routing(uci, mks({ auto_routing: false }));
	eq('routing: off restores pristine config', sprintf('%J', global.MOCK_UCI), pristine);

	// DNS override: 'standard' pushes the Proton in-tunnel resolvers, the
	// stamp records the mode, 'off' removes the override.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	uci = cursor();
	enforce_routing(uci, mks({ auto_routing: true, vpn_dns: 'standard' }));
	eq('dns: standard pair applied', global.MOCK_UCI.network.protonvpn.dns, [ '10.2.0.1', 'fd54:20a4:d33b:b10c:0:2:0:1' ]);
	eq('dns: stamp records the mode', global.MOCK_UCI.network.protonvpn.protonvpn_managed_dns, 'standard');
	enforce_routing(uci, mks({ auto_routing: true, vpn_dns: 'off' }));
	eq('dns: off removes the override', global.MOCK_UCI.network.protonvpn.dns, null);
	eq('dns: off clears the stamp', global.MOCK_UCI.network.protonvpn.protonvpn_managed_dns, null);

	// A disabled instance releases all managed objects.
	global.MOCK_UCI = { network: mknet(), firewall: mkfw() };
	uci = cursor();
	pristine = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, mks({ auto_routing: true, killswitch: true }));
	res = enforce_routing(uci, mks({ auto_routing: true, killswitch: true, enabled: false }));
	eq('routing: disabled releases everything', sprintf('%J', global.MOCK_UCI), pristine);
}

// ── 10. source-network steering: lookup/prohibit rules, reconciliation,
//        teardown. Numeric table '101' needs no rt_tables registration ─────
{
	let ssteer = function(over) {
		let base = { interface: 'pv_media', routing_table: '101', auto_routing: false,
			killswitch: false, ipv6_mode: 'block', vpn_dns: 'off', source_networks: [ 'media' ] };
		for (let k in over)
			base[k] = over[k];
		return base;
	};
	let mkall = function() {
		return { network: {
			pv_media: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
			peer_m: { '.type': 'wireguard_pv_media', interface: 'pv_media', endpoint_host: '138.199.7.129' },
			media: { '.type': 'interface', proto: 'static', ipaddr: '10.9.1.1', netmask: '255.255.255.0' },
			guest: { '.type': 'interface', proto: 'static', ipaddr: '10.9.2.1/24' }
		}, firewall: {
			zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
			zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] },
			zmedia: { '.type': 'zone', name: 'media', network: [ 'media' ] }
		} };
	};

	global.MOCK_UCI = mkall();
	let uci = cursor();
	let pris = sprintf('%J', global.MOCK_UCI);

	let res = enforce_routing(uci, ssteer({}));
	ok('steer: changed network', res.changed_network);
	ok('steer: changed firewall', res.changed_firewall);
	let det = detect_routing(uci, ssteer({}), false);
	eq('steer: mode', det.mode, 'steered');
	eq('steer: zone named after iface', det.zone, 'pv_media');
	ok('steer: default route into table', det.route_allowed_ips);
	ok('steer: v6 block on by default', det.ipv6_block);
	ok('steer: no kill switch by default', !det.killswitch);
	ok('steer: networks listed', index(det.networks, 'media') >= 0 && index(det.networks, 'pv_media') < 0);

	let lookup = null;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'rule' && sec['in'] == 'media' && sec.protonvpn_managed == '1' && sec.lookup)
			lookup = sec;
	}
	ok('steer: media lookup rule targets the table', lookup != null && lookup.lookup == '101');

	// Local subnets get stamped bypass routes in the instance table.
	let localr = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if (sec['.type'] == 'route' && sec.protonvpn_role == 'steer_local' && sec.table == '101')
			localr++;
	}
	eq('steer: local bypass routes created', localr, 2);

	// Reconciliation: switch the steering to another network, kill switch on.
	res = enforce_routing(uci, ssteer({ source_networks: [ 'guest' ], killswitch: true }));
	let media_rules = 0, guest_rules = 0;
	for (let k in global.MOCK_UCI.network) {
		let sec = global.MOCK_UCI.network[k];
		if ((sec['.type'] == 'rule' || sec['.type'] == 'rule6') && sec.protonvpn_managed == '1') {
			if (sec['in'] == 'media') media_rules++;
			if (sec['in'] == 'guest') guest_rules++;
		}
	}
	eq('steer: old network rules removed', media_rules, 0);
	eq('steer: new network gets lookup+ks+v6', guest_rules, 3);
	ok('steer: kill switch appears', detect_routing(uci, ssteer({ source_networks: [ 'guest' ] }), false).killswitch);

	// A user route inside the instance's table is a companion, not a manual
	// scheme — steering stays; a route referencing the interface forces manual.
	global.MOCK_UCI.network.companion = { '.type': 'route', interface: 'lan',
		target: '10.0.0.0/24', table: '101' };
	eq('steer: companion route in table keeps steering',
		detect_routing(uci, ssteer({ source_networks: [ 'guest' ] }), false).mode, 'steered');
	global.MOCK_UCI.network.takeover = { '.type': 'route', interface: 'pv_media', target: '0.0.0.0/0' };
	eq('steer: interface route forces manual',
		detect_routing(uci, ssteer({ source_networks: [ 'guest' ] }), false).mode, 'manual');
	delete global.MOCK_UCI.network.companion;
	delete global.MOCK_UCI.network.takeover;

	// A missing routing table disables steering with a note, creating nothing.
	global.MOCK_UCI = { network: { pv_media: { '.type': 'interface', proto: 'wireguard' } }, firewall: {} };
	uci = cursor();
	let before = sprintf('%J', global.MOCK_UCI);
	res = enforce_routing(uci, ssteer({ routing_table: '' }));
	eq('steer: no table -> untouched', sprintf('%J', global.MOCK_UCI), before);
	ok('steer: no table -> note', length(res.notes) > 0);

	// Teardown restores the pristine configuration.
	global.MOCK_UCI = mkall();
	uci = cursor();
	pris = sprintf('%J', global.MOCK_UCI);
	enforce_routing(uci, ssteer({ killswitch: true }));
	enforce_routing(uci, ssteer({ source_networks: [] }));
	eq('steer: teardown restores pristine config', sprintf('%J', global.MOCK_UCI), pris);
}

// ── 11. MTU recommendation (pure) + wireguard interfaces are never
//        steerable nor counted as WAN candidates ───────────────────────────
{
	eq('mtu 1500 -> 1420 (vendor default)', recommend_mtu(1500), 1420);
	eq('mtu 1492 PPPoE -> 1412', recommend_mtu(1492), 1412);
	eq('mtu 1428 LTE -> 1348', recommend_mtu(1428), 1348);
	eq('mtu clamps up to the 1280 IPv6 floor', recommend_mtu(1350), 1280);
	eq('mtu clamps down to the 1420 ceiling', recommend_mtu(1600), 1420);
	eq('mtu null when WAN unknown', recommend_mtu(null), null);
	eq('mtu null on zero/garbage', recommend_mtu(0), null);

	// With a wireguard interface present, runtime detection must not blow up
	// and must not offer the tunnel as a steerable network. (The WAN-MTU
	// probe itself needs a live ubus, so off-device it reports null.)
	global.MOCK_UCI = { network: {
		protonvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY },
		lan: { '.type': 'interface', proto: 'static', ipaddr: '192.168.1.1/24' }
	}, firewall: {
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan', 'protonvpn' ] }
	} };
	let uci = cursor();
	let det = detect_routing(uci, { interface: 'protonvpn', routing_table: '',
		auto_routing: false, killswitch: false, ipv6_mode: 'block', vpn_dns: 'off' }, true);
	eq('mtu: wireguard iface not steerable', index(det.networks, 'protonvpn') >= 0, false);
	ok('mtu: runtime detection survives off-device', det.mode == 'none');
	eq('mtu: no WAN MTU off-device', det.wan_mtu, null);
	eq('mtu: no recommendation without WAN MTU', det.recommended_mtu, null);
}

unlink(cpath);
rmdir(cdir);
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL ROTATE/APPLY/ROUTING TESTS PASSED');
exit(fails ? 1 : 0);

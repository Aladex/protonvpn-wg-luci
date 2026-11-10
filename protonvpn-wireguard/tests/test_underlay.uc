#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// A tunnel's endpoint must never route through another tunnel.
//
// The incident (2026-11-09, the owner's router): the cable uplink (DS-Lite)
// went down; the torrent instance `pv_media` reconnected, and netifd resolved
// its endpoint's host route through the only route left that covered it — the
// 0.0.0.0/0 of the guest instance's tunnel `protonvpn`:
//     79.127.154.1 dev protonvpn proto static scope link
// Torrents rode inside the guest tunnel, which itself rode the SIM, and stayed
// there after the cable came back until someone ran `ifup pv_media`.
//
// The fixtures below are that router, scrubbed: the DS-Lite uplink, the SIM
// uplink with no netifd routes (defaultroute=0; its default is put into
// `main` by an external failover script netifd never sees), two instances —
// `protonvpn` (nohostroute=1, rides `main` on purpose) and `pv_media` (relies
// on a netifd host route) — and the user's own WireGuard `wg0`.
//
// Each property P1–P7 of plans/sim-failover-endpoint/spec.md has a section.
// The kernel- and netifd-facing calls go through seams on protonvpn.routing
// (netifd_dump, stack_refusal, route_device) so that every scenario states
// exactly what the router reports; the real device classifier those seams
// stand in for is exercised against a fake `ip` in test_wan_default.uc.
//
// Run: part of tests/run.sh.

'use strict';

import { readfile, writefile, unlink, mkdir, open } from 'fs';
import { cursor } from 'uci';
const _cmn = require('protonvpn.common');
const _api = require('protonvpn.api');
const _routing = require('protonvpn.routing');
const _underlay = require('protonvpn.underlay');
const _apply = require('protonvpn.apply');
const _rotate = require('protonvpn.rotate');
const _service = require('protonvpn.service');
const _status = require('protonvpn.status');

let fails = 0;
function ok(l, c, extra) {
	if (c) printf('ok   %s\n', l);
	else { fails++; printf('FAIL %s%s\n', l, extra ? ' (' + extra + ')' : ''); }
}
function eq(l, got, want) {
	let g = sprintf('%J', got), w = sprintf('%J', want);
	ok(l, g == w, 'got ' + g + ', want ' + w);
}

const STATE = getenv('PROTONVPN_STATE_DIR') || '/tmp/protonvpn-test-state';
const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';
const IFUP_LOG = STATE + '/ifup.log';
const IFDOWN_LOG = STATE + '/ifdown.log';
const IFUP_OK = STATE + '/ifup-ok';
const EP = '79.127.154.1';
const CDIR = RUN + '/pvtest_underlay_' + time();

// ── Seams: what the router reports ───────────────────────────────────────

// netifd's interface dump; null = netifd did not answer.
let DUMP = null;
// Device -> null (a provider attachment) or why not. A device nobody listed
// is refused, the way the real classifier refuses what it cannot establish.
let KINDS = {};
// Endpoint -> the device the kernel routes it through (`ip route get`).
let ROUTES = {};
let LOG = [];

_routing.netifd_dump = function() { return DUMP; };
_routing.stack_refusal = function(dev) {
	return exists(KINDS, dev) ? KINDS[dev] : 'device kind could not be determined';
};
_routing.route_device = function(family, addr) { return ROUTES[addr]; };
_cmn.log = function(m) { push(LOG, m); };

function said(re) {
	let n = 0;
	for (let l in LOG)
		if (match(l, re))
			n++;
	return n;
}

// One netifd dump entry. `route` is the enabled-route list netifd dumps.
function ifc(name, proto, l3, routes, extra) {
	let o = { interface: name, up: true, pending: false, proto: proto,
		l3_device: l3, metric: 0, route: routes || [], 'ipv4-address': [] };
	for (let k in extra)
		o[k] = extra[k];
	return o;
}
function dflt(extra) {
	let r = { target: '0.0.0.0', mask: 0, nexthop: '0.0.0.0', source: '0.0.0.0/0' };
	for (let k in extra)
		r[k] = extra[k];
	return r;
}

// The owner's router as netifd dumps it with the cable up. `over` replaces
// or (with null) removes entries by name.
function router(over) {
	let list = {
		dslite: ifc('dslite', 'dslite', 'ds-dslite', [
			// A user route with an explicit table: netifd never uses these.
			{ target: '79.127.154.0', mask: 24, nexthop: '0.0.0.0', table: 107, source: '0.0.0.0/0' },
			dflt() ]),
		guest: ifc('guest', 'static', 'br-guest', [], { 'ipv4-address': [ { address: '10.207.90.1', mask: 24 } ] }),
		lan: ifc('lan', 'static', 'br-lan.1', [], { 'ipv4-address': [ { address: '10.207.83.1', mask: 24 } ] }),
		// ip4table'd, so their 0.0.0.0/0 shows no `table` key — and is a
		// candidate for netifd's host-route lookup.
		protonvpn: ifc('protonvpn', 'wireguard', 'protonvpn', [ dflt(), { target: '::', mask: 0, nexthop: '::', source: '::/0' } ], { ip4table: 107 }),
		pv_media: ifc('pv_media', 'wireguard', 'pv_media', [ dflt() ], { ip4table: 108 }),
		wan: ifc('wan', 'static', 'eth1', [], { 'ipv4-address': [ { address: '192.168.100.2', mask: 24 } ] }),
		wan2: ifc('wan2', 'dhcp', 'lan5', [], { 'ipv4-address': [ { address: '10.191.24.83', mask: 29 } ] }),
		wan6: ifc('wan6', 'dhcpv6', 'eth1', [ { target: '::', mask: 0, nexthop: 'fe80::1', source: '::/0' } ]),
		wg0: ifc('wg0', 'wireguard', 'wg0', [ { target: '10.28.0.0', mask: 24, nexthop: '0.0.0.0', source: '0.0.0.0/0' } ])
	};
	for (let k in over) {
		if (over[k] == null)
			delete list[k];
		else
			list[k] = over[k];
	}
	let out = [];
	for (let k in list)
		push(out, list[k]);
	return { interface: out };
}
const HW = { 'ds-dslite': null, 'br-guest': null, 'br-lan.1': null, eth1: null, lan5: null,
	eth0: null, 'br-wan2': null };
function kinds(extra) {
	let k = { ...HW };
	for (let d in extra)
		k[d] = extra[d];
	return k;
}
// The cable is down: netifd took DS-Lite down with it, and pv_media, whose
// host route depended on it, as well.
function outage() {
	return router({ dslite: ifc('dslite', 'dslite', null, [], { up: false }),
		pv_media: ifc('pv_media', 'wireguard', null, [], { up: false }) });
}

// The owner's configuration.
function config(over) {
	let net = {
		pv_media: { '.type': 'interface', proto: 'wireguard', private_key: KEY,
			vpn_type: 'protonvpn', ip4table: 'pv_media', auto: '1' },
		peer_m: { '.type': 'wireguard_pv_media', interface: 'pv_media', public_key: KEY,
			endpoint_host: EP, endpoint_port: '51820', protonvpn_gateway: 'NL#1' },
		protonvpn: { '.type': 'interface', proto: 'wireguard', private_key: KEY,
			vpn_type: 'protonvpn', ip4table: 'guest', nohostroute: '1', auto: '1' },
		peer_g: { '.type': 'wireguard_protonvpn', interface: 'protonvpn', public_key: KEY,
			endpoint_host: '146.70.170.2', endpoint_port: '51820', protonvpn_gateway: 'DE#1' }
	};
	for (let k in (over || {})) {
		if (over[k] == null)
			delete net[k];
		else if (!net[k])
			net[k] = over[k];
		else
			for (let o in over[k])
				net[k][o] = over[k][o];
	}
	return {
		protonvpn: {
			main: { '.type': 'instance', interface: 'protonvpn', enabled: '1', cache_dir: CDIR,
				country_code: 'de', routing_table: 'guest' },
			media: { '.type': 'instance', interface: 'pv_media', enabled: '1', cache_dir: CDIR,
				country_code: 'nl', routing_table: 'pv_media', max_retries: '3',
				verify_timeout: '2' }
		},
		network: net, firewall: {}, dhcp: {}
	};
}

function guards(iface) {
	let out = [];
	for (let t in [ 'rule', 'rule6' ])
		for (let k in global.MOCK_UCI.network) {
			let s = global.MOCK_UCI.network[k];
			if (s['.type'] == t && s.protonvpn_role == 'endpoint_guard' &&
			    (iface == null || s.protonvpn_iface == iface))
				push(out, { type: t, dest: s.dest, action: s.action, priority: s.priority });
		}
	return out;
}
function ifups() {
	let raw = readfile(IFUP_LOG) || '';
	return filter(split(raw, '\n'), (l) => match(l, /^ifup /));
}
function ifdowns() {
	return filter(split(readfile(IFDOWN_LOG) || '', '\n'), (l) => l != '');
}
function reset(cfg, dump, k, routes) {
	global.MOCK_UCI = cfg;
	DUMP = dump;
	KINDS = k || kinds();
	ROUTES = routes || {};
	LOG = [];
	unlink(IFUP_LOG);
	unlink(IFDOWN_LOG);
	for (let n in [ 'main', 'media' ]) {
		unlink(RUN + '/protonvpn_uplink_' + n + '.json');
		unlink(RUN + '/protonvpn_rotate_' + n + '.lock');
	}
	unlink(RUN + '/protonvpn_rotate.lock');
	unlink(RUN + '/protonvpn_uplink.lock');
	return cursor();
}
function media() { return global.MOCK_UCI.network.pv_media; }

// A server list with three NL servers, for apply and rotation.
mkdir(CDIR);
function relay(name, ip) {
	return { name: name, hostname: lc(name) + '.protonvpn.net', ip_address: ip,
		public_key: KEY, location: 'nl-amsterdam', country_code: 'nl',
		city_code: 'nl-amsterdam', port: 51820, load: 10, score: 1, features: 12,
		tier: 2, secure_core: false, tor: false, active: true };
}
_cmn.atomic_write(CDIR + '/protonvpn_servers_cache.json', sprintf('%J', {
	countries: [ { code: 'nl', name: 'NL', gateway_count: 3, cities: [
		{ code: 'nl-amsterdam', name: 'Amsterdam', country: 'NL', country_code: 'nl',
			gateway_count: 3, relays: [ relay('NL#1', EP), relay('NL#2', '79.127.154.2'),
				relay('NL#3', '79.127.154.3') ] } ] } ],
	stats: { countries: 1, cities: 1, gateways: 3, servers_seen: 3 },
	cached_at: time(), schema_version: _cmn.CACHE_SCHEMA_VERSION,
	cache_info: { created: _cmn.iso_ts(), expires_at: _cmn.iso_ts(time() + 86400) }
}));
// A registered certificate with its seed, so apply takes the keypair fast
// path and nothing here needs an account.
for (let n in [ 'main', 'media' ])
	_apply.record_cert_state(n, { key_seed: KEY, serial: '1',
		expires_at: time() + 86400, refresh_at: 0, created_at: time() });

// ════════════════════════════════════════════════════════════════════════
// P1 — no tunnel underlay
// ════════════════════════════════════════════════════════════════════════

// The lookup itself, against the owner's router.
{
	KINDS = kinds();
	let r = _underlay.pick(router(), EP);
	eq('P1 pick: with the cable up, DS-Lite carries the endpoint', r.iface, 'dslite');

	r = _underlay.pick(outage(), EP);
	eq('P1 pick: with the cable down, nothing does', r.iface, null);
	ok('P1 pick: and the guest tunnel was a candidate that was refused',
		length(filter(r.refused, (x) => x.iface == 'protonvpn')) == 1);
	ok('P1 pick: refused as WireGuard before any device is read',
		match(r.refused[0].why, /WireGuard/));

	// netifd's own order would have found the tunnel: an overlay of any kind
	// named to sort before the uplink is refused by its device stack.
	KINDS = kinds({ tun0: 'device kind tun is not a provider attachment' });
	r = _underlay.pick(router({ aaa: ifc('aaa', 'static', 'tun0', [ dflt() ]) }), EP);
	eq('P1 pick: a static tun that sorts first is not an uplink', r.iface, 'dslite');
	// Another VPN package's tunnel, which is not proto wireguard to netifd.
	KINDS = kinds({ nordlynx: 'device kind wireguard is not a provider attachment' });
	r = _underlay.pick(router({ dslite: null,
		nordvpn: ifc('nordvpn', 'none', 'nordlynx', [ dflt() ]) }), EP);
	eq('P1 pick: nor is a WireGuard device under another protocol', r.iface, null);
	// A device nobody can classify is refused too.
	KINDS = kinds();
	r = _underlay.pick(router({ dslite: ifc('dslite', 'dslite', 'mystery0', [ dflt() ]) }), EP);
	eq('P1 pick: an unclassifiable device is not trusted with the endpoint', r.iface, null);

	// A route with an explicit table is never used by netifd's lookup.
	KINDS = kinds();
	r = _underlay.pick(router({ dslite: ifc('dslite', 'dslite', 'ds-dslite', [
		{ target: '79.127.0.0', mask: 16, nexthop: '0.0.0.0', table: 107, source: '0.0.0.0/0' } ]) }),
		EP);
	eq('P1 pick: a route with its own table is not a candidate', r.iface, null);

	// The most specific route wins, across interfaces.
	r = _underlay.pick(router({ wan: ifc('wan', 'static', 'eth1',
		[ { target: '79.127.0.0', mask: 16, nexthop: '192.168.100.1', source: '0.0.0.0/0' } ]) }),
		EP);
	eq('P1 pick: a longer mask wins over the default', r.iface, 'wan');

	// Equal masks: a later interface wins only with a lower metric it states.
	r = _underlay.pick(router({ zwan: ifc('zwan', 'dhcp', 'eth0', [ dflt({ metric: 5 }) ], { metric: 10 }) }),
		EP);
	eq('P1 pick: an equal default with no better metric keeps the first by name', r.iface, 'dslite');
	r = _underlay.pick(router({ dslite: ifc('dslite', 'dslite', 'ds-dslite', [ dflt() ], { metric: 10 }),
		zwan: ifc('zwan', 'dhcp', 'eth0', [ dflt({ metric: 5 }) ]) }), EP);
	eq('P1 pick: a stated lower metric displaces it', r.iface, 'zwan');

	// An interface whose own subnet holds the endpoint wins outright.
	r = _underlay.pick(router({ wan: ifc('wan', 'static', 'eth1', [],
		{ 'ipv4-address': [ { address: '79.127.154.200', mask: 24 } ] }) }), EP);
	eq('P1 pick: an on-link uplink wins outright', r.iface, 'wan');

	// The instance's own interface is WireGuard like every other instance,
	// and is refused as such — even with a device the kernel calls hardware.
	KINDS = kinds({ pv_media: null });
	r = _underlay.pick(router({ dslite: null }), EP);
	eq('P1 pick: the instance never carries its own endpoint', r.iface, null);
	ok('P1 pick: it is refused as WireGuard', length(filter(r.refused, (x) => x.iface == 'pv_media' &&
		match(x.why, /WireGuard/))) == 1);

	// IPv6 endpoint over a DHCPv6 uplink.
	KINDS = kinds();
	r = _underlay.pick(router(), '2a07:b944::2:1');
	eq('P1 pick: an IPv6 endpoint goes over the IPv6 uplink', r.iface, 'wan6');
	eq('P1 pick: a name is never looked up', _underlay.pick(router(), 'nl-1.protonvpn.net').iface, null);
}

// Every package ifup goes through the gate, and the gate pins the winner.
{
	let uci = reset(config(), router());
	writefile(IFUP_OK, '');
	let up = _apply.bring_up('pv_media', uci);
	ok('P1 bring_up: with an uplink the tunnel is brought up', up);
	eq('P1 bring_up: and ifup was run once', ifups(), [ 'ifup pv_media' ]);
	eq('P1 bring_up: the endpoint is pinned to DS-Lite', media().tunlink, 'dslite');
	eq('P1 bring_up: and stamped as ours', media().protonvpn_tunlink, 'dslite');

	// Apply (connect): the same.
	uci = reset(config(), router());
	let r = _apply.apply(uci, 'media');
	eq('P1 apply: connects', r.state, 'success');
	eq('P1 apply: pinned', media().tunlink, 'dslite');

	// Rotation: the same, and the pin follows the new server's endpoint.
	uci = reset(config({ pv_media: { tunlink: 'dslite', protonvpn_tunlink: 'dslite' } }),
		router({ wan: ifc('wan', 'static', 'eth1',
			[ { target: '79.127.154.2', mask: 32, nexthop: '192.168.100.1', source: '0.0.0.0/0' },
			  { target: '79.127.154.3', mask: 32, nexthop: '192.168.100.1', source: '0.0.0.0/0' } ]) }));
	r = _rotate.rotate(uci, 'media');
	ok('P1 rotate: moved', r.ok == true, sprintf('%J', r));
	eq('P1 rotate: pinned to the uplink that covers the NEW endpoint', media().tunlink, 'wan');
	unlink(IFUP_OK);
}

// ════════════════════════════════════════════════════════════════════════
// P2 — fail closed, quietly
// ════════════════════════════════════════════════════════════════════════
{
	let uci = reset(config(), outage());
	writefile(IFUP_OK, '');
	let up = _apply.bring_up('pv_media', uci);
	ok('P2 bring_up: no uplink, not brought up', !up);
	eq('P2 bring_up: ifup was never run', ifups(), []);
	eq('P2 bring_up: no pin of ours yet, so NO_UPLINK keeps netifd from starting it',
		media().tunlink, _underlay.NO_UPLINK);
	ok('P2 bring_up: and it is stamped as ours', media().protonvpn_tunlink == _underlay.NO_UPLINK);
	ok('P2 bring_up: the reason is kept', match(_underlay.waiting('media') || '', /no uplink covers 79\.127\.154\.1/));
	ok('P2 bring_up: naming what was refused', match(_underlay.waiting('media') || '', /protonvpn \(it is a WireGuard tunnel\)/));
	eq('P2 bring_up: logged once', said(/media: waiting for an uplink/), 1);
	_apply.bring_up('pv_media', uci);
	_apply.bring_up('pv_media', uci);
	eq('P2 bring_up: and not again on every retry', said(/media: waiting for an uplink/), 1);
	ok('P2 bring_up: apply can tell a park from a failed ifup', _apply.parked() != null);

	// A real pin already in place is kept: netifd brings the tunnel back
	// through it on its own.
	uci = reset(config({ pv_media: { tunlink: 'dslite', protonvpn_tunlink: 'dslite' } }), outage());
	_apply.bring_up('pv_media', uci);
	eq('P2 bring_up: an existing pin survives the park', media().tunlink, 'dslite');
	eq('P2 bring_up: still no ifup', ifups(), []);

	// netifd not answering is not an answer.
	uci = reset(config(), null);
	ok('P2 bring_up: no dump, no ifup', !_apply.bring_up('pv_media', uci) && length(ifups()) == 0);
	eq('P2 bring_up: and the reason says so', _underlay.waiting('media'), 'netifd did not answer');

	// Rotation during the outage: skipped before a single candidate is
	// written, and not counted against the watchdog.
	uci = reset(config({ pv_media: { tunlink: 'dslite', protonvpn_tunlink: 'dslite' } }), outage());
	let before = sprintf('%J', global.MOCK_UCI.network);
	let r = _rotate.rotate(uci, 'media');
	eq('P2 rotate: skipped', r.skipped, true);
	eq('P2 rotate: waiting for an uplink', r.waiting_for_uplink, true);
	eq('P2 rotate: the peer was not touched', sprintf('%J', global.MOCK_UCI.network), before);
	eq('P2 rotate: no ifup', ifups(), []);
	eq('P2 watchdog: a parked recovery is not a failure', _service.watchdog_result_update(r, 2), 2);
	eq('P2 watchdog: a real failure still is', _service.watchdog_result_update({ error: 'x' }, 2), 3);

	// Apply during the outage: one candidate written and left in place for
	// the reconcile, no rollback, no ifup, no second server.
	uci = reset(config(), outage());
	r = _apply.apply(uci, 'media');
	eq('P2 apply: failure', r.state, 'failure');
	eq('P2 apply: waiting for an uplink', r.waiting_for_uplink, true);
	ok('P2 apply: and says so', match(r.error || '', /^waiting for an uplink: no uplink covers/));
	eq('P2 apply: no ifup', ifups(), []);
	eq('P2 apply: the peer it chose stays for the reconcile', global.MOCK_UCI.network.peer_m.endpoint_host,
		r.endpoint ? split(r.endpoint, ':')[0] : null);

	// Status.
	let st = _status.status(uci, 'media');
	ok('P2 status: uplink_wait carries the reason', st.uplink_wait != null &&
		match(st.uplink_wait.reason, /no uplink covers/));
	ok('P2 status: and since when', st.uplink_wait && st.uplink_wait.since > 0);
	unlink(IFUP_OK);
}

// ════════════════════════════════════════════════════════════════════════
// P3 — self-heal
// ════════════════════════════════════════════════════════════════════════
{
	// Parked during the outage...
	let uci = reset(config(), outage());
	writefile(IFUP_OK, '');
	_apply.bring_up('pv_media', uci);
	ok('P3 setup: parked', _underlay.waiting('media') != null);
	global.MOCK_UCI.network.pv_media.auto = '1';
	// ...the reconcile during the outage does nothing...
	let out = _rotate.uplink_reconcile(cursor());
	eq('P3 reconcile: still waiting while there is no uplink', out.media, 'waiting');
	eq('P3 reconcile: no ifup', ifups(), []);
	// ...and the cable comes back.
	DUMP = router({ pv_media: ifc('pv_media', 'wireguard', null, [], { up: false }) });
	out = _rotate.uplink_reconcile(cursor());
	eq('P3 reconcile: brought up once DS-Lite covers the endpoint', out.media, 'brought up');
	eq('P3 reconcile: by one ifup', ifups(), [ 'ifup pv_media' ]);
	eq('P3 reconcile: pinned to DS-Lite', media().tunlink, 'dslite');
	ok('P3 reconcile: no longer waiting', _underlay.waiting('media') == null);
	eq('P3 reconcile: and the log says the uplink is back', said(/media: uplink dslite covers the endpoint again/), 1);

	// Pinned to an uplink that went away, another one covering it: re-pinned.
	uci = reset(config({ pv_media: { tunlink: 'dslite', protonvpn_tunlink: 'dslite' } }),
		router({ dslite: ifc('dslite', 'dslite', null, [], { up: false }),
			pv_media: ifc('pv_media', 'wireguard', null, [], { up: false }),
			wan: ifc('wan', 'dhcp', 'eth1', [ dflt({ nexthop: '192.168.100.1' }) ]) }));
	out = _rotate.uplink_reconcile(cursor());
	eq('P3 reconcile: a dead pin is replaced by a live uplink', out.media, 'brought up');
	eq('P3 reconcile: the new pin', media().tunlink, 'wan');

	// Pinned to a dead uplink and nothing else: waiting, and it says so once.
	uci = reset(config({ pv_media: { tunlink: 'dslite', protonvpn_tunlink: 'dslite' } }),
		router({ dslite: ifc('dslite', 'dslite', null, [], { up: false }),
			pv_media: ifc('pv_media', 'wireguard', null, [], { up: false }) }));
	_rotate.uplink_reconcile(cursor());
	_rotate.uplink_reconcile(cursor());
	eq('P3 reconcile: a dead pin with no alternative waits', ifups(), []);
	eq('P3 reconcile: logged once over two ticks', said(/media: waiting for an uplink/), 1);

	// netifd already setting it up: left to netifd.
	uci = reset(config({ pv_media: { tunlink: _underlay.NO_UPLINK, protonvpn_tunlink: _underlay.NO_UPLINK } }),
		router({ pv_media: ifc('pv_media', 'wireguard', null, [], { up: false, pending: true }) }));
	eq('P3 reconcile: an interface being set up is netifd\'s', _rotate.uplink_reconcile(cursor()).media, 'pending');

	// Down for a reason that is not ours: the watchdog's, not the reconcile's.
	uci = reset(config({ pv_media: { tunlink: 'dslite', protonvpn_tunlink: 'dslite' } }),
		router({ pv_media: ifc('pv_media', 'wireguard', null, [], { up: false }) }));
	eq('P3 reconcile: a down instance on a live pin is not touched', _rotate.uplink_reconcile(cursor()).media, 'down');
	eq('P3 reconcile: no ifup', ifups(), []);

	// The wiring that makes the reconcile run at all. Read from the sources,
	// because the daemon's uloop and the hotplug-call environment do not exist
	// off-device; what is checked is that each of them is there and calls in.
	let src = function(rel) { return readfile(getenv('PVT_TESTS') + '/../' + rel) || ''; };
	let daemon = src('files/usr/bin/protonvpn-service');
	ok('P3 daemon: every tick runs the reconcile', index(daemon, '_rotate.uplink_reconcile()') >= 0);
	ok('P3 daemon: and skips watchdog recovery of a parked instance',
		index(daemon, '!_underlay.waiting(inst)') >= 0);
	let hook = src('files/etc/hotplug.d/iface/95-protonvpn');
	ok('P3 hotplug: an interface coming up wakes the reconcile',
		match(hook, /ifup\|ifupdate\|ifdown\)/) && index(hook, '/usr/bin/protonvpn-uplink') >= 0);
	ok('P3 hotplug: the worker calls the reconcile',
		index(src('files/usr/bin/protonvpn-uplink'), 'uplink_reconcile(') >= 0);
	let mk = src('Makefile');
	ok('P3 package: the hook is installed',
		index(mk, './files/etc/hotplug.d/iface/95-protonvpn $(1)/etc/hotplug.d/iface/95-protonvpn') >= 0);
	ok('P3 package: and so is the worker',
		index(mk, './files/usr/bin/protonvpn-uplink $(1)/usr/bin/protonvpn-uplink') >= 0);
	unlink(IFUP_OK);
}

// ════════════════════════════════════════════════════════════════════════
// P4 — detect foreign damage
// ════════════════════════════════════════════════════════════════════════
{
	// Up, with the endpoint routed through the guest tunnel — the incident.
	let uci = reset(config(), router({ dslite: ifc('dslite', 'dslite', null, [], { up: false }) }),
		null, { [EP]: 'protonvpn' });
	writefile(IFUP_OK, '');
	let out = _rotate.uplink_reconcile(cursor());
	eq('P4: the leak is found', out.media, 'leak');
	eq('P4: and the tunnel taken down', ifdowns(), [ 'pv_media' ]);
	eq('P4: logged loudly', said(/media: LEAK — 79\.127\.154\.1 is routed through WireGuard interface protonvpn/), 1);
	eq('P4: unpinned before, so NO_UPLINK now keeps netifd from repeating it', media().tunlink, _underlay.NO_UPLINK);
	ok('P4: parked as a leak', match(_underlay.waiting('media') || '', /^leak: /));
	eq('P4: one leak counted', (_underlay.park_state('media') || {}).leaks, 1);

	// The uplink is back, but the backoff holds it down for a while...
	DUMP = router({ pv_media: ifc('pv_media', 'wireguard', null, [], { up: false }) });
	ROUTES = {};
	out = _rotate.uplink_reconcile(cursor());
	eq('P4: within the backoff it stays down', out.media, 'leak backoff');
	eq('P4: no ifup', ifups(), []);
	// ...and then it is handed to P3.
	let st = _underlay.park_state('media');
	st.last_leak = time() - _cmn.WATCHDOG_COOLDOWN_BASE - 1;
	writefile(RUN + '/protonvpn_uplink_media.json', sprintf('%J', st));
	out = _rotate.uplink_reconcile(cursor());
	eq('P4: after the backoff it comes back through P3', out.media, 'brought up');
	eq('P4: pinned this time', media().tunlink, 'dslite');
	ok('P4: the leak history outlives the unpark', (_underlay.park_state('media') || {}).leaks == 1);
	eq('P4: the backoff doubles per leak', _underlay.leak_backoff({ leaks: 2 }), 2 * _cmn.WATCHDOG_COOLDOWN_BASE);
	eq('P4: and is capped', _underlay.leak_backoff({ leaks: 30 }), _cmn.WATCHDOG_COOLDOWN_MAX);

	// Through a non-WireGuard overlay device.
	uci = reset(config({ pv_media: { tunlink: 'dslite', protonvpn_tunlink: 'dslite' } }), router(),
		kinds({ tun0: 'device kind tun is not a provider attachment' }), { [EP]: 'tun0' });
	eq('P4: a tun is a leak too', _rotate.uplink_reconcile(cursor()).media, 'leak');
	eq('P4: an existing real pin of ours is kept', media().tunlink, 'dslite');

	// A healthy route is not a leak, and an unpinned instance is adopted.
	uci = reset(config(), router(), null, { [EP]: 'ds-dslite' });
	eq('P4: a route over the uplink is fine', _rotate.uplink_reconcile(cursor()).media, 'up');
	eq('P4: nothing taken down', ifdowns(), []);
	eq('P4: an instance up before the pin existed is pinned for its next setup', media().tunlink, 'dslite');
	eq('P4: without an ifup', ifups(), []);

	// No route at all (the guard refuses it): nothing leaves, nothing to do.
	uci = reset(config(), router({ dslite: ifc('dslite', 'dslite', null, [], { up: false }) }), null, {});
	eq('P4: an unreachable endpoint is not a leak', _rotate.uplink_reconcile(cursor()).media, 'up');
	unlink(IFUP_OK);
}

// ════════════════════════════════════════════════════════════════════════
// P5 — no kernel fall-through
// ════════════════════════════════════════════════════════════════════════
{
	let uci = reset(config(), router());
	writefile(IFUP_OK, '');
	_apply.bring_up('pv_media', uci);
	eq('P5: bring_up installs the guard for the endpoint',
		guards('pv_media'), [ { type: 'rule', dest: EP + '/32', action: 'unreachable', priority: '89999' } ]);
	let p = int(_routing.GUARD_PRIORITY);
	ok('P5: after main and default, before netifd\'s iif-lo rules', p > 32767 && p < 90000);

	// It follows the endpoint.
	_apply.connect_one(uci, 'pv_media', relay('NL#2', '79.127.154.2'), _cmn.load_settings(uci, 'media'));
	eq('P5: the guard follows a new endpoint, and only one is kept',
		map(guards('pv_media'), (g) => g.dest), [ '79.127.154.2/32' ]);

	// Also when parked: the guard is there before any ifup could happen.
	uci = reset(config(), outage());
	_apply.bring_up('pv_media', uci);
	eq('P5: a parked instance is guarded too', length(guards('pv_media')), 1);

	// nohostroute instances are guarded as well — and still brought up.
	uci = reset(config(), outage());
	ok('P5: a nohostroute instance is brought up as before', _apply.bring_up('protonvpn', uci));
	eq('P5: with a guard for its endpoint', map(guards('protonvpn'), (g) => g.dest), [ '146.70.170.2/32' ]);

	// An IPv6 endpoint gets a rule6.
	uci = reset(config({ peer_m: { endpoint_host: '2a07:b944::2:1' } }), router());
	_apply.bring_up('pv_media', uci);
	eq('P5: an IPv6 endpoint is guarded with a rule6',
		guards('pv_media'), [ { type: 'rule6', dest: '2a07:b944::2:1/128', action: 'unreachable', priority: '89999' } ]);

	// The daemon's reconcile guards instances no package ifup has touched.
	uci = reset(config(), router(), null, { [EP]: 'ds-dslite', '146.70.170.2': 'lan5' });
	_rotate.uplink_reconcile(cursor());
	eq('P5: the reconcile guards every enabled instance', length(guards(null)), 2);

	// Disconnect removes it; delete removes it.
	uci = reset(config(), router());
	_apply.bring_up('pv_media', uci);
	_apply.disconnect(cursor(), 'media');
	eq('P5: a disconnected instance carries no guard', guards('pv_media'), []);
	uci = reset(config(), router());
	_apply.bring_up('pv_media', uci);
	_apply.delete_instance(cursor(), 'media');
	eq('P5: a deleted instance leaves no guard behind', guards('pv_media'), []);
	// A disabled instance loses its guard at the next reconcile.
	uci = reset(config(), router());
	_apply.bring_up('pv_media', uci);
	global.MOCK_UCI.protonvpn.media.enabled = '0';
	_rotate.uplink_reconcile(cursor());
	eq('P5: a disabled instance loses its guard', guards('pv_media'), []);
	unlink(IFUP_OK);
}

// ════════════════════════════════════════════════════════════════════════
// P6 — neighbours
// ════════════════════════════════════════════════════════════════════════
{
	// nohostroute=1: no tunlink business at all, even with no uplink.
	let uci = reset(config(), outage());
	writefile(IFUP_OK, '');
	ok('P6: a nohostroute instance is brought up with no netifd uplink', _apply.bring_up('protonvpn', uci));
	eq('P6: and gets no tunlink', global.MOCK_UCI.network.protonvpn.tunlink, null);
	// One that used to be ours loses the pin when it switches to nohostroute.
	uci = reset(config({ protonvpn: { tunlink: 'dslite', protonvpn_tunlink: 'dslite' } }), router());
	_apply.bring_up('protonvpn', uci);
	eq('P6: switching to nohostroute drops our pin', global.MOCK_UCI.network.protonvpn.tunlink, null);
	eq('P6: and its stamp', global.MOCK_UCI.network.protonvpn.protonvpn_tunlink, null);

	// A user's own tunlink is theirs.
	uci = reset(config({ pv_media: { tunlink: 'wan2' } }), outage());
	ok('P6: a user tunlink is brought up as configured', _apply.bring_up('pv_media', uci));
	eq('P6: and left alone', media().tunlink, 'wan2');
	eq('P6: no stamp is added to it', media().protonvpn_tunlink, null);
	eq('P6: the reconcile leaves it alone too', _rotate.uplink_reconcile(cursor()).media, 'not managed');
	// A user tunlink that replaced ours (stamp left behind) is theirs as well.
	uci = reset(config({ pv_media: { tunlink: 'wan2', protonvpn_tunlink: 'dslite' } }), router());
	_apply.bring_up('pv_media', uci);
	eq('P6: an edited pin is the user\'s', media().tunlink, 'wan2');

	// auto='1' writing stays.
	uci = reset(config({ pv_media: { auto: '0' } }), router());
	_apply.connect_one(uci, 'pv_media', relay('NL#2', '79.127.154.2'), _cmn.load_settings(uci, 'media'));
	eq('P6: connect still writes auto=1', media().auto, '1');

	// A single-WAN router: pinned to its WAN, brought up as before.
	uci = reset(config(), { interface: [
		ifc('lan', 'static', 'br-lan', [], { 'ipv4-address': [ { address: '192.168.1.1', mask: 24 } ] }),
		ifc('pv_media', 'wireguard', null, [], { up: false }),
		ifc('wan', 'dhcp', 'eth0', [ dflt({ nexthop: '203.0.113.1' }) ]) ] }, kinds({ 'br-lan': null }));
	ok('P6: single WAN: brought up', _apply.bring_up('pv_media', uci));
	eq('P6: single WAN: pinned to it', media().tunlink, 'wan');
	unlink(IFUP_OK);
}

// ════════════════════════════════════════════════════════════════════════
// P7 — no leak while switching: everything is committed before the ifup
// ════════════════════════════════════════════════════════════════════════
{
	let uci = reset(config({ pv_media: { tunlink: 'wan', protonvpn_tunlink: 'wan' } }), router());
	writefile(IFUP_OK, '');
	// Record every commit in the same log the ifup stub writes to, with what
	// netifd would read from /etc/config/network at that moment.
	let real_commit = uci.commit;
	uci.commit = function(conf) {
		let fh = open(IFUP_LOG, 'a');
		let g = guards('pv_media');
		fh.write(sprintf('commit %s tunlink=%s guard=%s\n', conf, media().tunlink,
			length(g) ? g[0].dest : '-'));
		fh.close();
		return real_commit(conf);
	};
	_apply.connect_one(uci, 'pv_media', relay('NL#2', '79.127.154.2'), _cmn.load_settings(uci, 'media'));
	let lines = filter(split(readfile(IFUP_LOG) || '', '\n'), (l) => l != '');
	let at = index(lines, 'ifup pv_media');
	ok('P7: the tunnel was brought up', at > 0);
	eq('P7: the last commit before the ifup already holds the new pin and the new guard',
		at > 0 ? lines[at - 1] : null, 'commit network tunlink=dslite guard=79.127.154.2/32');
	unlink(IFUP_OK);
}

for (let n in [ 'main', 'media' ])
	unlink(RUN + '/protonvpn_uplink_' + n + '.json');
unlink(IFUP_LOG);
unlink(IFDOWN_LOG);
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL UNDERLAY TESTS PASSED');
exit(fails ? 1 : 0);

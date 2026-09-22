#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// How fast a client actually moves when a network is steered, and what is
// left behind on a network that was previously on an ISP relay.
//
// Measured on a live router: steering `lan` DID work, it just took up to ten
// minutes to start. Everything else was correct — the rules, masq6, the zone
// and forwarding, the gateway's IPv6 bit, bidirectional traffic on the tunnel.
// What was wrong was only the timing, from a captured advertisement:
//
//     prefix <our ULA>/64      valid 5400s  pref 2700s
//     prefix <ISP prefix>/64   valid 5400s  pref    0s   <- correctly deprecated
//     advertisement interval option: 600000ms
//
// The content is right. But unsolicited advertisements are ten minutes apart,
// and a client that missed the one carrying the switch kept preferring its
// ISP address until the next — four of five clients were still on ISP
// addresses. The same applies in reverse: without a prompt advertisement on
// release, clients keep a ULA that no longer routes anywhere.
//
// ── A NOTE ON MAKING THIS SUITE FASTER ───────────────────────────────────
//
// Most of what is slow here is slow on purpose, and most of that is safe to
// speed up — but not all of it, and the difference has already been got wrong
// once in this file.
//
// Safe, and done: the readiness budget is shortened through
// PROTONVPN_RA_SETTLE_MS (run.sh), which is the real knob rather than a stub,
// so every timeout test still runs the real code path at a smaller number.
// One test deliberately puts the production default back, in a child process,
// so a fast suite cannot quietly become one that no longer tests the timeout
// (helpers/real-budget.uc).
//
// Safe, and done: there is an instant `sleep` stub on PATH, because two
// places in the production code pause by shelling out and nothing asserts on
// those pauses.
//
// NOT safe, and this is the one that bit: that same `sleep` stub silently
// turned the slow-probe test into a false pass. The test measured how long a
// wedged ubus probe was allowed to take, the delay it was measuring went
// through PATH, and so the suite stayed green while the property stopped
// being tested at all. A timing test whose delay can be stubbed away is not a
// timing test. The wedge now sleeps by ABSOLUTE PATH (stubs/ubus) for exactly
// that reason — if you are making this suite faster, that is the line not to
// touch, and `ubus_wedges` is the helper that depends on it.
//
// Uses the mock 'uci' module; globals `KEY` and `fixture` come from run.sh.

'use strict';

import { unlink, writefile, mkdir, open } from 'fs';
import { cursor } from 'uci';

const _cmn = require('protonvpn.common');
const _routing = require('protonvpn.routing');
const enforce_routing = _routing.enforce,
      ipv6_state = _routing.ipv6_state,
      ra_refresh = _routing.ra_refresh;

const STATE = getenv('PROTONVPN_STATE_DIR') || '/tmp/protonvpn-test-state';
// Where the ubus stub reads the interface status it should report, and where
// the odhcpd stub records that it was asked to reload.
const UBUS_FIXTURE = STATE + '/ubus-netifd.json';
const ODHCPD_LOG = STATE + '/odhcpd.log';

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) { ok(l, sprintf('%J', g) == sprintf('%J', w)); }

function reset_stubs() {
	unlink(UBUS_FIXTURE);
	unlink(ODHCPD_LOG);
}
function odhcpd_calls() {
	let s = null;
	try { s = open(ODHCPD_LOG, 'r'); } catch (e) { return []; }
	if (!s)
		return [];
	let out = [];
	for (let l = s.read('line'); l && length(l); l = s.read('line'))
		push(out, trim(l));
	s.close();
	return out;
}

// The ubus stub answers `network.interface.<net> status` from this file, so a
// test can say what netifd reports and when it changes.
function netifd_says(map) {
	writefile(UBUS_FIXTURE, sprintf('%J', map));
}

// Wedge ubus: every answer takes `s` REAL seconds.
//
// Real because the stub sleeps by absolute path, deliberately bypassing the
// instant `sleep` stub this suite puts on PATH to make everything else fast.
// That stub once turned the slow-probe test below into a false pass — green
// suite, untested property — which is the whole reason this is spelled out
// here and in stubs/ubus. A timing test whose delay can be stubbed away is
// not a timing test.
const UBUS_WEDGE = STATE + '/ubus-wedge-s';
function ubus_wedges(s) {
	if (s == null)
		unlink(UBUS_WEDGE);
	else
		writefile(UBUS_WEDGE, '' + s);
}

// routing.uc logs through the module namespace, which is the seam the rest of
// this suite already uses to stub things out.
let logged = [];
const real_log = _cmn.log;
function capture_log() {
	logged = [];
	_cmn.log = function(m) { push(logged, '' + m); };
}
function restore_log() {
	_cmn.log = real_log;
}
function logged_matching(re) {
	let out = [];
	for (let l in logged)
		if (match(l, re))
			push(out, l);
	return out;
}

// Milliseconds on the monotonic clock — the same thing the bound is measured
// against, so a test cannot be fooled by the wall clock stepping.
function ms_now() {
	let c = clock(true);
	return c[0] * 1000 + int(c[1] / 1000000);
}

// The /64 this module actually asked netifd to give a network: the router's
// ULA with the per-network hint as the fourth hextet.
function hinted(net) {
	return 'fd7a:1b2c:3d4e:' + _routing.v6_hint(net) + '::1';
}
// Some OTHER /64 out of the same ULA — a different steered network's, which
// is exactly what makes "any address out of the ULA" the wrong question.
function other_ula(net) {
	return 'fd7a:1b2c:3d4e:' + _routing.v6_hint(net + '-elsewhere') + '::1';
}

function ssteer(over) {
	let base = { name: 'main', interface: 'pv_media', routing_table: '101',
		auto_routing: false, killswitch: false, ipv6_mode: 'block',
		vpn_dns: 'off', source_networks: [ 'media' ], enabled: true };
	for (let k in over)
		base[k] = over[k];
	return base;
}

// A network in the state the owner's `lan` was in: previously served by an
// ISP relay, so it carries the leftovers guest/media never had.
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
		dev_media: { '.type': 'device', name: 'br-media', type: 'bridge', ipv6: '0' }
	}, firewall: {
		zlan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		zwan: { '.type': 'zone', name: 'wan', masq: '1', network: [ 'wan' ] },
		zmedia: { '.type': 'zone', name: 'media', network: [ 'media' ] }
	}, dhcp: {
		media: { '.type': 'dhcp', interface: 'media',
			// The ISP-relay leftovers, exactly as measured on the live `lan`.
			ra: 'server', ra_flags: [ 'managed-config', 'other-config' ],
			dhcpv6: 'server', ndp: 'relay' }
	} };
}

const F_V6 = 28;

// How long a wedged ubus hangs for. Long enough that an unbounded probe is
// unmistakable against the suite's shortened budget, short enough that the
// mutation run which proves that stays affordable.
const WEDGE_S = 10;

// ── 1. what the takeover does with the ISP-relay leftovers ───────────────
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let d = global.MOCK_UCI.dhcp.media;

	// ndp 'relay' proxies neighbour discovery toward the uplink, which keeps
	// the pre-takeover path to the ISP router alive for exactly the clients
	// this is trying to move off it. It is the one leftover that works
	// against the takeover rather than merely alongside it.
	eq('takeover: neighbour-discovery relaying toward the WAN is switched off',
		d.ndp, 'disabled');
	eq('takeover: and the user value is recorded for the way back',
		d.protonvpn_saved_ndp, 'relay');

	// The M flag tells a client to go and ask DHCPv6 for its address. The RA
	// already carries the address; the round trip is pure delay on the switch
	// this whole change exists to make prompt, and a client with no DHCPv6 at
	// all waits for nothing.
	eq('takeover: the advertisement stops claiming managed configuration',
		d.ra_flags, 'none');
	eq('takeover: with the previous flags saved as the list they were',
		d.protonvpn_saved_ra_flags, [ 'managed-config', 'other-config' ]);

	// Deliberately untouched, in BOTH directions: we do not switch a service
	// on that the user disabled, and we do not switch off one they enabled.
	eq('takeover: the DHCPv6 server the user runs is left alone', d.dhcpv6, 'server');
	ok('takeover: and nothing is recorded for it',
		d.protonvpn_saved_dhcpv6 == null);

	// Idempotent, like every other claimed option.
	let again = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	ok('takeover: a second run changes nothing',
		again.changed_dhcp == false && again.changed_network == false);

	// And given back.
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	d = global.MOCK_UCI.dhcp.media;
	eq('takeover: release puts the relay back', d.ndp, 'relay');
	eq('takeover: and the flag list back', d.ra_flags, [ 'managed-config', 'other-config' ]);
	ok('takeover: and clears its own records',
		d.protonvpn_saved_ndp == null && d.protonvpn_saved_ra_flags == null);
}

// A network that never had these options must not acquire saved values for
// them, or release would write options the user never had.
{
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.dhcp.media = { '.type': 'dhcp', interface: 'media',
		ra: 'disabled', dhcpv6: 'disabled' };
	let uci = cursor();
	enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	let d = global.MOCK_UCI.dhcp.media;
	eq('takeover: a network without the leftovers still gets the flags cleared',
		d.ra_flags, 'none');
	ok('takeover: and records nothing that was never there',
		d.protonvpn_saved_ra_flags == null && d.protonvpn_saved_ndp == null);
	enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	d = global.MOCK_UCI.dhcp.media;
	ok('takeover: release removes what it added rather than inventing a value',
		d.ra_flags == null && d.ndp == null);
}

// ── 2. the networks whose clients have to be told ────────────────────────
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('plan: a claimed network is named, as one whose clients must move in',
		res.v6_ra, [ { net: 'media', want: true } ]);

	res = enforce_routing(uci, ssteer({ ipv6_mode: 'auto' }));
	eq('plan: an unchanged run asks for nothing', res.v6_ra, []);

	res = enforce_routing(uci, ssteer({ ipv6_mode: 'block' }));
	eq('plan: a released network is named, with the other direction',
		res.v6_ra, [ { net: 'media', want: false } ]);
}

// Two instances steering the same network: switching one off hands the
// addressing to the other rather than restoring it, so nothing about the
// announcement changes and there is nothing to re-advertise. Nudging odhcpd
// here would be noise — and worse, it would suggest to the reader that
// something moved.
{
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.pv_other = { '.type': 'interface', proto: 'wireguard',
		private_key: KEY, protonvpn_features: '' + F_V6 };
	global.MOCK_UCI.protonvpn = {
		main: { '.type': 'instance', interface: 'pv_media', enabled: '1',
			routing_table: '101', ipv6_mode: 'auto', source_network: [ 'media' ] },
		other: { '.type': 'instance', interface: 'pv_other', enabled: '1',
			routing_table: '102', ipv6_mode: 'auto', source_network: [ 'media' ] }
	};
	let uci = cursor();
	enforce_routing(uci, _cmn.load_settings(uci, 'main'));
	// The second instance finds the sections already owned and leaves them be.
	let second = enforce_routing(uci, _cmn.load_settings(uci, 'other'));
	eq('hand-over: the second instance announces nothing new', second.v6_ra, []);

	// Now switch the first off while the second still steers the network.
	let s = _cmn.load_settings(uci, 'main');
	s.enabled = false;
	let off = enforce_routing(uci, s);
	eq('hand-over: passing the network on re-advertises for nobody',
		off.v6_ra, []);
	eq('hand-over: and the announcement really did stay in place',
		global.MOCK_UCI.dhcp.media.ra, 'server');
}

// ── 3. the advertisement is not left to the next scheduled one ───────────
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	// netifd already reports the addressing we asked for: nothing to wait for.
	netifd_says({ media: [ hinted('media') ] });
	let notes = [];
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], notes);
	eq('refresh: odhcpd is told to re-advertise', odhcpd_calls(), [ 'reload' ]);
	eq('refresh: with nothing to report', logged_matching(/did not settle/), []);
}

{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	// The address netifd reports is still the ISP one, and never changes:
	// the wait must give up rather than hang, and still nudge odhcpd.
	netifd_says({ media: [ '2a02:3100:6014:6700::1' ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	eq('refresh: a network that never settles is still advertised for',
		odhcpd_calls(), [ 'reload' ]);
	ok('refresh: and the wait is reported rather than passed off as success',
		length(logged_matching(/media.*did not settle/)) == 1);
	restore_log();
}

{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	// Release: our prefix is gone from the bridge, so there is nothing to wait
	// for and the advertisement that deprecates it can go out now.
	netifd_says({ media: [ '2a02:3100:6014:6700::1' ] });
	let notes = [];
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: false } ], notes);
	eq('refresh: a release advertises too, or clients keep the ULA',
		odhcpd_calls(), [ 'reload' ]);
	eq('refresh: and waits for nothing it can already see is done',
		logged_matching(/did not settle/), []);
	restore_log();
}

{
	reset_stubs();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let notes = [];
	ra_refresh(uci, 'pv_media', [], notes);
	eq('refresh: nothing changed, nothing is reloaded', odhcpd_calls(), []);
}

// Without ubus there is no way to tell whether the addressing settled, and a
// question that cannot be answered is a reason to stop asking rather than to
// keep asking twenty times. The advertisement still goes out — a burst that
// may describe the old prefix still beats waiting ten minutes — but nothing
// is reported, because "it did not settle in time" would be a claim this path
// never established.
{
	reset_stubs();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let notes = [];
	capture_log();
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], notes);
	eq('refresh: with no ubus it still advertises', odhcpd_calls(), [ 'reload' ]);
	eq('refresh: and claims nothing it could not check',
		logged_matching(/did not settle|not verified/), []);
	restore_log();
}

// The wiring: enforcement produces the plan, but only the apply paths run it.
// An implementation that computed a perfect plan and never acted on it would
// pass every test above.
{
	reset_stubs();
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.protonvpn = { main: { '.type': 'instance', interface: 'pv_media',
		enabled: '1', routing_table: '101', ipv6_mode: 'auto',
		source_network: [ 'media' ] } };
	let uci = cursor();
	const _apply = require('protonvpn.apply');
	// Claim it first — there is nothing to release otherwise, and an empty
	// plan correctly nudges nobody.
	enforce_routing(uci, _cmn.load_settings(uci));
	reset_stubs();
	_apply.disconnect(uci, 'main');
	eq('wiring: releasing a network asks odhcpd to advertise',
		odhcpd_calls(), [ 'reload' ]);
}

// The stamp has exactly one reader — the page's "clients are moving" line,
// which is only ever shown while IPv6 is active on the tunnel. After a pure
// release there is nothing for it to say, so a disconnect must not edit the
// configuration to record something nobody will read.
{
	reset_stubs();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	netifd_says({ media: [ 'fd7a:1b2c:3d4e:1234::1' ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	ok('stamp: a claim records when the clients were told',
		int(global.MOCK_UCI.network.pv_media.protonvpn_v6_ra_at || '0') > 0);

	global.MOCK_UCI = mkall(F_V6);
	uci = cursor();
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: false } ], []);
	ok('stamp: a release advertises but records nothing',
		global.MOCK_UCI.network.pv_media.protonvpn_v6_ra_at == null);
}

// ── 4. and the user is told the clients are moving ───────────────────────
{
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	let s = ssteer({ ipv6_mode: 'auto' });
	enforce_routing(uci, s);
	uci.commit('network');

	let st = ipv6_state(uci, s, 'steered', true);
	ok('settling: with no advertisement recorded, nothing is claimed',
		st.active == true && st.clients_settling == false);

	// Stamped the moment the advertisement went out.
	uci.set('network', 'pv_media', 'protonvpn_v6_ra_at', '' + time());
	st = ipv6_state(uci, s, 'steered', true);
	ok('settling: right after the switch, the page can say clients are moving',
		st.clients_settling == true);

	// And it is a statement about the last few minutes, not a permanent one:
	// the card it appears on was cut from 748px of furniture to 248.
	uci.set('network', 'pv_media', 'protonvpn_v6_ra_at', '' + (time() - 3600));
	st = ipv6_state(uci, s, 'steered', true);
	ok('settling: an hour later it says nothing', st.clients_settling == false);

	// Never while IPv6 is not actually going through the tunnel — there is no
	// switch to describe.
	uci.set('network', 'pv_media', 'protonvpn_v6_ra_at', '' + time());
	let off = ipv6_state(uci, ssteer({ ipv6_mode: 'block' }), 'steered', true);
	ok('settling: and nothing at all when IPv6 is not on the tunnel',
		off.active == false && off.clients_settling == false);
}

// ── 5. the built-in client version, without a network round trip ─────────
{
	const _api = require('protonvpn.api');
	let v = _api.builtin_app_version();
	ok('appversion: the package names the version it stamps',
		type(v) == 'string' && match(v, /^linux-vpn-[a-z0-9-]+@[0-9]+\.[0-9]+\.[0-9]+$/));
	// Same value the request header carries when nothing overrides it, which
	// is the whole point: the page must not claim a version that is not the
	// one being sent.
	eq('appversion: and it is the one actually stamped', v, _api.app_version());
}

// ── 6. every instance gets the same in-tunnel address ────────────────────
// Proton assigns one fixed /128 to every client on every gateway, so with
// several instances netifd installs several identical `from <that address>
// lookup <table>` source rules and only the first can ever match. Pinned
// because the shape is what makes the collision unavoidable: if a future
// Proton ever hands out per-instance addresses, this test is where that shows
// up and the comment at the write site can go.
{
	const _apply = require('protonvpn.apply');
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.pv_other = { '.type': 'interface', proto: 'wireguard',
		private_key: KEY };
	let uci = cursor();
	let relay = { public_key: 'pk', ip_address: '1.2.3.4', port: 51820,
		name: 'NL#1', features: F_V6 };
	_apply.write_relay(uci, 'pv_media', relay,
		ssteer({ routing_table: 'pv_media' }));
	_apply.write_relay(uci, 'pv_other', relay,
		ssteer({ name: 'other', interface: 'pv_other', routing_table: 'pv_other' }));

	eq('shared /128: both instances carry the very same tunnel addresses',
		global.MOCK_UCI.network.pv_media.addresses,
		global.MOCK_UCI.network.pv_other.addresses);
	ok('shared /128: while asking for different tables',
		global.MOCK_UCI.network.pv_media.ip6table == 'pv_media' &&
		global.MOCK_UCI.network.pv_other.ip6table == 'pv_other');
	ok('shared /128: which is exactly what collides at priority 10000',
		index(global.MOCK_UCI.network.pv_media.addresses, _cmn.FIXED_ADDRESS6) >= 0);
}

// ── 7. the readiness wait answers the question that was asked ────────────
//
// It used to accept ANY /64 out of the router's ULA /48, which is a different
// question from the one being asked, and wrong in both directions: on a claim
// it could report ready while the hinted /64 had not appeared, so odhcpd was
// nudged against the old addressing and the ten-minute wait came straight
// back; on a release it timed out whenever any other ULA was still present.
// The ip6hint is computed per network, so the expected prefix is knowable.

// Claim, and the address that turned up belongs to a different network.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	netifd_says({ media: [ other_ula('media') ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	ok('precise: another network\'s ULA is not this one\'s addressing',
		length(logged_matching(/did not settle/)) == 1);
	eq('precise: and it still advertises rather than giving up', odhcpd_calls(), [ 'reload' ]);
	restore_log();
}

// Claim, and the hinted /64 is the one that turned up.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	netifd_says({ media: [ hinted('media') ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	eq('precise: the hinted /64 is what being ready means', logged_matching(/did not settle/), []);
	eq('precise: and the advertisement goes out', odhcpd_calls(), [ 'reload' ]);
	restore_log();
}

// Release, with somebody else's ULA still on the bridge. Ours is gone, which
// is the whole question — the old predicate called this a timeout.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	netifd_says({ media: [ other_ula('media') ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: false } ], []);
	eq('precise: a release only waits for OUR prefix to go',
		logged_matching(/did not settle/), []);
	restore_log();
}

// Release, ours still there: that is a real timeout.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	netifd_says({ media: [ hinted('media') ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: false } ], []);
	ok('precise: a prefix that will not go is reported',
		length(logged_matching(/did not settle/)) == 1);
	restore_log();
}

// A ULA that is not a /48 does not put the 16-bit hint in the fourth hextet,
// so the expected prefix cannot be named. The wait must not pretend: it says
// readiness was not verified, and — because what it guards against is nudging
// odhcpd before netifd is done — it still gives netifd the time.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.globals.ula_prefix = 'fd7a:1b2c:3d4e:4444::/64';
	let uci = cursor();
	netifd_says({ media: [ 'fd7a:1b2c:3d4e:4444::1' ] });
	let t0 = ms_now();
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	let spent = ms_now() - t0;
	ok('unverifiable: a prefix it cannot name is reported as unverified',
		length(logged_matching(/could not work out which/)) == 1);
	ok('unverifiable: and the ULA is named so it can be fixed',
		length(logged_matching(/fd7a:1b2c:3d4e:4444::\/64/)) == 1);
	eq('unverifiable: it never calls that a settled wait',
		logged_matching(/did not settle/), []);
	eq('unverifiable: the advertisement still goes out', odhcpd_calls(), [ 'reload' ]);
	// It waited, rather than: it waited exactly the budget. Measuring a sleep
	// against its own duration leaves no room for the clock's resolution.
	ok('unverifiable: and netifd still got the time',
		spent >= (_routing.ra_budget_ms() * 4) / 5, sprintf('spent %dms', spent));
	restore_log();
}

// No ULA at all is the other half of the same case, and the opposite answer:
// there is no ULA addressing to wait for, so sleeping through the budget
// would be five seconds before announcing nothing.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.globals.ula_prefix = '';
	let uci = cursor();
	let t0 = ms_now();
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	let spent = ms_now() - t0;
	// It did NOT wait: the budget is the thing it must not have spent, and
	// half of it is far beyond anything the work itself costs.
	ok('unverifiable: with no ULA there is nothing to wait for',
		spent < _routing.ra_budget_ms() / 2, sprintf('spent %dms', spent));
	ok('unverifiable: and it says the prefix is unset',
		length(logged_matching(/ula_prefix is unset/)) == 1);
	restore_log();
}

// ── 8. the bound is a bound, including the probe ─────────────────────────
//
// It was first a number of iterations times a sleep, which bounds only the
// sleeping. Then it was the clock either side of the sleep — which still left
// the PROBE itself outside every check, so one wedged ubus call overran the
// budget the log and the page both advertise. Each probe is bounded now, so
// the number the caller waits is the number the user is told.
//
// THE DELAY IN THIS TEST IS REAL, and must stay real. `ubus_wedges` sleeps by
// absolute path precisely because this suite puts an instant `sleep` on PATH;
// with that stub in the way this test passed while testing nothing. If you
// are making the suite faster, this is the one place not to.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	netifd_says({ media: [ other_ula('media') ] });   // never satisfied
	ubus_wedges(WEDGE_S);                             // and every answer hangs
	let t0 = ms_now();
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	let spent = ms_now() - t0;
	ubus_wedges(null);
	// A wedged probe must not outlast the budget by more than the granularity
	// of the tool that kills it. Unbounded, this is WEDGE_S seconds — an order
	// of magnitude over, which is what makes the assertion discriminating
	// rather than decorative.
	ok('bounded: a wedged probe does not outlive the budget',
		spent < (WEDGE_S * 1000) / 2, sprintf('spent %dms of a %ds wedge', spent, WEDGE_S));
	ok('bounded: and the user is told the check could not be made',
		length(logged_matching(/could not be checked|did not settle/)) == 1);
	restore_log();
}

// The wedged branch must not depend on WHICH status ubus exits with.
//
// The first version of this bound wrapped the call in `timeout` and keyed on
// 124, that tool's convention — on a target that has no `timeout` at all. The
// status a real ubus returns when its own -t fires is not something this
// repository can check, so the code decides from how long the call took, and
// this proves it by giving the stub a different status every time.
{
	for (let status in [ '7', '1', '4', '255' ]) {
		reset_stubs();
		capture_log();
		writefile(STATE + '/ubus-timeout-status', status);
		global.MOCK_UCI = mkall(F_V6);
		let uci = cursor();
		netifd_says({ media: [ other_ula('media') ] });
		ubus_wedges(WEDGE_S);
		ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
		ubus_wedges(null);
		unlink(STATE + '/ubus-timeout-status');
		ok('wedged: reported from the clock, whatever ubus exits with (' + status + ')',
			length(logged_matching(/could not be checked/)) == 1);
		restore_log();
	}
}

// A ubus that is not there at all answers at once, and that is a different
// thing to tell the user than one that will not answer.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	// No fixture written, so the stub exits immediately.
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	eq('wedged: an absent ubus is not reported as a wedged one',
		logged_matching(/could not be checked/), []);
	restore_log();
}

// The number in the message is the number the caller waited. Reporting the
// configured budget instead was close enough while the loop was the only
// thing being bounded, but a probe capped at whole seconds can overshoot a
// sub-second budget, and a log that rounds in its own favour is how a bound
// stops meaning anything.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	netifd_says({ media: [ other_ula('media') ] });
	let t0 = ms_now();
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	let spent = ms_now() - t0;
	let m = logged_matching(/did not settle within ([0-9]+)ms/);
	ok('message: the log names a duration', length(m) == 1);
	let said = int((match(m[0], /within ([0-9]+)ms/) || [ '', '0' ])[1]);
	// Tight on purpose: `said` and `spent` are the same measurement taken a
	// few instructions apart, so anything beyond the test's own overhead means
	// the log reports a different number from the one the caller waited —
	// which at a 300ms budget and a ~500ms loop is exactly what reporting the
	// BUDGET looks like.
	ok('message: and it is what the caller actually waited, not the budget',
		said > 0 && said <= spent && (spent - said) < 100,
		sprintf('said %dms, caller waited %dms', said, spent));
	restore_log();
}

// The budget is a setting, not a constant, so a slow router can be given more
// without a rebuild. Read at call time — checked in a child process, because
// the environment of THIS one is fixed by the time it starts.
{
	let uc = getenv('UCODE') || 'ucode';
	let l = getenv('PVT_UCODE_L') || '';
	let budget_of = function(prefix) {
		let r = _cmn.run([ 'sh', '-c', prefix + ' ' + uc + ' ' + l +
			" -e \"print(require('protonvpn.routing').ra_budget_ms())\"" ]);
		return trim(r.stdout || '');
	};
	// The suite runs with a shortened budget (see run.sh), so the DEFAULT can
	// only be read where that override is not in force.
	eq('budget: five seconds unless told otherwise',
		budget_of('unset PROTONVPN_RA_SETTLE_MS;'), '5000');
	eq('budget: and honours PROTONVPN_RA_SETTLE_MS when it is set',
		budget_of('PROTONVPN_RA_SETTLE_MS=1234'), '1234');
	// And the suite really is running on the knob rather than on a stub, which
	// is what makes every timeout test above an exercise of the real path.
	ok('budget: the suite itself runs on a shortened one',
		_routing.ra_budget_ms() < 5000);
}

// The production budget, end to end, in a child with the override unset. The
// shortened suite budget makes the timeout tests cheap; this is what stops
// that from quietly becoming a suite that no longer tests the timeout at all.
{
	reset_stubs();
	netifd_says({ media: [ other_ula('media') ] });   // never reaches ready
	let uc = getenv('UCODE') || 'ucode';
	let l = getenv('PVT_UCODE_L') || '';
	let r = _cmn.run([ 'sh', '-c', 'unset PROTONVPN_RA_SETTLE_MS; ' + uc + ' ' + l +
		' -S ' + getenv('PVT_HELPERS') + '/real-budget.uc' ]);
	let got = split(trim(r.stdout || ''), ' ');
	let spent = int(got[0] || '0'), budget = int(got[1] || '0');
	eq('real budget: the child ran on the production value', budget, 5000);
	ok('real budget: and a wait that never settles really does spend it',
		spent >= 4500 && spent < 12000, sprintf('spent %dms', spent));
}

// The same prefix has more than one spelling, and netifd is not the only
// thing that could ever answer this probe. Compared as numbers, so it does
// not matter which spelling arrives.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	// Upper case and a fully-expanded tail: the same /64 the hint asks for.
	let h = uc(_routing.v6_hint('media'));
	netifd_says({ media: [ 'FD7A:1B2C:3D4E:' + h + ':0:0:0:1' ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	eq('spelling: an upper-case, fully-expanded address is the same prefix',
		logged_matching(/did not settle/), []);
	restore_log();
}

{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	// One hextet different, spelled with a leading zero so a textual compare
	// would also call it different — for the wrong reason.
	netifd_says({ media: [ 'fd7a:1b2c:3d4e:0abc::1' ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	ok('spelling: and a genuinely different /64 is still different',
		length(logged_matching(/did not settle/)) == 1);
	restore_log();
}

// A zero run abbreviated inside the first four groups — the spelling the
// comparison could not see until `::` was expanded rather than skipped.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.network.globals.ula_prefix = 'fd7a:0:0::/48';
	let uci = cursor();
	// Same /64 as fd7a:0:0:<hint>::1, written with the zero run compressed.
	netifd_says({ media: [ 'fd7a::' + _routing.v6_hint('media') + ':0:0:0:1' ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	eq('spelling: a compressed zero run is the same prefix',
		logged_matching(/did not settle/), []);
	restore_log();
}

// Two zero runs is not an address, and neither is one with too many groups.
// Both expand to something if the checks are dropped, and the nine-group one
// expands to something whose first four hextets are exactly what we look for
// — so "reject what cannot be read" is load-bearing rather than tidiness.
{
	// The third one is the case that matters: expanded as if two runs were
	// legal, its first four hextets ARE the prefix being looked for, so a
	// version that does not reject it matches an address that is not one.
	for (let bad in [ 'fd7a::1b2c::1', 'fd7a:1b2c:3d4e:HINT:1:2:3:4:5',
			'fd7a:1b2c:3d4e:HINT::1::2' ]) {
		reset_stubs();
		capture_log();
		global.MOCK_UCI = mkall(F_V6);
		let uci = cursor();
		netifd_says({ media: [ replace(bad, 'HINT', _routing.v6_hint('media')) ] });
		ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
		ok('spelling: ' + bad + ' is not an address and does not match',
			length(logged_matching(/did not settle/)) == 1);
		restore_log();
	}
}

// An address that is not one. Nothing netifd writes looks like this, but the
// comparison must reject what it cannot read rather than let two unreadable
// fields agree with each other.
{
	reset_stubs();
	capture_log();
	global.MOCK_UCI = mkall(F_V6);
	let uci = cursor();
	netifd_says({ media: [ 'fd7a:1b2c:3d4e:zzzz::1' ] });
	ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
	ok('spelling: a group that is not hex is not a match',
		length(logged_matching(/did not settle/)) == 1);
	restore_log();
}

// ── 9. the timeout reaches the log on EVERY path ─────────────────────────
//
// It used to be pushed into the notes array, which only apply() logs — so on
// both release paths a timeout was silent, and a silent timeout is
// indistinguishable from success.
{
	reset_stubs();
	global.MOCK_UCI = mkall(F_V6);
	global.MOCK_UCI.protonvpn = { main: { '.type': 'instance', interface: 'pv_media',
		enabled: '1', routing_table: '101', ipv6_mode: 'auto',
		source_network: [ 'media' ] } };
	let uci = cursor();
	const _apply = require('protonvpn.apply');
	enforce_routing(uci, _cmn.load_settings(uci));
	// Our prefix stays on the bridge, so the release can never be observed.
	netifd_says({ media: [ hinted('media') ] });
	capture_log();
	_apply.disconnect(uci, 'main');
	ok('logged: a release that times out says so without apply() to relay it',
		length(logged_matching(/did not settle/)) == 1);
	// And it says which way it went, because "it timed out" alone leaves the
	// reader not knowing whether the clients were told at all.
	ok('logged: and whether the advertisement was sent anyway',
		length(logged_matching(/advertised anyway/)) == 1);
	restore_log();
}

if (fails)
	printf('\n%d check(s) failed\n', fails);
exit(fails ? 1 : 0);

#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Integration test for the rpcd ubus object. loadfile()s the object and calls
// its methods against the mock uci/ubus and a fixture-built cache. This is the
// only layer the LuCI view ever talks to, so a method that silently disappears
// or stops validating its arguments breaks the UI without breaking any unit
// test. Globals `RPCD`, `fixture` and `KEY` are supplied by run.sh.
//
// Only offline-reachable paths are exercised: every method that would reach
// api.protonvpn.ch is called on the argument-validation / no-session branch
// that returns before any request is made.

'use strict';

// Runtime scratch dir of THIS run (tests/run.sh gives each run its own, so
// two suites can execute concurrently); never the shared /tmp.
const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';

import { readfile, mkdir, unlink, open } from 'fs';
const _common = require('protonvpn.common');
const _cache = require('protonvpn.cache');
const _api = require('protonvpn.api');
const _apply_mod = require('protonvpn.apply');

// Our own pid: the one process guaranteed to be alive when a 'running' apply
// record has to look live to the liveness check.
let self_pid = null;
{
	let raw = readfile('/proc/self/stat');
	if (raw)
		self_pid = int(split(trim(raw), ' ')[0]);
}

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) {
	let gs = sprintf('%J', g), ws = sprintf('%J', w);
	ok(l, gs == ws);
	if (gs != ws)
		printf('       got:  %s\n       want: %s\n', gs, ws);
}

// The suite shares /tmp and the state dir with the other test programs; start
// from a known-empty credential state so the "not logged in" branches are the
// ones actually taken.
unlink(_api.SESSION_FILE);
unlink(_common.FETCH_STATUS_FILE);
unlink(_common.APPLY_STATUS_FILE);
unlink(_common.APPLY_LOCK_FILE);
unlink(RUN + '/protonvpn_rotate_state.json');

// Load the rpcd program; its top-level return is { protonvpn: methods }.
let obj = loadfile(RPCD)();
let m = obj ? obj.protonvpn : null;
ok('rpcd object present', m != null);

// 1. The method table is the ubus contract. The LuCI view calls these by name,
//    so a rename is a silent 404 in the browser rather than a build error.
{
	let expected = [
		'status', 'instances', 'locations', 'servers', 'external_ip',
		'refresh_status', 'session_state', 'account',
		'auth_info', 'auth_finish', 'set_totp', 'refresh_session', 'logout',
		'certificate_renew', 'apply', 'apply_start', 'apply_status',
		'rotate_now', 'disconnect',
		'clear_credentials', 'create_instance', 'delete_instance', 'refresh_locations'
	];
	let missing = [];
	for (let name in expected)
		if (!m[name] || type(m[name].call) != 'function')
			push(missing, name);
	eq('every documented method is callable', missing, []);

	// The LuCI ACL is the other half of the contract: a method rpcd exports but
	// the ACL does not list is invisible to the browser (Permission denied),
	// and an ACL entry with no method behind it is dead configuration. Neither
	// shows up as an error anywhere else, so compare the two sets directly.
	let acl_path = replace(RPCD, /\/protonvpn-wireguard\/.*$/, '') +
		'/luci-app-protonvpn/root/usr/share/rpcd/acl.d/luci-app-protonvpn.json';
	let acl_raw = readfile(acl_path);
	ok('the LuCI ACL file is readable', acl_raw != null);
	if (acl_raw) {
		let acl = json(acl_raw)['luci-app-protonvpn'];
		let granted = {};
		for (let scope in [ 'read', 'write' ])
			for (let name in acl[scope].ubus.protonvpn)
				granted[name] = true;
		let ungranted = [], orphaned = [];
		for (let name in keys(m))
			if (!granted[name])
				push(ungranted, name);
		for (let name in keys(granted))
			if (!m[name])
				push(orphaned, name);
		eq('every rpcd method is granted by the ACL', sort(ungranted), []);
		eq('every ACL entry has a method behind it', sort(orphaned), []);
	}

	// rpcd derives the accepted argument names from the `args` template; a
	// method that takes arguments without declaring them gets them stripped.
	let undeclared = [];
	for (let name in [ 'status', 'servers', 'auth_info', 'auth_finish', 'set_totp',
	                   'external_ip', 'certificate_renew', 'apply', 'apply_start',
	                   'rotate_now',
	                   'disconnect', 'create_instance', 'delete_instance' ])
		if (type(m[name].args) != 'object')
			push(undeclared, name);
	eq('argument-taking methods declare their schema', undeclared, []);
	eq('servers declares the location set', type(m.servers.args.locations), 'array');
}

// Build a cache on disk for the read methods.
let cache = _cache.normalize(json(readfile(fixture)).LogicalServers);
let cdir = RUN + '/pvrpcd_' + time();
mkdir(cdir);
ok('fixture cache written', _cache.write_cache(cache, cdir + '/protonvpn_servers_cache.json') == true);

// 2. status / instances against an unconfigured instance.
{
	global.MOCK_UCI = { protonvpn: {
		main: { '.type': 'instance', interface: 'protonvpn', cache_dir: cdir } },
		network: {} };
	global.MOCK_UBUS = {};

	eq('status not_configured', m.status.call().state, 'not_configured');
	// An unknown instance must be rejected rather than silently defaulted to
	// 'main' — the UI would otherwise show another tunnel's state.
	eq('status rejects an unknown instance',
		m.status.call({ args: { instance: 'nope' } }).error, 'no such instance');
	// A name that cannot be a section at all fails the same way.
	eq('status rejects an invalid instance name',
		m.status.call({ args: { instance: 'no way' } }).error, 'no such instance');
	// An empty argument is the documented way of saying 'main'.
	eq('status defaults to main', m.status.call({ args: { instance: '' } }).instance, 'main');

	// build_status() is what the UI polls; it must always carry the rotation
	// block with a resolved next_run, which plain status() leaves null.
	let st = m.status.call();
	eq('status carries the rotation block', type(st.rotation), 'object');
	eq('status resolves next_run for the UI', st.rotation.next_run, null); // rotation off
	eq('status carries routing detection', type(st.routing), 'object');
	ok('status never leaks the private key',
		index(sprintf('%J', st), KEY) < 0);

	eq('instances lists main', length(m.instances.call().instances), 1);
}

// 3. locations / servers read straight from the cache document.
{
	let loc = m.locations.call();
	eq('locations available', loc.available, true);
	eq('locations ready', loc.state, 'ready');
	eq('locations country count', length(loc.countries), 7);
	ok('locations carry the per-kind counts for the UI',
		loc.countries[0].standard_count != null &&
		loc.countries[0].secure_core_count != null &&
		loc.countries[0].tor_count != null);

	// Legacy single country/city call.
	eq('servers legacy city call',
		length(m.servers.call({ args: { country: 'nl', city: 'nl-amsterdam',
			hop_mode: 'standard' } }).relays), 2);
	// A location set wins over country/city, mirroring how the backend selects.
	eq('servers union of two countries',
		length(m.servers.call({ args: { locations: [ 'nl', 'jp' ], country: 'fr',
			hop_mode: 'standard' } }).relays), 4);
	// A city inside an already-requested country must not be counted twice.
	eq('servers union dedups a city inside its country',
		length(m.servers.call({ args: { locations: [ 'nl', 'nl-amsterdam' ],
			hop_mode: 'standard' } }).relays), 2);
	// Hop mode is a hard filter: picking a Secure Core relay for a 'standard'
	// tunnel would build a peer the client cannot actually use.
	eq('servers filter secure_core',
		length(m.servers.call({ args: { locations: [ 'jp' ],
			hop_mode: 'secure_core' } }).relays), 1);
	eq('servers filter tor',
		length(m.servers.call({ args: { locations: [ 'fr' ], hop_mode: 'tor' } }).relays), 1);
	// Garbage entries in the set are dropped, not passed through to the cache.
	eq('servers ignore malformed location entries',
		length(m.servers.call({ args: { locations: [ 'nl', 'not a code', 42 ],
			hop_mode: 'standard' } }).relays), 2);
	eq('servers with no selection return nothing',
		length(m.servers.call({ args: { hop_mode: 'standard' } }).relays), 0);
	// The public key stays in the cache: the browser has no use for it and it
	// is the one field that would let a compromised view build a tunnel.
	let rel = m.servers.call({ args: { locations: [ 'nl' ], hop_mode: 'standard' } }).relays;
	ok('servers never expose the relay public key', rel[0].public_key == null);
	ok('servers carry the grouping fields the UI needs',
		rel[0].country_code != null && rel[0].city_code != null && rel[0].name != null);

	// With no cache on disk the UI must be told to fetch, not shown an empty list.
	global.MOCK_UCI.protonvpn.main.cache_dir = RUN + '/pvrpcd_absent';
	let none = m.locations.call();
	eq('locations missing without a cache', none.state, 'missing');
	eq('locations unavailable without a cache', none.available, false);
	eq('servers unavailable without a cache',
		m.servers.call({ args: { locations: [ 'nl' ] } }).available, false);
	global.MOCK_UCI.protonvpn.main.cache_dir = cdir;
}

// 3b. A servers reply has to fit in ONE ubus message (issue #4). ubusd drops a
//     client that sends a frame larger than UBUS_MAX_MSGLEN (ubusd_main.c,
//     client_cb), and rpcd, having lost its bus connection, leaves uloop and
//     exits: every LuCI session dies with it and procd reports a crash loop.
//     The United States alone has more gateways than one message can carry,
//     so the reply is paged, and walking the pages must yield the same set
//     the unpaged selection would have.
//
//     The size is computed the way rpcd encodes the reply (ucode.c,
//     rpc_ucode_ucv_to_blob) using libubox's blobmsg layout, not estimated
//     from the JSON text: that is the number ubusd compares.
{
	const UBUS_MAX_MSGLEN = 1048576;
	let align4 = (n) => (n + 3) & ~3;
	// Padded length of one blobmsg attribute: blob_attr header, blobmsg_hdr
	// (u16 name length + name + NUL, aligned) and the payload.
	function blob_len(name, v) {
		let payload = 0, t = type(v);
		if (t == 'bool')
			payload = 1;
		else if (t == 'int')
			payload = (v >= -2147483648 && v <= 2147483647) ? 4 : 8;
		else if (t == 'double')
			payload = 8;
		else if (t == 'string')
			payload = length(v) + 1;
		else if (t == 'array')
			for (let e in v)
				payload += blob_len('', e);
		else if (t == 'object')
			for (let k, e in v)
				payload += blob_len(k, e);
		return align4(4 + align4(2 + length(name) + 1) + payload);
	}
	// ubus_send_reply(): message root + UBUS_ATTR_OBJID + UBUS_ATTR_DATA
	// headers around the fields rpcd put in its blob_buf.
	function ubus_reply_len(reply) {
		let n = 4 + 8 + 4;
		for (let k, v in reply)
			n += blob_len(k, v);
		return n;
	}
	// The model pinned on values worked out by hand from libubox's layout.
	eq('blob model: one u32 field', ubus_reply_len({ a: 1 }), 16 + 12);
	eq('blob model: an array of one short string', ubus_reply_len({ relays: [ 'x' ] }), 16 + 28);

	// A fleet the size of Proton's US one: thousands of logicals, one server
	// each, spread over a dozen cities, plus a small neighbour for set unions.
	let cities = [ 'New York City', 'Los Angeles', 'Chicago', 'Dallas', 'Miami',
		'Seattle', 'Atlanta', 'Denver', 'Phoenix', 'Secaucus', 'Ashburn', 'San Jose' ];
	function logical(cc, i, city) {
		return {
			Name: sprintf('%s-%s#%d', uc(cc), uc(substr(city, 0, 2)), i),
			EntryCountry: uc(cc), ExitCountry: uc(cc), City: city,
			Tier: (i % 10) ? 2 : 0, Features: (i % 3) ? 0 : 16,
			Score: 1.0 + i / 10000.0, Load: i % 100, Status: 1,
			Servers: [ { EntryIP: sprintf('10.%d.%d.1', (i >> 8) & 255, i & 255),
				Domain: sprintf('node-%s-%02d.protonvpn.net', cc, i % 90),
				X25519PublicKey: 'lDqI02+FFU6CeisxCSKxVgi28TKT9SowZybo1M4abEU=',
				Status: 1 } ]
		};
	}
	let fleet = [];
	for (let i = 1; i <= 5000; i++)
		push(fleet, logical('us', i, cities[i % length(cities)]));
	for (let i = 1; i <= 400; i++)
		push(fleet, logical('ca', i, 'Toronto'));
	let big = _cache.normalize(fleet);
	let bdir = RUN + '/pvrpcd_big_' + time();
	mkdir(bdir);
	ok('large fixture cache written',
		_cache.write_cache(big, bdir + '/protonvpn_servers_cache.json') == true);
	big = _cache.read_cache(bdir + '/protonvpn_servers_cache.json');
	global.MOCK_UCI.protonvpn.main.cache_dir = bdir;

	// What the old single reply would have weighed: the reason for the paging.
	let unpaged = [];
	for (let r in _cache.pool_relays(big, [ 'us' ], 'standard'))
		push(unpaged, _cache.trim_relay(r));
	ok('the unpaged US selection does not fit one ubus message',
		ubus_reply_len({ relays: unpaged, available: true }) > UBUS_MAX_MSGLEN);

	// Walk the pages the way the view does. Returns the collected names and
	// what went wrong, if anything.
	function walk(args) {
		let names = [], pages = 0, offset = 0, oversized = 0, stamps = {}, bad = null;
		while (pages < 1000) {
			let a = {};
			for (let k, v in args)
				a[k] = v;
			a.offset = offset;
			let rep = m.servers.call({ args: a });
			pages++;
			if (ubus_reply_len(rep) > UBUS_MAX_MSGLEN)
				oversized++;
			stamps['' + rep.generation] = true;
			for (let r in rep.relays)
				push(names, r.name + '@' + r.hostname);
			if (rep.next == null)
				break;
			if (type(rep.next) != 'int' || rep.next <= offset) {
				bad = sprintf('next %J after offset %d', rep.next, offset);
				break;
			}
			offset = rep.next;
		}
		return { names, pages, oversized, stamps: length(keys(stamps)), bad };
	}
	function names_of(list) {
		let out = [];
		for (let r in list)
			push(out, r.name + '@' + r.hostname);
		return out;
	}
	let cases = [
		[ 'country us', { country: 'us' },
			names_of(_cache.city_relays(big, 'us', '', '')) ],
		[ 'locations us', { locations: [ 'us' ], hop_mode: 'standard' },
			names_of(_cache.pool_relays(big, [ 'us' ], 'standard')) ],
		[ 'locations us+ca', { locations: [ 'us', 'ca' ], hop_mode: 'standard' },
			names_of(_cache.pool_relays(big, [ 'us', 'ca' ], 'standard')) ]
	];
	for (let c in cases) {
		let w = walk(c[1]);
		eq(`servers ${c[0]}: every page fits one ubus message`, w.oversized, 0);
		ok(`servers ${c[0]}: the selection is split over several pages`, w.pages > 1);
		eq(`servers ${c[0]}: pages advance`, w.bad, null);
		eq(`servers ${c[0]}: the pages together are exactly the selection`, w.names, c[2]);
		eq(`servers ${c[0]}: every page names the same cache`, w.stamps, 1);
	}

	let first = m.servers.call({ args: { locations: [ 'us' ], hop_mode: 'standard', offset: 0 } });
	eq('servers report the size of the whole selection', first.total, 5000);
	eq('servers at offset 0 start at the beginning', first.offset, 0);
	let past = m.servers.call({ args: { locations: [ 'us' ], offset: 6000 } });
	eq('servers past the end are an empty last page',
		[ past.relays, past.total, past.offset, past.next, past.available ],
		[ [], 5000, 5000, null, true ]);
	eq('servers treat a negative offset as the beginning',
		m.servers.call({ args: { locations: [ 'us' ], offset: -5 } }).offset, 0);
	eq('servers treat a non-numeric offset as the beginning',
		m.servers.call({ args: { locations: [ 'us' ], offset: 'x' } }).offset, 0);

	// Paging is opt-in. A caller that sends no offset is a client written
	// before it existed — an already-open LuCI page, a script — and reads
	// `relays` as the whole list. Handing it the first page would be read as
	// "these are all the servers", and the view drops a pin it cannot find in
	// the list. So it gets an explicit error it can act on instead, small
	// enough to cross the bus.
	let legacy_big = m.servers.call({ args: { locations: [ 'us' ], hop_mode: 'standard' } });
	ok('servers without an offset refuse a selection too large for one reply',
		type(legacy_big.error) == 'string' && length(legacy_big.error) > 0);
	eq('servers without an offset never send a partial list', legacy_big.relays, null);
	eq('servers without an offset say the list is available in pages', legacy_big.paged, true);
	ok('the refusal is small', ubus_reply_len(legacy_big) < 4096);
	ok('the refusal says what to do',
		index(legacy_big.error, 'reload') >= 0 || index(legacy_big.error, 'Reload') >= 0);
	let legacy_cc = m.servers.call({ args: { country: 'us' } });
	eq('servers country call without an offset refuses too', legacy_cc.paged, true);

	// The page budget is not the last line of defence: whatever a page ends up
	// weighing, the reply is measured once more before it is sent. Shown by
	// raising the budget past the bus limit — the module object is shared with
	// the rpcd program, so it pages with the raised value.
	let saved_budget = _cache.SERVERS_PAGE_BUDGET;
	_cache.SERVERS_PAGE_BUDGET = 4 * UBUS_MAX_MSGLEN;
	let unguarded = m.servers.call({ args: { locations: [ 'us' ], offset: 0 } });
	_cache.SERVERS_PAGE_BUDGET = saved_budget;
	ok('an oversized page is never sent, whatever the budget',
		ubus_reply_len(unguarded) <= UBUS_MAX_MSGLEN);
	ok('an oversized page becomes an explicit error',
		type(unguarded.error) == 'string' && unguarded.relays == null);

	// The same race the view guards against, at its source: two caches
	// published within one second must not look like one. Replace the cache
	// with another list, then give it the timestamp of the old one — the walk
	// has to see a different generation all the same.
	let gen1 = m.servers.call({ args: { locations: [ 'us' ], offset: 0 } }).generation;
	let again = _cache.normalize([ logical('us', 9001, 'Austin') ]);
	ok('replacement cache written',
		_cache.write_cache(again, bdir + '/protonvpn_servers_cache.json') == true);
	let raw = json(readfile(bdir + '/protonvpn_servers_cache.json'));
	raw.cached_at_epoch = big.cached_at_epoch;
	raw.cached_at = big.cached_at;
	_common.atomic_write(bdir + '/protonvpn_servers_cache.json', sprintf('%J', raw));
	let gen2 = m.servers.call({ args: { locations: [ 'us' ], offset: 0 } }).generation;
	ok('a generation is a non-empty string', type(gen1) == 'string' && length(gen1) > 0);
	ok('a cache replaced within the same second has another generation', gen1 != gen2);
	// The same document published at another path is another cache: the
	// setting that picks the directory can change between two pages.
	let bdir2 = bdir + '_copy';
	mkdir(bdir2);
	_common.atomic_write(bdir2 + '/protonvpn_servers_cache.json', sprintf('%J', raw));
	global.MOCK_UCI.protonvpn.main.cache_dir = bdir2;
	ok('the same cache at another path has another generation',
		m.servers.call({ args: { locations: [ 'us' ], offset: 0 } }).generation != gen2);

	// A selection that fits is answered as before: the whole list, nothing
	// added, which is exactly what a client from before the paging expects.
	global.MOCK_UCI.protonvpn.main.cache_dir = cdir;
	let small = m.servers.call({ args: { locations: [ 'nl' ], hop_mode: 'standard' } });
	let small_list = [];
	for (let r in _cache.pool_relays(cache, [ 'nl' ], 'standard'))
		push(small_list, _cache.trim_relay(r));
	eq('servers without an offset answer a small selection in the old shape',
		small, { relays: small_list, available: true });
	let small_paged = m.servers.call({ args: { locations: [ 'nl' ], hop_mode: 'standard', offset: 0 } });
	eq('servers fitting one page carry no continuation', small_paged.next, null);
	eq('servers fitting one page carry the whole selection',
		length(small_paged.relays), small_paged.total);

	// 3c. Nothing that reaches the bus may exceed it, whatever the cache holds.
	//     A cache on disk is not necessarily one this version normalized (an
	//     older package wrote it, or it was edited by hand), so the reply path
	//     cannot rely on normalization alone. Both records below are the
	//     reviewer's: one field of 1.1 million characters, and one field that
	//     is an array of 90 000 zeros — 270 KB as JSON but over 1 MB as blob.
	let long_name = 'x';
	for (let i = 0; i < 21; i++)
		long_name += long_name;
	long_name = substr(long_name, 0, 1100000);
	let zeros = [];
	for (let i = 0; i < 90000; i++)
		push(zeros, 0);
	// A relay record as the cache stores it.
	let cached_relay = (name) => ({ hostname: 'node-us-01.protonvpn.net',
		ip_address: '10.0.0.1', name: name, public_key: 'k', load: 10, score: 1.5,
		features: 0, secure_core: false, tor: false, entry_country: 'us', tier: 2,
		location: 'us-chicago', port: 51820, active: true, country_code: 'us',
		city_code: 'us-chicago', city: 'Chicago' });
	for (let bad in [ [ 'an oversized name', long_name ], [ 'a nested name', zeros ] ]) {
		let doc = { countries: [ { code: 'us', name: 'US', display_name: 'US',
			gateway_count: 2, cities: [ { code: 'us-chicago', name: 'Chicago',
				country: 'US', country_code: 'us', gateway_count: 2,
				relays: [ cached_relay('US#1'), cached_relay(bad[1]) ] } ] } ],
			stats: { countries: 1, cities: 1, gateways: 2, servers_seen: 2 } };
		let hdir = sprintf('%s/pvrpcd_hostile_%d_%d', RUN, time(), length(bad[0]));
		mkdir(hdir);
		_cache.write_cache(doc, hdir + '/protonvpn_servers_cache.json');
		global.MOCK_UCI.protonvpn.main.cache_dir = hdir;
		for (let args in [ { country: 'us' }, { country: 'us', offset: 0 },
		                   { locations: [ 'us' ] }, { locations: [ 'us' ], offset: 0 },
		                   { locations: [ 'us' ], offset: 1 } ]) {
			let rep = m.servers.call({ args: args });
			let what = sprintf('%s, %J', bad[0], keys(args));
			ok(`servers with ${what}: the reply fits one ubus message`,
				ubus_reply_len(rep) <= UBUS_MAX_MSGLEN);
			ok(`servers with ${what}: an unsendable record is an explicit error`,
				type(rep.error) == 'string' && rep.relays == null);
		}
	}
	global.MOCK_UCI.protonvpn.main.cache_dir = cdir;
}

// 4. refresh_status: the UI polls this while a fetch runs, so the idle answer
//    must be a state object rather than null.
{
	eq('refresh_status idle without a job file', m.refresh_status.call().state, 'idle');
	_cache.write_fetch_status({ state: 'running', progress: 10 });
	eq('refresh_status reports a running job', m.refresh_status.call().state, 'running');
	// A refresh cannot even be started while one is in flight.
	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: time() + 1800, session_expires_at: time() + 30 * 86400,
		scope: 'vpn', twofa: false });
	eq('refresh_locations refuses to stack jobs',
		m.refresh_locations.call({}).already_running, true);
	unlink(_api.SESSION_FILE);
	unlink(_common.FETCH_STATUS_FILE);
	eq('refresh_status idle again', m.refresh_status.call().state, 'idle');
}

// 4b. apply_start / apply_status: the pair the UI uses instead of the blocking
//     `apply`. The synchronous method stays, but the page must be able to
//     start an apply and poll it, and a poll must never come back null.
{
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance',
		interface: 'protonvpn', cache_dir: cdir } }, network: {} };

	eq('apply_status idle without a job file', m.apply_status.call({}).state, 'idle');
	eq('apply_start rejects an unknown instance',
		m.apply_start.call({ args: { instance: 'nope' } }).error, 'no such instance');

	// A running apply is visible to the poller and blocks a second start —
	// two applies would rewrite the same interface and commit the same config.
	let now = time();
	_apply_mod.write_apply_status({ instance: 'main', state: 'running',
		pid: self_pid, started_at: _common.iso_ts(now), started_at_epoch: now,
		finished_at: null, result: null, error: null });
	eq('apply_status reports a running apply', m.apply_status.call({}).state, 'running');
	let busy = m.apply_start.call({ args: { instance: 'main' } });
	eq('apply_start refuses to stack applies', busy.already_running, true);
	eq('apply_start names the instance holding it', busy.apply.instance, 'main');

	// The finished record is what the UI turns into its result banner, so the
	// full apply() result has to survive the round trip through the file.
	_apply_mod.write_apply_status({ instance: 'main', state: 'failed',
		started_at: _common.iso_ts(now), started_at_epoch: now,
		finished_at: _common.iso_ts(now), pid: null,
		result: { state: 'failure', error: 'not logged in' },
		error: 'not logged in' });
	let done = m.apply_status.call({});
	eq('apply_status reports the terminal state', done.state, 'failed');
	eq('apply_status carries the apply result', done.result.state, 'failure');
	eq('apply_status carries the error', done.error, 'not logged in');

	unlink(_common.APPLY_STATUS_FILE);
	eq('apply_status idle again', m.apply_status.call({}).state, 'idle');
}

// 5. Credential-facing methods, all on their offline branch. None of these may
//    reach the network, and none may echo a secret back to the browser.
{
	eq('session_state without a session', m.session_state.call({}).state, 'no_session');
	eq('session_state asks for a login', m.session_state.call({}).action_required, 're_login');
	// The client version this package stamps, carried on a call the page
	// already makes when it loads. Without it the "built into the package"
	// option can only be offered unnamed until somebody presses Fetch — a
	// network round trip to read a label, on the one control people reach for
	// when a sign-in has just been refused for being too old.
	eq('session_state names the built-in client version, with no session',
		m.session_state.call({}).app_version_builtin,
		require('protonvpn.api').builtin_app_version());
	eq('account without a session', m.account.call({}).error, 'not logged in');
	eq('refresh_locations without a session', m.refresh_locations.call({}).error, 'not logged in');

	// auth_info is the SRP step-1 relay; the username is bounded before it ever
	// becomes part of a request URL.
	eq('auth_info rejects an empty username',
		m.auth_info.call({ args: { username: '' } }).error, 'invalid username');
	eq('auth_info rejects a whitespace-only username',
		m.auth_info.call({ args: { username: '   ' } }).error, 'invalid username');
	let long_name = '';
	for (let i = 0; i < 200; i++)
		long_name += 'a';
	eq('auth_info rejects an over-long username',
		m.auth_info.call({ args: { username: long_name } }).error, 'invalid username');

	// auth_finish carries the browser-computed proof. Both completeness and
	// encoding are checked before the proof is forwarded.
	eq('auth_finish rejects a missing proof',
		m.auth_finish.call({ args: {} }).error, 'incomplete SRP proof');
	eq('auth_finish rejects a partial proof',
		m.auth_finish.call({ args: { username: 'u', srp_session: 's',
			client_ephemeral: 'AAAA' } }).error, 'incomplete SRP proof');
	eq('auth_finish rejects a non-base64 ephemeral',
		m.auth_finish.call({ args: { username: 'u', srp_session: 's',
			client_ephemeral: 'not base64!', client_proof: 'AAAA' } }).error,
		'malformed SRP proof encoding');
	eq('auth_finish rejects a non-base64 proof',
		m.auth_finish.call({ args: { username: 'u', srp_session: 's',
			client_ephemeral: 'AAAA', client_proof: '../../etc/passwd' } }).error,
		'malformed SRP proof encoding');

	// TOTP codes are 6-8 digits; anything else is rejected locally so a typo
	// does not burn one of the account's rate-limited attempts.
	eq('set_totp rejects letters', m.set_totp.call({ args: { code: 'abcdef' } }).error,
		'invalid TOTP code');
	eq('set_totp rejects a short code', m.set_totp.call({ args: { code: '123' } }).error,
		'invalid TOTP code');
	eq('set_totp rejects an over-long code',
		m.set_totp.call({ args: { code: '1234567890' } }).error, 'invalid TOTP code');
	eq('set_totp rejects a missing code', m.set_totp.call({ args: {} }).error,
		'invalid TOTP code');
}

// 6. Instance-scoped write methods reject an unknown instance before doing any
//    work — this is the guard that keeps a typo from acting on 'main'.
{
	for (let name in [ 'apply', 'apply_start', 'rotate_now', 'disconnect',
	                   'certificate_renew', 'clear_credentials', 'external_ip' ])
		eq(name + ' rejects an unknown instance',
			m[name].call({ args: { instance: 'nope' } }).error, 'no such instance');
}

// 7. apply / rotate_now on a configured-but-logged-out instance.
{
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
		country_code: 'nl', hop_mode: 'standard', cache_dir: cdir } },
		network: {} };
	// Without a session there is no certificate to register, so apply must fail
	// loudly with the actionable error rather than half-configure the interface.
	let ap = m.apply.call({});
	eq('apply fails without a session', ap.state, 'failure');
	eq('apply names the missing session', ap.error, 'not logged in');
	ok('apply wrote no interface', global.MOCK_UCI.network.protonvpn == null);

	// A pinned server turns rotation into a no-op instead of an error.
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
		fixed_server: 'NL#85', cache_dir: cdir } },
		network: { protonvpn: { '.type': 'interface', private_key: KEY } } };
	let rn = m.rotate_now.call({});
	eq('rotate_now skipped with a pinned server', rn.skipped, true);
	eq('rotate_now explains the skip', rn.reason, 'fixed server configured');

	// Without a key there is nothing to rotate; say so instead of burning
	// max_retries on candidates that cannot possibly hand shake.
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
		cache_dir: cdir } }, network: {} };
	eq('rotate_now skipped without a keypair',
		m.rotate_now.call({}).reason, 'instance has no keypair yet; apply first');
}

// 8. disconnect must take the tunnel down AND release the managed routing
//    objects; leaving a steering rule behind sends LAN traffic into a dead
//    table, which looks like a total loss of internet.
{
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
		enabled: '1', routing_table: 'pvx', source_network: 'lan', cache_dir: cdir } },
		network: {
			protonvpn: { '.type': 'interface', private_key: KEY, auto: '1',
				protonvpn_managed_routing: '1' },
			steerrule: { '.type': 'rule', 'in': 'lan', lookup: 'pvx',
				protonvpn_managed: '1', protonvpn_role: 'steer_lookup',
				protonvpn_iface: 'protonvpn' }
		}, firewall: {} };
	let dc = m.disconnect.call({});
	eq('disconnect ok', dc.ok, true);
	eq('disconnect flips the master switch off', global.MOCK_UCI.protonvpn.main.enabled, '0');
	eq('disconnect keeps the interface down', global.MOCK_UCI.network.protonvpn.auto, '0');
	ok('disconnect releases the steering rule', global.MOCK_UCI.network.steerrule == null);

	// clear_credentials is the step beyond disconnect: it drops the identity so
	// the instance reports 'not_configured' again, but must keep the interface
	// section and the settings — otherwise "log out" would silently destroy a
	// configured tunnel the user only wanted to re-key.
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
		country_code: 'nl', cache_dir: cdir } },
		network: {
			protonvpn: { '.type': 'interface', private_key: KEY, auto: '1' },
			pvpeer: { '.type': 'wireguard_protonvpn', interface: 'protonvpn',
				endpoint_host: '1.2.3.4' }
		} };
	eq('clear_credentials ok', m.clear_credentials.call({}).ok, true);
	ok('clear_credentials removes the key',
		global.MOCK_UCI.network.protonvpn.private_key == null);
	ok('clear_credentials removes the peer', global.MOCK_UCI.network.pvpeer == null);
	ok('clear_credentials keeps the interface section',
		global.MOCK_UCI.network.protonvpn != null);
	eq('clear_credentials keeps the interface down',
		global.MOCK_UCI.network.protonvpn.auto, '0');
	ok('clear_credentials keeps the settings',
		global.MOCK_UCI.protonvpn.main.country_code == 'nl');
	eq('the instance is back to not_configured', m.status.call().state, 'not_configured');
}

// 9. Instance lifecycle. create/delete deliberately do NOT default to 'main',
//    because deleting 'main' resets every one of its settings.
{
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
		cache_dir: cdir } }, network: {} };

	eq('create rejects a missing name', m.create_instance.call({ args: {} }).error,
		'invalid instance name');
	eq('create rejects an empty name',
		m.create_instance.call({ args: { instance: '' } }).error, 'invalid instance name');
	eq('create rejects a name with a space',
		m.create_instance.call({ args: { instance: 'no way' } }).error, 'invalid instance name');
	// 'globals' anchors the shared cache options; an instance by that name
	// would shadow them.
	eq('create rejects the reserved globals name',
		m.create_instance.call({ args: { instance: 'globals' } }).error, 'this name is reserved');

	let cr = m.create_instance.call({ args: { instance: 'extra' } });
	eq('create ok', cr.ok, true);
	eq('create derives the interface name', cr.interface, 'pv_extra');
	ok('create rejects a duplicate',
		m.create_instance.call({ args: { instance: 'extra' } }).error != null);
	eq('instances lists both', length(m.instances.call().instances), 2);

	eq('delete rejects a missing name', m.delete_instance.call({ args: {} }).error,
		'invalid instance name');
	eq('delete rejects an unknown instance',
		m.delete_instance.call({ args: { instance: 'ghost' } }).error, 'no such instance');
	eq('delete ok', m.delete_instance.call({ args: { instance: 'extra' } }).ok, true);
	eq('instances back to one', length(m.instances.call().instances), 1);
}

// 10. Deleting 'main' resets it to defaults instead of removing the section —
//     the UI has no way to recreate it, and the migration stamp must survive so
//     uci-defaults does not re-run an old migration.
{
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
		country_code: 'nl', rotation_enabled: '1', config_version: '1', cache_dir: cdir } },
		network: { protonvpn: { '.type': 'interface', private_key: KEY,
			vpn_type: 'protonvpn' } } };
	let rr = m.delete_instance.call({ args: { instance: 'main' } });
	ok('main reset ok', rr.ok == true && rr.reset == 'main');
	ok('main section kept', global.MOCK_UCI.protonvpn.main != null);
	ok('main options wiped', global.MOCK_UCI.protonvpn.main.country_code == null &&
		global.MOCK_UCI.protonvpn.main.rotation_enabled == null);
	eq('migration stamp kept', global.MOCK_UCI.protonvpn.main.config_version, '1');
	ok('main network interface removed', global.MOCK_UCI.network.protonvpn == null);
}

// The rpcd object opens ubus connections through status(); none may survive the
// call, or a polling UI exhausts ubusd's descriptors.
{
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn',
		cache_dir: cdir } },
		network: { protonvpn: { '.type': 'interface', private_key: KEY } } };
	global.MOCK_UBUS = { 'network.interface.protonvpn~status': { up: true, l3_device: 'protonvpn' } };
	global.MOCK_UBUS_OPEN = 0;
	for (let i = 0; i < 10; i++)
		m.status.call({});
	eq('rpcd status leaves no ubus connection open', global.MOCK_UBUS_OPEN, 0);
}

// ── the external-IP probe reads a third party's HTTP response ───────────
//
// This is the one input in the package an outsider controls, and its shape
// test is all that stands between the response and the page. Anchored, `^`
// and `$` match a LINE under REG_NEWLINE, so anything at all was accepted as
// long as the FIRST line looked like an address — the probe would then report
// that whole string as the router's external IP.
{
	const resp = RUN + '/curl-response';
	function probe(body) {
		let f = open(resp, 'w');
		// The probe calls curl without -w, so the stub answers with the body
		// alone, exactly as the real curl does.
		f.write('200\n' + body + '\n');
		f.close();
		let r = m.external_ip.call({ args: { instance: 'main' } });
		unlink(resp);
		return r;
	}

	eq('a plain address is reported', probe('203.0.113.7').ip, '203.0.113.7');
	eq('and an IPv6 one', probe('2001:db8::1').ip, '2001:db8::1');
	ok('an address with anything after it is refused',
		probe('203.0.113.7\n<script>alert(1)</script>').ip == null);
	ok('and the refusal is reported as one',
		index(probe('203.0.113.7\nrubbish').error || '', 'could not determine') >= 0);
	ok('a response that is not an address at all is refused',
		probe('not an address').ip == null);
}

unlink(RUN + '/protonvpn_rotate_state.json');
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL RPCD TESTS PASSED');
exit(fails ? 1 : 0);

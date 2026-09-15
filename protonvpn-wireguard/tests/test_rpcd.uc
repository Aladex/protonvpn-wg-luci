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

import { readfile, mkdir, unlink } from 'fs';
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

unlink(RUN + '/protonvpn_rotate_state.json');
printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL RPCD TESTS PASSED');
exit(fails ? 1 : 0);

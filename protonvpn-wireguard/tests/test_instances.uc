// SPDX-License-Identifier: MIT
// Instance lifecycle: several tunnels side by side, each with its own key,
// certificate, interface and settings. The backend has always been written per
// instance; these tests pin the contract down and cover the rpcd surface that
// exposes it.

'use strict';

import { cursor } from 'uci';
import { unlink } from 'fs';

const _apply = require('protonvpn.apply');
const _api = require('protonvpn.api');
const _common = require('protonvpn.common');

let ok = true;
function check(name, cond) {
	printf('%s %s\n', cond ? 'ok  ' : 'FAIL', name);
	if (!cond)
		ok = false;
}

const statedir = getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn';

function reset_uci() {
	global.MOCK_UCI = {
		protonvpn: {
			globals: { '.type': 'globals' },
			main: { '.type': 'instance', interface: 'protonvpn' }
		},
		network: {}
	};
	return cursor();
}

// ── creation ─────────────────────────────────────────────────────────────
{
	let uci = reset_uci();
	let r = _apply.create_instance(uci, 'media');
	check('create_instance succeeds', r.ok == true);
	check('and derives the interface name from the instance', r.interface == 'pv_media');
	check('the section is an instance', uci.get('protonvpn', 'media') == 'instance');
	check('with the interface stored', uci.get('protonvpn', 'media', 'interface') == 'pv_media');
	check('and enabled by default', uci.get('protonvpn', 'media', 'enabled') == '1');

	check('a duplicate name is refused',
		(_apply.create_instance(uci, 'media') || {}).error != null);
	check('the globals section name is reserved',
		(_apply.create_instance(uci, 'globals') || {}).error != null);
	check('an invalid name is refused',
		(_apply.create_instance(uci, 'no spaces!') || {}).error != null);
	// 'pv_' + name has to stay within the netifd interface name limit.
	check('a name too long for an interface is refused',
		(_apply.create_instance(uci, 'abcdefghijklmnopqrstuvwxyz') || {}).error != null);

	// Two instances must never end up sharing one WireGuard interface.
	uci.set('network', 'pv_other', 'interface');
	check('an interface that already exists is refused',
		(_apply.create_instance(uci, 'other') || {}).error != null);
}

// ── per-instance keys and certificates ───────────────────────────────────
{
	unlink(statedir + '/certificate.json');
	let uci = reset_uci();
	_apply.create_instance(uci, 'media');

	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: time() + 1800, session_expires_at: time() + 86400,
		scope: 'vpn', twofa: false });

	let serial = 100;
	let real_create = _api.certificate_create;
	_api.certificate_create = function(pubkey, mode, days, renew) {
		return { ok: true, serial: '' + (++serial), mode: mode,
			expires_at: time() + 365 * 86400, refresh_at: time() + 300 * 86400 };
	};

	check('main gets a keypair', (_apply.ensure_keypair(uci, 'main') || {}).ok == true);
	let k1 = uci.get('network', 'protonvpn', 'private_key');
	check('media gets a keypair', (_apply.ensure_keypair(uci, 'media') || {}).ok == true);
	let k2 = uci.get('network', 'pv_media', 'private_key');
	_api.certificate_create = real_create;

	check('each instance has its own key', k1 != null && k2 != null && k1 != k2);
	check('creating the second key leaves the first alone',
		uci.get('network', 'protonvpn', 'private_key') == k1);

	let c1 = _apply.read_cert_state('main') || {};
	let c2 = _apply.read_cert_state('media') || {};
	check('certificates are recorded per instance',
		c1.serial != null && c2.serial != null && c1.serial != c2.serial);
	check('and so are the key seeds', c1.key_seed != null && c2.key_seed != null &&
		c1.key_seed != c2.key_seed);

	_apply.forget_cert_state('media');
	check('forgetting one instance keeps the other',
		_apply.read_cert_state('media') == null &&
		(_apply.read_cert_state('main') || {}).serial == c1.serial);

	unlink(_api.SESSION_FILE);
	unlink(statedir + '/certificate.json');
}

// ── deletion: 'main' is reset, the others are removed ────────────────────
{
	let uci = reset_uci();
	_apply.create_instance(uci, 'media');
	uci.set('protonvpn', 'media', 'locations', 'nl');

	let d = _apply.delete_instance(uci, 'media');
	check('delete_instance reports the name', d.deleted == 'media');
	check('and the section is gone', uci.get('protonvpn', 'media') == null);

	uci.set('protonvpn', 'main', 'locations', 'de');
	let m = _apply.delete_instance(uci, 'main');
	// Symmetric with `deleted`: the field names the instance it acted on.
	check('deleting main resets instead', m.reset == 'main' && m.deleted == null);
	check('main survives as a section', uci.get('protonvpn', 'main') == 'instance');
	check('but its settings are back to default',
		uci.get('protonvpn', 'main', 'locations') == null);

	check('an unknown instance is an error',
		(_apply.delete_instance(uci, 'nope') || {}).error != null);
}

// ── rpcd surface ─────────────────────────────────────────────────────────
{
	let mod = loadfile(RPCD)();
	let m = (mod && mod.protonvpn) ? mod.protonvpn : {};
	check('rpcd exposes create_instance', m.create_instance != null);
	check('rpcd exposes delete_instance', m.delete_instance != null);
	if (m.create_instance)
		check('create_instance takes an instance argument',
			m.create_instance.args != null && m.create_instance.args.instance != null);
	if (m.delete_instance)
		check('delete_instance takes an instance argument',
			m.delete_instance.args != null && m.delete_instance.args.instance != null);

	if (m.create_instance && m.delete_instance) {
		reset_uci();
		let r = m.create_instance.call({ args: { instance: 'media' } });
		check('the rpc creates the instance', r.ok == true && r.interface == 'pv_media');
		check('and refuses an empty name',
			(m.create_instance.call({ args: { instance: '' } }) || {}).error != null);
		// Unlike every other method, delete must not silently fall back to
		// 'main' when the caller passes nothing — that would wipe the wrong
		// instance's settings.
		check('delete refuses an empty name',
			(m.delete_instance.call({ args: { instance: '' } }) || {}).error != null);
		let d = m.delete_instance.call({ args: { instance: 'media' } });
		check('the rpc deletes the instance', d.deleted == 'media');
	}
}

// ── routing tables: one per instance, never shared ───────────────────────
// netifd resolves named tables through /etc/iproute2/rt_tables, so two
// instances landing on the same id would quietly steer each other's traffic.
{
	const _routing = require('protonvpn.routing');
	const rt = getenv('PROTONVPN_RT_TABLES');
	const readfile = require('fs').readfile;

	function ids_in(data) {
		let out = {};
		for (let line in split(data || '', '\n')) {
			let m = match(line, /^[ \t]*([0-9]+)[ \t]+([^ \t#]+)/);
			if (m)
				out[m[2]] = m[1];
		}
		return out;
	}

	unlink(rt);
	check('the first instance gets a table', _routing.ensure_rt_table('pv_a') == true);
	check('and so does the second', _routing.ensure_rt_table('pv_b') == true);
	let ids = ids_in(readfile(rt));
	check('both are registered', ids.pv_a != null && ids.pv_b != null);
	check('with different ids', ids.pv_a != ids.pv_b);

	// Re-registering must be a no-op, not a duplicate line with a new id.
	_routing.ensure_rt_table('pv_a');
	let again = ids_in(readfile(rt));
	check('re-registering keeps the same id', again.pv_a == ids.pv_a);

	// An id already taken by the user must not be handed out.
	unlink(rt);
	_common.atomic_write(rt, '100\tmine\n');
	_routing.ensure_rt_table('pv_c');
	let mixed = ids_in(readfile(rt));
	check('a user entry keeps its id', mixed.mine == '100');
	check('and is not reused', mixed.pv_c != '100');

	// Teardown removes only what we stamped.
	_routing.drop_rt_table('pv_c');
	let left = ids_in(readfile(rt));
	check('dropping removes our line', left.pv_c == null);
	check('and leaves the user entry alone', left.mine == '100');

	// A numeric table needs no registration at all.
	check('a numeric table is left to netifd', _routing.ensure_rt_table('101') == true);

	unlink(rt);
}

// ── deleting an instance must not leave a year-long registration ─────────
// The API refuses DELETE for our scope (403/9100), so the only way to stop a
// dead instance's certificate from squatting a device slot is to renew it down
// to the minimum: a renewal supersedes the previous registration for that key.
{
	unlink(statedir + '/certificate.json');
	let uci = reset_uci();
	_apply.create_instance(uci, 'media');

	let tombstoned = null, deleted = null;
	let real_tomb = _api.certificate_tombstone;
	let real_del = _api.certificate_delete;
	let real_pem = _api.pem_from_seed;
	_api.certificate_tombstone = function(pem) { tombstoned = pem; return { ok: true }; };
	_api.certificate_delete = function(serial) { deleted = serial; return { skipped: true }; };
	_api.pem_from_seed = function(seed) {
		return { pem_public: '-----BEGIN PUBLIC KEY-----' + seed };
	};

	_apply.record_cert_state('media', { serial: '77', key_seed: 'SEEDSEED' });
	_apply.delete_instance(uci, 'media');
	check('deletion shortens the certificate instead of leaking it',
		tombstoned == '-----BEGIN PUBLIC KEY-----SEEDSEED');
	check('and does not bother with the DELETE that always fails', deleted == null);
	check('and forgets the instance either way', _apply.read_cert_state('media') == null);

	// Without a seed the key cannot be rebuilt locally — but the listing
	// carries the public key of every certificate, which is all a tombstone
	// needs, so an instance from before seeds were kept is still cleaned up.
	tombstoned = null;
	let real_list = _api.certificate_list;
	_api.certificate_list = function(mode) {
		return { ok: true, certificates: [
			{ serial: '11', client_key: 'PEM-OTHER-KEY', expires_at: time() + 99 },
			{ serial: '88', client_key: 'PEM-EIGHTY-EIGHT', expires_at: time() + 99 }
		] };
	};
	_apply.create_instance(uci, 'other');
	_apply.record_cert_state('other', { serial: '88' });
	_apply.delete_instance(uci, 'other');
	check('with no seed the public key is looked up in the listing',
		tombstoned == 'PEM-EIGHTY-EIGHT');
	check('and the futile revoke is not attempted', deleted == null);

	// Nothing to work with at all: fall back to the revoke that always fails,
	// so at least the log tells the user where to clean up by hand.
	tombstoned = null;
	_api.certificate_list = function(mode) { return { error: 'offline' }; };
	_apply.create_instance(uci, 'third');
	_apply.record_cert_state('third', { serial: '99' });
	_apply.delete_instance(uci, 'third');
	check('with no listing either it still tries to revoke', deleted == '99');
	check('and invents no tombstone', tombstoned == null);
	_api.certificate_list = real_list;

	_api.certificate_tombstone = real_tomb;
	_api.certificate_delete = real_del;
	_api.pem_from_seed = real_pem;
	unlink(statedir + '/certificate.json');
}

// ── the account card counts device slots, not live sessions ──────────────
// /vpn/v1/sessions tracks the legacy OpenVPN/IKEv2 logins and stays empty
// however many WireGuard tunnels are up, so a card driven by it read "0 of 11"
// with two tunnels running. What a WireGuard client occupies is a registered
// certificate — count those instead.
{
	let mod = loadfile(RPCD)();
	let m = (mod && mod.protonvpn) ? mod.protonvpn : {};
	let real_call = _api.api_call;
	let real_list = _api.certificate_list;
	let asked = [];

	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: time() + 1800, session_expires_at: time() + 86400,
		scope: 'vpn', twofa: false });
	// rpcd reaches the API through the module namespace, so this is stubbable.
	_api.api_call = function(opts) {
		push(asked, opts.url);
		return { code: 200, data: { VPN: { PlanTitle: 'VPN Plus', MaxTier: 2,
			MaxConnect: 11, Name: 'leaky', Password: 'leaky' } } };
	};
	// The API keeps listing certificates after they expire, so the card must
	// count only the live ones.
	_api.certificate_list = function(mode) {
		let now = time();
		return { ok: true, certificates: [
			{ serial: '1', expires_at: now + 86400 },
			{ serial: '2', expires_at: now + 86400 },
			{ serial: '3', expires_at: now + 86400 },
			{ serial: 'stale', expires_at: now - 60 },
			{ serial: 'ancient', expires_at: 0 }
		] };
	};

	let acct = m.account.call({});
	check('the card reports the plan', acct.plan == 'VPN Plus');
	check('and the device allowance', acct.max_connect == 11);
	check('and counts registered certificates', acct.devices_used == 3);
	check('expired certificates are not counted', acct.devices_used != 5);
	check('the old sessions field is gone', acct.sessions_used == null);
	check('the legacy OpenVPN credentials are never echoed',
		index(sprintf('%J', acct), 'leaky') < 0);
	let hit_sessions = false;
	for (let u in asked)
		if (index(u, '/sessions') >= 0)
			hit_sessions = true;
	check('and /vpn/v1/sessions is not called at all', hit_sessions == false);

	// A listing failure must not hide the plan limits we already have.
	_api.certificate_list = function(mode) { return { error: 'boom' }; };
	let degraded = m.account.call({});
	check('a listing failure still reports the plan', degraded.plan == 'VPN Plus');
	check('and leaves the count unknown', degraded.devices_used == null);

	_api.api_call = real_call;
	_api.certificate_list = real_list;
	unlink(_api.SESSION_FILE);
}

unlink(statedir + '/certificate.json');
exit(ok ? 0 : 1);

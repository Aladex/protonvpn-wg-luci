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

unlink(statedir + '/certificate.json');
exit(ok ? 0 : 1);

// SPDX-License-Identifier: MIT
// Tests for the status contract: the state machine, the two credential
// horizons and — most importantly — that status() closes every ubus
// connection it opens. That last one is a regression guard: the same leak
// shipped in nordvpn 1.4.0 and took the whole router's ubus down within hours.

'use strict';

import { cursor } from 'uci';
import { unlink } from 'fs';
const _status = require('protonvpn.status');
const status = _status.status, session_info = _status.session_info,
      certificate_info = _status.certificate_info,
      required_action = _status.required_action;
const _api = require('protonvpn.api');

let failures = 0;

function ok(name, cond) {
	print(cond ? 'ok   ' : 'FAIL ', name, '\n');
	if (!cond)
		failures++;
}

function eq(name, got, want) {
	let g = sprintf('%J', got), w = sprintf('%J', want);
	print((g == w) ? 'ok   ' : 'FAIL ', name, '\n');
	if (g != w) {
		print('       got:  ', g, '\n');
		print('       want: ', w, '\n');
		failures++;
	}
}

const KEYV = '0000000000000000000000000000000000000000000=';

function base_uci(over) {
	let inst = { '.type': 'instance', interface: 'protonvpn' };
	for (let k in (over || {}))
		inst[k] = over[k];
	return {
		protonvpn: { main: inst },
		network: { protonvpn: { '.type': 'interface', private_key: KEYV } }
	};
}

// 1. state machine
{
	global.MOCK_UBUS = {};
	global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', interface: 'protonvpn' } },
		network: {} };
	eq('no key means not_configured', status(cursor()).state, 'not_configured');

	global.MOCK_UCI = base_uci();
	eq('interface down means disconnected', status(cursor()).state, 'disconnected');

	global.MOCK_UBUS = { 'network.interface.protonvpn~status': { up: true, l3_device: 'protonvpn' } };
	eq('up without a handshake means connecting', status(cursor()).state, 'connecting');

	let st = status(cursor());
	eq('hop mode is reported', st.hop_mode, 'standard');
	eq('rotation block present', type(st.rotation), 'object');
	eq('next_run is left to the caller', st.rotation.next_run, null);
	ok('no secret in the status object', sprintf('%J', st) != null &&
		index(sprintf('%J', st), KEYV) < 0);
}

// 2. the ubus connection is always closed (regression guard)
{
	global.MOCK_UCI = base_uci();
	global.MOCK_UBUS = { 'network.interface.protonvpn~status': { up: true, l3_device: 'protonvpn' } };
	global.MOCK_UBUS_OPEN = 0;
	for (let i = 0; i < 25; i++)
		status(cursor());
	eq('status leaves no ubus connection open', global.MOCK_UBUS_OPEN, 0);

	// Also when the netifd call itself fails.
	global.MOCK_UBUS = {};
	global.MOCK_UBUS_OPEN = 0;
	status(cursor());
	eq('status closes ubus even when the call fails', global.MOCK_UBUS_OPEN, 0);
}

// 3. session horizons: an expired ACCESS token must never look like a dead
//    session, because the daemon refreshes it silently.
{
	unlink(_api.SESSION_FILE);
	eq('no session file', session_info(time()).state, 'no_session');

	let now = time();
	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: now - 10, session_expires_at: now + 86400,
		scope: 'vpn', twofa: false });
	let si = session_info(now);
	eq('stale access token still means an active session', si.state, 'active');
	ok('access horizon is exposed separately', si.access_expires_at == now - 10);

	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: now + 100, session_expires_at: now - 1,
		scope: 'vpn', twofa: false });
	eq('an expired session horizon means expired', session_info(now).state, 'expired');

	_api.session_store({ uid: 'u', access_token: 'a', refresh_token: 'r',
		access_expires_at: now + 100, session_expires_at: now + 86400,
		scope: '', twofa: true });
	eq('a half-authenticated session needs 2fa', session_info(now).state, 'needs_2fa');

	ok('session_info never returns the tokens',
		index(sprintf('%J', session_info(now)), '"a"') < 0);
	unlink(_api.SESSION_FILE);
}

// 4. certificate info and the resulting action
{
	let now = time();
	// Start from a clean slate: the suite shares one state directory.
	unlink((getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn') + '/certificate.json');
	let none = certificate_info('main', now);
	eq('no certificate recorded', none.present, false);

	eq('needs 2fa wins over everything',
		required_action({ state: 'needs_2fa' }, none), 'totp');
	eq('no session asks for a login',
		required_action({ state: 'no_session' }, none), 're_login');
	eq('expired session asks for a login',
		required_action({ state: 'expired' }, none), 're_login');
	eq('active session with no certificate needs nothing',
		required_action({ state: 'active' }, none), null);
	eq('an expired certificate must be renewed',
		required_action({ state: 'active' },
			{ present: true, expired: true }), 'renew_certificate');
	eq('a valid certificate needs nothing',
		required_action({ state: 'active' },
			{ present: true, expired: false }), null);
}


// 5. daemon scheduling for the two Proton-specific jobs
{
	const _svc = require('protonvpn.service');
	let now = 100000;

	// Session: the ACCESS token is the short-lived half. Letting it lapse would
	// break every API call while the 30-day session is still perfectly valid.
	eq('no session, nothing to refresh', _svc.should_refresh_session(null, now), false);
	eq('fresh access token needs no refresh',
		_svc.should_refresh_session({ access_expires_at: now + 1800,
			session_expires_at: now + 30 * 86400 }, now), false);
	eq('access token about to expire triggers a refresh',
		_svc.should_refresh_session({ access_expires_at: now + 60,
			session_expires_at: now + 30 * 86400 }, now), true);
	eq('an already expired access token triggers a refresh',
		_svc.should_refresh_session({ access_expires_at: now - 1,
			session_expires_at: now + 30 * 86400 }, now), true);
	eq('an ageing session horizon also triggers a refresh',
		_svc.should_refresh_session({ access_expires_at: now + 1800,
			session_expires_at: now + 3 * 86400 }, now), true);

	// Certificate: prefer Proton's own RefreshTime over any threshold we invent.
	eq('no certificate, nothing to renew', _svc.should_renew_certificate(null, now), false);
	eq('a young certificate is left alone',
		_svc.should_renew_certificate({ expires_at: now + 365 * 86400,
			refresh_at: now + 300 * 86400 }, now), false);
	eq('past RefreshTime the certificate is renewed',
		_svc.should_renew_certificate({ expires_at: now + 90 * 86400,
			refresh_at: now - 1 }, now), true);
	eq('without RefreshTime the expiry threshold still fires',
		_svc.should_renew_certificate({ expires_at: now + 10 * 86400, refresh_at: 0 }, now), true);
	eq('an expired certificate is renewable',
		_svc.should_renew_certificate({ expires_at: now - 1, refresh_at: 0 }, now), true);
}

print(failures ? sprintf('\nFAILURES: %d\n', failures) : '\nALL STATUS TESTS PASSED\n');
if (failures)
	exit(1);

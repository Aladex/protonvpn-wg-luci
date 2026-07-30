// SPDX-License-Identifier: MIT
// Runtime status for the UI/RPC. Combines UCI config, netifd (ubus)
// interface state, the WireGuard handshake age and the credential state
// (session expiry, certificate expiry). Never returns any secret.

'use strict';

import { connect } from 'ubus';
const _common = require('protonvpn.common');
const load_settings = _common.load_settings,
      validate_wg_key = _common.validate_wg_key,
      run = _common.run;
const _api = require('protonvpn.api');

// Newest WireGuard handshake age in seconds for device `dev`, or null.
function handshake_age(dev) {
	let res = run([ 'wg', 'show', dev, 'latest-handshakes' ]);
	if (res.code != 0)
		return null;
	let best = 0;
	for (let line in split(trim(res.stdout || ''), '\n')) {
		let parts = split(line, '\t');
		if (length(parts) >= 2) {
			let ts = int(parts[1]);
			if (ts > best)
				best = ts;
		}
	}
	if (best == 0)
		return null;
	let age = time() - best;
	return age < 0 ? 0 : age;
}

function find_peer(uci, iface) {
	let found = null;
	uci.foreach('network', null, function(sec) {
		if (sec['.type'] && index(sec['.type'], 'wireguard_') == 0 && sec.interface == iface) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// Credential state for the UI. Two horizons on purpose: the access token lives
// 30 minutes and the daemon rotates it silently, so only the ~30-day session
// horizon may ever ask the user to log in again. No token is ever returned.
function session_info(now) {
	let s = _api.session_load();
	if (!s)
		return { present: false, state: 'no_session', expires_at: 0 };
	if (s.twofa)
		return { present: true, state: 'needs_2fa',
			expires_at: s.session_expires_at || 0 };
	if (s.session_expires_at && s.session_expires_at <= now)
		return { present: true, state: 'expired',
			expires_at: s.session_expires_at };
	return {
		present: true, state: 'active',
		expires_at: s.session_expires_at || 0,
		access_expires_at: s.access_expires_at || 0,
		scope: s.scope || ''
	};
}

// Stored certificate metadata, when apply.uc has registered one. Its expiry is
// the real deadline: a dead session only blocks API calls, while an expired
// certificate means the tunnel cannot come up at all.
function certificate_info(instance, now) {
	let cert = null;
	try {
		cert = require('protonvpn.apply').read_cert_state(instance);
	} catch (e) {
		cert = null;
	}
	if (!cert || !cert.expires_at)
		return { present: false, expires_at: 0, expired: false, days_left: null };
	let left = cert.expires_at - now;
	return {
		present: true,
		serial: cert.serial || null,
		expires_at: cert.expires_at,
		// Proton tells us when it wants the certificate renewed; prefer that
		// over guessing a threshold from the expiry.
		refresh_at: cert.refresh_at || 0,
		expired: left <= 0,
		days_left: left > 0 ? int(left / 86400) : 0
	};
}

// What the user must do, if anything, ordered by urgency: an expired
// certificate stops the tunnel, a dead session only stops API work.
function required_action(session, cert) {
	if (session.state == 'needs_2fa')
		return 'totp';
	if (session.state == 'no_session' || session.state == 'expired')
		return 're_login';
	if (cert.present && cert.expired)
		return 'renew_certificate';
	return null;
}

// Runtime status of one instance. Return shape:
//   { instance, configured, enabled, fixed, interface, hop_mode,
//     state: 'not_configured'|'disconnected'|'connecting'|'connected'|'degraded',
//     location: { country, city }, gateway, endpoint ('host:port' or null),
//     latest_handshake_seconds (null or int),
//     session: {...}, certificate: {...}, action_required,
//     rotation: { enabled, mode, interval, time, next_run: null } }
// State machine: no key -> 'not_configured'; interface down -> 'disconnected';
// no handshake -> 'connecting'; handshake <= 180 s -> 'connected'; else
// 'degraded'. `next_run` is filled in by the caller.
function status(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = s.interface;
	let now = time();

	let has_key = validate_wg_key(uci.get('network', iface, 'private_key')) != null;
	let peer = find_peer(uci, iface);
	let endpoint_host = peer ? uci.get('network', peer, 'endpoint_host') : null;
	let endpoint_port = peer ? uci.get('network', peer, 'endpoint_port') : null;

	let session = session_info(now);
	let cert = certificate_info(s.name, now);

	let result = {
		instance: s.name,
		configured: has_key,
		// Administrative master switch, distinct from the runtime state: a
		// disabled instance is deliberately down, not merely disconnected.
		enabled: s.enabled,
		// A pinned server disables rotation, so the UI hides "Rotate now".
		fixed: (s.fixed_server && s.fixed_server != '') ? true : false,
		state: has_key ? 'disconnected' : 'not_configured',
		interface: iface,
		hop_mode: s.hop_mode,
		location: {
			country: uci.get('network', iface, 'protonvpn_country_code'),
			city: uci.get('network', iface, 'protonvpn_city_code')
		},
		gateway: peer ? uci.get('network', peer, 'protonvpn_gateway') : null,
		endpoint: endpoint_host ? (endpoint_host + ':' + (endpoint_port || '')) : null,
		latest_handshake_seconds: null,
		session: session,
		certificate: cert,
		action_required: required_action(session, cert),
		rotation: {
			enabled: s.rotation_enabled,
			mode: s.rotation_mode,
			interval: s.rotation_interval,
			time: s.rotation_time,
			next_run: null
		}
	};

	if (!has_key)
		return result;

	// Interface up? and its L3 device name, via netifd. The connection is closed
	// immediately: status() runs on every daemon tick once the watchdog is on,
	// and one leaked connection per tick exhausts ubusd's descriptors within
	// hours — after which nothing on the router can reach ubus at all. That
	// exact bug shipped in nordvpn 1.4.0; do not repeat it here.
	let ifup = false, l3dev = iface;
	let ub = connect();
	if (ub) {
		let st = ub.call('network.interface.' + iface, 'status', {});
		if (st) {
			ifup = st.up ? true : false;
			if (st.l3_device)
				l3dev = st.l3_device;
		}
		ub.disconnect();
	}

	let hs = handshake_age(l3dev);
	if (hs != null)
		result.latest_handshake_seconds = hs;

	if (!ifup)
		result.state = 'disconnected';
	else if (hs == null)
		result.state = 'connecting';
	else if (hs <= 180)
		result.state = 'connected';
	else
		result.state = 'degraded';

	return result;
}

return { status, session_info, certificate_info, required_action };

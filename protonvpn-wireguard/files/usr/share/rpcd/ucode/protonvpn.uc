#!/usr/bin/env ucode
// SPDX-License-Identifier: MIT
// rpcd ubus object 'protonvpn'. Thin glue over the backend modules with a
// fixed request schema per method. Read methods never mutate; write methods
// delegate to the shared apply/rotation workers. No secret is ever returned
// — session tokens stay server-side; the browser only ever sees the SRP
// parameters and its own computed proof.

'use strict';

import { cursor } from 'uci';
const _common = require('protonvpn.common');
const validate_instance = _common.validate_instance,
      validate_country_code = _common.validate_country_code,
      validate_location_code = _common.validate_location_code,
      load_settings = _common.load_settings,
      list_instances = _common.list_instances,
      cache_file_path = _common.cache_file_path;
const status_mod = require('protonvpn.status');
const _apply = require('protonvpn.apply');
const _rotate = require('protonvpn.rotate');
const next_rotation = require('protonvpn.service').next_rotation;
const detect_routing = require('protonvpn.routing').detect;
const _cache = require('protonvpn.cache');
const _api = require('protonvpn.api');

// Resolve and validate args.instance (default 'main'); null when the section
// does not exist.
function req_instance(uci, request) {
	let a = (request && request.args) ? request.args : {};
	let name = (a.instance == null || a.instance == '') ? 'main' : validate_instance(a.instance);
	if (!name || uci.get('protonvpn', name) == null)
		return null;
	return name;
}

// Full status object: runtime status + rotation.last_success/next_run +
// routing detection.
function build_status(uci, name) {
	let st = status_mod.status(uci, name);
	let state = _rotate.read_state(name);
	if (state && state.last_success)
		st.rotation.last_success = state.last_success;
	let s = load_settings(uci, name);
	st.rotation.next_run = next_rotation(s, _rotate.last_attempt_ts(name), time());
	st.routing = detect_routing(uci, s, true);
	return st;
}

const methods = {};

// ── Read methods ─────────────────────────────────────────────────────────

methods.status = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return build_status(uci, name);
	}
};

methods.instances = {
	call: function(request) {
		let uci = cursor();
		let out = [];
		for (let name in list_instances(uci))
			push(out, build_status(uci, name));
		return { instances: out };
	}
};

// SRP step 1 relay: fetch the SRP parameters for `username` from the API and
// hand them to the browser (salt, PGP-signed modulus, server ephemeral,
// SRP session id). No state is persisted; no secret crosses this boundary.
methods.auth_info = {
	args: { username: '' },
	call: function(request) {
		let username = trim('' + (request.args.username || ''));
		if (!length(username) || length(username) > 128)
			return { error: 'invalid username' };
		return _api.auth_info(username);
	}
};

methods.locations = {
	call: function(request) {
		let uci = cursor();
		let path = cache_file_path(load_settings(uci));
		let cache = _cache.read_cache(path);
		if (!cache)
			return { available: false, state: 'missing',
				fetch: _cache.read_fetch_status() };
		return {
			available: true,
			state: _cache.cache_is_stale(path) ? 'stale' : 'ready',
			countries: _cache.locations_tree(cache),
			stats: cache.stats,
			cache_info: cache.cache_info,
			cached_at: cache.cached_at,
			fetch: _cache.read_fetch_status()
		};
	}
};

methods.servers = {
	args: { country: '', city: '', hop_mode: '', locations: [] },
	call: function(request) {
		let a = request.args;
		let uci = cursor();
		let cache = _cache.read_cache(cache_file_path(load_settings(uci)));
		if (!cache)
			return { relays: [], available: false };

		let hop = '' + (a.hop_mode || '');
		// A location set wins over the single country/city arguments, mirroring
		// how the backend itself selects.
		if (type(a.locations) == 'array' && length(a.locations) > 0) {
			let set = [];
			for (let e in a.locations) {
				if (type(e) != 'string')
					continue;
				let cc = validate_country_code(e);
				if (cc) {
					push(set, cc);
					continue;
				}
				let lc_ = validate_location_code(e);
				if (lc_)
					push(set, lc_);
			}
			let out = [];
			for (let r in _cache.pool_relays(cache, set, hop))
				push(out, _cache.trim_relay(r));
			return { relays: out, available: true };
		}

		let cc = validate_country_code('' + (a.country || ''));
		let city = a.city ? validate_location_code('' + a.city) : '';
		if (!cc && !city)
			return { relays: [], available: true };
		return { relays: _cache.city_relays(cache, cc || '', city || '', hop),
			available: true };
	}
};

methods.external_ip = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		let iface = load_settings(uci, name).interface;
		// Bound to the tunnel device on purpose: this is the one check that
		// proves traffic really leaves through the VPN, which a handshake
		// alone does not.
		for (let url in [ 'https://api.ipify.org', 'https://ifconfig.me/ip' ]) {
			let r = _common.run([ 'curl', '-s', '-m', '8', '--interface', iface, url ]);
			let ip = trim(r.stdout || '');
			// one_line() first: this is a third party's HTTP response, and
			// `^...$` matches a LINE, so without it anything at all was
			// accepted as long as the first line looked like an address.
			if (r.code == 0 && length(ip) > 0 && length(ip) <= 45 &&
			    _common.one_line(ip) && match(ip, /^[0-9a-fA-F:.]+$/))
				return { ip: ip, interface: iface };
		}
		return { error: 'could not determine the external IP' };
	}
};

// ── Write methods ────────────────────────────────────────────────────────

// SRP step 3 relay: submit the browser-computed ClientEphemeral/ClientProof.
// On success the session is stored server-side (0600, outside UCI).
methods.auth_finish = {
	args: { username: '', srp_session: '', client_ephemeral: '', client_proof: '' },
	call: function(request) {
		let a = request.args;
		let proof = {
			username: trim('' + (a.username || '')),
			srp_session: '' + (a.srp_session || ''),
			client_ephemeral: '' + (a.client_ephemeral || ''),
			client_proof: '' + (a.client_proof || '')
		};
		if (!length(proof.username) || !length(proof.srp_session) ||
		    !length(proof.client_ephemeral) || !length(proof.client_proof))
			return { error: 'incomplete SRP proof' };
		// Base64 fields only — reject anything that could not be a proof.
		if (!match(proof.client_ephemeral, /^[A-Za-z0-9+\/=]+$/) ||
		    !match(proof.client_proof, /^[A-Za-z0-9+\/=]+$/))
			return { error: 'malformed SRP proof encoding' };
		return _api.auth_finish(proof);
	}
};

methods.set_totp = {
	args: { code: '' },
	call: function(request) {
		let code = trim('' + (request.args.code || ''));
		if (!match(code, /^[0-9]{6,8}$/))
			return { error: 'invalid TOTP code' };
		return _api.totp_submit(code);
	}
};

methods.refresh_session = {
	call: function(request) {
		let res = _api.auth_refresh();
		if (res.ok) {
			let s = _api.session_load();
			return { ok: true,
				access_expires_at: s ? s.access_expires_at : null,
				session_expires_at: s ? s.session_expires_at : null };
		}
		return res;
	}
};

methods.logout = {
	call: function(request) {
		// Signing out invalidates every credential the tunnels depend on, so
		// take them down rather than leave interfaces up on a session that no
		// longer exists.
		let uci = cursor();
		for (let name in list_instances(uci))
			_apply.disconnect(uci, name);
		return _api.logout();
	}
};

// Account limits and live connection usage. MaxConnect is shared with every
// other device on the account (phone, laptop), so showing "N of M" is what
// explains a tunnel that silently refuses to come up.
methods.account = {
	call: function(request) {
		let s = _api.session_load();
		if (!s)
			return { error: 'not logged in' };
		let res = _api.api_call({ url: _common.API_BASE + '/vpn',
			uid: s.uid, token: s.access_token });
		if (res.code == 401) {
			let rf = _api.auth_refresh();
			if (!rf.ok)
				return { error: rf.error || 'session expired' };
			s = _api.session_load();
			res = _api.api_call({ url: _common.API_BASE + '/vpn',
				uid: s.uid, token: s.access_token });
		}
		if (res.code != 200)
			return { error: _api.api_error(res) };
		let v = res.data ? res.data.VPN : null;
		if (!v)
			return { error: 'unexpected /vpn response' };

		// How much of the device allowance is taken. NOT /vpn/v1/sessions: that
		// endpoint tracks the legacy OpenVPN/IKEv2 sessions and stays empty
		// however many WireGuard tunnels are up (verified live). What a
		// WireGuard client actually occupies is a registered certificate, so
		// count those. A failure here must not hide the plan limits we already
		// have — the field simply stays null.
		let used = null;
		let certs = _api.certificate_list('persistent');
		if (certs.ok && type(certs.certificates) == 'array') {
			// The listing keeps returning certificates well past their expiry,
			// so count only the ones still valid — an expired registration is
			// not occupying anything, and counting it made the card climb every
			// time an instance was created and removed.
			let now = time();
			used = 0;
			for (let c in certs.certificates)
				if ((c.expires_at || 0) > now)
					used++;
		}

		// Never echo VPN.Name / VPN.Password: those are the legacy
		// OpenVPN/IKEv2 credentials and have no business in a status response.
		return {
			plan: v.PlanTitle || v.PlanName || '',
			tier: v.MaxTier,
			max_connect: v.MaxConnect,
			devices_used: used
		};
	}
};

// Session state for the login UI: never returns the tokens themselves, only
// whether a session exists, when it expires and what the user must do next.
methods.session_state = {
	call: function(request) {
		let s = _api.session_load();
		if (!s)
			return { state: 'no_session', action_required: 're_login' };
		let now = time();
		if (s.twofa)
			return { state: 'needs_2fa', action_required: 'totp',
				session_expires_at: s.session_expires_at };
		// Only the SESSION horizon (the ~30-day refresh token) can force a
		// re-login. The access token lives 30 minutes and the daemon rotates it
		// silently, so its expiry must never surface as "please log in again".
		if (s.session_expires_at && s.session_expires_at <= now)
			return { state: 'expired', action_required: 're_login',
				session_expires_at: s.session_expires_at };
		return {
			state: 'active', action_required: null,
			session_expires_at: s.session_expires_at,
			access_expires_at: s.access_expires_at,
			access_stale: _api.access_token_stale(s, now),
			scope: s.scope || ''
		};
	}
};

methods.certificate_renew = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return _apply.renew_certificate(uci, name);
	}
};

methods.apply = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return _apply.apply(uci, name);
	}
};

// Asynchronous apply for the UI. `apply` above stays synchronous for scripts
// and the CLI, but a first connect can take tens of seconds and rpcd answers
// one call at a time — long enough that the browser's own rollback
// confirmation went unserved and the config was reverted underneath the user.
// Same shape as refresh_locations/refresh_status: start, then poll.
methods.apply_start = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return _apply.start_apply(name);
	}
};

// Apply progress/outcome for the UI.
methods.apply_status = {
	call: function(request) {
		return _apply.apply_status_report() || { state: 'idle' };
	}
};

methods.rotate_now = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return _rotate.rotate(uci, name);
	}
};

methods.disconnect = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return _apply.disconnect(uci, name);
	}
};

// Drop the instance's WireGuard identity (key, peer, certificate) while
// keeping its settings, so it returns to "not configured" rather than
// disappearing. Deliberately separate from disconnect, which only parks the
// tunnel, and from delete_instance, which removes the section as well.
methods.clear_credentials = {
	args: { instance: '' },
	call: function(request) {
		let uci = cursor();
		let name = req_instance(uci, request);
		if (!name)
			return { error: 'no such instance' };
		return _apply.clear_credentials(uci, name);
	}
};

// Instance management. These deliberately do NOT go through req_instance():
// it defaults an empty argument to 'main', and a create/delete that quietly
// acts on 'main' because the caller sent nothing is not a mistake worth being
// forgiving about — deleting 'main' resets every one of its settings.
function named_instance(request) {
	let a = (request && request.args) ? request.args : {};
	if (a.instance == null || a.instance == '')
		return null;
	return validate_instance(a.instance);
}

methods.create_instance = {
	args: { instance: '' },
	call: function(request) {
		let name = named_instance(request);
		if (!name)
			return { error: 'invalid instance name' };
		return _apply.create_instance(cursor(), name);
	}
};

methods.delete_instance = {
	args: { instance: '' },
	call: function(request) {
		let name = named_instance(request);
		if (!name)
			return { error: 'invalid instance name' };
		let uci = cursor();
		if (uci.get('protonvpn', name) == null)
			return { error: 'no such instance' };
		return _apply.delete_instance(uci, name);
	}
};

methods.refresh_locations = {
	call: function(request) {
		if (!_api.session_load())
			return { error: 'not logged in' };
		let st = _cache.read_fetch_status();
		if (st && st.state == 'running')
			return { already_running: true, fetch: st };
		// Detached: the fetch takes seconds and must not block the ubus call.
		_common.run([ 'sh', '-c',
			'/usr/bin/protonvpn-cache-update >/dev/null 2>&1 &' ]);
		return { started: true };
	}
};

// The client versions the official Linux app has released, for the
// app_version override in Advanced settings. Reaches out to the upstream
// repository, so it runs ONLY when the user presses the button — never on
// page load and never as part of a sign-in. It reports; the user picks a
// value and saves it like any other setting.
methods.client_versions = {
	call: function(request) {
		return _api.client_versions();
	}
};

// Cache-refresh progress for the UI.
methods.refresh_status = {
	call: function(request) {
		return _cache.read_fetch_status() || { state: 'idle' };
	}
};

return { protonvpn: methods };

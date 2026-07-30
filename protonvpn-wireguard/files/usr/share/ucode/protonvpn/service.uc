// SPDX-License-Identifier: MIT
// Pure scheduling decisions for the protonvpn procd daemon. Kept separate
// from the uloop event loop so the timing logic can be unit-tested offline.

'use strict';

const _common = require('protonvpn.common');
const WATCHDOG_GRACE = _common.WATCHDOG_GRACE,
      WATCHDOG_COOLDOWN_BASE = _common.WATCHDOG_COOLDOWN_BASE,
      WATCHDOG_COOLDOWN_MAX = _common.WATCHDOG_COOLDOWN_MAX,
      SESSION_REFRESH_AGE = _common.SESSION_REFRESH_AGE,
      SESSION_MAX_AGE = _common.SESSION_MAX_AGE,
      CERT_RENEW_DAYS = _common.CERT_RENEW_DAYS,
      CERT_MAX_DAYS = _common.CERT_MAX_DAYS;
const ACCESS_REFRESH_MARGIN = require('protonvpn.api').ACCESS_REFRESH_MARGIN;

// Refresh when the interval elapsed, or on first tick if the cache is stale.
function should_refresh(settings, last_cache, now, cache_stale) {
	if (last_cache == 0 && cache_stale)
		return true;
	return (now - last_cache) >= settings.cache_refresh_interval;
}

// `hm` is the current local time as "HH:MM". Rotation only runs when the
// instance is enabled, rotation is on, and no fixed server is pinned.
function should_rotate(settings, last_rotate, now, hm) {
	if (!settings.enabled || !settings.rotation_enabled)
		return false;
	if (settings.fixed_server && settings.fixed_server != '')
		return false;
	if (settings.rotation_mode == 'time')
		return (hm == settings.rotation_time && (now - last_rotate) > 90);
	return (now - last_rotate) >= (settings.rotation_interval * 60);
}

// Epoch of the next scheduled rotation, or null when rotation cannot run
// (disabled, pinned). Mirrors the should_rotate gating.
function next_rotation(settings, last_rotate, now) {
	if (!settings.enabled || !settings.rotation_enabled)
		return null;
	if (settings.fixed_server && settings.fixed_server != '')
		return null;
	if (settings.rotation_mode == 'time') {
		let hm = split(settings.rotation_time, ':');
		let tm = localtime(now);
		tm.hour = int(hm[0]);
		tm.min = int(hm[1]);
		tm.sec = 0;
		let t = timelocal(tm);
		if (t <= now) {
			tm.mday += 1; // timelocal() normalizes month/year overflow
			t = timelocal(tm);
		}
		return t;
	}
	let base = (last_rotate && last_rotate > 0) ? last_rotate : now;
	let t = base + settings.rotation_interval * 60;
	return t < now ? now : t;
}

// PROTON-SPECIFIC: true when the stored session should be refreshed via
// POST /auth/refresh. The session lives 30 days; refresh once it is older
// than SESSION_REFRESH_AGE (or earlier when expires_at says so), so the
// router never falls into the "must re-login via SRP" state while online.
// `session` is protonvpn.api session_load() output; null session -> false
// (nothing to refresh — the user must log in).
function should_refresh_session(session, now) {
	if (!session)
		return false;                 // nothing to refresh; the user must log in
	// The ACCESS token is the short-lived one (measured live: 1800s at login),
	// and letting it lapse would make every API call fail even though the
	// 30-day session is perfectly alive. Refresh ahead of its expiry.
	if (session.access_expires_at &&
	    now >= session.access_expires_at - ACCESS_REFRESH_MARGIN)
		return true;
	// Belt and braces: refresh well before the session horizon itself, so a
	// router that is up but idle never drifts into "log in again".
	if (session.session_expires_at &&
	    now >= session.session_expires_at - (SESSION_MAX_AGE - SESSION_REFRESH_AGE))
		return true;
	return false;
}

// PROTON-SPECIFIC: true when the WireGuard certificate should be renewed.
// Persistent certificates live up to 365 days; renew after CERT_RENEW_DAYS
// (over the live session, no SRP needed — like the cache refresh pattern).
// `cert` is the stored certificate metadata { created_at, expires_at };
// null cert -> false (the initial registration happens on apply/login).
function should_renew_certificate(cert, now) {
	if (!cert || !cert.expires_at)
		return false;                 // the first registration happens on apply
	// Proton tells us when it wants a fresh registration (RefreshTime, ~75% of
	// the lifetime); prefer that over any threshold we invent.
	if (cert.refresh_at && now >= cert.refresh_at)
		return true;
	return now >= cert.expires_at - (CERT_MAX_DAYS - CERT_RENEW_DAYS) * 86400;
}

// Watchdog decision: recover a persistently unhealthy instance by rotating
// away from the dead server. Requires the master switch and the per-instance
// watchdog option; a pinned server disables it (mirrors should_rotate). The
// grace period absorbs transient rekeys and the post-apply connecting
// window; the cooldown backs off exponentially per failed attempt so a dead
// pool is not hammered. All timers come from the persisted per-instance
// state: `degraded_since` (0 = healthy), `last_recover` (0 = never), `fails`.
// States that may trigger a watchdog recovery. The grace period gives a fresh
// connection time to complete its first handshake.
function is_unhealthy(state) {
	return state == 'connecting' || state == 'degraded' ||
		state == 'disconnected';
}

function should_recover(settings, state, degraded_since, last_recover, fails, now) {
	if (!settings.enabled || !settings.watchdog)
		return false;
	if (settings.fixed_server && settings.fixed_server != '')
		return false;
	if (!is_unhealthy(state))
		return false;
	if (!degraded_since || now - degraded_since < WATCHDOG_GRACE)
		return false;
	// Clamp the shift so a long-dead instance cannot overflow it.
	let shift = fails > 0 ? fails - 1 : 0;
	if (shift > 20)
		shift = 20;
	let cooldown = WATCHDOG_COOLDOWN_BASE * (1 << shift);
	if (cooldown > WATCHDOG_COOLDOWN_MAX)
		cooldown = WATCHDOG_COOLDOWN_MAX;
	return last_recover == 0 || now - last_recover >= cooldown;
}

// Next watchdog timers from the observed state transition. Inactive,
// unconfigured, and connected instances start with a clean recovery episode.
// `st` is { degraded_since, last_recover, recover_fails } from persisted
// state.
function watchdog_update(state, st, now, active) {
	let ds = (st && st.degraded_since > 0) ? st.degraded_since : 0;
	let last = (st && st.last_recover > 0) ? st.last_recover : 0;
	let fails = (st && st.recover_fails > 0) ? st.recover_fails : 0;
	if (!active || state == 'connected' || state == 'not_configured')
		return { degraded_since: 0, last_recover: 0, recover_fails: 0 };
	if (is_unhealthy(state) && ds == 0)
		ds = now;
	return { degraded_since: ds, last_recover: last, recover_fails: fails };
}

// Fold a completed recovery worker result into the failure counter. Losing
// the rotation-lock race is not a recovery failure; the active worker owns
// it.
function watchdog_result_update(result, fails) {
	let n = (type(fails) == 'int' && fails > 0) ? fails : 0;
	if (result && result.ok)
		return n;
	if (result && result.skipped && result.reason == 'rotation already running')
		return n;
	return n + 1;
}

return {
	should_refresh, should_rotate, next_rotation, should_recover,
	watchdog_update, watchdog_result_update,
	should_refresh_session, should_renew_certificate
};

#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Behavioural tests for protonvpn.service — the pure scheduling decisions the
// procd daemon makes on every tick. These functions have no I/O, so the only
// thing standing between a wrong inequality and a router that rotates every
// tick (or never) is this file. Globals `RPCD` and `fixture` come from run.sh.
//
// Constants asserted against (protonvpn.common): WATCHDOG_GRACE=60,
// WATCHDOG_COOLDOWN_BASE=120, WATCHDOG_COOLDOWN_MAX=900.

'use strict';

import { writefile, unlink } from 'fs';
const _cmn = require('protonvpn.common');
const _rotate = require('protonvpn.rotate');
// Runtime scratch dir of THIS run (see tests/run.sh); never the shared /tmp.
const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';

const _service = require('protonvpn.service');
const should_refresh = _service.should_refresh,
      should_rotate = _service.should_rotate,
      next_rotation = _service.next_rotation,
      should_recover = _service.should_recover,
      watchdog_update = _service.watchdog_update,
      watchdog_result_update = _service.watchdog_result_update,
      should_refresh_session = _service.should_refresh_session,
      should_renew_certificate = _service.should_renew_certificate;

let fails = 0;
function ok(l, c) { if (c) printf('ok   %s\n', l); else { fails++; printf('FAIL %s\n', l); } }
function eq(l, g, w) {
	let gs = sprintf('%J', g), ws = sprintf('%J', w);
	ok(l, gs == ws);
	if (gs != ws)
		printf('       got:  %s\n       want: %s\n', gs, ws);
}

// 1. cache refresh cadence. The first tick after a boot is special: an empty
//    clock must not be read as "the interval already elapsed" unless the cache
//    on disk really is stale, or every restart would re-download the list.
{
	let s = { cache_refresh_interval: 21600 };

	ok('refresh on first tick if stale', should_refresh(s, 0, 1000, true) == true);
	ok('no refresh on first tick if fresh', should_refresh(s, 0, 1000, false) == false);
	ok('refresh after interval', should_refresh(s, 1000, 1000 + 21600, false) == true);
	ok('no refresh before interval', should_refresh(s, 1000, 1000 + 21599, false) == false);
	ok('refresh exactly on the interval boundary',
		should_refresh(s, 1000, 1000 + 21600, false) == true);
	// A boot with a stale cache still refreshes once the interval has elapsed
	// even if the first-tick shortcut did not apply.
	ok('long-idle instance refreshes', should_refresh(s, 1000, 1000 + 86400, false) == true);
}

// 2. rotation trigger. Three independent gates (master switch, rotation
//    switch, pinned server) plus the mode-specific clock.
{
	let s = { enabled: true, rotation_enabled: true, fixed_server: '',
		rotation_mode: 'interval', rotation_interval: 360, rotation_time: '04:30' };

	ok('rotate after interval', should_rotate(s, 1000, 1000 + 360 * 60, '12:00') == true);
	ok('no rotate before interval', should_rotate(s, 1000, 1000 + 60, '12:00') == false);
	ok('no rotate when the instance is disabled',
		should_rotate({ ...s, enabled: false }, 0, 999999, '12:00') == false);
	ok('no rotate when rotation is off',
		should_rotate({ ...s, rotation_enabled: false }, 0, 999999, '12:00') == false);
	// A pinned server is an explicit user choice; rotating away from it would
	// silently undo the pin.
	ok('no rotate with a pinned server',
		should_rotate({ ...s, fixed_server: 'NL#85' }, 0, 999999, '12:00') == false);

	let st = { ...s, rotation_mode: 'time' };
	ok('rotate at the matching wall-clock time', should_rotate(st, 0, 999999, '04:30') == true);
	ok('no rotate at any other time', should_rotate(st, 0, 999999, '04:31') == false);
	// The daemon ticks faster than once a minute, so the matching HH:MM would
	// otherwise fire several times in the same minute. The 90-second debounce
	// is what makes a time-mode rotation happen exactly once per day.
	ok('time mode debounces repeat ticks in the same minute',
		should_rotate(st, 999999 - 30, 999999, '04:30') == false);
	ok('time mode fires again once the debounce elapsed',
		should_rotate(st, 999999 - 91, 999999, '04:30') == true);
	ok('time mode still honours the pinned server',
		should_rotate({ ...st, fixed_server: 'NL#85' }, 0, 999999, '04:30') == false);
}

// 3. next_rotation — the countdown the UI shows. It must mirror should_rotate's
//    gating exactly, otherwise the UI promises a rotation that never runs.
{
	let s = { enabled: true, rotation_enabled: true, fixed_server: '',
		rotation_mode: 'interval', rotation_interval: 360, rotation_time: '04:30' };
	let now = time();

	eq('next_run counts from the last attempt', next_rotation(s, 1000, 500), 1000 + 360 * 60);
	eq('next_run without history counts from now', next_rotation(s, 0, now), now + 360 * 60);
	// An overdue schedule (router asleep, clock jumped) must show "now", not a
	// timestamp in the past that renders as a negative countdown.
	eq('next_run overdue clamps to now', next_rotation(s, 100, 999999), 999999);
	eq('next_run null when rotation is off',
		next_rotation({ ...s, rotation_enabled: false }, 0, now), null);
	eq('next_run null when the master switch is off',
		next_rotation({ ...s, enabled: false }, 0, now), null);
	eq('next_run null with a pinned server',
		next_rotation({ ...s, fixed_server: 'NL#85' }, 0, now), null);

	let st = { ...s, rotation_mode: 'time' };
	let nr = next_rotation(st, 0, now);
	ok('time mode schedules into the future', nr > now);
	ok('time mode stays within 24h', (nr - now) <= 86400);
	let lt = localtime(nr);
	ok('time mode lands on 04:30:00', lt.hour == 4 && lt.min == 30 && lt.sec == 0);
	// Day/month/year rollover is delegated to timelocal(); prove the result is
	// still a valid future instant when "today at 04:30" has already passed.
	let noon = timelocal({ ...localtime(now), hour: 12, min: 0, sec: 0 });
	let nr2 = next_rotation(st, 0, noon);
	ok('past time-of-day rolls over to tomorrow', nr2 > noon && (nr2 - noon) <= 86400);
	let lt2 = localtime(nr2);
	ok('rolled-over slot is still 04:30:00', lt2.hour == 4 && lt2.min == 30 && lt2.sec == 0);
}

// 4. watchdog recovery decision. Gate order: master switch + watchdog option,
//    pinned server, unhealthy state, grace period, cooldown with exponential
//    backoff. Getting the backoff wrong means a dead server pool gets hammered
//    with a full rotation attempt every tick.
{
	let s = { enabled: true, watchdog: true, fixed_server: '' };
	let now = 100000;
	let ds = now - 120; // unhealthy for 120s, the 60s grace has elapsed

	// Option / master gates.
	ok('recover: watchdog off -> false',
		should_recover({ ...s, watchdog: false }, 'degraded', ds, 0, 0, now) == false);
	ok('recover: instance disabled -> false',
		should_recover({ ...s, enabled: false }, 'degraded', ds, 0, 0, now) == false);
	ok('recover: pinned server -> false',
		should_recover({ ...s, fixed_server: 'NL#85' }, 'degraded', ds, now - 1000, 0, now) == false);

	// State gate. 'connecting' counts as unhealthy on purpose: a tunnel that
	// never completes its first handshake would otherwise sit there forever.
	ok('recover: connected -> false', should_recover(s, 'connected', 0, 0, 0, now) == false);
	ok('recover: not_configured -> false', should_recover(s, 'not_configured', 0, 0, 0, now) == false);
	ok('recover: connecting within grace -> false',
		should_recover(s, 'connecting', now - 30, 0, 0, now) == false);
	ok('recover: connecting past grace -> true',
		should_recover(s, 'connecting', ds, 0, 0, now) == true);
	ok('recover: disconnected past grace -> true',
		should_recover(s, 'disconnected', ds, 0, 0, now) == true);

	// Grace gate: absorbs transient rekeys and the post-apply window.
	ok('recover: within grace -> false', should_recover(s, 'degraded', now - 30, 0, 0, now) == false);
	ok('recover: exactly at grace -> true', should_recover(s, 'degraded', now - 60, 0, 0, now) == true);
	ok('recover: no degraded_since -> false', should_recover(s, 'degraded', 0, 0, 0, now) == false);

	// First attempt of an episode ignores the cooldown entirely.
	ok('recover: grace elapsed, never recovered -> true',
		should_recover(s, 'degraded', ds, 0, 0, now) == true);

	// Cooldown with exponential backoff: 120s, 240s, 480s, then clamped at 900s.
	ok('recover: 1st retry within base cooldown -> false',
		should_recover(s, 'degraded', ds, now - 60, 1, now) == false);
	ok('recover: 1st retry after base cooldown -> true',
		should_recover(s, 'degraded', ds, now - 120, 1, now) == true);
	ok('recover: 2nd retry before doubled cooldown -> false',
		should_recover(s, 'degraded', ds, now - 180, 2, now) == false);
	ok('recover: 2nd retry after doubled cooldown -> true',
		should_recover(s, 'degraded', ds, now - 240, 2, now) == true);
	ok('recover: 3rd retry before 480s cooldown -> false',
		should_recover(s, 'degraded', ds, now - 300, 3, now) == false);
	ok('recover: 3rd retry after 480s cooldown -> true',
		should_recover(s, 'degraded', ds, now - 480, 3, now) == true);

	// Backoff clamps to COOLDOWN_MAX so a long outage keeps retrying hourly-ish
	// rather than drifting to never.
	ok('recover: 4th retry hits the 900s cap -> false',
		should_recover(s, 'degraded', ds, now - 899, 4, now) == false);
	ok('recover: 4th retry after the cap -> true',
		should_recover(s, 'degraded', ds, now - 900, 4, now) == true);
	ok('recover: clamped backoff not elapsed -> false',
		should_recover(s, 'degraded', ds, now - 600, 10, now) == false);
	ok('recover: clamped backoff elapsed -> true',
		should_recover(s, 'degraded', ds, now - 900, 10, now) == true);
	// The shift is clamped at 20; an instance dead for weeks must not overflow
	// it into a nonsense (or negative) cooldown.
	ok('recover: absurd failure count still recovers after the cap',
		should_recover(s, 'degraded', ds, now - 900, 5000, now) == true);
	ok('recover: absurd failure count still respects the cap',
		should_recover(s, 'degraded', ds, now - 899, 5000, now) == false);
}

// 5. watchdog state transitions: how the daemon folds one status() reading into
//    the persisted timers, once per tick.
{
	let now = 100000;

	// Entering an unhealthy state stamps degraded_since exactly once.
	let u = watchdog_update('degraded', { degraded_since: 0, last_recover: 0, recover_fails: 0 }, now, true);
	eq('watchdog: degraded stamps degraded_since', u.degraded_since, now);
	eq('watchdog: stamp keeps fails', u.recover_fails, 0);

	// Staying unhealthy must keep the ORIGINAL stamp, or the grace period would
	// restart every tick and the watchdog would never fire.
	u = watchdog_update('degraded', { degraded_since: now - 90, last_recover: now - 60, recover_fails: 1 }, now, true);
	eq('watchdog: still degraded keeps the stamp', u.degraded_since, now - 90);
	eq('watchdog: still degraded keeps the last recovery', u.last_recover, now - 60);
	eq('watchdog: still degraded keeps fails', u.recover_fails, 1);

	// A healthy tunnel ends the episode: timers and backoff reset together.
	u = watchdog_update('connected', { degraded_since: now - 90, last_recover: now - 60, recover_fails: 3 }, now, true);
	eq('watchdog: connected clears every timer',
		[ u.degraded_since, u.last_recover, u.recover_fails ], [ 0, 0, 0 ]);

	// connecting opens the grace window before the first handshake exists.
	u = watchdog_update('connecting', { degraded_since: 0, last_recover: 0, recover_fails: 0 }, now, true);
	eq('watchdog: connecting stamps degraded_since', u.degraded_since, now);
	u = watchdog_update('disconnected', { degraded_since: 0, last_recover: 0, recover_fails: 0 }, now, true);
	eq('watchdog: disconnected stamps degraded_since', u.degraded_since, now);

	// Instances that are switched off or unconfigured start a clean episode
	// when they become eligible again, instead of inheriting stale backoff.
	let stale = { degraded_since: now - 90, last_recover: now - 60, recover_fails: 2 };
	u = watchdog_update('disconnected', stale, now, false);
	eq('watchdog: inactive clears every timer',
		[ u.degraded_since, u.last_recover, u.recover_fails ], [ 0, 0, 0 ]);
	u = watchdog_update('not_configured', stale, now, true);
	eq('watchdog: not configured clears every timer',
		[ u.degraded_since, u.last_recover, u.recover_fails ], [ 0, 0, 0 ]);
	// A missing state file must not crash the daemon's first tick.
	u = watchdog_update('degraded', null, now, true);
	eq('watchdog: absent state starts a fresh episode',
		[ u.degraded_since, u.last_recover, u.recover_fails ], [ now, 0, 0 ]);

	// Only a genuinely failed recovery advances the backoff.
	eq('watchdog: failed result increments backoff',
		watchdog_result_update({ error: 'no working server found' }, 0), 1);
	eq('watchdog: skipped no-op increments backoff',
		watchdog_result_update({ skipped: true, reason: 'no other server for the current selection' }, 1), 2);
	eq('watchdog: success keeps backoff',
		watchdog_result_update({ ok: true, server: 'NL#85' }, 2), 2);
	// Losing the rotation-lock race is not a failure — another worker owns the
	// attempt; counting it would back the watchdog off for someone else's work.
	eq('watchdog: lock skip keeps backoff',
		watchdog_result_update({ skipped: true, reason: 'rotation already running' }, 2), 2);
	eq('watchdog: a null result counts as a failure', watchdog_result_update(null, 0), 1);
	eq('watchdog: a negative counter is normalized', watchdog_result_update(null, -5), 1);
}

// 6. Proton-specific credential horizons, at the exact thresholds.
//    ACCESS_REFRESH_MARGIN=300s; the session horizon margin is
//    SESSION_MAX_AGE - SESSION_REFRESH_AGE = 5 days; the certificate threshold
//    is CERT_MAX_DAYS - CERT_RENEW_DAYS = 65 days before expiry.
{
	let now = 100000;
	let live = { access_expires_at: now + 1800, session_expires_at: now + 30 * 86400 };

	eq('session: exactly at the access margin refreshes',
		should_refresh_session({ ...live, access_expires_at: now + 300 }, now), true);
	eq('session: one second outside the access margin waits',
		should_refresh_session({ ...live, access_expires_at: now + 301 }, now), false);
	eq('session: exactly at the session margin refreshes',
		should_refresh_session({ ...live, session_expires_at: now + 5 * 86400 }, now), true);
	eq('session: one second outside the session margin waits',
		should_refresh_session({ ...live, session_expires_at: now + 5 * 86400 + 1 }, now), false);
	// A session record without horizons (older format) must not loop the daemon
	// into refreshing on every single tick.
	eq('session: missing horizons never force a refresh',
		should_refresh_session({ uid: 'u' }, now), false);

	eq('certificate: exactly at the renew threshold renews',
		should_renew_certificate({ expires_at: now + 65 * 86400, refresh_at: 0 }, now), true);
	eq('certificate: one second before the threshold waits',
		should_renew_certificate({ expires_at: now + 65 * 86400 + 1, refresh_at: 0 }, now), false);
	// Proton's own RefreshTime wins over our threshold, in both directions.
	eq('certificate: RefreshTime exactly reached renews',
		should_renew_certificate({ expires_at: now + 365 * 86400, refresh_at: now }, now), true);
	eq('certificate: RefreshTime in the future is respected',
		should_renew_certificate({ expires_at: now + 365 * 86400, refresh_at: now + 1 }, now), false);
	eq('certificate: a record without an expiry is ignored',
		should_renew_certificate({ serial: 'x' }, now), false);
}

// 7. Watchdog metadata shares the per-instance rotation state file. A recovery
//    must persist last_recover/recover_fails WITHOUT clobbering the rotation
//    clock — losing last_attempt would make the daemon rotate again on the very
//    next tick.
{
	let state_path = RUN + '/protonvpn_rotate_state.json';
	unlink(state_path);
	_rotate.mark_attempt(1000);
	_rotate.record({ degraded_since: 2000 });
	_rotate.record({ last_recover: 3000, recover_fails: 1 });
	let st = _rotate.read_state();
	eq('watchdog: recovery keys persisted',
		[ st.last_recover, st.recover_fails, st.degraded_since ], [ 3000, 1, 2000 ]);
	eq('watchdog: rotation clock untouched', _rotate.last_attempt_ts(), 1000);
	unlink(state_path);
}

// 8. Concurrent state writers. The daemon tick and a forked rotation worker
//    both call record(), which is a read-modify-write cycle over one JSON file.
//    Without the state lock the later writer resurrects a stale snapshot and
//    silently drops the other one's field. Proven with a REAL second ucode
//    process, because an in-process test cannot exercise flock() at all.
{
	let state_path = RUN + '/protonvpn_rotate_state.json';
	let state_lock_path = RUN + '/protonvpn_rotate_state.lock';
	let child_script = RUN + '/protonvpn_record_child.uc';
	unlink(state_path);
	unlink(state_lock_path);

	_rotate.record({ base: 1 });
	// Snapshot taken BEFORE the child runs: this is exactly the stale view a
	// racing writer would hold.
	let parent_snapshot = _rotate.read_state();

	let state_lock = _cmn.acquire_lock(state_lock_path, 30);
	ok('concurrent: test acquired the state lock', state_lock != null);
	writefile(child_script,
		"'use strict';\nrequire('protonvpn.rotate').record({ child_writer: 1 });\n");

	let libdir = replace(RPCD, /\/rpcd\/ucode\/protonvpn\.uc$/, '/ucode');
	let mocks = replace(fixture, /\/fixtures\/[^/]+$/, '/mocks');
	// A minimal ucode build (CI, dev hosts) ships fs.so/math.so outside the
	// default search path; forward run.sh's extra -L so the child resolves them.
	let child_argv = [
		getenv('UCODE') || 'ucode',
		'-L', mocks + '/*.uc',
		'-L', libdir + '/*.uc'
	];
	let extra_l = getenv('UCODE_EXTRA_L');
	if (extra_l)
		push(child_argv, '-L', extra_l);
	push(child_argv, '-S', child_script);

	let child = _cmn.open_cmd(child_argv, 'r');
	ok('concurrent: child writer started', child != null);
	// Let the child reach record() and block on the lock we are holding.
	sleep(100);
	parent_snapshot.parent_writer = 1;
	_cmn.atomic_write(state_path, sprintf('%J', parent_snapshot));
	_cmn.release_lock(state_lock);
	child.read('all');
	child.close();

	let concurrent = _rotate.read_state();
	eq('concurrent: both writers survive the race',
		[ concurrent.parent_writer, concurrent.child_writer ], [ 1, 1 ]);
	eq('concurrent: the pre-existing field survives too', concurrent.base, 1);

	unlink(child_script);
	unlink(state_path);
	unlink(state_lock_path);
}

printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL SERVICE TESTS PASSED');
exit(fails ? 1 : 0);

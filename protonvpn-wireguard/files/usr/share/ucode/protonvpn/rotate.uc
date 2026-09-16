// SPDX-License-Identifier: MIT
// One-shot rotation worker. Builds the candidate set once, tries servers
// without replacement, verifies each with a WireGuard handshake, and
// restores the previously working peer if every candidate fails. Overlapping
// runs are prevented with a lock. Rotation is cheap for Proton: the local
// keypair/certificate is account-wide, so only the peer pubkey and endpoint
// change per server.

'use strict';

import { rand, srand } from 'math';
import { readfile } from 'fs';
import { cursor } from 'uci';
const _common = require('protonvpn.common');
const load_settings = _common.load_settings,
      cache_file_path = _common.cache_file_path,
      iso_ts = _common.iso_ts,
      atomic_write = _common.atomic_write,
      acquire_lock = _common.acquire_lock,
      release_lock = _common.release_lock,
      log = _common.log,
      run = _common.run,
      validate_wg_key = _common.validate_wg_key,
      require_ipv6_active = _common.require_ipv6_active,
      validate_instance = _common.validate_instance;
const read_cache = require('protonvpn.cache').read_cache;
const reconcile_ipv6 = require('protonvpn.routing').reconcile_ipv6;
const _select = require('protonvpn.select');
const selection_candidates = _select.selection_candidates,
      selection_report = _select.selection_report;
const _apply = require('protonvpn.apply');
const bring_up = _apply.bring_up,
      current_peer = _apply.current_peer,
      restore_peer = _apply.restore_peer,
      tear_down_peer = _apply.tear_down_peer,
      saved_ipv6_capable = _apply.saved_ipv6_capable,
      drop_noncompliant_peer = _apply.drop_noncompliant_peer,
      mark_ipv6_unmet = _apply.mark_ipv6_unmet,
      teardown_note = _apply.teardown_note,
      connect_one = _apply.connect_one,
      verify_handshake = _apply.verify_handshake,
      restore_wan_default = _apply.restore_wan_default;

const ROTATE_LOCK = _common.RUN_DIR + '/protonvpn_rotate.lock';
const ROTATE_STATE = _common.RUN_DIR + '/protonvpn_rotate_state.json';
const ROTATE_STATE_LOCK = _common.RUN_DIR + '/protonvpn_rotate_state.lock';

// Per-instance state/lock paths. The 'main' instance keeps the historical
// filenames so upgrades do not reset the persisted rotation clock.
function state_path(instance) {
	let n = validate_instance(instance) || 'main';
	return (n == 'main') ? ROTATE_STATE :
		_common.RUN_DIR + '/protonvpn_rotate_state_' + n + '.json';
}

function lock_path(instance) {
	let n = validate_instance(instance) || 'main';
	return (n == 'main') ? ROTATE_LOCK :
		_common.RUN_DIR + '/protonvpn_rotate_' + n + '.lock';
}

function state_lock_path(instance) {
	let n = validate_instance(instance) || 'main';
	return (n == 'main') ? ROTATE_STATE_LOCK :
		_common.RUN_DIR + '/protonvpn_rotate_state_' + n + '.lock';
}

// Fisher-Yates shuffle in a copy. Exported for testing.
function shuffle(list) {
	let a = [];
	for (let x in list)
		push(a, x);
	for (let i = length(a) - 1; i > 0; i--) {
		let j = rand() % (i + 1);
		let t = a[i]; a[i] = a[j]; a[j] = t;
	}
	return a;
}

// Exclusion key of the current peer: gateway || endpoint_host || null.
// The stamped protonvpn_gateway is the intended key; fall back to
// endpoint_host so a peer written without the stamp (hand-made, or a
// restored null-gateway snapshot) still cannot be re-selected and reported
// as a rotation. Pure/testable.
function current_key(saved) {
	return saved ? (saved.gateway || saved.endpoint_host || null) : null;
}

// Selection minus the current gateway, shuffled, capped at `limit`. Drawn
// from the instance's location set (or the legacy country/city selection).
// Pure/testable.
function plan_candidates(cache, settings, current_gateway, limit) {
	let list = selection_candidates(cache, settings);
	// The stamp holds the logical name ('NL#85'), but an older stamp or a
	// hand-made peer may carry the per-server domain — exclude on either, or
	// rotation could pick the server it is already on and report a change.
	if (current_gateway)
		list = filter(list, function(r) {
			return r.name != current_gateway && r.hostname != current_gateway;
		});
	list = shuffle(list);
	if (limit && length(list) > limit)
		list = slice(list, 0, limit);
	return list;
}

// Persisted { last_attempt, last_success, server, updated_at } or null.
function read_state(instance) {
	let f = readfile(state_path(instance));
	if (!f)
		return null;
	try {
		return json(f);
	} catch (e) {
		return null;
	}
}

// Merge fields into the persisted state under the state lock; stamps
// updated_at, atomic write. The atomic rename protects readers from partial
// JSON; the lock protects the read-modify-write cycle from concurrent daemon
// and worker updates. Returns the merged state or null.
function record(fields, instance) {
	let lock = null;
	// A state update normally holds the lock for only a few milliseconds.
	// Wait through a stale lock's 30-second reclamation window instead of
	// silently dropping rotation or watchdog metadata.
	for (let i = 0; i < 1550 && !lock; i++) {
		lock = acquire_lock(state_lock_path(instance), 30);
		if (!lock)
			sleep(20);
	}
	if (!lock) {
		log('could not lock rotation state for ' +
			(validate_instance(instance) || 'main'));
		return null;
	}

	let st = read_state(instance) || {};
	for (let k in fields)
		st[k] = fields[k];
	st.updated_at = iso_ts();
	let ok = atomic_write(state_path(instance), sprintf('%J', st));
	release_lock(lock);
	if (!ok) {
		log('could not write rotation state for ' +
			(validate_instance(instance) || 'main'));
		return null;
	}
	return st;
}

// Persisted last_attempt epoch or 0. The daemon schedules from this
// persisted value instead of an in-memory counter, so a restart — e.g.
// after every config save — does not reset the rotation clock and fire
// again.
function last_attempt_ts(instance) {
	let st = read_state(instance);
	return (st && type(st.last_attempt) == 'int') ? st.last_attempt : 0;
}

// Record a rotation attempt timestamp (called by the daemon before forking
// so overlapping ticks cannot double-fire).
function mark_attempt(ts, instance) {
	record({ last_attempt: ts }, instance);
}

function rotate_inner(uci, instance) {
	let s = load_settings(uci, instance);
	if (s.fixed_server && s.fixed_server != '')
		return { skipped: true, reason: 'fixed server configured' };

	let iface = s.interface;

	// Fail fast instead of burning max_retries × verify_timeout on servers that
	// cannot possibly hand shake: without a key there is no tunnel to move, and
	// an expired certificate makes every candidate reject us. The UI turns
	// these into 're_login' / 'renew_certificate' instead of a vague failure.
	if (!validate_wg_key(uci.get('network', iface, 'private_key')))
		return { skipped: true, reason: 'instance has no keypair yet; apply first' };
	let cert = _apply.read_cert_state(s.name);
	if (cert && cert.expires_at && cert.expires_at <= time())
		return { error: 'the WireGuard certificate expired; renew it before rotating',
			certificate_expired: true };

	let cache = read_cache(cache_file_path(s));
	if (!cache)
		return { error: 'server list not available; refresh the cache first' };

	// Checked before the plan is built, so the reason survives: once the
	// current gateway is excluded an empty plan is indistinguishable from
	// "nothing else to move to", and rotation would report a routine no-op
	// while the instance is in fact pinned to a configuration that can never
	// satisfy the IPv6 requirement. The watchdog rotates through here too, so
	// this is also what stops it recovering onto a gateway without IPv6.
	let sel = selection_report(cache, s);
	if (length(sel.list) == 0 && sel.ipv6_filtered && sel.matched > 0) {
		// And if the tunnel is currently on a gateway without the bit, it goes
		// too: reporting the requirement as failed while continuing to carry
		// the user on a gateway that violates it is the worst of both worlds.
		// A compliant tunnel is left alone — see apply.drop_noncompliant_peer.
		let down = drop_noncompliant_peer(uci, s);
		mark_ipv6_unmet(uci, s, 'no_gateway');
		if (down && reconcile_ipv6(uci, s)) {
			uci.commit('network');
			run([ 'ubus', 'call', 'network', 'reload' ]);
		}
		return { error: 'no IPv6 gateways in the selected locations' +
				(down ? teardown_note(s) : ''),
			ipv6_required: true, tunnel_down: down || null };
	}

	srand(time());
	let saved = current_peer(uci, iface);
	let current_gw = current_key(saved);
	let plan = plan_candidates(cache, s, current_gw, s.max_retries);
	if (length(plan) == 0)
		// Only the current server matches the selection — nothing to rotate to.
		// Keep the working tunnel; this is a no-op, not a failure.
		return { skipped: true, reason: 'no other server for the current selection' };

	for (let relay in plan) {
		// Never rotate onto the current server: a successful rotation must change
		// the gateway. plan_candidates already drops it; this guards the case
		// where the exclusion key was unknown (unstamped peer).
		if (current_gw && (relay.name == current_gw || relay.hostname == current_gw))
			continue;
		if (!connect_one(uci, iface, relay, s))
			continue;
		// Verify the tunnel by its WireGuard handshake, not by a ping routed
		// through it: a routed ping can fail on a perfectly good server, which
		// made rotation cycle servers.
		if (verify_handshake(iface, s.verify_timeout)) {
			let id = relay.name || relay.hostname;
			// Whether IPv6 may go through the tunnel is a property of the
			// gateway, and rotation has just changed it. Nothing else re-runs
			// the routing enforcement on this path, so the v6 rules would keep
			// describing the gateway we left: a lookup rule pointing at a
			// server that drops IPv6 black-holes every steered client, and the
			// other way round IPv6 stays blocked on a server that forwards it.
			if (reconcile_ipv6(uci, s)) {
				uci.commit('network');
				// Plain netifd rules; a reload applies the delta and leaves
				// the freshly connected interface alone.
				run([ 'ubus', 'call', 'network', 'reload' ]);
			}
			record({ last_success: time(), server: id }, instance);
			log('rotated ' + s.name + ' to ' + id);
			return { ok: true, server: id };
		}
	}

	// Every different candidate failed to handshake — keep a working tunnel by
	// rolling back to the last working peer. Unless the requirement is on and
	// that peer is one it excludes: the candidates were filtered, but the peer
	// being rolled back to predates the requirement, and restoring it would
	// put the instance straight back on the gateway the refusal is about.
	if (saved && require_ipv6_active(s) && !saved_ipv6_capable(saved)) {
		tear_down_peer(uci, iface);
		// As in apply: the candidates were filtered, so these gateways do
		// forward IPv6 and were only unreachable.
		mark_ipv6_unmet(uci, s, 'unreachable');
		log(s.name + ': took the tunnel down rather than roll back to a ' +
			'gateway that does not forward IPv6');
		if (reconcile_ipv6(uci, s)) {
			uci.commit('network');
			run([ 'ubus', 'call', 'network', 'reload' ]);
		}
		return { error: 'could not reach an IPv6 gateway for the current selection' +
				teardown_note(s),
			ipv6_required: true, tunnel_down: true, restored: false };
	}
	if (saved) {
		restore_peer(uci, iface, saved);
		uci.commit('network');
		bring_up(iface);
	}
	return { error: 'no working server found', restored: saved != null };
}

// Public rotation entry: per-instance lock, skip on pinned fixed_server or
// empty plan, try candidates with handshake verify (never the current
// gateway), restore the saved peer on total failure.
function rotate(uci, instance) {
	uci = uci || cursor();
	let lock = acquire_lock(lock_path(instance), 300);
	if (!lock)
		return { skipped: true, reason: 'rotation already running' };

	let res;
	try {
		res = rotate_inner(uci, instance);
	} catch (e) {
		res = { error: 'rotation error: ' + e };
	}
	release_lock(lock);
	restore_wan_default();
	return res;
}

return { shuffle, current_key, plan_candidates, read_state, record, last_attempt_ts, mark_attempt, rotate };

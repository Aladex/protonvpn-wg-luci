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

// Seconds given to any `ubus` call. ubus bounds itself with -t, which is the
// only bound available here: stock OpenWrt has no `timeout` binary, no busybox
// timeout applet, and this package declares no coreutils-timeout — a previous
// attempt wrapped the probe in `timeout` and was inert on the router while the
// suite, running on a machine that has GNU timeout, stayed green.
//
// Every call, not just the readiness probe: a wedged ubusd otherwise hangs an
// apply, the rpcd request behind it and the page in front of that, with no
// bound anywhere on the path.
const UBUS_TIMEOUT_S = '5';
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
const _routing = require('protonvpn.routing');
const reconcile_ipv6 = _routing.reconcile_ipv6;
const _underlay = require('protonvpn.underlay');
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
      restore_wan_default = _apply.restore_wan_default,
      wan_default_snapshot = _apply.wan_default_snapshot;

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
			run([ 'ubus', '-t', UBUS_TIMEOUT_S, 'call', 'network', 'reload' ]);
		}
		return { error: 'no IPv6 gateways in the selected locations' +
				(down ? teardown_note(s) : ''),
			ipv6_required: true, tunnel_down: down || null };
	}

	srand(time());
	let saved = current_peer(uci, iface);

	// Asked before a single candidate is written. With no uplink to carry the
	// current endpoint there is none for the next one either, and walking the
	// plan would rewrite the peer once per server, roll it back, and report a
	// failure the watchdog then backs off from — for an outage that has
	// nothing to do with any server. The watchdog recovers through here, so
	// this is also what keeps a WAN outage from burning its retries.
	if (saved) {
		let gate = _underlay.prepare(uci, s, true);
		if (!gate.go)
			// A leak hold refuses a manual rotation the same way it refuses
			// the schedule and the watchdog; only the wording differs.
			return { skipped: true, reason: gate.hold ? 'held after a leak' : _apply.WAITING,
				waiting_for_uplink: true, held: gate.hold || null, detail: gate.reason };
	}

	let current_gw = current_key(saved);
	let plan = plan_candidates(cache, s, current_gw, s.max_retries);
	if (length(plan) == 0)
		// Only the current server matches the selection — nothing to rotate to.
		// Keep the working tunnel; this is a no-op, not a failure.
		return { skipped: true, reason: 'no other server for the current selection' };

	let parked = null;
	for (let relay in plan) {
		// Never rotate onto the current server: a successful rotation must change
		// the gateway. plan_candidates already drops it; this guards the case
		// where the exclusion key was unknown (unstamped peer).
		if (current_gw && (relay.name == current_gw || relay.hostname == current_gw))
			continue;
		if (!connect_one(uci, iface, relay, s)) {
			// Parked on this candidate's endpoint (the check above passed for
			// the current one, so only an endpoint-specific route can do
			// this). Stop: the rollback below puts the working peer back, and
			// its bring_up goes through the same gate.
			parked = _apply.parked();
			if (parked)
				break;
			continue;
		}
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
				run([ 'ubus', '-t', UBUS_TIMEOUT_S, 'call', 'network', 'reload' ]);
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
			run([ 'ubus', '-t', UBUS_TIMEOUT_S, 'call', 'network', 'reload' ]);
		}
		return { error: 'could not reach an IPv6 gateway for the current selection' +
				teardown_note(s),
			ipv6_required: true, tunnel_down: true, restored: false };
	}
	if (saved) {
		restore_peer(uci, iface, saved);
		uci.commit('network');
		bring_up(iface, uci);
	}
	if (parked)
		return { skipped: true, reason: _apply.WAITING, waiting_for_uplink: true,
			detail: parked, restored: saved != null };
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

	// Before anything here reloads netifd: what the heal puts back.
	let snap = wan_default_snapshot();
	let res;
	try {
		res = rotate_inner(uci, instance);
	} catch (e) {
		res = { error: 'rotation error: ' + e };
	}
	release_lock(lock);
	restore_wan_default(snap);
	return res;
}

// ── Uplink reconcile ─────────────────────────────────────────────────────
// The other half of protonvpn.underlay: what happens AFTER the gate. Run by
// the daemon on every tick and by the hotplug hook on every interface event
// (/etc/hotplug.d/iface/95-protonvpn), for every enabled instance with an
// endpoint:
//
//   * up — ask the kernel where its endpoint goes (underlay.leak), FIRST and
//     for every instance: no exemption covers a route through a tunnel, not
//     nohostroute=1 and not a tunlink set by hand. Through a tunnel it is a
//     leak, whoever caused it — a boot, a reload, a hand-run ifup, a stray
//     route in `main`: logged as one, taken down, and parked with a backoff
//     that grows per leak (P4). Pinned to NO_UPLINK only when nothing else
//     owns the tunlink question: a nohostroute instance is never pinned, a
//     user's tunlink is never rewritten. Otherwise an instance of ours with no
//     tunlink at all is pinned now, which takes effect at netifd's next setup
//     of it — exactly the setup an outage forces.
//   * down and waiting — parked by the gate or by a leak, pinned to NO_UPLINK,
//     or pinned by us to an interface that is gone: brought up through the
//     gate as soon as it would let it through (P3), possibly over another
//     uplink than before. A nohostroute instance taken down for a leak comes
//     back once the kernel's route to its endpoint no longer goes through a
//     tunnel — through `main`, as it always does, or nowhere (the guard).
//
// An instance that is down for any other reason is not touched: that is the
// watchdog's, and an instance that is merely being set up (`pending`) is
// netifd's. Everything this commits is recorded and loaded through
// routing.activate_network, which also retries a reload that failed before.
const UPLINK_LOCK = _common.RUN_DIR + '/protonvpn_uplink.lock';
// Written by `protonvpn-uplink --uninstall` before it cleans up, and removed
// by the init script's start: while it exists the reconcile does nothing, so
// a removal that has to be retried is not undone in between.
const UNINSTALL_MARK = _common.RUN_DIR + '/protonvpn_uninstalling';

function hold_for_uninstall() {
	return _common.atomic_write(UNINSTALL_MARK, sprintf('%d\n', time()));
}

function commit_pending(uci) {
	uci.commit('network');
	_routing.owe_network();
}

function reconcile_one(uci, s, by, data) {
	let iface = s.interface;
	let name = s.name;
	if (!s.enabled || uci.get('network', iface) == null) {
		_underlay.unpark(name);
		return 'inactive';
	}
	let ep = _routing.endpoint_literal(uci, iface);
	if (!ep)
		return 'no endpoint';
	let nohost = uci.get('network', iface, 'nohostroute') == '1';
	let owner = _underlay.pin_owner(uci, iface);
	let st = by[iface];

	if (st && st.up) {
		let why = _underlay.leak(data, ep.addr);
		if (why) {
			_common.log(name + ': LEAK — ' + why + '; taking the tunnel down');
			if (!nohost && owner == 'none' && _underlay.set_pin(uci, iface, _underlay.NO_UPLINK))
				commit_pending(uci);
			_underlay.park_leak(name, why);
			run([ 'ifdown', iface ]);
			return 'leak';
		}
		if (!nohost && owner == 'none') {
			let res = _underlay.pick(data, ep.addr);
			if (res.iface && _underlay.set_pin(uci, iface, res.iface)) {
				commit_pending(uci);
				_common.log(name + ': endpoint pinned to uplink ' + res.iface);
			}
		}
		_underlay.unpark(name, 'connected');
		_underlay.forget_leaks(name);
		return 'up';
	}
	if (st && st.pending)
		return 'pending';

	// Ours to bring back: what is waiting (parked by the gate, held after a
	// leak, a failed reload) and, for an instance we pin, a pin whose
	// interface is gone. Whether it may come back now is the gate's own
	// decision — the leak hold included — so the reconcile can be no more
	// lenient than rotation, the watchdog or a manual connect.
	let waiting = _underlay.waiting(name) != null;
	let pin = uci.get('network', iface, 'tunlink');
	let gone = !nohost && owner == 'managed' &&
		(pin == _underlay.NO_UPLINK || !(by[pin] && by[pin].up));
	if (!waiting && !gone)
		return 'down';
	let d = _underlay.decide(uci, s, data);
	if (!d.go) {
		_underlay.park(name, d.reason);
		return d.hold ? 'leak backoff' : 'waiting';
	}
	let via = d.to;

	// The rotation lock: rotation and the watchdog bring this instance up
	// too, and two ifups at once would race each other's peer.
	let lock = acquire_lock(lock_path(name), 300);
	if (!lock)
		return 'busy';
	let up = false;
	try {
		up = bring_up(iface, uci);
	} catch (e) {
		_common.log(name + ': bringing the tunnel up failed: ' + e);
	}
	release_lock(lock);
	if (up)
		_common.log(name + ': bringing the tunnel up' + (via ? ' through uplink ' + via : ''));
	return up ? 'brought up' : 'waiting';
}

// Returns { <instance>: what was done } or { skipped: why }.
function uplink_reconcile(uci) {
	if (readfile(UNINSTALL_MARK) != null)
		return { skipped: 'the package is being removed' };
	let lock = acquire_lock(UPLINK_LOCK, 60);
	if (!lock)
		return { skipped: 'already running' };
	let out = {};
	try {
		uci = uci || cursor();
		let data = _routing.netifd_dump();
		if (data == null) {
			out = { skipped: 'netifd did not answer' };
		} else {
			let by = {};
			for (let i in ((type(data.interface) == 'array') ? data.interface : []))
				if (type(i) == 'object' && type(i.interface) == 'string')
					by[i.interface] = i;
			// The endpoint guards first, for every instance — nohostroute ones
			// and disabled ones (which lose theirs) included. Bring_up keeps
			// them current for every package ifup; this covers the instances
			// no package ifup has touched since this version was installed.
			let guards = false;
			for (let n in _common.list_instances(uci))
				if (_routing.reconcile_endpoint_guard(uci, load_settings(uci, n)))
					guards = true;
			if (guards)
				commit_pending(uci);
			for (let n in _common.list_instances(uci))
				out[n] = reconcile_one(uci, load_settings(uci, n), by, data);
			// One reload for whatever this run committed — and for anything an
			// earlier run committed whose reload failed. With nothing owed,
			// nothing runs. A bring_up above has already loaded its own.
			_routing.activate_network();
		}
	} catch (e) {
		out = { error: '' + e };
	}
	release_lock(lock);
	return out;
}

return { shuffle, current_key, plan_candidates, read_state, record, last_attempt_ts, mark_attempt, rotate,
	uplink_reconcile, hold_for_uninstall, UNINSTALL_MARK };

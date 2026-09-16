// SPDX-License-Identifier: MIT
// What the view RENDERS for the IPv6 requirement, executed against the real
// overview.js (see luci-harness.mjs).
//
// These assert rendered text rather than delivered fields on purpose. The
// reply to a click is seen only by whoever was watching the screen at that
// moment; a page reload, the 5-second poll and a background rotation all
// rebuild the page from status alone, and those are the normal case. So
// anything the user must see has to be derivable from status and actually
// drawn — twice now this app has had a fact that the backend delivered
// faithfully and nothing ever showed (`features` in 0.5.0, then
// `ipv6_required`/`tunnel_down`).
//
// Run: node --test luci-app-protonvpn/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadView, makeCtx, findClass, El } from './luci-harness.mjs';

const { spec } = loadView();

// The status an instance is in after the requirement could not be met: the
// peer is gone, so nothing is connected and no gateway is stamped.
function refusedStatus(over) {
	const ipv6 = Object.assign({
		mode: 'auto', active: false, gateway_ipv6: false,
		reason: 'ipv6_required_unavailable',
		require_ipv6: true, require_ipv6_active: true,
		required_cause: 'no_gateway'
	}, (over || {}).ipv6 || {});
	const routing = Object.assign({ mode: 'steered', killswitch: false },
		(over || {}).routing || {});
	return Object.assign({
		instance: 'main', configured: true, enabled: true,
		state: 'disconnected', gateway: null, endpoint: null,
		latest_handshake_seconds: null, hop_mode: 'standard'
	}, over, { ipv6, routing });
}

function band(status) {
	const ctx = makeCtx(spec, { status });
	ctx.updateStatusBand();
	return findClass(ctx.stateEl, 'pv-state-sub') || '';
}

// ── the blocking finding: the exposure has to come from status ───────────

test('the band warns that steered IPv4 is on the provider when the kill switch is off',
	() => {
		const sub = band(refusedStatus());
		// The two halves are one situation: IPv6 was required and unavailable
		// so the tunnel is down, AND those networks are now unprotected.
		// Someone who reads only the first half makes the wrong decision about
		// the second.
		assert.match(sub, /provider/i,
			'the band never says the steered networks are on the provider: ' + sub);
		assert.match(sub, /kill switch/i,
			'the band never advises the kill switch: ' + sub);
	});

test('with the kill switch on the band does not claim an exposure', () => {
	const sub = band(refusedStatus({ routing: { killswitch: true } }));
	assert.doesNotMatch(sub, /provider/i,
		'the band claims an exposure the kill switch is preventing: ' + sub);
	// The existing line already covers the consequence of the kill switch.
	assert.match(sub, /Kill switch is blocking/i, sub);
});

test('a connected tunnel with IPv6 working says nothing about an exposure', () => {
	const sub = band(refusedStatus({
		state: 'connected', gateway: 'NL#1', latest_handshake_seconds: 3,
		ipv6: { active: true, gateway_ipv6: true, reason: null, required_cause: null }
	}));
	assert.match(sub, /IPv6 through the tunnel/, sub);
	assert.doesNotMatch(sub, /provider/i, sub);
	assert.doesNotMatch(sub, /kill switch/i, sub);
});

test('auto_routing does not get the steered-network warning', () => {
	// With auto_routing the requirement is inactive and there are no steered
	// networks to be exposed, so the sentence would be false.
	const sub = band(refusedStatus({
		routing: { mode: 'auto', killswitch: false },
		ipv6: { require_ipv6_active: false, reason: 'auto_routing',
			required_cause: null }
	}));
	assert.doesNotMatch(sub, /provider/i, sub);
});

test('the exposure sentence is for steered routing only', () => {
	// Status cannot currently produce "requirement unmet" together with
	// auto_routing — require_ipv6_active() rules it out, so the band test
	// above returns early on the reason and never reaches this guard. It is
	// asserted at the method boundary instead, because the sentence names
	// STEERED traffic: said about a routed-everything instance it would be
	// simply untrue, and that must not depend on a distant precondition
	// staying the way it is today.
	const ctx = makeCtx(spec, {});
	const unmet = ctx.ipv6Unmet(refusedStatus({
		routing: { mode: 'auto', killswitch: false }
	}));
	assert.equal(unmet.exposed, false,
		'an instance with no steered networks is reported as exposing them');
	assert.equal(unmet.exposure, null, 'and is given the warning anyway');
});

// ── the worth-fixing finding: one reason, three situations ───────────────

test('no eligible gateway says the locations have none', () => {
	const sub = band(refusedStatus({ ipv6: { required_cause: 'no_gateway' } }));
	assert.match(sub, /IPv6 required/, sub);
	assert.match(sub, /support|forward/i, sub);
});

test('unreachable gateways are not blamed on the locations', () => {
	const sub = band(refusedStatus({ ipv6: { required_cause: 'unreachable' } }));
	// The gateways here DO forward IPv6; they were merely unreachable, and
	// retrying may simply work. Telling the user to widen the locations or
	// drop the requirement would have them undo a setting that was not the
	// problem — wrong advice is worse than none.
	assert.match(sub, /could not be reached|unreachable/i,
		'an unreachable-gateway refusal is worded as if none existed: ' + sub);
	assert.doesNotMatch(sub, /none of|no gateway/i,
		'it still claims the locations have no IPv6 gateway: ' + sub);
});

test('a pinned server without IPv6 is named as the pin', () => {
	const sub = band(refusedStatus({ ipv6: { required_cause: 'pinned' } }));
	assert.match(sub, /pinned/i,
		'a pinned non-IPv6 server is reported as a location problem: ' + sub);
	assert.doesNotMatch(sub, /none of|no gateway/i, sub);
});

test('an unknown cause still says the requirement is why', () => {
	// A router that has never connected has no cause stamped; the band must
	// still explain itself rather than fall silent.
	const sub = band(refusedStatus({ ipv6: { required_cause: null } }));
	assert.match(sub, /IPv6 required/, sub);
});

// ── the routing note, for the Save-time reader ───────────────────────────
// refreshStatus() repaints the band but does not recompute this note, so the
// band above is the surface that matters for background updates. The note is
// still what someone sees while editing, so it must not contradict it.

function noteFor(status) {
	const el = () => {
		const n = El('div', {});
		n.textContent = '';
		n.classList = { toggle: () => {}, add: () => {}, remove: () => {} };
		return n;
	};
	const ctx = makeCtx(spec, {
		status,
		autoRouting: { checked: status.routing.mode === 'auto' },
		ksBox: { checked: !!status.routing.killswitch },
		v6Sel: { value: status.ipv6.mode,
			querySelector: () => ({ disabled: false }) },
		v6Note: el(), v6Warn: el(), v6Only: { checked: true, disabled: false },
		v6OnlyNote: el(),
		v6Row: { classList: { toggle: () => {} } },
		v6OnlyRow: { classList: { toggle: () => {} } },
		ksRow: { classList: { toggle: () => {} } },
		steerRow: { classList: { toggle: () => {} } },
		steerBoxes: { guest: { checked: true } },
		hopValue: 'standard',
		_serverChosen: '',
		srvRenderTrigger: () => {}, srvRenderPanel: () => {}
	});
	ctx.onRoutingToggle(true);
	return ctx.v6Note.textContent || '';
}

test('the routing note distinguishes unreachable from unsupported', () => {
	const none = noteFor(refusedStatus({ ipv6: { required_cause: 'no_gateway' } }));
	assert.match(none, /IPv6/, none);
	const unreach = noteFor(refusedStatus({ ipv6: { required_cause: 'unreachable' } }));
	assert.doesNotMatch(unreach, /widen/i,
		'the note tells the user to widen locations that were not the problem: ' + unreach);
	assert.match(unreach, /could not be reached|unreachable|again/i, unreach);
});

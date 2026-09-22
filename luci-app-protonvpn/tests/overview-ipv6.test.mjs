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
import { loadView, makeCtx, findClass, findAllClass, findOneClass, text, El } from './luci-harness.mjs';

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

// What the card says in prose. The IPv6 findings are sentences rather than
// facts — acting on them depends on the wording — so when the card was
// rebuilt around labelled facts they kept their own note lines instead of
// being folded into the middot run-on that used to carry everything.
function band(status) {
	const ctx = makeCtx(spec, { status });
	ctx.updateStatusBand();
	return findAllClass(ctx.stateEl, 'pv-state-note').map(text).join(' · ');
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
	// "IPv6 is working" is a fact, not a finding: it became a labelled pair
	// when the card stopped joining everything with middots. The exposure
	// sentences stay in the notes, and there must be none of them here.
	const status = refusedStatus({
		state: 'connected', gateway: 'NL#1', latest_handshake_seconds: 3,
		ipv6: { active: true, gateway_ipv6: true, reason: null, required_cause: null }
	});
	const ctx = makeCtx(spec, { status });
	ctx.updateStatusBand();
	const ipv6Fact = findAllClass(ctx.stateEl, 'pv-fact')
		.filter((f) => text(f.children[0]) === 'IPv6').map((f) => text(f.children[1]));
	assert.deepEqual(ipv6Fact, [ 'through the tunnel' ]);
	const sub = findAllClass(ctx.stateEl, 'pv-state-note').map(text).join(' · ');
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
		refs: { routing_table: { value: 'main' } },
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

// ── inert 'auto': the page must say why, and the save must agree ─────────
// The backend (protonvpn.common require_ipv6_active) treats 'auto' as inert
// when auto_routing is on, when no source network is steered, or when there
// is no routing table to steer into. The forum report behind these tests:
// IPv6 set to Automatic, IPv6 never arrives, and nothing on the page says
// why. Each condition has a different fix, so the wording has to name the
// one that applies, and what is stored must match what the control shows.

// A context standing in the traffic-routing panel mid-edit: the widgets
// onRoutingToggle reads, with a stable auto option record so its disabled
// flag can be asserted afterwards.
function routingCtx(over) {
	const autoOpt = { disabled: false };
	const state = Object.assign({
		status: {},
		autoRouting: { checked: false },
		ksBox: { checked: false },
		v6Sel: { value: 'auto',
			querySelector: (sel) => (sel === 'option[value="auto"]' ? autoOpt : null) },
		v6Note: El('div', { class: 'hidden' }),
		v6Warn: El('div', { class: 'hidden' }),
		v6Only: { checked: false, disabled: false },
		v6OnlyNote: El('div', { class: 'hidden' }),
		v6Row: El('div', {}),
		v6OnlyRow: El('div', {}),
		ksRow: El('div', {}),
		steerRow: El('div', {}),
		steerBoxes: { guest: { checked: true } },
		refs: { routing_table: { value: 'protonvpn' } },
		hopValue: 'standard',
		_serverChosen: '',
		srvRenderTrigger: () => {}, srvRenderPanel: () => {}
	}, over);
	const ctx = makeCtx(spec, state);
	ctx.autoOpt = autoOpt;
	return ctx;
}

// A context far enough through collectIntoUci to store the routing block.
function saveCtx(spec2, over) {
	return makeCtx(spec2, Object.assign({
		refs: {},
		autoRouting: { checked: false },
		ksBox: { checked: false },
		v6Sel: { value: 'auto' },
		v6Only: { checked: false },
		dnsSel: { value: 'off' },
		steerBoxes: { guest: { checked: true } },
		hopValue: 'standard',
		poolEntries: [],
		_serverChosen: ''
	}, over));
}

test('a save with no steered network stores the block the control was forced to show', () => {
	const { spec: spec2, uciData } = loadView();
	const ctx = saveCtx(spec2, { steerBoxes: { guest: { checked: false } } });
	ctx.collectIntoUci();
	assert.equal(uciData.protonvpn.main.ipv6_mode, 'block',
		"'auto' with nothing steered is inert in the backend, so storing it silently would leave the page claiming Automatic");
});

test('unticking the last steered network forces the control to Block and says why', () => {
	const ctx = routingCtx({ steerBoxes: { guest: { checked: false } } });
	ctx.onRoutingToggle();
	assert.equal(ctx.v6Sel.value, 'block',
		'the control still offers the Automatic the save would have to rewrite');
	assert.equal(ctx.autoOpt.disabled, true,
		'Automatic stays selectable where it cannot apply');
	const warn = (ctx._notices || []).find((n) => n.kind === 'warning');
	assert.ok(warn, 'the rewrite of the user\'s mode happens with no word about it');
	assert.match(warn.text, /steered network/i,
		'the warning does not name the condition: ' + warn.text);
});

test('a missing routing table is named as the reason, and the mode is not rewritten', () => {
	const ctx = routingCtx({ refs: { routing_table: { value: '' } } });
	ctx.onRoutingToggle(true);
	const note = ctx.v6Note.textContent || '';
	assert.match(note, /routing table/i,
		'the note never says which condition defeats Automatic: ' + note);
	assert.match(note, /Advanced/i,
		'the fix differs per condition, so the note must point at it: ' + note);
	assert.ok(!ctx.v6Note.classList.contains('hidden'),
		'the note is rendered but kept hidden');
	assert.equal(ctx.v6Sel.value, 'auto',
		'the save fills the table from the interface name, so the mode must survive');
	assert.equal(ctx.autoOpt.disabled, false,
		'Automatic is disabled over a condition the save itself cures');
});

test('with steering in place Automatic stays offered, shown and saved', () => {
	const ctx = routingCtx();
	ctx.onRoutingToggle(true);
	assert.equal(ctx.v6Sel.value, 'auto',
		'the force-to-Block reached a mode the backend would honour');
	assert.equal(ctx.autoOpt.disabled, false,
		'Automatic is disabled although steering would carry it');
	const { spec: spec2, uciData } = loadView();
	saveCtx(spec2).collectIntoUci();
	assert.equal(uciData.protonvpn.main.ipv6_mode, 'auto',
		'the save rewrote a mode the backend would honour');
});

test('auto_routing still stores the block an Automatic selection behaves as', () => {
	const { spec: spec2, uciData } = loadView();
	saveCtx(spec2, { autoRouting: { checked: true } }).collectIntoUci();
	assert.equal(uciData.protonvpn.main.ipv6_mode, 'block',
		'the existing auto_routing rewrite regressed while widening it');
});

test('the IPv6 description says what the default is and why', () => {
	const { spec: spec2 } = loadView();
	const ctx = makeCtx(spec2, {
		status: { routing: { mode: 'steered', networks: [ 'guest' ] } },
		srvRenderTrigger: () => {}, srvRenderPanel: () => {}
	});
	const node = ctx.buildRoutingSection();
	const v6row = findAllClass(node, 'cbi-value').find((r) => {
		const title = findOneClass(r, 'cbi-value-title');
		return title && text(title) === 'IPv6';
	});
	assert.ok(v6row, 'the routing section renders no IPv6 row');
	// The row holds note/warn divs in the same class; the description is the
	// one that actually says something.
	const desc = findAllClass(v6row, 'cbi-value-description')
		.map(text).filter(Boolean).join(' ');
	assert.match(desc, /default/i,
		'the description never says Block is the shipped default: ' + desc);
	assert.match(desc, /block/i,
		'the description never names the default mode: ' + desc);
});

// A saved 'auto' with auto_routing off and no source_network is a supported
// legacy configuration (the former collector rewrote only auto_routing).
// Building the page normalizes the selector to Block and hides the IPv6
// row, so unless initialization itself says something, the later save
// writes Block without a word — the exact silent downgrade this feature
// exists to remove.
test('normalizing a saved Automatic during initialization is announced, and the save agrees', () => {
	const { spec: spec2, uciData } = loadView({ uci: { protonvpn: { main: {
		ipv6_mode: 'auto', auto_routing: '0' } } } });
	const ctx = makeCtx(spec2, {
		status: { routing: { mode: 'steered', networks: [ 'guest' ] } },
		refs: {},
		srvRenderTrigger: () => {}, srvRenderPanel: () => {}
	});
	ctx.buildRoutingSection();
	assert.equal(ctx.v6Sel.value, 'block',
		'the selector is not normalized to what the save will store');
	assert.ok(ctx.v6Row.classList.contains('hidden'),
		'the IPv6 row should stay hidden while nothing is steered');
	const warn = (ctx._notices || []).find((n) => n.kind === 'warning');
	assert.ok(warn,
		'the saved Automatic is silently downgraded on page load — no note (row hidden), no notice');
	assert.match(warn.text, /steered network/i,
		'the notice does not name the condition: ' + warn.text);
	ctx.collectIntoUci();
	assert.equal(uciData.protonvpn.main.ipv6_mode, 'block',
		'the save stores something other than what the control was showing');
});

test('routed-everything mode disables Automatic, and the save stores Block', () => {
	const ctx = routingCtx({ autoRouting: { checked: true } });
	ctx.onRoutingToggle(true);
	assert.equal(ctx.autoOpt.disabled, true,
		'Automatic stays selectable while all LAN traffic goes through the VPN');
	assert.equal(ctx.v6Sel.value, 'block',
		'the control still shows the Automatic the collector rewrites');
	const note = ctx.v6Note.textContent || '';
	assert.match(note, /LAN traffic/i,
		'the note does not name the auto_routing condition: ' + note);
	assert.ok(!ctx.v6Note.classList.contains('hidden'),
		'the note is rendered but kept hidden');
	const { spec: spec2, uciData } = loadView();
	saveCtx(spec2, { autoRouting: { checked: true } }).collectIntoUci();
	assert.equal(uciData.protonvpn.main.ipv6_mode, 'block',
		'the save stores something other than what the control was showing');
});

test('saving steering with an empty table fills it from the interface, field included', () => {
	const { spec: spec2, uciData } = loadView();
	const tableField = { value: '' };
	saveCtx(spec2, {
		refs: { routing_table: tableField, interface: { value: 'pv_guest' } }
	}).collectIntoUci();
	assert.equal(uciData.protonvpn.main.routing_table, 'pv_guest',
		'Automatic is saved while the routing table it needs is absent');
	assert.equal(tableField.value, 'pv_guest',
		'the Advanced field keeps showing an empty table the save replaced');
	assert.equal(uciData.protonvpn.main.ipv6_mode, 'auto',
		'Automatic must survive: with the table filled, the backend honours it');
	assert.deepEqual(uciData.protonvpn.main.source_network, [ 'guest' ],
		'the steered network the table was filled for is not stored');
});

// ── the clients are not on the new address the instant the rules exist ─────
//
// The reported defect: "IPv6 does not work through the VPN after enabling
// lan". It did work; it took up to ten minutes to start, because a client
// that missed the router advertisement carrying the switch kept its ISP
// address until the next one. The page said IPv6 was active throughout, which
// is what sent the investigation everywhere except at the actual cause.
//
// The backend now forces an advertisement on both claim and release and
// reports, for a few minutes afterwards, that the clients are still moving.

test('the card says the clients are moving while they still are', () => {
	const ctx = makeCtx(spec, { status: refusedStatus({
		state: 'connected', gateway: 'NL#1', latest_handshake_seconds: 3,
		ipv6: { active: true, gateway_ipv6: true, reason: null,
			required_cause: null, clients_settling: true }
	}) });
	ctx.updateStatusBand();
	const notes = findAllClass(ctx.stateEl, 'pv-state-note').map(text).join(' ');
	assert.match(notes, /moving to the tunnel address/i, notes);
});

test('and stops saying it once they have', () => {
	// It is a statement about the last few minutes, not a standing one: the
	// card it sits on was cut from 748px of permanent explanation to 248.
	const ctx = makeCtx(spec, { status: refusedStatus({
		state: 'connected', gateway: 'NL#1', latest_handshake_seconds: 3,
		ipv6: { active: true, gateway_ipv6: true, reason: null,
			required_cause: null, clients_settling: false }
	}) });
	ctx.updateStatusBand();
	const notes = findAllClass(ctx.stateEl, 'pv-state-note').map(text).join(' ');
	assert.doesNotMatch(notes, /moving to the tunnel address/i, notes);
});

test('it is never said while IPv6 is not on the tunnel', () => {
	// The backend already refuses to set it in that case; the page must not
	// reintroduce it by reading the flag on its own.
	const ctx = makeCtx(spec, { status: refusedStatus({
		ipv6: { active: false, clients_settling: true }
	}) });
	ctx.updateStatusBand();
	const notes = findAllClass(ctx.stateEl, 'pv-state-note').map(text).join(' ');
	assert.doesNotMatch(notes, /moving to the tunnel address/i, notes);
});

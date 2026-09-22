// SPDX-License-Identifier: MIT
// Three things a visual redesign breaks quietly, and one of them this page
// carried in from before the redesign.
//
//  1. Rows that act must be operable from the keyboard. Every row in this
//     page — the picked locations, the country and city rows in the picker,
//     the expander, the remove row, the server rows — was a <div> or a <span>
//     with a click handler. Tab does not reach one, Enter does not fire one,
//     and nothing draws a focus ring around one. A row that selects, expands
//     or removes is a button, so it is built as a button.
//
//  2. A saved location the server list no longer knows used to vanish from
//     the page. It stayed in poolEntries and collectIntoUci wrote it back on
//     every save, so the set could not be edited to something valid from the
//     page at all — the only way out was uci. It is shown, marked, and
//     removable.
//
//  3. The five-second status poll rebuilds both cards with dom.content(),
//     which destroys whatever was focused inside them. Values and the open
//     action menu already survive that repaint; focus has to as well, or the
//     page is unusable without a mouse.
//
// Run: node --test luci-app-protonvpn/tests/*.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadView, makeCtx, text, findClass, findOneClass, findAllClass,
	fakeDocument, resetFocus, El } from './luci-harness.mjs';

const { spec, src } = loadView();
const EV = { preventDefault: () => {}, stopPropagation: () => {} };
const DAY = 24 * 60 * 60 * 1000;
const inDays = (n) => Math.floor((Date.now() + n * DAY) / 1000);

// Two countries with cities, marked available: "available" is what lets the
// page tell a code the cache never heard of from one it is simply not
// offering in this hop mode.
function locations() {
	return { available: true, countries: [
		{ code: 'DE', standard_count: 4, cities: [
			{ code: 'DE-FRA', name: 'Frankfurt', standard_count: 2 },
			{ code: 'DE-BER', name: 'Berlin', standard_count: 2 } ] },
		{ code: 'NL', standard_count: 3, cities: [
			{ code: 'NL-AMS', name: 'Amsterdam', standard_count: 3 } ] },
		// Secure Core only: offered in one hop mode and not in another, which
		// is a different thing from not existing.
		{ code: 'SE', standard_count: 0, secure_core_count: 5, cities: [] }
	] };
}

function pickerCtx(state) {
	const ctx = makeCtx(spec, Object.assign({
		locations: locations(),
		poolChips: El('div', { class: 'pv-pool' }),
		poolCount: El('span', { class: 'pv-pool-count' }),
		poolNote: El('div', { class: 'cbi-value-description' }),
		poolTrigger: El('button', { class: 'cbi-button pv-pool-trigger' }),
		poolPanel: El('div', { class: 'pv-pool-panel pv-pool-acc hidden' })
	}, state));
	ctx.rebuildPoolWidget();
	return ctx;
}

const has = (n, cls) => String((n && n.attrs && n.attrs.class) || '')
	.split(/\s+/).includes(cls);
const rowFor = (el, label) => findAllClass(el, 'pv-acc-row')
	.find((r) => text(r).includes(label));
const cell = (row, cls) => findOneClass(row, cls);

// A control is keyboard-operable when the browser gives it keyboard
// behaviour for free — that is what being a <button> means. Anything else
// has to prove it carries the role, a tab stop AND key handling; a
// role/tabindex pair without Enter and Space is still not a button.
function assertOperable(node, what) {
	assert.ok(node, what + ' is missing');
	if (node.tag === 'button') {
		assert.equal(node.attrs.type, 'button',
			what + ' must be type=button so it never submits the LuCI form');
		return;
	}
	assert.equal(node.attrs.role, 'button', what + ' is not a button and has no role');
	assert.ok(node.attrs.tabindex === 0 || node.attrs.tabindex === '0',
		what + ' has no tab stop');
	assert.equal(typeof node.attrs.keydown, 'function',
		what + ' has a role but no Enter/Space handling');
}

// ── 1. keyboard operability ────────────────────────────────────────────────

test('the country row hit target is a real button', () => {
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	assertOperable(cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-hit'), 'the country row');
});

test('the expander is a real button and says whether it is open', () => {
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	const exp = cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-exp');
	assertOperable(exp, 'the expander');
	assert.equal(exp.attrs['aria-expanded'], 'false');
	exp.attrs.click(EV);
	assert.equal(cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs['aria-expanded'],
		'true', 'the expander must report the state it just entered');
});

test('the city row hit target is a real button, and its spacer stays inert', () => {
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	const fra = rowFor(ctx._poolListEl, 'Frankfurt');
	assertOperable(cell(fra, 'pv-acc-hit'), 'the city row');
	const spacer = cell(fra, 'pv-acc-exp');
	assert.equal(spacer.tag, 'span', 'the city spacer must not become a tab stop');
	assert.ok(!spacer.attrs.click);
});

test('a row that toggles says whether it is on', () => {
	// aria-pressed, not a class: the ☑ in the box cell is the sighted cue and
	// a screen reader never sees it.
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	const hit = () => cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-hit');
	assert.equal(hit().attrs['aria-pressed'], 'false');
	hit().attrs.click(EV);
	assert.equal(hit().attrs['aria-pressed'], 'true');
});

test('the edit-mode remove row is a real button', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	ctx.poolOpenCountry('NL', true);
	const rm = findAllClass(ctx._poolListEl, 'pv-acc-row')
		.find((r) => has(r, 'pv-pool-remove'));
	assertOperable(cell(rm, 'pv-acc-hit'), 'the remove row');
});

test('a picked location is reachable and removable from the keyboard', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	const row = findAllClass(ctx.poolChips, 'pv-selrow')[0];
	assertOperable(findOneClass(row, 'pv-selname'), 'the picked-location name');
	assertOperable(findOneClass(row, 'pv-selx'), 'the remove control');
});

test('activating the picked-location name opens its editor', () => {
	// The row keeps its click for the mouse, so the whole row stays a hit
	// target; the button is what a keyboard reaches, and the two must not
	// both fire.
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	const row = findAllClass(ctx.poolChips, 'pv-selrow')[0];
	let bubbled = 0;
	findOneClass(row, 'pv-selname').attrs.click(
		{ preventDefault() {}, stopPropagation() { bubbled++; } });
	assert.equal(ctx._poolCountry, 'NL');
	assert.ok(ctx._poolEdit);
	assert.equal(bubbled, 1, 'the name must stop the row handler from firing too');
});

test('every server row that picks a server is a real button', () => {
	const ctx = makeCtx(spec, {
		srvPanel: El('div', { class: 'pv-pool-panel' }),
		_serverData: { relays: [
			{ hostname: 'nl-1.example', name: 'NL#1', country_code: 'NL',
			  city: 'Amsterdam', load: 12, features: 16 } ] },
		_serverChosen: '', poolEntries: []
	});
	ctx.srvRenderPanel();
	const rows = findAllClass(ctx._srvListEl, 'pv-pool-row')
		.filter((r) => typeof r.attrs.click === 'function');
	assert.ok(rows.length >= 2, 'the quick rows and the server row all pick');
	rows.forEach((r, i) => assertOperable(r, 'server picker row ' + i));
});

test('the panel filter and its close control are already real controls', () => {
	// Pinned rather than changed: these two were right, and a later rework
	// must not quietly turn them into divs like everything around them was.
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	const filt = findOneClass(ctx.poolPanel, 'pv-pool-filter');
	assert.equal(filt.tag, 'input');
	assert.equal(findOneClass(ctx.poolPanel, 'pv-pool-x').tag, 'button');
	const box = findOneClass(ctx.poolPanel, 'pv-pool-v6only');
	assert.ok(findAllClass(box, '').length >= 0);
});

test('the focus ring is drawn, and only ever withdrawn for the mouse', () => {
	assert.ok(/:focus\{[^}]*outline:2px solid/.test(src),
		'a focused row must be visibly focused');
	// Withdrawing the ring for POINTER focus is correct and is why
	// :focus-visible exists. Withdrawing it for keyboard focus is the defect,
	// so every outline suppression has to be guarded by :not(:focus-visible).
	for (const rule of src.split('}')) {
		if (!/outline:\s*(none|0)\b/.test(rule))
			continue;
		assert.match(rule, /:focus:not\(:focus-visible\)/,
			'this rule hides the focus ring unconditionally: ' + rule);
	}
});

test('a row button still looks like the row it replaced', () => {
	// The theme styles bare buttons heavily — border, background, its own
	// font. Turning a row into a button without resetting all of that would
	// fix the keyboard by wrecking the design.
	const reset = /\.pv-rowbtn\{([^}]*)\}/.exec(src);
	assert.ok(reset, 'the row buttons need their theme styling reset back to a row');
	for (const decl of [ 'border:0', 'background:transparent', 'font:inherit',
		'color:inherit', 'text-align:left' ])
		assert.ok(reset[1].includes(decl), 'the reset is missing ' + decl);
	// A <button> also brings the UA's own horizontal padding with it. Left
	// alone it indents the name away from the flag and the detail beside it,
	// and the columns lining up is the whole reason this list replaced chips.
	assert.ok(/button\.pv-selname\{[^}]*padding:0\}/.test(src),
		'the name button must not indent itself out of its column');
});

// ── 2. a location the server list no longer knows ──────────────────────────

test('a saved code the server list does not know is still shown', () => {
	const ctx = pickerCtx({ poolEntries: [
		{ code: 'NL', kind: 'country' }, { code: 'ZZ', kind: 'country' } ] });
	const names = findAllClass(ctx.poolChips, 'pv-selrow')
		.map((r) => text(findOneClass(r, 'pv-selname')));
	assert.equal(names.length, 2,
		'the unknown entry vanished, so it can only be removed through uci');
	assert.ok(names.some((n) => n.includes('ZZ')), 'the unknown code must name itself');
});

test('an unknown location is marked as one, and keeps the old dashed meaning', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'ZZ', kind: 'country' } ] });
	const row = findAllClass(ctx.poolChips, 'pv-selrow')[0];
	assert.ok(has(row, 'pv-sel-stale'),
		'the chip this list replaced was dashed for exactly this case');
	assert.match(text(findOneClass(row, 'pv-seldetail')), /not in the server list/i,
		'the row has to say why it is different');
	assert.ok(/\.pv-selrow\.pv-sel-stale\{[^}]*dashed/.test(src),
		'the dashed style must actually reach the row');
});

test('an unknown location can be removed from the page', () => {
	const ctx = pickerCtx({ poolEntries: [
		{ code: 'NL', kind: 'country' }, { code: 'ZZ', kind: 'country' } ] });
	const row = findAllClass(ctx.poolChips, 'pv-selrow')
		.find((r) => text(findOneClass(r, 'pv-selname')).includes('ZZ'));
	findOneClass(row, 'pv-selx').attrs.click(EV);
	assert.deepEqual(ctx.poolEntries.map((e) => e.code), [ 'NL' ],
		'removing the unknown entry must leave the valid one alone');
});

test('an unknown city code is removable through its country row too', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'QQ-XYZ', kind: 'city' } ] });
	const row = findAllClass(ctx.poolChips, 'pv-selrow')[0];
	assert.ok(has(row, 'pv-sel-stale'));
	findOneClass(row, 'pv-selx').attrs.click(EV);
	assert.deepEqual(ctx.poolEntries.map((e) => e.code), []);
});

test('an unknown location is not counted as part of the set', () => {
	// The summary counts what the connection can actually pick from. An entry
	// that resolves to nothing offers nothing, and counting it would promise
	// servers that are not there.
	const ctx = pickerCtx({ poolEntries: [
		{ code: 'NL', kind: 'country' }, { code: 'ZZ', kind: 'country' } ] });
	assert.match(text(ctx.poolCount), /1 countries|1 country/,
		'got: ' + text(ctx.poolCount));
});

test('a location merely not offered in this hop mode is still hidden, not condemned', () => {
	// SE exists, with Secure Core gateways only. In Standard it is not on
	// offer — that is a mode filter, not a dead entry, and it must not be
	// shown as unknown or the round trip back to Secure Core reads as a lie.
	const ctx = pickerCtx({ hopValue: 'standard',
		poolEntries: [ { code: 'NL', kind: 'country' }, { code: 'SE', kind: 'country' } ] });
	const rows = findAllClass(ctx.poolChips, 'pv-selrow');
	assert.equal(rows.length, 1, 'SE must not appear at all in Standard');
	assert.deepEqual(ctx.poolEntries.map((e) => e.code), [ 'NL', 'SE' ],
		'and it must not be dropped from the set either');
});

test('nothing is condemned while the server list has not loaded', () => {
	// Every code looks unknown against an empty cache. Marking the whole set
	// dead on a slow page load would be the worst possible moment to do it.
	const ctx = pickerCtx({ locations: { available: false, countries: [] },
		poolEntries: [ { code: 'NL', kind: 'country' } ] });
	assert.equal(findAllClass(ctx.poolChips, 'pv-sel-stale').length, 0);
});

// ── 3. focus across the five-second repaint ────────────────────────────────

const CONNECTED = {
	state: 'connected', configured: true, enabled: true, gateway: 'UK#264',
	latest_handshake_seconds: 62, ipv6: { mode: 'auto', active: true },
	rotation: { enabled: true }, certificate: { present: true, days_left: 311 }
};

function stateCard(status) {
	const ctx = makeCtx(spec, { status });
	ctx.stateEl = El('div', { class: 'pv-state' });
	ctx.updateStatusBand();
	return ctx;
}

function accountCard() {
	const ctx = makeCtx(spec, {
		session: { state: 'active', session_expires_at: inDays(26) }, refs: {} });
	ctx.bandEl = El('div', { class: 'pv-acct' });
	ctx.renderBand();
	return ctx;
}

test('focus inside the state card survives the poll repaint', () => {
	resetFocus();
	const ctx = stateCard(CONNECTED);
	const before = findOneClass(ctx.stateEl, 'pv-kebab');
	before.focus();
	assert.equal(fakeDocument.activeElement, before);
	ctx.updateStatusBand();
	const after = findOneClass(ctx.stateEl, 'pv-kebab');
	assert.notEqual(after, before, 'the repaint really does rebuild the control');
	assert.equal(fakeDocument.activeElement, after,
		'focus was dropped to the document — every five seconds');
});

test('the repaint restores the same control, not merely something', () => {
	resetFocus();
	const ctx = stateCard(CONNECTED);
	const sec = findOneClass(ctx.stateEl, 'pv-sec');
	const rotate = findAllClass(sec, 'cbi-button')
		.find((b) => text(b).includes('Rotate'));
	rotate.focus();
	ctx.updateStatusBand();
	const back = fakeDocument.activeElement;
	assert.ok(back && text(back).includes('Rotate'),
		'focus landed on ' + JSON.stringify(back && text(back)));
});

test('focus inside the account card survives its repaint', () => {
	resetFocus();
	const ctx = accountCard();
	findOneClass(ctx.bandEl, 'pv-kebab').focus();
	ctx.renderBand();
	assert.equal(fakeDocument.activeElement, findOneClass(ctx.bandEl, 'pv-kebab'));
});

test('focus on the client-version select survives the repaint', () => {
	// The control itself is kept across repaints, but dom.content() takes it
	// out of the card and puts it back, and a browser blurs what it removes.
	resetFocus();
	const ctx = accountCard();
	ctx.appVerSel.focus();
	ctx.renderBand();
	assert.equal(fakeDocument.activeElement, ctx.appVerSel);
});

test('a repaint does not steal focus from outside the card', () => {
	resetFocus();
	const ctx = stateCard(CONNECTED);
	const elsewhere = El('input', { type: 'text' });
	elsewhere.focus();
	ctx.updateStatusBand();
	assert.equal(fakeDocument.activeElement, elsewhere,
		'the card grabbed focus that was not its to take');
});

test('picking a country in the picker keeps focus on the row that was pressed', () => {
	// Activating a row re-renders the whole list. Without this the first
	// Enter throws focus to the document and the keyboard user cannot pick a
	// second country without reaching for the mouse.
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	const hit = cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-hit');
	hit.focus();
	hit.attrs.click(EV);
	const back = fakeDocument.activeElement;
	assert.ok(back && has(back, 'pv-acc-hit') && text(back).includes('DE'),
		'focus landed on ' + JSON.stringify(back && text(back)));
});

test('removing the last picked location leaves focus somewhere usable', () => {
	// The row the user activated is gone by definition, so the key cannot be
	// restored. Landing on the control that adds a new one is the answer;
	// landing on <body> is not.
	resetFocus();
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	const x = findOneClass(findAllClass(ctx.poolChips, 'pv-selrow')[0], 'pv-selx');
	x.focus();
	x.attrs.click(EV);
	assert.equal(fakeDocument.activeElement, ctx.poolTrigger);
});

// ── 4. the panel flows keep the keyboard ───────────────────────────────────
//
// The card repaint was only one of the paths that rebuilds something a user
// can be standing in. Closing a panel HIDES it, and a browser blurs what it
// hides, so focus falls to <body> — at the top of the document, nowhere near
// the control that was just used. The panel's own trigger is the place to
// come back to, and it is the element being un-hidden at that very moment.

function srvCtx(state) {
	const ctx = makeCtx(spec, Object.assign({
		srvPanel: El('div', { class: 'pv-pool-panel hidden' }),
		srvTrigger: El('button', { class: 'cbi-button pv-srv-trigger' }),
		_serverChosen: '', poolEntries: [], _srvOpen: false,
		_serverData: { relays: [
			{ hostname: 'nl-1.example', name: 'NL#1', country_code: 'NL',
			  city: 'Amsterdam', load: 12, features: 16 },
			{ hostname: 'nl-2.example', name: 'NL#2', country_code: 'NL',
			  city: 'Rotterdam', load: 44, features: 16 } ] }
	}, state));
	// Nothing in these tests exercises rotation gating or the dirty flag.
	ctx.updateRotationAvailability = () => {};
	return ctx;
}

const srvRows = (ctx) => findAllClass(ctx._srvListEl, 'pv-pool-row')
	.filter((r) => typeof r.attrs.click === 'function');
// The two quick-pick rows at the top are always offered; the filter narrows
// the server rows under them.
const srvServerRows = (ctx) => srvRows(ctx).filter((r) => !has(r, 'pv-srv-quick'));

test('closing the location panel puts focus back on the control that opened it', () => {
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolTrigger.focus();
	ctx.poolOpenPanel();
	const close = findOneClass(ctx.poolPanel, 'pv-pool-x');
	close.focus();
	close.attrs.click(EV);
	assert.equal(fakeDocument.activeElement, ctx.poolTrigger,
		'focus was left on a hidden panel, which means it was lost');
});

test('closing the server panel puts focus back on its trigger', () => {
	resetFocus();
	const ctx = srvCtx();
	ctx.srvTrigger.focus();
	ctx.srvOpenPanel();
	const close = findOneClass(ctx.srvPanel, 'pv-pool-x');
	close.focus();
	close.attrs.click(EV);
	assert.equal(fakeDocument.activeElement, ctx.srvTrigger);
});

test('picking a server with the keyboard lands back on the trigger', () => {
	// srvSetChosen() closes the panel, so the row that was just activated
	// stops existing. The trigger now shows the pick, which is both the
	// nearest thing and the way to change it again.
	resetFocus();
	const ctx = srvCtx();
	ctx.srvTrigger.focus();
	ctx.srvOpenPanel();
	const row = srvRows(ctx).find((r) => text(r).includes('NL#2'));
	row.focus();
	row.attrs.click(EV);
	assert.equal(ctx._serverChosen, 'NL#2');
	assert.equal(fakeDocument.activeElement, ctx.srvTrigger,
		'focus ended up on a hidden panel row');
});

test('clearing a pinned server from the trigger keeps focus on the trigger', () => {
	// The × lives inside the trigger and rebuilds it away on activation, so
	// the control the user pressed is gone by the time the click returns.
	resetFocus();
	const ctx = srvCtx({ _serverChosen: 'NL#1' });
	ctx.srvRenderTrigger();
	const clear = findOneClass(ctx.srvTrigger, 'pv-srv-x');
	clear.focus();
	clear.attrs.click(EV);
	assert.equal(ctx._serverChosen, '');
	assert.equal(fakeDocument.activeElement, ctx.srvTrigger);
});

test('a panel repaint keeps focus on its close button', () => {
	// refreshServerList() repaints an open panel whenever its answer lands,
	// which can be while the user is sitting on the ✕ about to press it.
	resetFocus();
	const ctx = srvCtx();
	ctx.srvTrigger.focus();
	ctx.srvOpenPanel();
	findOneClass(ctx.srvPanel, 'pv-pool-x').focus();
	ctx.srvRenderPanel();
	assert.equal(fakeDocument.activeElement.attrs['data-pv-focus'],
		'srv-panel-close', 'the ✕ lost focus to the repaint');
});

test('the location panel keeps focus on its close button too', () => {
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolTrigger.focus();
	ctx.poolOpenPanel();
	findOneClass(ctx.poolPanel, 'pv-pool-x').focus();
	ctx.poolRenderPanel();
	assert.equal(fakeDocument.activeElement.attrs['data-pv-focus'], 'panel-close');
});

test('a panel closing does not yank focus from somewhere else on the page', () => {
	// The document-level outside-click handler closes panels. Whatever the
	// user just clicked or tabbed to keeps focus; the panel is not entitled
	// to it merely because it is going away.
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	const elsewhere = El('input', { type: 'text' });
	elsewhere.focus();
	ctx.poolClosePanel();
	assert.equal(fakeDocument.activeElement, elsewhere);
});

// Both panels focus their filter on a deferred tick, because the click that
// opened them is still settling. The tests wait for that tick rather than
// pretending the call is synchronous.
const tick = () => new Promise((r) => setTimeout(r, 0));

test('opening the server panel puts focus in its filter', async () => {
	resetFocus();
	const ctx = srvCtx();
	ctx.srvTrigger.focus();
	ctx.srvOpenPanel();
	await tick();
	assert.equal(fakeDocument.activeElement,
		findOneClass(ctx.srvPanel, 'pv-pool-filter'),
		'a panel opened from the keyboard has to put the keyboard somewhere');
});

test('opening the location panel puts focus in its filter', async () => {
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolTrigger.focus();
	ctx.poolOpenPanel();
	await tick();
	assert.equal(fakeDocument.activeElement,
		findOneClass(ctx.poolPanel, 'pv-pool-filter'));
});

test('a repaint of an open panel does not pull focus back to the filter', async () => {
	// The deferred focus is for an OPEN. A repaint under the user's hands —
	// a country picked, the hop mode changed, a server list arriving — must
	// leave them where they are, even one tick later.
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolTrigger.focus();
	ctx.poolOpenPanel();
	await tick();
	const hit = cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-hit');
	hit.focus();
	ctx.poolRenderPanel();
	await tick();
	assert.equal(fakeDocument.activeElement.attrs['data-pv-focus'], 'cc:DE',
		'the open-time filter focus fired on a repaint');
});

test('rebuilding the server panel under the user keeps their place', async () => {
	// refreshServerList() re-renders an open panel when its answer arrives,
	// which is asynchronous and lands whenever it lands.
	resetFocus();
	const ctx = srvCtx();
	ctx.srvTrigger.focus();
	ctx.srvOpenPanel();
	await tick();
	const row = srvRows(ctx).find((r) => text(r).includes('NL#2'));
	row.focus();
	ctx.srvRenderPanel();
	const back = fakeDocument.activeElement;
	assert.ok(back && text(back).includes('NL#2'),
		'focus landed on ' + JSON.stringify(back && text(back)));
	assert.notEqual(back, row, 'the rebuild really did replace the row');
	// And it must still be there one tick later: the open-time filter focus
	// is deferred, so a repaint that wrongly schedules it looks correct until
	// the timer fires.
	await tick();
	assert.ok(text(fakeDocument.activeElement).includes('NL#2'),
		'the deferred filter focus fired on a repaint');
});

test('the clear button keeps focus when the trigger rebuilds around it', () => {
	// Re-pinning leaves the × in place, so focus belongs on the × — the
	// trigger fallback is for when it is gone. Without a stable key on it
	// the fallback would fire here too, and the difference is invisible in
	// the clearing case where both answers agree.
	resetFocus();
	const ctx = srvCtx({ _serverChosen: 'NL#1' });
	ctx.srvRenderTrigger();
	findOneClass(ctx.srvTrigger, 'pv-srv-x').focus();
	ctx._serverChosen = 'NL#2';
	ctx.srvRenderTrigger();
	const back = fakeDocument.activeElement;
	assert.equal(back.attrs['data-pv-focus'], 'srv-clear',
		'focus fell back to the trigger instead of staying on the control');
	assert.notEqual(back, ctx.srvTrigger);
});

test('filtering the server list keeps focus in the filter box', () => {
	resetFocus();
	const ctx = srvCtx();
	ctx.srvOpenPanel();
	const filt = findOneClass(ctx.srvPanel, 'pv-pool-filter');
	filt.focus();
	filt.value = 'NL#2';
	filt.listeners.input.forEach((fn) => fn());
	assert.equal(fakeDocument.activeElement, filt,
		'typing in the filter threw focus out of it');
	assert.equal(srvServerRows(ctx).length, 1, 'and the filter still filtered');
});

test('filtering the location list keeps focus in the filter box', () => {
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	const filt = findOneClass(ctx.poolPanel, 'pv-pool-filter');
	filt.focus();
	filt.value = 'NL';
	filt.listeners.input.forEach((fn) => fn());
	assert.equal(fakeDocument.activeElement, filt);
});

test('the IPv6-only toggle keeps focus on itself across a full panel repaint', () => {
	// Toggling it re-renders the list; picking a country from it re-renders
	// the whole panel, checkbox included.
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	const box = findOneClass(ctx.poolPanel, 'pv-pool-v6only');
	const input = (box.children || []).find((c) => c && c.tag === 'input');
	input.focus();
	input.checked = true;
	input.attrs.change();
	assert.equal(fakeDocument.activeElement, input, 'the list re-render moved focus');
	ctx.poolRenderPanel();
	const after = fakeDocument.activeElement;
	assert.ok(after && after.attrs['data-pv-focus'] === 'panel-v6only',
		'a whole-panel repaint lost the checkbox');
});

test('a repaint never lands focus on the remove row it was not on', () => {
	// Edit mode appends "Remove this country" to the list. Restoring focus by
	// anything positional could put a keyboard user on it without them ever
	// having moved there, one Enter away from dropping the country.
	resetFocus();
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	ctx.poolOpenCountry('NL', true);
	const hit = cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-hit');
	hit.focus();
	ctx.poolRenderPanel();
	const back = fakeDocument.activeElement;
	assert.ok(back, 'focus was dropped entirely');
	assert.ok(!String(back.attrs['data-pv-focus'] || '').startsWith('rm:'),
		'focus jumped onto the destructive row');
	assert.equal(back.attrs['data-pv-focus'], 'cc:DE');
});

// ── 5. a dead code survives a save, on purpose ─────────────────────────────
//
// collectIntoUci writes every saved code back, including ones the server list
// cannot resolve, and that is deliberate. Dropping them would silently
// destroy a user's set whenever the list is stale, partial or still loading —
// which is a worse failure than the one this started as. The original defect
// was writing them back while they were INVISIBLE; they are shown and
// removable now, so the write is honest.

function saveCtx(entries) {
	const view = loadView({ uci: { protonvpn: { main: { '.type': 'instance' } } } });
	const ctx = makeCtx(view.spec, Object.assign({
		locations: locations(), refs: {},
		poolChips: El('div', { class: 'pv-pool' }),
		poolCount: El('span', { class: 'pv-pool-count' }),
		poolNote: El('div', { class: 'cbi-value-description' }),
		poolTrigger: El('button', { class: 'cbi-button pv-pool-trigger' }),
		poolPanel: El('div', { class: 'pv-pool-panel pv-pool-acc hidden' }),
		poolEntries: entries
	}));
	ctx.rebuildPoolWidget();
	return { view, ctx };
}

test('a code the server list does not know survives a save', () => {
	const { view, ctx } = saveCtx([
		{ code: 'NL', kind: 'country' }, { code: 'ZZ', kind: 'country' } ]);
	ctx.collectIntoUci();
	assert.deepEqual(view.uciData.protonvpn.main.locations, [ 'NL', 'ZZ' ],
		'a stale server list must never silently delete a saved location');
});

test('and it is still shown and removable after that save', () => {
	const { view, ctx } = saveCtx([
		{ code: 'NL', kind: 'country' }, { code: 'ZZ', kind: 'country' } ]);
	ctx.collectIntoUci();
	ctx.rebuildPoolWidget();
	const row = findAllClass(ctx.poolChips, 'pv-selrow')
		.find((r) => text(findOneClass(r, 'pv-selname')).includes('ZZ'));
	assert.ok(row, 'the round trip through uci must not hide it again');
	assert.ok(has(row, 'pv-sel-stale'));
	findOneClass(row, 'pv-selx').attrs.click(EV);
	ctx.collectIntoUci();
	assert.deepEqual(view.uciData.protonvpn.main.locations, [ 'NL' ],
		'removing it on the page must be what finally takes it out of uci');
});

test('a code hidden only by the hop mode survives a save too', () => {
	// SE is Secure Core only. In Standard it is not shown at all, and that is
	// exactly when dropping it would lose a set the user never edited.
	const { view, ctx } = saveCtx([
		{ code: 'NL', kind: 'country' }, { code: 'SE', kind: 'country' } ]);
	assert.equal(findAllClass(ctx.poolChips, 'pv-selrow').length, 1);
	ctx.collectIntoUci();
	assert.deepEqual(view.uciData.protonvpn.main.locations, [ 'NL', 'SE' ]);
});

test('the write site says why it filters nothing', () => {
	// This was re-flagged in review because the reasoning lived only at the
	// display site. Someone reading the write on its own sees codes going to
	// uci that the page could not resolve, and "fixes" it.
	const write = /var codes = \(this\.poolEntries[\s\S]{0,900}?uci\.unset\('protonvpn', inst, 'country_code'\)/
		.exec(src);
	assert.ok(write, 'the locations write site moved; this test needs updating');
	const before = src.slice(Math.max(0, write.index - 1400), write.index);
	assert.match(before, /hop mode/i,
		'the comment must name the kept-across-modes case');
	assert.match(before, /server list/i,
		'and the absent-from-the-list case');
	assert.match(before, /rebuildPoolWidget|shown|display/i,
		'and point at where those entries are made visible and removable');
});

// ── 6. dismissing a picker from the keyboard ───────────────────────────────
//
// Both pickers could be opened with the keyboard and not closed with it.
// Escape had no handler; the ✕ and a click outside are the only other ways
// out and both are mouse-only. The trigger is hidden while its panel is open,
// so "press the trigger again" was not a path either — poolOpenPanel()'s
// close branch could not be reached at all.

function press(el, key) {
	const ev = { key: key, preventDefault() {}, stopPropagation() {} };
	(((el.listeners || {}).keydown) || []).forEach((fn) => fn(ev));
	return ev;
}

test('Escape closes the location panel and hands the keyboard back', () => {
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolTrigger.focus();
	ctx.poolOpenPanel();
	cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-hit').focus();
	press(ctx.poolPanel, 'Escape');
	assert.equal(ctx._poolOpen, false, 'Escape did not close the panel');
	assert.ok(ctx.poolPanel.classList.contains('hidden'));
	assert.equal(fakeDocument.activeElement, ctx.poolTrigger,
		'the same hand-back the ✕ already does');
});

test('Escape closes the server panel and hands the keyboard back', () => {
	resetFocus();
	const ctx = srvCtx();
	ctx.srvTrigger.focus();
	ctx.srvOpenPanel();
	const row = srvRows(ctx)[0];
	row.focus();
	press(ctx.srvPanel, 'Escape');
	assert.equal(ctx._srvOpen, false);
	assert.equal(fakeDocument.activeElement, ctx.srvTrigger);
});

test('Escape inside the filter closes the panel rather than clearing the field', async () => {
	// One rule, wherever focus is. Escape meaning two different things
	// depending on which control holds the keyboard is worse than either
	// meaning on its own, and the filter is reset on every open anyway, so
	// closing costs the user nothing they would want to keep.
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolTrigger.focus();
	ctx.poolOpenPanel();
	await tick();
	const filt = findOneClass(ctx.poolPanel, 'pv-pool-filter');
	assert.equal(fakeDocument.activeElement, filt, 'precondition: the filter has focus');
	filt.value = 'DE';
	filt.listeners.input.forEach((fn) => fn());
	press(ctx.poolPanel, 'Escape');
	assert.equal(ctx._poolOpen, false,
		'Escape in the filter must close, not merely clear');
	assert.equal(fakeDocument.activeElement, ctx.poolTrigger);
});

test('Escape works on the panel opened from a picked-location row too', () => {
	// poolOpenCountry() is a third way in, from the selected-set list rather
	// than the trigger. A dismissal that only covers one entrance is not one.
	resetFocus();
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	ctx.poolTrigger.focus();
	ctx.poolOpenCountry('NL', true);
	cell(rowFor(ctx._poolListEl, 'NL'), 'pv-acc-hit').focus();
	press(ctx.poolPanel, 'Escape');
	assert.equal(ctx._poolOpen, false);
	assert.equal(fakeDocument.activeElement, ctx.poolTrigger);
});

test('a key that is not Escape leaves the panel alone', () => {
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	for (const key of [ 'Enter', 'Tab', 'a', 'ArrowDown', 'Esc' ])
		press(ctx.poolPanel, key);
	assert.equal(ctx._poolOpen, true, 'something other than Escape closed it');
});

test('Escape swallows the event so it cannot also reach the page behind', () => {
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	let stopped = 0, defaulted = 0;
	const ev = { key: 'Escape',
		preventDefault() { defaulted++; }, stopPropagation() { stopped++; } };
	ctx.poolPanel.listeners.keydown.forEach((fn) => fn(ev));
	assert.ok(stopped > 0 && defaulted > 0,
		'an Escape that closes a panel must not also reach whatever is behind it');
});

// ── 7. the trigger model ───────────────────────────────────────────────────
//
// Decided: the trigger stays HIDDEN while its panel is open, and the toggle
// is dropped from the model. The panel opens in the trigger's place and its
// head repeats the trigger's own label, so a visible trigger would be a
// duplicate affordance in the same spot — which the original design already
// rejected. A hidden trigger also cannot usefully carry aria-expanded, so
// keeping a toggle would be claiming a disclosure relationship nobody can
// perceive. Escape, the ✕ and a click outside are the three ways out, and
// Escape is the one that was missing.

test('the trigger is hidden while its panel is open, and back when it closes', () => {
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	assert.ok(ctx.poolTrigger.classList.contains('hidden'),
		'the panel opens in the trigger\'s place');
	ctx.poolClosePanel();
	assert.ok(!ctx.poolTrigger.classList.contains('hidden'));
});

test('opening a panel is not a toggle, because the trigger is not there to press', () => {
	// The close branch this replaced could not be reached: its only caller is
	// the trigger's own click, and the trigger is hidden by then. A second
	// open must leave the panel open rather than pretending to toggle.
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	ctx.poolOpenPanel();
	assert.equal(ctx._poolOpen, true);
	const srv = srvCtx();
	srv.srvOpenPanel();
	srv.srvOpenPanel();
	assert.equal(srv._srvOpen, true);
});

test('opening from the keyboard does not leave focus on the hidden trigger', async () => {
	// Focus on a display:none element is focus nowhere, which is the exact
	// hole this round is about.
	resetFocus();
	const ctx = pickerCtx();
	ctx.poolTrigger.focus();
	ctx.poolOpenPanel();
	await tick();
	assert.notEqual(fakeDocument.activeElement, ctx.poolTrigger);
	assert.equal(fakeDocument.activeElement,
		findOneClass(ctx.poolPanel, 'pv-pool-filter'));
});

// ── 8. the partial-selection state ─────────────────────────────────────────

test('a country with some of its cities picked reports itself as mixed', () => {
	// aria-pressed has exactly this value for exactly this case. The ▪ in the
	// box cell is the sighted cue and a screen reader never sees it, which is
	// the same argument that put aria-pressed on the row to begin with.
	const ctx = pickerCtx({ poolEntries: [ { code: 'DE-FRA', kind: 'city' } ] });
	ctx.poolOpenPanel();
	const de = cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-hit');
	assert.equal(findClass(de, 'box'), '▪', 'precondition: the partial mark');
	assert.equal(de.attrs['aria-pressed'], 'mixed');
});

test('whole and empty countries still report true and false', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	ctx.poolOpenPanel();
	assert.equal(cell(rowFor(ctx._poolListEl, 'NL'), 'pv-acc-hit').attrs['aria-pressed'],
		'true');
	assert.equal(cell(rowFor(ctx._poolListEl, 'DE'), 'pv-acc-hit').attrs['aria-pressed'],
		'false');
});

// ── 9. the Escape handler is bound once, not once per open ────────────────

test('opening a panel repeatedly does not stack Escape handlers', () => {
	// bindPanelEscape() runs on the way in, from three different entrances,
	// so without its guard a panel opened and closed a few times would carry
	// a handler per open. They all close the same panel, so the duplicates
	// are invisible — until one of them is asked to do something a second
	// time is not idempotent.
	const ctx = pickerCtx();
	ctx.poolOpenPanel();
	ctx.poolClosePanel();
	ctx.poolOpenPanel();
	ctx.poolClosePanel();
	ctx.poolOpenCountry('NL', true);
	assert.equal(ctx.poolPanel.listeners.keydown.length, 1,
		'one panel, one Escape handler');
	assert.equal(ctx.poolPanel._pvEscapeBound, true);
});

test('each panel gets its own handler', () => {
	const pool = pickerCtx();
	pool.poolOpenPanel();
	const srv = srvCtx();
	srv.srvOpenPanel();
	assert.equal(pool.poolPanel.listeners.keydown.length, 1);
	assert.equal(srv.srvPanel.listeners.keydown.length, 1);
});

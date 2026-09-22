// SPDX-License-Identifier: MIT
// The page's furniture: what the two cards say when nothing is wrong, and the
// layout rules that keep them from pushing a phone sideways.
//
// Measured on the owner's router before this change: the account card was
// 424px tall at 390px wide and 478px at 320px, and with the state card that
// came to 597/704px of permanent explanation before the first control. The
// document itself was 518px wide inside a 320px viewport, so the whole page
// scrolled sideways.
//
// The one mistake behind all three of the owner's complaints — the wrapping
// version row, the chip that grew without bound, the picker row that widened
// the form — was relying on flex-wrap for a "text + action" pair. The fix is
// always the same shape: an explicit grid where only the text column flexes,
// with min-width:0 all the way up. These tests pin that shape, because it is
// invisible in a screenshot and easy to lose in a refactor.
//
// Run: node --test luci-app-protonvpn/tests/*.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadView, makeCtx, text, findClass, findOneClass, findAllClass,
	El } from './luci-harness.mjs';

const { spec, src } = loadView();
const EV = { preventDefault: () => {}, stopPropagation: () => {} };

// Dates are always derived from now: a literal would sit in the future today
// and in the past next year, and the card branches on exactly that.
const DAY = 24 * 60 * 60 * 1000;
const inDays = (n) => Math.floor((Date.now() + n * DAY) / 1000);

// The worst real case Proton can produce: a long country name and a country
// narrowed to a long list of cities.
const COUNTRIES = [
	{ code: 'BA', name: 'Bosnia and Herzegovina', gateway_count: 12,
	  standard_count: 12, ipv6_count: 12, cities: [] },
	{ code: 'US', name: 'United States', gateway_count: 2143,
	  standard_count: 2143, ipv6_count: 1802, cities: [
		{ code: 'US-ATL', name: 'Atlanta', standard_count: 40 },
		{ code: 'US-CHI', name: 'Chicago', standard_count: 60 },
		{ code: 'US-DAL', name: 'Dallas', standard_count: 55 },
		{ code: 'US-LAX', name: 'Los Angeles', standard_count: 90 },
		{ code: 'US-NYC', name: 'New York City', standard_count: 200 } ] }
];

function band(session, extra) {
	const ctx = makeCtx(spec, Object.assign({ session, refs: {} }, extra || {}));
	ctx.bandEl = El('div', { class: 'pv-acct' });
	ctx.renderBand();
	return ctx;
}

function stateCard(status, extra) {
	const ctx = makeCtx(spec, Object.assign({ status }, extra || {}));
	ctx.stateEl = El('div', { class: 'pv-state' });
	ctx.updateStatusBand();
	return ctx;
}

const CONNECTED = {
	state: 'connected', configured: true, enabled: true, gateway: 'UK#264',
	location: { country: 'UK', city: 'UK-LON' },
	endpoint: '146.70.204.162:51820',
	latest_handshake_seconds: 62,
	ipv6: { mode: 'auto', active: true },
	rotation: { enabled: true },
	certificate: { present: true, days_left: 311 }
};

// ── 1. the account card in the healthy state ───────────────────────────────

test('a healthy account card is one line, not a paragraph', () => {
	const ctx = band({ state: 'active', session_expires_at: inDays(26) });
	const lines = findAllClass(ctx.bandEl, 'pv-line');
	assert.equal(lines.length, 1, 'the healthy card must have exactly one header line');
	const whole = text(ctx.bandEl);
	assert.ok(!whole.includes('keeps it alive on its own'),
		'the standing explanation costs space on every page load and earns it once');
	assert.match(findClass(ctx.bandEl, 'pv-grow'), /signed in/,
		'the one line still has to say the account is signed in');
});

test('the healthy line still names the session horizon', () => {
	const when = inDays(26);
	const ctx = band({ state: 'active', session_expires_at: when });
	const detail = findClass(ctx.bandEl, 'pv-grow');
	const day = String(new Date(when * 1000).getDate());
	assert.ok(detail.includes(day),
		'the detail must carry the session expiry date, got ' + JSON.stringify(detail));
});

for (const [ state, needle ] of [
	[ 'expired', 'tunnel keeps running' ],
	[ 'needs_2fa', 'password was accepted' ],
	[ 'no_session', 'fetch the server list' ]
]) {
	test('the ' + state + ' card keeps its explanation — it is the one that needs action', () => {
		const ctx = band({ state, session_expires_at: inDays(-1) });
		assert.ok(text(ctx.bandEl).includes(needle),
			'a state that asks the user to do something must still explain itself');
	});
}

// ── 2. the client-version control ──────────────────────────────────────────

test('the client version sits under a disclosure that names the current value', () => {
	const ctx = band({ state: 'active', session_expires_at: inDays(26) });
	const sum = findOneClass(ctx.bandEl, 'pv-more-summary');
	assert.ok(sum, 'the client version must be behind a summary, not standing open');
	assert.match(text(sum), /Client version/);
	assert.match(text(sum), /[Bb]uilt into the package/,
		'the summary must say which version is in force without being opened');
});

test('the disclosure summary follows a configured override', () => {
	const view = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', app_version: 'linux-vpn-gtk@4.18.1' } } } });
	const ctx = makeCtx(view.spec, { session: { state: 'active',
		session_expires_at: inDays(26) }, refs: {} });
	ctx.bandEl = El('div', { class: 'pv-acct' });
	ctx.renderBand();
	assert.match(text(findOneClass(ctx.bandEl, 'pv-more-summary')),
		/linux-vpn-gtk@4\.18\.1/,
		'an override in force must be visible without opening the disclosure');
});

test('the built-in option names what it is instead of calling itself recommended', () => {
	const ctx = band({ state: 'active', session_expires_at: inDays(26) });
	const opt = ctx.appVerSel.children[0];
	assert.match(text(opt), /^Built into the package/);
	assert.ok(!/recommended/i.test(text(opt)),
		'"recommended" says nothing the user can act on');
});

test('the version row is a grid, so the select shrinks and the button cannot wrap', () => {
	const ctx = band({ state: 'active', session_expires_at: inDays(26) });
	const row = findOneClass(ctx.bandEl, 'pv-verrow');
	assert.ok(row, 'the select and its button must share an explicit grid row');
	assert.ok(!findAllClass(ctx.bandEl, 'pv-inline').length,
		'.pv-inline is flex-wrap — the very thing that broke this row onto two lines');
	assert.ok(src.includes('.pv-verrow{display:grid;grid-template-columns:minmax(0,1fr) auto;'),
		'the row must be minmax(0,1fr) auto');
	assert.ok(src.includes('.pv-verrow select{min-width:0;width:100%}'),
		'a select will not shrink below its longest option without min-width:0');
	assert.ok(src.includes('.pv-verrow button{white-space:nowrap'),
		'the button is the column that must never wrap');
});

test('the client-version help is one sentence, not five lines', () => {
	const help = spec.CLIENT_VERSION_HELP;
	assert.ok(help.length < 200,
		'the note was 570 characters of permanent furniture; got ' + help.length);
	assert.ok(help.includes('5003'),
		'the one code this control actually fixes still has to be named');
});

// ── 3. the state card's facts ──────────────────────────────────────────────

test('the facts are labelled pairs, not a middot run-on', () => {
	const ctx = stateCard(CONNECTED, {
		account: { plan: 'Proton Unlimited', max_connect: 11, devices_used: 3 },
		extIp: { key: 'main|UK#264', ip: '146.70.204.166' }
	});
	const facts = findAllClass(ctx.stateEl, 'pv-fact');
	const labels = facts.map((f) => text(f.children[0]));
	assert.deepEqual(labels,
		[ 'Handshake', 'IPv6', 'Rotation', 'Certificate', 'External IP', 'Plan' ],
		'every fact must carry its own label');
	// The label is the only place the word appears: fmtHandshake used to
	// carry it too, which read as "Handshake  Handshake 1 minute ago".
	const hs = facts[0];
	assert.ok(!text(hs.children[1]).includes('Handshake'),
		'the value must not repeat its own label');
	// Each value in its own element is what lets it ellipsise on its own
	// instead of the whole run-on line wrapping.
	for (const f of facts)
		assert.equal(f.children.length, 2, 'a fact is exactly a label and a value');
	assert.ok(!text(ctx.stateEl).includes('certificate 311 days left'),
		'the run-on phrasing must be gone');
});

test('a fact with nothing to say is left out rather than shown empty', () => {
	const ctx = stateCard({ state: 'disconnected', configured: true, enabled: true });
	const labels = findAllClass(ctx.stateEl, 'pv-fact').map((f) => text(f.children[0]));
	assert.ok(!labels.includes('External IP'));
	assert.ok(!labels.includes('Certificate'));
});

test('the facts grid is one column when narrow, so nothing is truncated there', () => {
	// The external IP was the value that lost its tail at 320px, and an IPv4
	// address has no space to wrap at — a narrow column can only cut it.
	// Measured with two columns at 320: the IP, the certificate and the plan
	// all lost text. With one, none of them does.
	assert.ok(src.includes('.pv-facts{display:grid;grid-template-columns:minmax(0,1fr);'),
		'the facts grid must be a single column below 34em');
	assert.ok(src.includes('@media (min-width:34em){.pv-facts{display:flex;flex-wrap:wrap'),
		'above 34em the facts flow, because forcing columns there truncated the IP');
	assert.ok(/@media \(min-width:34em\)\{[^@]*\.pv-facts \.pv-fact span\{white-space:nowrap\}\}/
		.test(src),
	'values go nowrap only where they flow; below that they may wrap rather than be cut');
});

// ── 4. actions follow available width ──────────────────────────────────────

test('every action is inline from 34em, and the kebab only below it', () => {
	assert.ok(src.includes('.pv-sec{display:none;'),
		'the secondary actions start hidden, for the narrow case');
	assert.ok(src.includes('@media (min-width:34em){.pv-sec{display:flex}'),
		'from 34em the secondary actions are simply there');
	assert.ok(/@media \(min-width:34em\)\{[^}]*\}[^@]*\.pv-kebab\{display:none\}\}/.test(src),
		'the kebab must be hidden inside the same 34em query');
});

test('the kebab is offered only when it has something to reveal', () => {
	const live = stateCard(CONNECTED);
	assert.ok(findOneClass(live.stateEl, 'pv-kebab'),
		'a connected instance has four actions and needs the narrow-screen fallback');
	// Nothing configured yet: Refresh is the only action, so it is primary
	// and there is nothing for a kebab to hide.
	const bare = stateCard({ state: 'not_configured' });
	assert.equal(findOneClass(bare.stateEl, 'pv-kebab'), null,
		'a kebab that opens onto nothing is an extra click for nothing');
	assert.equal(findAllClass(bare.stateEl, 'pv-sec').length, 0);
});

test('pressing the kebab opens the secondary actions', () => {
	const ctx = stateCard(CONNECTED);
	const kebab = findOneClass(ctx.stateEl, 'pv-kebab');
	assert.ok(!ctx.stateEl.classList.contains('pv-acts-open'));
	kebab.attrs.click(EV);
	assert.ok(ctx.stateEl.classList.contains('pv-acts-open'),
		'the kebab must actually reveal the actions it stands for');
	kebab.attrs.click(EV);
	assert.ok(!ctx.stateEl.classList.contains('pv-acts-open'));
});

test('the status poll does not close an open action menu', () => {
	// Both cards are repainted every five seconds, and the repaint assigns
	// className wholesale. Without carrying the flag across, a menu the user
	// has just opened shuts by itself within five seconds — under the finger
	// that is reaching for the button inside it.
	const ctx = stateCard(CONNECTED);
	findOneClass(ctx.stateEl, 'pv-kebab').attrs.click(EV);
	assert.ok(ctx.stateEl.classList.contains('pv-acts-open'));
	ctx.updateStatusBand();
	assert.ok(ctx.stateEl.classList.contains('pv-acts-open'),
		'the repaint closed the menu');
	// And the same card, repainted while closed, must stay closed.
	findOneClass(ctx.stateEl, 'pv-kebab').attrs.click(EV);
	ctx.updateStatusBand();
	assert.ok(!ctx.stateEl.classList.contains('pv-acts-open'));
});

test('the account card keeps its open menu across a repaint too', () => {
	const ctx = band({ state: 'active', session_expires_at: inDays(26) });
	findOneClass(ctx.bandEl, 'pv-kebab').attrs.click(EV);
	ctx.renderBand();
	assert.ok(ctx.bandEl.classList.contains('pv-acts-open'),
		'renderBand runs on the same five-second poll');
});

test('the primary action stays outside the kebab', () => {
	const ctx = stateCard(CONNECTED);
	const acts = findOneClass(ctx.stateEl, 'pv-acts');
	assert.match(text(acts), /Reconnect/,
		'the action a user came for must never be one click deeper');
	const sec = text(findOneClass(ctx.stateEl, 'pv-sec'));
	for (const label of [ 'Refresh', 'Rotate now', 'Disable' ])
		assert.ok(sec.includes(label), label + ' belongs to the secondary set');
});

// ── 5. the selected set is an aligned list ─────────────────────────────────

function poolCtx(seed) {
	const view = loadView({ uci: { protonvpn: { main: {
		'.type': 'instance', hop_mode: 'standard', locations: seed } } } });
	const ctx = makeCtx(view.spec, {
		locations: { available: true, countries: COUNTRIES }, refs: {} });
	ctx.buildConnection();
	return ctx;
}

test('the selected set is one aligned row per country, not a pill', () => {
	const ctx = poolCtx([ 'BA', 'US-ATL', 'US-CHI', 'US-DAL', 'US-LAX', 'US-NYC' ]);
	assert.equal(findAllClass(ctx.poolChips, 'pv-chip').length, 0,
		'chips had no width bound and fell apart with a real selection');
	const rows = findAllClass(ctx.poolChips, 'pv-selrow');
	assert.equal(rows.length, 2, 'one row per country: BA and US');
	for (const r of rows) {
		assert.ok(findOneClass(r, 'pv-selname'), 'the name needs its own column to ellipsise in');
		assert.ok(findOneClass(r, 'pv-seldetail'), 'the detail is a column, not part of the name');
		assert.ok(findOneClass(r, 'pv-selx'), 'each row removes its own country');
	}
});

test('a long city list stays inside the name column', () => {
	const ctx = poolCtx([ 'US-ATL', 'US-CHI', 'US-DAL', 'US-LAX', 'US-NYC' ]);
	const row = findAllClass(ctx.poolChips, 'pv-selrow')[0];
	assert.match(text(findOneClass(row, 'pv-selname')), /Atlanta.*New York City/,
		'the cities are still named');
	assert.match(text(findOneClass(row, 'pv-seldetail')), /5 cities/,
		'the count is its own column so the name can be cut instead');
	assert.ok(src.includes('.pv-selrow .pv-selname{min-width:0;overflow:hidden;' +
		'text-overflow:ellipsis;white-space:nowrap}'),
	'the name column is the only one allowed to lose text');
	assert.ok(src.includes('.pv-selrow{display:grid;' +
		'grid-template-columns:auto minmax(0,1fr) auto auto;'),
	'flag | name | detail | remove, with only the name flexing');
});

test('the remove button on a row drops that country', () => {
	const ctx = poolCtx([ 'BA', 'US-ATL' ]);
	const rows = findAllClass(ctx.poolChips, 'pv-selrow');
	findOneClass(rows[0], 'pv-selx').attrs.click(EV);
	assert.deepEqual(ctx.poolEntries.map((e) => e.code), [ 'US-ATL' ],
		'removing BA must leave the US selection alone');
});

test('the row itself still opens the country editor', () => {
	const ctx = poolCtx([ 'BA' ]);
	const row = findAllClass(ctx.poolChips, 'pv-selrow')[0];
	row.attrs.click(EV);
	assert.equal(ctx._poolCountry, 'BA');
	assert.ok(ctx._poolEdit);
});

// ── 6. the min-width:0 chain ───────────────────────────────────────────────

test('the fieldset can shrink — the root cause of the sideways page', () => {
	// A <fieldset> carries a UA default of min-width:min-content, so
	// .cbi-section refuses to go below the widest nowrap thing inside it and
	// drags the document with it. This one line took the document from 381
	// to the viewport width at both 320 and 360.
	assert.ok(src.includes('fieldset.cbi-section{min-width:0}'),
		'fieldset.cbi-section{min-width:0} is the fix and it is one line');
});

test('the chain continues down to the picker row', () => {
	// A flex item defaults to min-width:auto, so a nowrap descendant's
	// min-content width propagates outward one ancestor at a time. Breaking
	// the chain anywhere lets a long country name widen the LuCI form row.
	for (const rule of [
		'.cbi-value-field,.pv-pool-wrap,.pv-pool-panel,.pv-sel{min-width:0}',
		'.pv-pool-row .grow{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis}'
	])
		assert.ok(src.includes(rule), 'missing: ' + rule);
});

test('the header line is a grid with exactly one flexing column', () => {
	assert.ok(src.includes('.pv-line{display:grid;' +
		'grid-template-columns:auto auto minmax(0,1fr) auto auto;'),
	'led, label, detail, primary, secondary — only the detail may flex');
	// Five columns for five items. A fifth item on a four-column template
	// wraps to a second row, which is the wrapping header all over again;
	// measured at 820px before this was widened.
	const cols = /\.pv-line\{display:grid;grid-template-columns:([^;]*);/.exec(src)[1];
	assert.equal(cols.split(' ').length, 5,
		'the template must have a column per header item, got ' + cols);
	assert.ok(src.includes('.pv-line .pv-grow{min-width:0;overflow:hidden;' +
		'text-overflow:ellipsis;white-space:nowrap}'),
	'the flexing column is the one that ellipsises');
});

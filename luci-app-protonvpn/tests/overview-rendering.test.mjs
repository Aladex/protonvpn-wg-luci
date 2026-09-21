// SPDX-License-Identifier: MIT
// How messages actually reach the screen.
//
// LuCI's DOM.append() (luci.js) has two branches: an ARRAY member that is not
// an element becomes document.createTextNode(...), while a SCALAR child is
// assigned with `node.innerHTML = ...`. dom.content() delegates to append(),
// and E(tag, attrs, child) calls append() with that child, so `E('p', {}, s)`
// and `dom.content(el, s)` both parse `s` as HTML.
//
// Two consequences, both real:
//
//   * our own hint contains the literal `linux-vpn-gtk@<version>`, and
//     `<version>` is eaten as a phantom tag — which is exactly what the
//     forum user photographed;
//   * Proton's `Error` is remote text, so a sign-in error is an HTML
//     injection into the admin's LuCI page.
//
// Every one of these paths must hand append() an array (or a text node), and
// these tests read what a browser would render, not what the view passed.
//
// Run: node --test luci-app-protonvpn/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadView, makeCtx, findClass, findOneClass, findAllClass, text,
	htmlAssignments, El } from './luci-harness.mjs';

const EV = { preventDefault: () => {}, stopPropagation: () => {} };

// An opaque value straight from the backend, carrying a tag. Its only job is
// to prove a backend string reaches the page with its tag intact — there are
// no date semantics here to exercise, so it is deliberately not a date. A
// calendar literal in a test is a branch waiting to flip once the calendar
// catches up with it, and the assertion below reads this same constant so the
// two cannot drift apart.
const BACKEND_MARKER = 'cache-stamp <from-backend>';

// What api_error() builds for Code 5003: Proton's own sentence, the code and
// status, then our appended hint — which contains a literal <version>.
const MSG_5003 = 'This version of the app is no longer supported. (Code 5003, HTTP 422) — ' +
	"the client version this package stamps is what Proton rejects here. " +
	"Update the protonvpn-wireguard package; if no update is available yet, " +
	"set the current official client string in uci: option app_version " +
	"'linux-vpn-gtk@<version>' in the protonvpn globals section.";

// Remote text, straight from the API response body.
const MSG_INJECT = 'Bad credentials <img src=x onerror="alert(1)"> and <b>bold</b>.';

function openLogin(opts) {
	opts = opts || {};
	const view = loadView({ rpc: opts.rpc || {} });
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	ctx.afterLogin = () => Promise.resolve();
	const attempts = [];
	if (!opts.real)
		ctx.submitCredentials = function (fail, render) {
			attempts.push({ fail, render });
			return Promise.resolve();
		};
	ctx.showLoginModal();
	const modal = view.modals[view.modals.length - 1];
	return { view, ctx, modal, attempts,
		btn: findOneClass(modal.children, 'pv-login-go') };
}

test('a sign-in error keeps the literal <version> the hint contains', () => {
	const { ctx, btn, attempts } = openLogin();
	btn.attrs.click(EV);
	attempts[0].fail(MSG_5003);
	// The whole point of the hint is the string the user has to type.
	assert.match(text(ctx.loginErr), /linux-vpn-gtk@<version>/,
		'<version> was eaten as a tag — the user is told to type a value that is not shown');
});

test('a sign-in error is not injected as markup', () => {
	const { ctx, btn, attempts } = openLogin();
	btn.attrs.click(EV);
	attempts[0].fail(MSG_INJECT);
	assert.equal(htmlAssignments(ctx.loginErr).length, 0,
		"Proton's own Error text is assigned to innerHTML");
	assert.match(text(ctx.loginErr), /<img src=x onerror="alert\(1\)">/,
		'the remote text is not shown verbatim');
	assert.match(text(ctx.loginErr), /<b>bold<\/b>/);
});

test('the two-factor step renders its error as text too', async () => {
	const view = loadView({ rpc: { set_totp: { error: MSG_INJECT } } });
	const ctx = makeCtx(view.spec, { refs: {}, loginStep: 'totp' });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal('totp');
	const btn = findOneClass(view.modals[view.modals.length - 1].children, 'pv-login-go');
	ctx.totpEl.value = '123456';
	btn.attrs.click(EV);
	await new Promise((r) => setTimeout(r, 10));
	assert.equal(htmlAssignments(ctx.loginErr).length, 0);
	assert.match(text(ctx.loginErr), /<img src=x/);
});

test('the password step renders its error as text too', async () => {
	globalThis.window = { ProtonSRP: {} };
	const view = loadView({ rpc: { auth_info: { error: MSG_INJECT } } });
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	ctx.afterLogin = () => Promise.resolve();
	ctx.showLoginModal();
	const btn = findOneClass(view.modals[view.modals.length - 1].children, 'pv-login-go');
	ctx.userEl.value = 'user@proton.me';
	ctx.passEl.value = 'secret';
	btn.attrs.click(EV);
	await new Promise((r) => setTimeout(r, 10));
	assert.equal(htmlAssignments(ctx.loginErr).length, 0);
	assert.match(text(ctx.loginErr), /<img src=x/);
});

test('notice() renders its text rather than parsing it', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	// The real notice(), not makeCtx's recording stand-in.
	view.spec.notice.call(ctx, MSG_5003, 'error');
	const rec = view.notices[view.notices.length - 1];
	assert.ok(rec, 'nothing was notified');
	assert.match(rec.text, /linux-vpn-gtk@<version>/,
		'a 5003 notice loses the very string it tells the user to type');
});

test('notice() does not parse a remote message as markup', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, MSG_INJECT, 'error');
	assert.match(view.notices[view.notices.length - 1].text, /<img src=x/);
});

// The version control is on the Proton account card, so the note that carries
// the backend's error string is built there.
function versionCard(rpc) {
	const view = loadView({
		uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main' } } },
		rpc: { client_versions: rpc } });
	const ctx = makeCtx(view.spec, { refs: {}, session: { state: 'active' },
		bandEl: El('div', { class: 'pv-acct' }) });
	ctx.renderBand();
	return ctx.bandEl;
}

test('the version-list failure note is rendered as text', async () => {
	const band = versionCard({ versions: [], current: '',
		error: 'could not fetch <tags>: ' + MSG_INJECT });
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	const note = findOneClass(band, 'pv-appver-note');
	assert.equal(htmlAssignments(note).length, 0,
		'a backend error string is assigned to innerHTML');
	assert.match(text(note), /<img src=x/);
	assert.match(text(note), /<tags>/);
});

test('the version-list success note is rendered as text', async () => {
	const band = versionCard({ versions: [ 'linux-vpn-gtk@4.17.0' ],
		current: 'linux-vpn-gtk@4.17.0',
		error: 'partial: <b>tags</b> missing' });
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	const note = findOneClass(band, 'pv-appver-note');
	assert.equal(htmlAssignments(note).length, 0);
	assert.match(text(note), /<b>tags<\/b>/);
});

// A version string straight out of the backend's list reaches the select as an
// option value, which is a second place a remote string lands on this page.
test('the fetched version list is rendered as text', async () => {
	const band = versionCard({ versions: [ 'linux-vpn-gtk@4.17.0 <v>' ],
		current: '', error: null });
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	const sel = findOneClass(band, 'pv-appver-list');
	assert.deepEqual(htmlAssignments(sel), []);
	assert.match(text(sel), /<v>/);
});

test('the instance-name error is rendered as text', async () => {
	const view = loadView({
		rpc: { create_instance: { error: MSG_INJECT } },
		uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main' } } }
	});
	const ctx = makeCtx(view.spec, { refs: {}, instances: [ { instance: 'main' } ] });
	const input = El('input', { value: 'work' });
	const err = El('div', {});
	await ctx.addInstance(input, err);
	assert.equal(htmlAssignments(err).length, 0,
		'a backend error string is assigned to innerHTML');
	assert.match(text(err), /<img src=x/);
});

test('the local instance-name refusal is rendered as text', () => {
	const view = loadView({ uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main' } } } });
	const ctx = makeCtx(view.spec, { refs: {} });
	const err = El('div', {});
	ctx.addInstance(El('input', { value: '!!!' }), err);
	assert.equal(htmlAssignments(err).length, 0);
	assert.match(text(err), /1-12 letters/);
});

test('an instance-name rpc rejection is rendered as text', async () => {
	const view = loadView({
		rpc: { create_instance: () => Promise.reject(new Error(MSG_INJECT)) },
		uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main' } } }
	});
	const ctx = makeCtx(view.spec, { refs: {} });
	const err = El('div', {});
	await ctx.addInstance(El('input', { value: 'work' }), err);
	assert.equal(htmlAssignments(err).length, 0);
	assert.match(text(err), /<img src=x/);
});

// ── the sweep ────────────────────────────────────────────────────────────
//
// The list of places that put text on this page is long and it grows. Fixing
// the ones somebody remembered is how this defect got here: every suite was
// green and 66 mutants died while the sign-in error was an innerHTML
// assignment carrying remote text. So instead of trusting a list, render the
// whole page — every panel, and each modal — and assert that nothing at all
// reached innerHTML.
//
// If this fails on a line you just wrote: wrap the child in nodes(), or pass
// an array. It is never correct to hand DOM.append() a bare string here.

// A session that still has a month to run. Generated rather than written
// down for the same reason as above: a fixed epoch is a calendar literal in
// disguise, and the page's session branch reads this value.
function sessionHorizon() {
	return Math.floor(Date.now() / 1000) + 30 * 24 * 60 * 60;
}

function fullPage() {
	const uci = { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'linux-vpn-gtk@4.18.2',
			hop_mode: 'standard', locations: [ 'DE' ], watchdog: '1', mtu: '1420' },
		work: { '.type': 'instance', '.name': 'work' },
		globals: { '.type': 'globals', '.name': 'globals' }
	} };
	// Remote-looking values everywhere a name, a city or a message can come
	// from the API — each one carrying a tag, so a scalar assignment loses it.
	const locations = {
		available: true, state: 'fresh',
		cache_info: { created: BACKEND_MARKER },
		stats: { gateways: 42 },
		countries: [ { code: 'DE', name: 'Germany <de>', count: 7, ipv6_count: 3,
			cities: [ { code: 'DE#BER', name: 'Berlin <ber>', count: 4, ipv6_count: 2 } ] } ]
	};
	const status = {
		instance: 'main', configured: true, enabled: true, state: 'connected',
		gateway: 'DE#7 <gw>', endpoint: '1.2.3.4:51820', latest_handshake_seconds: 12,
		hop_mode: 'standard',
		ipv6: { mode: 'auto', active: true, gateway_ipv6: true, require_ipv6: false },
		routing: { mode: 'steered', killswitch: false, recommended_mtu: 1420, wan_mtu: 1500,
			interface: 'protonvpn <if>', table: 'protonvpn' },
		rotation: { enabled: false }
	};
	const view = loadView({ uci, rpc: {
		servers: { servers: [ { hostname: 'de-07.protonvpn.net <host>', city: 'Berlin <ber>',
			name: 'DE#7 <gw>', load: 23, tier: 0, ipv6: true } ] },
		account: { plan: 'Proton Unlimited <plan>', max_connect: 10, devices_used: 2 },
		client_versions: { versions: [ 'linux-vpn-gtk@4.18.2' ],
			current: 'linux-vpn-gtk@4.18.2', error: 'partial <err>' }
	} });
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.maybeFetchExternalIp = () => {};
	ctx.loadAccount = () => Promise.resolve();
	ctx.bindOutsideClose = () => {};
	const body = view.spec.render.call(ctx,
		[ null, { state: 'active', session_expires_at: sessionHorizon() }, locations, status,
			{ instances: [ { instance: 'main' }, { instance: 'work' } ] } ]);
	return { view, ctx, body };
}

test('nothing on the rendered page goes through innerHTML', () => {
	const { body } = fullPage();
	const assigned = htmlAssignments(body);
	assert.deepEqual(assigned, [],
		'these children were assigned as HTML instead of appended as text');
});

test('nothing in the sign-in modal goes through innerHTML', () => {
	const { view, ctx } = fullPage();
	ctx.showLoginModal();
	ctx.showLoginModal('totp');
	const built = view.modals.map((m) => m.children);
	assert.deepEqual(htmlAssignments(built), []);
});

test('nothing in the instance modals goes through innerHTML', () => {
	const { view, ctx } = fullPage();
	ctx.showAddInstanceModal();
	ctx.showDeleteInstanceModal('main', EV);
	ctx.showDeleteInstanceModal('work', EV);
	assert.deepEqual(htmlAssignments(view.modals.map((m) => m.children)), []);
});

test('nothing in the Advanced panel goes through innerHTML', () => {
	const { ctx } = fullPage();
	assert.deepEqual(htmlAssignments(ctx.buildAdvanced()), []);
});

test('nothing on the account card goes through innerHTML, fetched list and all', async () => {
	const { ctx } = fullPage();
	await findOneClass(ctx.bandEl, 'pv-appver-fetch').attrs.click(EV);
	assert.deepEqual(htmlAssignments(ctx.bandEl), []);
});

test('a value from the backend still reaches the page intact', () => {
	const { body } = fullPage();
	// The sweep says nothing reached innerHTML; this says the text SURVIVED.
	// Both matter: dropping the string entirely would also pass the sweep.
	// The cache summary passes this value straight through from the backend.
	assert.ok(text(body).includes(BACKEND_MARKER),
		'a backend value did not reach the page intact');
});

// ── nodes() has to be total ──────────────────────────────────────────────
//
// It used to pass every object through on the assumption that an object is
// an element. A boxed `new String(markup)` is an object and is not an
// element, so it went to the innerHTML branch and had its tags eaten — the
// original defect, reachable again through a value nobody thought about.
// Nothing in the view produces one today; the point is that the helper is
// total, so no future caller can find the hole.

test('a boxed string reaching notice() is still rendered as text', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, new String(MSG_INJECT), 'error');
	const rec = view.notices[view.notices.length - 1];
	assert.match(rec.text, /<img src=x/, 'a boxed string was parsed as markup');
});

test('a boxed string reaching the sign-in error is still rendered as text', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, { refs: {} });
	ctx.LOGIN_RETRY_PAUSE_MS = 400;
	ctx.showLoginModal();
	ctx.failLogin(ctx.loginInFlight, new String('linux-vpn-gtk@<version>'), true);
	assert.equal(htmlAssignments(ctx.loginErr).length, 0);
	assert.match(text(ctx.loginErr), /linux-vpn-gtk@<version>/);
});

test('a boxed number is rendered as text too', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, new Number(42), 'info');
	assert.equal(view.notices[view.notices.length - 1].text, '42');
});

test('real elements still pass through untouched', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, El('span', {}, [ 'built <here>' ]), 'info');
	const rec = view.notices[view.notices.length - 1];
	assert.equal(rec.text, 'built <here>',
		'narrowing the passthrough broke the element branch');
});

// DOM.append()'s third branch: a function is called and its return value is
// appended recursively (`return this.append(node, children(node))`), so a
// function that returns a scalar lands on innerHTML just like a bare string.
// Passing functions through untouched left that hole open. No call site in
// this view passes one today — the point, again, is that none can.

test('a function returning a string is rendered as text', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, () => 'linux-vpn-gtk@<version>', 'info');
	assert.match(view.notices[view.notices.length - 1].text, /linux-vpn-gtk@<version>/,
		'the function result was parsed as markup');
});

test('a function returning remote text is not injected as markup', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, () => MSG_INJECT, 'error');
	assert.match(view.notices[view.notices.length - 1].text, /<img src=x/);
});

test('a function returning an element still works', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, () => El('span', {}, [ 'built <here>' ]), 'info');
	assert.equal(view.notices[view.notices.length - 1].text, 'built <here>');
});

test('a function returning an array still works', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, () => [ 'a <b>', ' and c' ], 'info');
	assert.equal(view.notices[view.notices.length - 1].text, 'a <b> and c');
});

test('a function returning another function is still safe', () => {
	const view = loadView();
	const ctx = makeCtx(view.spec, {});
	view.spec.notice.call(ctx, () => () => 'deep <tag>', 'info');
	assert.match(view.notices[view.notices.length - 1].text, /deep <tag>/);
});

// The page sweep above renders everything a page load renders — which is not
// everything the page can render. refreshCache() rewrites the cache summary
// row from a button press, and a mutation run over this suite showed those
// three sinks were reachable by no test at all: dropping nodes() from them
// killed nothing. They are correct; they were simply unguarded. A sink only a
// user action reaches is exactly the kind this defect hid in the first time.

async function drivenCacheRow(opts) {
	const { view, ctx } = fullPage();
	ctx.buildAdvanced();
	ctx.handleRefreshLocations = opts.refresh;
	ctx.locations = Object.assign({}, ctx.locations, opts.locations || {});
	await ctx.refreshCache({ target: El('button', {}) });
	return { view, ctx, row: ctx.cacheRow };
}

test('the refreshing cache row does not go through innerHTML', async () => {
	const { row } = await drivenCacheRow({ refresh: () => Promise.resolve() });
	assert.deepEqual(htmlAssignments(row), []);
	assert.ok(text(row).includes(BACKEND_MARKER),
		'the refreshed summary lost the backend value');
});

test('a failed refresh leaves the row as text and still reports', async () => {
	const { ctx, row } = await drivenCacheRow({
		refresh: () => Promise.reject(new Error(MSG_INJECT))
	});
	assert.deepEqual(htmlAssignments(row), []);
	// makeCtx() records notices instead of building them; that notice() puts
	// its text through nodes() is covered above. What matters here is that the
	// failure is reported at all and reaches the user intact.
	const said = (ctx._notices || []).map((n) => n.text).join(' ');
	assert.match(said, /Refresh failed/, 'a failed refresh said nothing');
	assert.match(said, /<img src=x/, 'the failure text was mangled on the way');
});

test('a cache row with no server list still renders as text', async () => {
	const { row } = await drivenCacheRow({
		refresh: () => Promise.resolve(),
		locations: { available: false }
	});
	assert.deepEqual(htmlAssignments(row), []);
	assert.match(text(row), /not loaded/);
});

test('the in-progress cache row is text while the refresh runs', async () => {
	// The transient state, which awaiting the refresh skips straight past.
	const { ctx } = fullPage();
	ctx.buildAdvanced();
	let release;
	ctx.handleRefreshLocations = () => new Promise((r) => { release = r; });
	const running = ctx.refreshCache({ target: El('button', {}) });
	assert.deepEqual(htmlAssignments(ctx.cacheRow), []);
	assert.match(text(ctx.cacheRow), /Refreshing/);
	release();
	await running;
});

// SPDX-License-Identifier: MIT
// The Proton client version on the Proton account card: the select itself,
// and the button that asks upstream which versions exist.
//
// Why this suite exists: `app_version` is the header Proton gates sign-ins
// on, and it used to be reachable only over uci — the one setting a user
// needs precisely when they cannot sign in, hidden from the page they are
// sitting in front of. It then spent a release inside Advanced settings as a
// free-text box, which is the same problem one fold down: a global setting
// filed under a per-instance accordion, typed by hand, where a typo stores a
// value the router silently ignores.
//
// It now lives next to the sign-in controls, always visible, and it is a
// select — so the only values that can be chosen are ones that exist. The
// button that fills it must stay help: it fetches a list, the user picks, the
// user saves. A page that quietly restamps the version would break sign-ins
// for a reason its owner cannot see, and a page that drops a value already in
// force would do it silently.
//
// Run: node --test luci-app-protonvpn/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadView, makeCtx, findClass, findOneClass, findAllClass, text, El } from './luci-harness.mjs';

const EV = { preventDefault: () => {}, stopPropagation: () => {} };
const here = dirname(fileURLToPath(import.meta.url));

const LIST = {
	versions: [ 'linux-vpn-gtk@4.18.2', 'linux-vpn-gtk@4.17.0', 'linux-vpn-gtk@4.9.0' ],
	current: 'linux-vpn-gtk@4.18.2',
	configured: 'linux-vpn-gtk@4.18.2',
	error: null
};

const MAIN = { protonvpn: { main: { '.type': 'instance', '.name': 'main' } } };

// The account card, rendered against a config and a session state the test
// supplies. The card is what the page repaints on every status poll, so it is
// also the thing every test here has to build through rather than around.
function card(opts) {
	opts = opts || {};
	const view = loadView({ uci: opts.uci || MAIN, rpc: opts.rpc || {} });
	const ctx = makeCtx(view.spec, {
		refs: {}, dirty: 0,
		session: opts.session || { state: 'active', session_expires_at: 1900000000 },
		bandEl: El('div', { class: 'pv-acct' })
	});
	ctx.markDirty = function () { this.dirty = (this.dirty || 0) + 1; };
	ctx.renderBand();
	return { view, ctx, band: ctx.bandEl };
}

// Advanced settings, built against a config the test supplies.
function advanced(opts) {
	opts = opts || {};
	const view = loadView({ uci: opts.uci || MAIN, rpc: opts.rpc || {} });
	const ctx = makeCtx(view.spec, { refs: {}, dirty: 0 });
	ctx.markDirty = function () { this.dirty = (this.dirty || 0) + 1; };
	return { view, ctx, panel: ctx.buildAdvanced() };
}

const fire = (el, ev) => (el.listeners[ev] || []).forEach((fn) => fn(EV));

// The values the select offers, in order, and the labels next to them.
function options(sel) {
	return (sel.children || []).map((o) => String((o.attrs && o.attrs.value) || ''));
}
function labels(sel) {
	return (sel.children || []).map((o) => text(o));
}

// ── where it lives ───────────────────────────────────────────────────────

test('the client version sits on the Proton account card', () => {
	const { ctx, band } = card();
	assert.ok(ctx.refs.app_version, 'no app_version control was built');
	assert.ok(findOneClass(band, 'pv-appver-list'),
		'the account card offers no version control');
	assert.match(text(band), /client version/i,
		'the control is there but nothing labels it');
});

test('it is no longer buried in Advanced settings', () => {
	const { panel } = advanced();
	assert.equal(findOneClass(panel, 'pv-appver-list'), null,
		'the version control is still in Advanced settings');
	assert.equal(findOneClass(panel, 'pv-appver-fetch'), null,
		'the fetch button is still in Advanced settings');
	assert.doesNotMatch(text(panel), /client version/i,
		'Advanced settings still talks about the client version');
});

// It is the setting somebody needs while staring at a failed sign-in, so it
// cannot be hidden behind the state the sign-in happens to be in.
[ 'active', 'expired', 'needs_2fa', 'none' ].forEach((state) => {
	test('the control is on the card in session state ' + state, () => {
		const { band } = card({ session: { state: state } });
		assert.ok(findOneClass(band, 'pv-appver-list'),
			'the version control disappears in this state');
		assert.ok(findOneClass(band, 'pv-appver-fetch'),
			'the fetch button disappears in this state');
	});
});

test('the card is repainted on every poll and keeps the control', () => {
	const { ctx, band } = card();
	ctx.renderBand();
	ctx.renderBand();
	assert.equal(findAllClass(band, 'pv-appver-list').length, 1,
		'a repaint duplicated or dropped the version control');
});

// ── no hand typing ───────────────────────────────────────────────────────

test('the control is a select, not a text box', () => {
	const { ctx } = card();
	assert.equal(ctx.refs.app_version.tag, 'select',
		'the version is still typed by hand');
});

// ── what it offers when nothing has been fetched ─────────────────────────

test('the built-in version is always reachable', () => {
	const { ctx } = card();
	assert.ok(options(ctx.refs.app_version).includes(''),
		'there is no way back to the version built into the package');
	assert.match(labels(ctx.refs.app_version).join(' '), /built into the package/i,
		'the empty option does not say what it means');
});

test('with nothing fetched the list is exactly the built-in option', () => {
	const { ctx } = card();
	// Anything else would be invented: the page has not asked upstream what
	// exists, and offering a guess is how a user picks a version that was
	// never released.
	assert.deepEqual(options(ctx.refs.app_version), [ '' ]);
});

test('a value already saved in uci is offered and selected', () => {
	const { ctx } = card({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'linux-vpn-gtk@4.9.0' }
	} } });
	const sel = ctx.refs.app_version;
	assert.ok(options(sel).includes('linux-vpn-gtk@4.9.0'),
		'opening the page dropped the version that is in force');
	assert.equal(sel.value, 'linux-vpn-gtk@4.9.0',
		'the control does not show what the router is stamping today');
});

test('the saved value survives even when it is not a shape the router accepts', () => {
	// uci is editable by hand and the backend ignores anything malformed. The
	// page must still show what is stored: dropping it from the list would
	// change the stored value the next time anybody presses Save.
	const { ctx } = card({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'nonsense' }
	} } });
	assert.ok(options(ctx.refs.app_version).includes('nonsense'),
		'a hand-edited value was silently dropped by opening the page');
	assert.equal(ctx.refs.app_version.value, 'nonsense');
});

// The de-duplication of the option list must not mistake a JavaScript object's
// inherited property names for entries it has already added. `toString` and
// `constructor` are perfectly ordinary uci strings, and treating one as
// already-present drops it from the list — so the control shows a different
// value than the one in force, and the next Save quietly unsets it.
[ 'toString', 'constructor', 'valueOf', '__proto__', 'hasOwnProperty' ].forEach((name) => {
	test('a saved value of "' + name + '" is still offered', () => {
		const { ctx } = card({ uci: { protonvpn: {
			main: { '.type': 'instance', '.name': 'main', app_version: name }
		} } });
		const sel = ctx.refs.app_version;
		assert.ok(options(sel).includes(name),
			'the stored value was swallowed by the de-duplication map');
		assert.equal(sel.value, name,
			'the control shows something other than the value in force');
	});
});

test('a fetched list is not thinned by inherited property names', async () => {
	const { ctx, band } = card({ rpc: { client_versions: {
		versions: [ 'toString', 'linux-vpn-gtk@4.17.0', 'constructor' ],
		current: '', error: null } } });
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	assert.deepEqual(options(ctx.refs.app_version),
		[ '', 'toString', 'linux-vpn-gtk@4.17.0', 'constructor' ]);
});

test('the value is read from the globals section when the config has one', () => {
	const { ctx } = card({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'linux-vpn-gtk@1.1.1' },
		globals: { '.type': 'globals', '.name': 'globals', app_version: 'linux-vpn-gtk@4.17.0' }
	} } });
	// globals_section() in the backend prefers globals, so the page must show
	// the value the router actually stamps, not a stale one from main.
	assert.equal(ctx.refs.app_version.value, 'linux-vpn-gtk@4.17.0');
});

test('building the page fetches no version list', () => {
	const { view } = card();
	assert.equal(view.rpcCalls.filter((c) => c.method === 'client_versions').length, 0,
		'the page reached out to the upstream repository just by being opened');
});

// ── the fetch ────────────────────────────────────────────────────────────

test('the button asks the backend once and shows that it is working', async () => {
	let resolve;
	const { view, band } = card({
		rpc: { client_versions: () => new Promise((r) => { resolve = r; }) }
	});
	const btn = findOneClass(band, 'pv-appver-fetch');
	assert.ok(btn, 'no fetch button was built');
	const running = btn.attrs.click(EV);
	assert.equal(view.rpcCalls.filter((c) => c.method === 'client_versions').length, 1);
	assert.ok(btn.disabled, 'the button stays pressable while the fetch runs');
	assert.equal(findAllClass(btn, 'spinning').length, 1, 'nothing says it is working');
	btn.attrs.click(EV);
	assert.equal(view.rpcCalls.filter((c) => c.method === 'client_versions').length, 1,
		'a second press started a second fetch');
	resolve(LIST);
	await running;
	assert.ok(!btn.disabled, 'the button never came back');
	assert.equal(findAllClass(btn, 'spinning').length, 0);
});

test('a fetched list fills the select, and the selection is left alone', async () => {
	const { ctx, band } = card({ rpc: { client_versions: LIST } });
	const sel = ctx.refs.app_version;
	const before = sel.value;
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	LIST.versions.forEach((v) => assert.ok(options(sel).includes(v),
		v + ' is missing from the list'));
	assert.match(labels(sel).join(' '), /current/i,
		'nothing marks which release upstream ships now');
	assert.equal(sel.value, before, 'fetching the list changed the setting by itself');
	assert.equal(ctx.dirty, 0, 'fetching alone marked the form dirty');
});

test('the built-in option stays reachable after a fetch', async () => {
	const { ctx, band } = card({ rpc: { client_versions: LIST } });
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	// Going back to the package's own version is the correct choice for almost
	// everyone, so a successful fetch must not be able to take it away.
	assert.ok(options(ctx.refs.app_version).includes(''),
		'a fetch removed the way back to the built-in version');
});

test('a saved value the fetch does not know about is still offered', async () => {
	const { ctx, band } = card({
		uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main',
			app_version: 'linux-vpn-gtk@3.0.0' } } },
		rpc: { client_versions: LIST }
	});
	const sel = ctx.refs.app_version;
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	assert.ok(options(sel).includes('linux-vpn-gtk@3.0.0'),
		'a fetch dropped the value that is actually in force');
	assert.equal(sel.value, 'linux-vpn-gtk@3.0.0',
		'a fetch moved the selection off the value in force');
});

test('a saved value the fetch DOES know about is offered once', async () => {
	const { ctx, band } = card({
		uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main',
			app_version: 'linux-vpn-gtk@4.17.0' } } },
		rpc: { client_versions: LIST }
	});
	const sel = ctx.refs.app_version;
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	assert.equal(options(sel).filter((v) => v === 'linux-vpn-gtk@4.17.0').length, 1,
		'the value in force is listed twice');
});

test('picking an entry marks the form dirty and nothing else does', async () => {
	const { ctx, band } = card({ rpc: { client_versions: LIST } });
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	const sel = ctx.refs.app_version;
	sel.value = 'linux-vpn-gtk@4.17.0';
	fire(sel, 'change');
	assert.equal(ctx.refs.app_version.value, 'linux-vpn-gtk@4.17.0');
	assert.ok(ctx.dirty > 0, 'the pick left the form looking saved');
});

test('a second fetch keeps the choice the user already made', async () => {
	const { ctx, band } = card({ rpc: { client_versions: LIST } });
	const btn = findOneClass(band, 'pv-appver-fetch');
	await btn.attrs.click(EV);
	const sel = ctx.refs.app_version;
	sel.value = 'linux-vpn-gtk@4.9.0';
	fire(sel, 'change');
	await btn.attrs.click(EV);
	assert.equal(sel.value, 'linux-vpn-gtk@4.9.0',
		'refilling the list threw away an unsaved choice');
});

test('a repaint keeps a fetched list and an unsaved choice', async () => {
	const { ctx, band } = card({ rpc: { client_versions: LIST } });
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	const sel = ctx.refs.app_version;
	sel.value = 'linux-vpn-gtk@4.9.0';
	fire(sel, 'change');
	// The 5-second status poll repaints this card. Rebuilding the control
	// there would wipe both the fetched list and the user's pick, on a timer,
	// while they are looking at it.
	ctx.renderBand();
	const after = findOneClass(band, 'pv-appver-list');
	assert.equal(after.value, 'linux-vpn-gtk@4.9.0',
		'the poll threw away an unsaved choice');
	assert.ok(options(after).includes('linux-vpn-gtk@4.17.0'),
		'the poll threw away the fetched list');
	assert.equal(ctx.refs.app_version, after,
		'the ref points at a control the card no longer shows');
});

// The control is on the account card, but it is collected and validated with
// the form. buildFormSections() resets `refs`, so without a re-registration
// save() would stop seeing the setting at all — and a discard would leave the
// abandoned choice sitting on the card.
test('rebuilding the form keeps the control wired to it', () => {
	const { ctx } = card({ uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main',
		app_version: 'linux-vpn-gtk@4.9.0' } } } });
	const sel = ctx.refs.app_version;
	ctx.buildFormSections();
	assert.equal(ctx.refs.app_version, sel,
		'a form rebuild stranded the client-version control');
});

test('a form rebuild puts the control back on what uci holds', async () => {
	const { ctx } = card({
		uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main',
			app_version: 'linux-vpn-gtk@4.9.0' } } },
		rpc: { client_versions: LIST }
	});
	const sel = ctx.refs.app_version;
	await findOneClass(ctx.bandEl, 'pv-appver-fetch').attrs.click(EV);
	sel.value = 'linux-vpn-gtk@4.18.2';
	// Discard rebuilds the form from uci; the card is not rebuilt with it, so
	// an unsaved choice would otherwise survive a discard.
	ctx.buildFormSections();
	assert.equal(sel.value, 'linux-vpn-gtk@4.9.0',
		'a discard left the abandoned choice on the card');
	assert.ok(options(sel).includes('linux-vpn-gtk@4.17.0'),
		'a discard threw away the fetched list as well');
});

// ── degrading honestly ───────────────────────────────────────────────────

test('a fetch that fails says so and leaves the choices standing', async () => {
	const { ctx, band } = card({
		uci: { protonvpn: { main: { '.type': 'instance', '.name': 'main',
			app_version: 'linux-vpn-gtk@4.9.0' } } },
		rpc: { client_versions: { versions: [], current: '',
			error: 'the released versions could not be fetched (tags: HTTP 403)' } }
	});
	const sel = ctx.refs.app_version;
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	assert.ok(/HTTP 403/.test(findClass(band, 'pv-appver-note') || ''),
		'the reason the list is missing never reached the page');
	// A failed fetch must not turn the control into a dead end: the built-in
	// option and the value in force are both still choosable.
	assert.deepEqual(options(sel).slice().sort(), [ '', 'linux-vpn-gtk@4.9.0' ]);
	assert.equal(sel.value, 'linux-vpn-gtk@4.9.0', 'a failed fetch changed the setting');
});

test('a fetch that fails after one that worked keeps the list it had', async () => {
	let answer = LIST;
	const { ctx, band } = card({ rpc: { client_versions: () => Promise.resolve(answer) } });
	const btn = findOneClass(band, 'pv-appver-fetch');
	await btn.attrs.click(EV);
	// Upstream goes down between the two presses. Emptying the list here would
	// take away choices the user could see a moment ago, over a failure that
	// told us nothing new about which versions exist.
	answer = { versions: [], current: '', error: 'tags: HTTP 503' };
	await btn.attrs.click(EV);
	LIST.versions.forEach((v) => assert.ok(options(ctx.refs.app_version).includes(v),
		'a failed second fetch threw away ' + v));
	assert.match(findClass(band, 'pv-appver-note') || '', /HTTP 503/,
		'the second failure was not reported');
});

test('an rpc that rejects does not take the page down', async () => {
	const { ctx, band } = card({
		rpc: { client_versions: () => Promise.reject(new Error('ubus call failed')) }
	});
	const btn = findOneClass(band, 'pv-appver-fetch');
	await btn.attrs.click(EV);
	assert.ok(/could not/i.test(findClass(band, 'pv-appver-note') || ''),
		'the failure is swallowed and the user is told nothing');
	assert.ok(!btn.disabled, 'the button is left dead after a rejected call');
	assert.ok(options(ctx.refs.app_version).includes(''),
		'a rejected call left no choice at all');
});

test('a partly retrieved list is offered with the problem named', async () => {
	const { ctx, band } = card({
		rpc: { client_versions: { versions: [ 'linux-vpn-gtk@4.17.0' ], current: '',
			error: 'the current release could not be fetched (versions.yml: HTTP 500)' } }
	});
	await findOneClass(band, 'pv-appver-fetch').attrs.click(EV);
	assert.ok(options(ctx.refs.app_version).includes('linux-vpn-gtk@4.17.0'),
		'what was retrieved is thrown away because the rest failed');
	assert.match(findClass(band, 'pv-appver-note') || '', /HTTP 500/);
});

// ── saving ───────────────────────────────────────────────────────────────

test('the chosen value is saved like any other setting', () => {
	const { spec, uciData } = loadView({ uci: {
		protonvpn: { main: { '.type': 'instance', '.name': 'main' } }
	} });
	const ctx = makeCtx(spec, {
		refs: { app_version: { value: 'linux-vpn-gtk@4.17.0' } },
		autoRouting: { checked: false }, ksBox: { checked: false },
		v6Sel: { value: 'auto' }, v6Only: { checked: false }, dnsSel: { value: 'off' },
		steerBoxes: {}, hopValue: 'standard', poolEntries: [], _serverChosen: ''
	});
	ctx.collectIntoUci();
	assert.equal(uciData.protonvpn.main.app_version, 'linux-vpn-gtk@4.17.0');
});

test('the value is saved into the globals section when there is one', () => {
	const { spec, uciData } = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main' },
		globals: { '.type': 'globals', '.name': 'globals' }
	} } });
	const ctx = makeCtx(spec, {
		refs: { app_version: { value: 'linux-vpn-gtk@4.17.0' } },
		autoRouting: { checked: false }, ksBox: { checked: false },
		v6Sel: { value: 'auto' }, v6Only: { checked: false }, dnsSel: { value: 'off' },
		steerBoxes: {}, hopValue: 'standard', poolEntries: [], _serverChosen: ''
	});
	ctx.collectIntoUci();
	// The backend reads globals when it exists; writing to main would store a
	// value the router never stamps.
	assert.equal(uciData.protonvpn.globals.app_version, 'linux-vpn-gtk@4.17.0');
	assert.equal(uciData.protonvpn.main.app_version, undefined);
});

test('choosing the built-in option drops the override', () => {
	const { spec, uciData } = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'linux-vpn-gtk@4.9.0' }
	} } });
	const ctx = makeCtx(spec, {
		refs: { app_version: { value: '' } },
		autoRouting: { checked: false }, ksBox: { checked: false },
		v6Sel: { value: 'auto' }, v6Only: { checked: false }, dnsSel: { value: 'off' },
		steerBoxes: {}, hopValue: 'standard', poolEntries: [], _serverChosen: ''
	});
	ctx.collectIntoUci();
	assert.equal(uciData.protonvpn.main.app_version, undefined,
		'the built-in option leaves the old override stamped');
});

test('rpcd access to client_versions is granted', () => {
	const acl = JSON.parse(readFileSync(
		join(here, '../root/usr/share/rpcd/acl.d/luci-app-protonvpn.json'), 'utf8'));
	const app = acl['luci-app-protonvpn'];
	const granted = [].concat(app.read.ubus.protonvpn || [], app.write.ubus.protonvpn || []);
	// A method the page may call but the ACL does not list is a button that
	// works for root in a shell and for nobody in LuCI.
	assert.ok(granted.includes('client_versions'),
		'the page calls client_versions and the ACL does not allow it');
});

// ── saving a value the router would ignore ───────────────────────────────
//
// The select can only offer '' , the values the backend's own reader produced,
// and whatever is already in uci — so the only way a malformed value reaches
// Save is that last one, a config edited by hand. The backend's app_version()
// silently drops it and stamps the built-in version instead, so storing it
// would leave the page showing an override that is not in force: it looks
// applied, it changes nothing, and the next sign-in fails the same way. The
// save refuses, and the way out is one click away in the same control.

// The shapes the backend's own suite pins, mirrored here.
const REJECTED = [
	'garbage',
	'linux-vpn@4.9.0',
	'linux-vpn-gtk@4.18',
	'linux-vpn-gtk@4.18.2-beta',
	'xxlinux-vpn-gtk@4.18.2',
	'linux-vpn-gtk@4.18.2\nheader = "Injected: yes"',
	'LINUX-VPN-GTK@4.18.2',
	'linux-vpn-gtk@a.b.c'
];
// Surrounding whitespace is accepted because collectIntoUci() trims before
// storing, so what the router actually reads is the clean value. An interior
// newline is a different thing and stays in REJECTED: trimming cannot save it,
// and the backend refuses CR/LF outright because the value is concatenated
// into a curl config where an extra line injects options.
const ACCEPTED = [ '', '   ', 'linux-vpn-gtk@4.18.2 ', '\tlinux-vpn-gtk@4.18.2\n',
	'linux-vpn-gtk@4.18.2', 'linux-vpn-cli@1.0.0', 'linux-vpn-gtk@10.2.30' ];

// A context far enough through save() to reach (or be stopped before) the
// collectIntoUci() call.
function saveCtx(view, value) {
	const ctx = makeCtx(view.spec, {
		refs: { app_version: { value: value } },
		poolEntries: [ { code: 'DE', count: 4 } ],
		autoRouting: { checked: false }, ksBox: { checked: false },
		v6Sel: { value: 'auto' }, v6Only: { checked: false }, dnsSel: { value: 'off' },
		steerBoxes: {}, hopValue: 'standard', _serverChosen: '',
		saveBtn: El('button', {}), discardBtn: El('button', {})
	});
	ctx.collected = 0;
	ctx.collectIntoUci = function () { this.collected++; };
	ctx.applyAsync = () => Promise.resolve({ state: 'success', gateway: 'DE#1' });
	ctx.forgetExternalIp = () => {};
	ctx.clearChangeIndicator = () => {};
	ctx.refreshStatus = () => Promise.resolve();
	ctx.buildFormSections = () => [];
	ctx.formNode = El('div', {});
	return ctx;
}

REJECTED.forEach((bad) => {
	test('save refuses the malformed client version ' + JSON.stringify(bad), () => {
		const view = loadView({ uci: { protonvpn: {
			main: { '.type': 'instance', '.name': 'main' } } } });
		const ctx = saveCtx(view, bad);
		ctx.save();
		assert.equal(ctx.collected, 0,
			'a value the router will ignore was collected for saving');
		assert.ok((ctx._notices || []).length > 0, 'the user was not told why nothing was saved');
		assert.equal(view.uciData.protonvpn.main.app_version, undefined);
		assert.equal(view.uciData.protonvpn.globals, undefined);
	});
});

ACCEPTED.forEach((good) => {
	test('save accepts the client version ' + JSON.stringify(good), () => {
		const view = loadView({ uci: { protonvpn: {
			main: { '.type': 'instance', '.name': 'main' } } } });
		const ctx = saveCtx(view, good);
		ctx.save();
		assert.equal(ctx.collected, 1,
			'a value the router accepts was refused');
	});
});

test('the refusal names the value that was refused', () => {
	const view = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main' } } } });
	const ctx = saveCtx(view, 'linux-vpn@4.9.0');
	ctx.save();
	const said = (ctx._notices || []).map((n) => n.text).join(' ');
	assert.match(said, /linux-vpn@4\.9\.0/, 'the message does not say which value is wrong');
	assert.match(said, /linux-vpn-gtk@/, 'the message does not show an acceptable shape');
});

test('the refusal also lands next to the control', () => {
	const view = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'garbage' } } } });
	const ctx = makeCtx(view.spec, {
		refs: {}, session: { state: 'active' }, bandEl: El('div', { class: 'pv-acct' })
	});
	ctx.renderBand();
	Object.assign(ctx, {
		poolEntries: [ { code: 'DE', count: 4 } ],
		saveBtn: El('button', {}), discardBtn: El('button', {})
	});
	ctx.collectIntoUci = () => assert.fail('a malformed value reached collectIntoUci');
	ctx.save();
	// The notice at the top of the page is not necessarily where the user is
	// looking; the control that has to change is on the card.
	assert.match(text(findOneClass(ctx.bandEl, 'pv-appver-note')) || '', /garbage/);
});

test('a save the control does not block still goes through', () => {
	const view = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main' } } } });
	const ctx = saveCtx(view, 'linux-vpn-gtk@4.18.2');
	// The pre-existing refusal must not have been displaced by the new one.
	ctx.poolEntries = [];
	ctx.save();
	assert.equal(ctx.collected, 0, 'the location check was lost');
	assert.match((ctx._notices || []).map((n) => n.text).join(' '), /at least one location/);
});

// ── naming the built-in version without a network round trip ──────────────
//
// The label on the "no override" option is the version this package stamps.
// It used to be learnable only from client_versions(), which is a fetch the
// user has to ask for — so the option read "Built into the package" and left
// them to guess which version that was, on the one control they reach for
// when a sign-in has just been refused for being too old. The backend now
// carries it on session_state, which the page already calls on load.

const BUILTIN = 'linux-vpn-gtk@4.18.2';

test('the built-in option names the version, straight from the session state', () => {
	const { ctx } = card({ session: { state: 'active',
		session_expires_at: 1900000000, app_version_builtin: BUILTIN } });
	assert.equal(text(ctx.appVerSel.children[0]),
		'Built into the package (' + BUILTIN + ')');
});

test('and the disclosure summary names it too, unopened', () => {
	const { ctx, band } = card({ session: { state: 'active',
		session_expires_at: 1900000000, app_version_builtin: BUILTIN } });
	void ctx;
	assert.match(text(findOneClass(band, 'pv-more-summary')),
		/Built into the package \(linux-vpn-gtk@4\.18\.2\)/);
});

test('a backend too old to send it still gives a usable label', () => {
	// Degrade honestly: the option is still the right one to pick, it just
	// cannot say which version it is.
	const { ctx } = card({ session: { state: 'active', session_expires_at: 1900000000 } });
	assert.equal(text(ctx.appVerSel.children[0]), 'Built into the package');
});

test('an override in force does not make the built-in label lie', () => {
	// The stored value is what is stamped; the built-in is what the empty
	// option means. Naming the built-in on the "no override" option is right
	// either way, and the summary follows the SELECTION, not the built-in.
	const { ctx, band } = card({
		uci: { protonvpn: { main: { '.type': 'instance',
			app_version: 'linux-vpn-gtk@4.18.1' } } },
		session: { state: 'active', session_expires_at: 1900000000,
			app_version_builtin: BUILTIN } });
	assert.equal(text(ctx.appVerSel.children[0]),
		'Built into the package (' + BUILTIN + ')');
	assert.match(text(findOneClass(band, 'pv-more-summary')), /4\.18\.1/);
});

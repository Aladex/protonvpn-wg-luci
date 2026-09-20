// SPDX-License-Identifier: MIT
// The Proton client version in Advanced settings: the field itself, and the
// button that asks upstream which versions exist.
//
// Why this suite exists: `app_version` is the header Proton gates sign-ins
// on, and it used to be reachable only over uci — the one setting a user
// needs precisely when they cannot sign in, hidden from the page they are
// sitting in front of. The button that now helps them find a value must stay
// help: it
// fetches a list, and the user picks and saves. A page that quietly restamps
// the version would break sign-ins for a reason its owner cannot see.
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

// Advanced settings, built against a config the test supplies.
function advanced(opts) {
	opts = opts || {};
	const uci = opts.uci || { protonvpn: { main: { '.type': 'instance', '.name': 'main' } } };
	const view = loadView({ uci, rpc: opts.rpc || {} });
	const ctx = makeCtx(view.spec, { refs: {}, dirty: 0 });
	ctx.markDirty = function () { this.dirty = (this.dirty || 0) + 1; };
	const panel = ctx.buildAdvanced();
	return { view, ctx, panel };
}

const fire = (el, ev) => (el.listeners[ev] || []).forEach((fn) => fn(EV));

test('Advanced settings carries a field for the Proton client version', () => {
	const { ctx, panel } = advanced();
	assert.ok(ctx.refs.app_version, 'no app_version field was built');
	assert.match(text(panel), /client version/i,
		'the field is there but nothing labels it');
});

test('the field shows what is configured today', () => {
	const { ctx } = advanced({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'linux-vpn-gtk@4.9.0' }
	} } });
	assert.equal(ctx.refs.app_version.attrs.value, 'linux-vpn-gtk@4.9.0');
});

test('the field reads the globals section when the config has one', () => {
	const { ctx } = advanced({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'linux-vpn-gtk@1.1.1' },
		globals: { '.type': 'globals', '.name': 'globals', app_version: 'linux-vpn-gtk@4.17.0' }
	} } });
	// globals_section() in the backend prefers globals, so the page must read
	// the value the router actually stamps, not a stale one from main.
	assert.equal(ctx.refs.app_version.attrs.value, 'linux-vpn-gtk@4.17.0');
});

test('building the page fetches no version list', () => {
	const { view } = advanced();
	assert.equal(view.rpcCalls.filter((c) => c.method === 'client_versions').length, 0,
		'the page reached out to the upstream repository just by being opened');
});

test('the button asks the backend once and shows that it is working', async () => {
	let resolve;
	const { view, ctx, panel } = advanced({
		rpc: { client_versions: () => new Promise((r) => { resolve = r; }) }
	});
	const btn = findOneClass(panel, 'pv-appver-fetch');
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

test('a fetched list is offered, and the field is left alone', async () => {
	const { ctx, panel } = advanced({ rpc: { client_versions: LIST } });
	const before = ctx.refs.app_version.value;
	await findOneClass(panel, 'pv-appver-fetch').attrs.click(EV);
	const sel = findOneClass(panel, 'pv-appver-list');
	assert.ok(sel, 'the fetched versions are not offered anywhere');
	const shown = text(sel);
	LIST.versions.forEach((v) => assert.ok(shown.includes(v), v + ' is missing from the list'));
	assert.match(shown, /current/i, 'nothing marks which release upstream ships now');
	assert.equal(ctx.refs.app_version.value, before,
		'fetching the list changed the setting by itself');
	assert.equal(ctx.dirty, 0, 'fetching alone marked the form dirty');
});

test('picking an entry fills the field and nothing else does', async () => {
	const { ctx, panel } = advanced({ rpc: { client_versions: LIST } });
	await findOneClass(panel, 'pv-appver-fetch').attrs.click(EV);
	const sel = findOneClass(panel, 'pv-appver-list');
	sel.value = 'linux-vpn-gtk@4.17.0';
	fire(sel, 'change');
	assert.equal(ctx.refs.app_version.value, 'linux-vpn-gtk@4.17.0');
	assert.ok(ctx.dirty > 0, 'the pick left the form looking saved');
});

test('the placeholder entry does not wipe the field', async () => {
	const { ctx, panel } = advanced({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'linux-vpn-gtk@4.9.0' }
	} }, rpc: { client_versions: LIST } });
	await findOneClass(panel, 'pv-appver-fetch').attrs.click(EV);
	const sel = findOneClass(panel, 'pv-appver-list');
	sel.value = '';
	fire(sel, 'change');
	assert.equal(ctx.refs.app_version.value, 'linux-vpn-gtk@4.9.0');
});

test('a fetch that fails says so instead of looking like nothing happened', async () => {
	const { ctx, panel } = advanced({
		rpc: { client_versions: { versions: [], current: '',
			error: 'the released versions could not be fetched (tags: HTTP 403)' } }
	});
	const before = ctx.refs.app_version.value;
	await findOneClass(panel, 'pv-appver-fetch').attrs.click(EV);
	const note = findClass(panel, 'pv-appver-note');
	assert.ok(note && /HTTP 403/.test(note),
		'the reason the list is missing never reached the page');
	assert.equal(findOneClass(panel, 'pv-appver-list'), null,
		'an empty list is offered as if it were a choice');
	assert.equal(ctx.refs.app_version.value, before,
		'a failed fetch changed the setting');
});

test('an rpc that rejects does not take the page down', async () => {
	const { panel } = advanced({
		rpc: { client_versions: () => Promise.reject(new Error('ubus call failed')) }
	});
	const btn = findOneClass(panel, 'pv-appver-fetch');
	await btn.attrs.click(EV);
	assert.ok(/could not/i.test(findClass(panel, 'pv-appver-note') || ''),
		'the failure is swallowed and the user is told nothing');
	assert.ok(!btn.disabled, 'the button is left dead after a rejected call');
});

test('a partly retrieved list is offered with the problem named', async () => {
	const { panel } = advanced({
		rpc: { client_versions: { versions: [ 'linux-vpn-gtk@4.17.0' ], current: '',
			error: 'the current release could not be fetched (versions.yml: HTTP 500)' } }
	});
	await findOneClass(panel, 'pv-appver-fetch').attrs.click(EV);
	assert.ok(findOneClass(panel, 'pv-appver-list'),
		'what was retrieved is thrown away because the rest failed');
	assert.match(findClass(panel, 'pv-appver-note') || '', /HTTP 500/);
});

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

test('emptying the field drops the override', () => {
	const { spec, uciData } = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main', app_version: 'linux-vpn-gtk@4.9.0' }
	} } });
	const ctx = makeCtx(spec, {
		refs: { app_version: { value: '  ' } },
		autoRouting: { checked: false }, ksBox: { checked: false },
		v6Sel: { value: 'auto' }, v6Only: { checked: false }, dnsSel: { value: 'off' },
		steerBoxes: {}, hopValue: 'standard', poolEntries: [], _serverChosen: ''
	});
	ctx.collectIntoUci();
	assert.equal(uciData.protonvpn.main.app_version, undefined,
		'an emptied field leaves the old override stamped');
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
// The field is free text and the backend accepts exactly one shape
// (app_version() in protonvpn.api). Anything else is silently dropped there
// and the built-in version is stamped instead — so storing it leaves the page
// showing an override that is not in force. That is the worst possible answer
// for a setting somebody is editing precisely because sign-ins are failing:
// it looks applied, it changes nothing, and the next sign-in fails the same
// way. The save has to refuse.

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

test('the refusal also lands next to the field', () => {
	const view = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main' } } } });
	const ctx = makeCtx(view.spec, { refs: {} });
	const panel = ctx.buildAdvanced();
	ctx.refs.app_version.value = 'garbage';
	Object.assign(ctx, {
		poolEntries: [ { code: 'DE', count: 4 } ],
		saveBtn: El('button', {}), discardBtn: El('button', {})
	});
	ctx.collectIntoUci = () => assert.fail('a malformed value reached collectIntoUci');
	ctx.save();
	// Advanced settings is a <details> the user may have open; the notice at
	// the top of the page is not where they are looking.
	assert.match(text(findOneClass(panel, 'pv-appver-note')) || '', /garbage/);
});

test('a save the field does not block still goes through', () => {
	const view = loadView({ uci: { protonvpn: {
		main: { '.type': 'instance', '.name': 'main' } } } });
	const ctx = saveCtx(view, 'linux-vpn-gtk@4.18.2');
	// The pre-existing refusal must not have been displaced by the new one.
	ctx.poolEntries = [];
	ctx.save();
	assert.equal(ctx.collected, 0, 'the location check was lost');
	assert.match((ctx._notices || []).map((n) => n.text).join(' '), /at least one location/);
});

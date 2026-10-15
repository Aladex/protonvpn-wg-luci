// SPDX-License-Identifier: MIT
// The server list can arrive in pages (issue #4): one ubus message cannot
// carry a country the size of the United States, and rpcd died trying. These
// run the real refreshServerList() against fake `servers` methods that answer
// the way protonvpn.uc does — the whole list when no offset is sent and it
// fits, a `paged` refusal when it does not, pages when an offset is sent —
// and check that the view ends up with the whole selection or, when it cannot
// get it, says so and leaves the pin alone.
//
// Run: node --test luci-app-protonvpn/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadView, makeCtx, El, findOneClass, findAllClass, text } from './luci-harness.mjs';

function relays(n, prefix) {
	const out = [];
	for (let i = 0; i < n; i++)
		out.push({ hostname: `node-us-${i}.example`, name: `${prefix || 'US'}#${i}`,
			country_code: 'us', city: 'Chicago', load: i % 100, features: 0 });
	return out;
}

const TOO_LARGE = { error: 'too many servers for one reply: reload the page', paged: true,
	available: true };

// A current backend over `lists[generation]`, paging by `size`. `genAt(n)`
// says which cache answers the n-th call, so a test can replace the cache in
// the middle of a walk.
function pagedServers(lists, size, genAt) {
	let calls = 0;
	return (_locations, _hop, offset) => {
		const gen = genAt ? genAt(calls) : 'g1';
		calls++;
		const all = lists[gen];
		if (offset === undefined)
			return all.length > size ? TOO_LARGE : { relays: all.slice(), available: true };
		const start = Math.min(Math.max(offset | 0, 0), all.length);
		const page = { relays: all.slice(start, start + size), total: all.length,
			offset: start, available: true, generation: gen };
		if (start + size < all.length)
			page.next = start + size;
		return page;
	};
}

function srvCtx(servers, state, uci) {
	const loaded = loadView({ rpc: { servers }, uci });
	const ctx = makeCtx(loaded.spec, Object.assign({
		srvTrigger: El('button', { class: 'cbi-button pv-srv-trigger' }),
		poolEntries: [ { code: 'us' } ], _serversReq: 0, _building: false,
		_serverChosen: '', _srvOpen: false, _serverData: null
	}, state));
	// Rendering and rotation gating are covered elsewhere; here only the data
	// the list is built from matters.
	ctx.srvRenderTrigger = () => {};
	ctx.srvRenderPanel = () => {};
	ctx.updateRotationAvailability = () => {};
	ctx.hopMode = () => 'standard';
	ctx.requireV6Active = () => false;
	ctx.dirty = 0;
	ctx.markDirty = () => { ctx.dirty++; };
	return { ctx, calls: () => loaded.rpcCalls.filter((c) => c.method === 'servers') };
}

const PIN = { protonvpn: { main: { fixed_server: 'US#2400' } } };

// The page's own first load runs while the form is being built, so it is not
// a user edit and never drops the persisted pin.
async function initialLoad(ctx) {
	ctx._building = true;
	await ctx.refreshServerList();
	ctx._building = false;
}
const names = (list) => list.map((r) => r.name);

test('a selection too large for one reply is fetched page by page', async () => {
	const all = relays(2500);
	const { ctx, calls } = srvCtx(pagedServers({ g1: all }, 1000));
	await ctx.refreshServerList();
	assert.deepEqual(names(ctx._serverData.relays), names(all),
		'only part of the selection made it into the list');
	assert.deepEqual(calls().map((c) => c.args[2]), [ undefined, 0, 1000, 2000 ],
		'asked unpaged first, then by the offset each page named');
	assert.deepEqual(calls()[1].args.slice(0, 2), [ [ 'us' ], 'standard' ]);
	assert.equal(ctx._serverError, null);
});

test('a selection that fits costs a single unpaged call', async () => {
	const { ctx, calls } = srvCtx(pagedServers({ g1: relays(5) }, 1000));
	await ctx.refreshServerList();
	assert.equal(ctx._serverData.relays.length, 5);
	assert.deepEqual(calls().map((c) => c.args[2]), [ undefined ]);
});

test('against a backend from before the paging the list still loads', async () => {
	// rpcd refuses an argument a method did not declare, so an offset sent to
	// an older backend is answered with UBUS_STATUS_INVALID_ARGUMENT, which
	// LuCI hands over as the bare number. The view must not depend on it:
	// its first call carries no offset, which is the call such a backend
	// answers with the whole list.
	const all = relays(40);
	const old = (_l, _h, offset) => offset !== undefined ? 2 : { relays: all.slice(), available: true };
	const { ctx, calls } = srvCtx(old, { _serverChosen: 'US#30' },
		{ protonvpn: { main: { fixed_server: 'US#30' } } });
	await ctx.refreshServerList();
	assert.deepEqual(names(ctx._serverData.relays), names(all));
	assert.equal(calls().length, 1);
	assert.equal(ctx._serverChosen, 'US#30');
});

test('a pin on a later page is not taken for an unreachable one', async () => {
	// The pin check looks the server up in the list. Judged against the first
	// page alone, a perfectly valid pin further down would be dropped the
	// moment the user touched the locations.
	const { ctx } = srvCtx(pagedServers({ g1: relays(2500) }, 1000),
		{ _serverChosen: 'US#2400' }, PIN);
	await ctx.refreshServerList();
	assert.equal(ctx._serverChosen, 'US#2400', 'the pin was dropped');
	assert.equal(ctx.dirty, 0);
});

test('a cache replaced mid-walk restarts the walk instead of mixing two lists', async () => {
	const lists = { g1: relays(2500, 'OLD'), g2: relays(1800, 'NEW') };
	const { ctx, calls } = srvCtx(pagedServers(lists, 1000, (n) => n < 2 ? 'g1' : 'g2'));
	await ctx.refreshServerList();
	assert.deepEqual(names(ctx._serverData.relays), names(lists.g2));
	assert.deepEqual(calls().map((c) => c.args[2]), [ undefined, 0, 1000, 0, 1000 ]);
});

test('a cache replaced within the same second is still told apart', async () => {
	// The review's case: A,B,C,D replaced by X,A,B,C,D between two pages, both
	// stamped in the same second. Spliced by offset that reads A,B,B,C,D. The
	// backend names each publication by its generation, not its timestamp,
	// and the view compares that.
	const mk = (ns) => ns.map((n) => ({ name: n, hostname: n + '.example' }));
	const lists = { g1: mk([ 'A', 'B', 'C', 'D' ]), g2: mk([ 'X', 'A', 'B', 'C', 'D' ]) };
	const base = pagedServers(lists, 2, (n) => n < 2 ? 'g1' : 'g2');
	const sameSecond = (l, h, o) => {
		const r = base(l, h, o);
		if (r.relays && o !== undefined)
			r.cached_at_epoch = 1;      // what an older reply would have compared
		return r;
	};
	const { ctx } = srvCtx(sameSecond);
	await ctx.refreshServerList();
	assert.deepEqual(names(ctx._serverData.relays), [ 'X', 'A', 'B', 'C', 'D' ]);
});

test('a list that never settles is an error, and the pin survives it', async () => {
	// Every call answers from another cache. After a few restarts the view has
	// to give up — but giving up must not look like success: the partial list
	// it holds says nothing about which servers exist, and the reachability
	// check would drop a pin it simply has not seen yet.
	let n = 0, flap = false;
	const before = relays(3);
	const flapping = (_l, _h, offset) => {
		n++;
		if (!flap)
			return { relays: before.slice(), available: true };
		if (offset === undefined)
			return TOO_LARGE;
		const o = offset | 0;
		return { relays: relays(3000).slice(o, o + 1000), total: 3000, offset: o,
			next: o + 1000 < 3000 ? o + 1000 : undefined, available: true,
			generation: 'g' + n };
	};
	const { ctx } = srvCtx(flapping, { _serverChosen: 'US#2400' }, PIN);
	await initialLoad(ctx);
	flap = true;
	n = 0;
	await ctx.refreshServerList();
	assert.ok(n < 20, `the walk made ${n} calls`);
	assert.equal(ctx._serverChosen, 'US#2400', 'the pin was dropped');
	assert.equal(ctx.dirty, 0, 'a failed load changed the configuration');
	assert.deepEqual(names(ctx._serverData.relays), names(before),
		'the last complete list for the same selection was not kept');
	assert.equal(typeof ctx._serverError, 'string');
});

test('a page that does not advance is an error, not the end of the list', async () => {
	let n = 0;
	const stuck = (_l, _h, offset) => {
		n++;
		if (offset === undefined)
			return TOO_LARGE;
		return { relays: relays(3), total: 9, offset: offset | 0, next: offset | 0,
			available: true, generation: 'g1' };
	};
	const { ctx } = srvCtx(stuck, { _serverChosen: 'US#2400' }, PIN);
	await ctx.refreshServerList();
	assert.equal(n, 2);
	assert.equal(ctx._serverData, null, 'a partial list was published');
	assert.equal(ctx._serverChosen, 'US#2400');
	assert.equal(typeof ctx._serverError, 'string');
});

test('pages that add up to less than their total are an error', async () => {
	const short = (_l, _h, offset) => offset === undefined ? TOO_LARGE
		: { relays: relays(4), total: 5, offset: 0, available: true, generation: 'g1' };
	const { ctx } = srvCtx(short, { _serverChosen: 'US#2400' }, PIN);
	await ctx.refreshServerList();
	assert.equal(ctx._serverData, null);
	assert.equal(ctx._serverChosen, 'US#2400');
	assert.equal(typeof ctx._serverError, 'string');
});

test('an error from the backend is shown, and the pin survives it', async () => {
	const refusing = () => ({ error: 'server entry 3 is too large to send', available: true });
	const { ctx } = srvCtx(refusing, { _serverChosen: 'US#2400' }, PIN);
	await ctx.refreshServerList();
	assert.match(ctx._serverError, /server entry 3 is too large to send/);
	assert.equal(ctx._serverChosen, 'US#2400');
	assert.equal(ctx.dirty, 0);
});

test('a call that failed in ubus says which status it got', async () => {
	// LuCI resolves a failed call with the bare status code when no data came
	// back (rpc.declare without `reject`), so the number is all there is to
	// tell the user — 6 is UBUS_STATUS_PERMISSION_DENIED, for one.
	const { ctx } = srvCtx(() => 6, { _serverChosen: 'US#2400' }, PIN);
	await ctx.refreshServerList();
	assert.match(ctx._serverError, /ubus code 6/);
	assert.equal(ctx._serverChosen, 'US#2400');
});

test('a failed later page keeps the last complete list for the same selection', async () => {
	let fail = false;
	const before = relays(2);
	const failing = (_l, _h, offset) => {
		if (!fail)
			return { relays: before.slice(), available: true };
		if (offset === undefined)
			return TOO_LARGE;
		if (offset > 0)
			return Promise.reject(new Error('page unavailable'));
		return { relays: relays(1000), total: 2000, offset: 0, next: 1000,
			available: true, generation: 'g1' };
	};
	const { ctx } = srvCtx(failing, { _serverChosen: 'US#1500' },
		{ protonvpn: { main: { fixed_server: 'US#1500' } } });
	await initialLoad(ctx);
	fail = true;
	await ctx.refreshServerList();
	assert.deepEqual(names(ctx._serverData.relays), names(before));
	assert.equal(ctx._serverChosen, 'US#1500');
	assert.match(ctx._serverError, /page unavailable/);
});

// A retained list belongs to the selection that produced it (locations and
// hop mode). After the user changes the selection and the new list fails to
// load, the old servers must not stay on offer: picking one stores it as
// fixed_server, and the backend resolves that name across the whole cache, so
// the next connection would go to the OLD location — CH while US is set.
function relaysIn(cc, n) {
	const out = [];
	for (let i = 0; i < n; i++)
		out.push({ hostname: `node-${cc}-${i}.example`, name: `${cc.toUpperCase()}#${i}`,
			country_code: cc, city: 'Somewhere', load: 10 + i, features: 0 });
	return out;
}

// Render the panel's list and press every row that picks a server, the way a
// user could. "Automatic" is left alone: it unpins, which is always allowed.
function pressEveryServerRow(ctx) {
	ctx._srvListEl = El('div', {});
	ctx._srvFilter = '';
	ctx.srvClosePanel = () => {};
	ctx.srvRenderList();
	const rows = findAllClass(ctx._srvListEl, 'pv-rowbtn')
		.filter((r) => r.attrs['data-pv-focus'] !== 'srv:auto');
	for (const r of rows)
		r.attrs.click({ stopPropagation() {}, preventDefault() {} });
	return { rows, rendered: text(ctx._srvListEl) };
}

test('a failed load for other locations offers none of the old servers', async () => {
	const servers = (locations) => locations[0] === 'ch'
		? { relays: relaysIn('ch', 3), available: true }
		: Promise.reject(new Error('page unavailable'));
	const { ctx } = srvCtx(servers, { poolEntries: [ { code: 'ch' } ], _serverChosen: 'US#2400' },
		PIN);
	await initialLoad(ctx);
	assert.equal(ctx._serverData.relays.length, 3, 'the CH list did not load');
	ctx.poolEntries = [ { code: 'us' } ];
	await ctx.refreshServerList();
	assert.match(ctx._serverError, /page unavailable/);
	assert.equal(ctx.srvLowestLoad(), null, 'Lowest load still offers a CH server');
	const { rows, rendered } = pressEveryServerRow(ctx);
	assert.equal(rows.length, 0, 'server rows from the old selection are still on offer');
	assert.doesNotMatch(rendered, /CH#/);
	assert.equal(ctx._serverChosen, 'US#2400', 'the pin changed');
	assert.equal(ctx.srvRelayByHost('CH#0'), null);
});

test('a failed load for another hop mode offers none of the old servers', async () => {
	let hop = 'standard';
	const servers = (_l, h) => h === 'standard'
		? { relays: relaysIn('ch', 3), available: true }
		: Promise.reject(new Error('page unavailable'));
	const { ctx } = srvCtx(servers, { poolEntries: [ { code: 'ch' } ], _serverChosen: '' });
	ctx.hopMode = () => hop;
	await initialLoad(ctx);
	assert.equal(ctx._serverData.relays.length, 3);
	hop = 'secure_core';
	await ctx.refreshServerList();
	assert.equal(ctx.srvLowestLoad(), null, 'Lowest load still offers a Standard server');
	const { rows } = pressEveryServerRow(ctx);
	assert.equal(rows.length, 0, 'Standard servers stay on offer for a Secure Core tunnel');
	assert.equal(ctx._serverChosen, '', 'a stale server was pinned');
});

test('a failed reload of the same selection keeps its servers on offer', async () => {
	// Same locations, same hop mode: the list is still the right one, only
	// not refreshed — taking it away would leave the user nothing to pick.
	let fail = false;
	const servers = () => fail ? Promise.reject(new Error('page unavailable'))
		: { relays: relaysIn('us', 3), available: true };
	const { ctx } = srvCtx(servers, { _serverChosen: '' });
	await initialLoad(ctx);
	fail = true;
	await ctx.refreshServerList();
	assert.equal(ctx.srvLowestLoad().name, 'US#0');
	const { rows } = pressEveryServerRow(ctx);
	assert.ok(rows.some((r) => r.attrs['data-pv-focus'] === 'srv:US#1'));
});

test('a successful load clears an earlier error', async () => {
	const { ctx } = srvCtx(pagedServers({ g1: relays(5) }, 1000), { _serverError: 'old' });
	await ctx.refreshServerList();
	assert.equal(ctx._serverError, null);
});

test('the error is drawn in the server panel with a way to try again', () => {
	const { ctx } = srvCtx(pagedServers({ g1: relays(5) }, 1000), {
		_serverError: 'page unavailable', _serverData: null,
		_srvListEl: El('div', {}), _srvFilter: ''
	});
	let retried = 0;
	ctx.refreshServerList = () => { retried++; };
	ctx.srvRenderList();
	const row = findOneClass(ctx._srvListEl, 'pv-srv-error');
	assert.ok(row, 'no error row');
	assert.match(text(row), /page unavailable/);
	const retry = findOneClass(row, 'pv-srv-retry');
	assert.ok(retry, 'no retry control');
	retry.attrs.click({ stopPropagation() {}, preventDefault() {} });
	assert.equal(retried, 1);
});

test('a newer refresh supersedes a walk that is still paging', async () => {
	let release;
	const gate = new Promise((r) => { release = r; });
	const all = relays(2500, 'OLD');
	let n = 0;
	const slow = (_l, _h, offset) => {
		n++;
		if (offset === undefined)
			return TOO_LARGE;
		const start = offset | 0;
		const page = { relays: all.slice(start, start + 1000), total: all.length,
			offset: start, available: true, generation: 'g1' };
		if (start + 1000 < all.length)
			page.next = start + 1000;
		// The second page of the first walk hangs until released.
		return n === 3 ? gate.then(() => page) : page;
	};
	const { ctx } = srvCtx(slow);
	const first = ctx.refreshServerList();
	await new Promise((r) => setTimeout(r, 0));
	// The user picks another location: a new walk starts and finishes.
	ctx.poolEntries = [];
	ctx.refreshServerList();
	release();
	await first;
	assert.equal(ctx._serverData, null,
		'the superseded walk wrote its list over the newer state');
	assert.equal(ctx._serverError, null, 'the superseded walk reported an error');
	assert.equal(n, 3, 'the superseded walk kept fetching pages');
});

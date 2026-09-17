// SPDX-License-Identifier: MIT
// What the location picker RENDERS as an accordion, executed against the real
// overview.js (see luci-harness.mjs).
//
// The reference interaction (Mullvad's documented picker, Proton's own
// client): the row body selects, a separate right-hand cell expands the
// country's cities in place — the list is never swapped for a city page.
// These tests pin the two hit targets per row and the behaviours that must
// survive the rework: whole-country toggle, per-city narrowing, partial
// marks, the chip click as the edit-mode entry, chip edit mode with its
// remove action, the filter driven through its own input listener, the
// per-hop-mode counters (standard, secure core AND tor) on country and city
// rows, the IPv6 count label, the metadata as a flex:none sibling of the
// ellipsising name, and the cache-supplied average load next to it.
//
// Run: node --test luci-app-protonvpn/tests/*.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadView, makeCtx, findClass, findAllClass, findOneClass, text, El } from './luci-harness.mjs';

const { spec, src } = loadView();

const EV = { stopPropagation() {} };

// Fresh fixture per test: DE with two cities, NL with one. Names come back
// as the raw ISO codes (no Intl in the harness), which keeps the row labels
// short and unambiguous.
function locations() {
	return { countries: [
		{ code: 'DE', standard_count: 4, cities: [
			{ code: 'DE-FRA', name: 'Frankfurt', standard_count: 2 },
			{ code: 'DE-BER', name: 'Berlin', standard_count: 2 } ] },
		{ code: 'NL', standard_count: 3, cities: [
			{ code: 'NL-AMS', name: 'Amsterdam', standard_count: 3 } ] }
	] };
}

// The state buildConnection() would have put on the context before the user
// opens anything: chip anchors present, entries resolved, _ccData filled.
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

function has(node, cls) {
	return String((node && node.attrs && node.attrs.class) || '')
		.split(/\s+/).includes(cls);
}

function accRows(el) {
	return findAllClass(el, 'pv-acc-row');
}

// The acc row for a location, matched on its name cell (flag + name in the
// .grow span). The counter, load figure and IPv6 label live in the separate
// pv-acc-meta sibling, so matching on the flattened row text would tie the
// lookup to a layout instead of to the row's identity.
function mustRow(el, label) {
	const row = accRows(el).find((r) => {
		const g = findOneClass(r, 'grow');
		const t = g ? text(g) : '';
		return t === label || t.endsWith(' ' + label);
	});
	assert.ok(row, 'no acc row renders ' + label);
	return row;
}

// The metadata sibling of a row's hit cell.
function metaOf(row) {
	const meta = findOneClass(cell(row, 'pv-acc-hit'), 'pv-acc-meta');
	assert.ok(meta, 'the hit cell carries a pv-acc-meta sibling');
	return meta;
}

function cell(row, cls) {
	return (row.children || []).find((c) => has(c, cls)) || null;
}

function codes(ctx) {
	return (ctx.poolEntries || []).map((e) => e.code);
}

// ── row structure ──────────────────────────────────────────────────────────

test('the Locations description matches the accordion picker', () => {
	const ctx = makeCtx(spec, { locations: locations() });
	ctx._building = true;
	const node = ctx.buildConnection();
	ctx._building = false;
	const loc = findAllClass(node, 'cbi-value').find((r) => {
		const title = findOneClass(r, 'cbi-value-title');
		return title && text(title) === 'Locations';
	});
	assert.ok(loc, 'the connection section renders no Locations row');
	const desc = findAllClass(loc, 'cbi-value-description').map(text).join(' ');
	assert.match(desc, /adds the whole country/, desc);
	assert.match(desc, /arrow/i,
		'the description never says how a country is expanded: ' + desc);
	assert.doesNotMatch(desc, /chip/i,
		'the description still sends the user to the chips: ' + desc);
	assert.doesNotMatch(desc, /back/i,
		'the description still mentions a screen to go back from: ' + desc);
});


test('country rows are acc rows built from a hit cell and a separate expand cell', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	assert.equal(accRows(ctx._poolListEl).length, 2,
		'one acc row per country');
	const de = mustRow(ctx._poolListEl, 'DE');
	assert.ok(has(de, 'pv-pool-row'), 'acc rows keep the base row class');
	assert.equal((de.children || []).length, 2,
		'a country row has exactly two cells (hit + exp)');
	assert.ok(has(cell(de, 'pv-acc-hit'), 'pv-acc-hit'), 'first cell is the hit');
	assert.ok(has(cell(de, 'pv-acc-exp'), 'pv-acc-exp'), 'second cell is the expander');
});

test('the hit cell toggles the whole country; the exp cell does not select', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	assert.deepEqual(codes(ctx), [],
		'expanding must not put the country in the set by itself');
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-hit').attrs.click(EV);
	assert.deepEqual(codes(ctx), [ 'DE' ], 'the hit adds the whole country');
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-hit').attrs.click(EV);
	assert.deepEqual(codes(ctx), [], 'a second hit takes it back out');
});

// ── inline expansion ───────────────────────────────────────────────────────

test('the exp cell expands and collapses the cities inline, never swapping the list', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	const el = ctx._poolListEl;
	assert.ok(has(mustRow(el, 'DE'), 'pv-acc-open'),
		'the expanded country carries pv-acc-open');
	assert.equal(accRows(el).filter((r) => has(r, 'pv-acc-city')).length, 2,
		'DE shows its two cities inline');
	assert.ok(mustRow(el, 'NL'), 'the rest of the country list stays on screen');
	assert.ok(text(el).indexOf('Back to countries') < 0,
		'the page-swap head must not come back');
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	assert.equal(accRows(ctx._poolListEl).filter((r) => has(r, 'pv-acc-city')).length, 0,
		'a second exp click collapses the cities');
	assert.ok(!has(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-open'));
});

test('a city hit narrows the country and the row shows the partial mark', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	cell(mustRow(ctx._poolListEl, 'Frankfurt'), 'pv-acc-hit').attrs.click(EV);
	assert.deepEqual(codes(ctx), [ 'DE-FRA' ], 'one city hit narrows to that city');
	const de = mustRow(ctx._poolListEl, 'DE');
	assert.ok(has(de, 'is-in'), 'a narrowed country reads as already picked');
	assert.equal(findClass(de, 'box'), '▪', 'the partial mark is ▪');
});

test('unchecking a city from a whole country keeps the other cities', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'DE', kind: 'country' } ] });
	ctx.poolTogglePanel();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	cell(mustRow(ctx._poolListEl, 'Frankfurt'), 'pv-acc-hit').attrs.click(EV);
	assert.deepEqual(codes(ctx), [ 'DE-BER' ],
		'from a whole country, one unchecked city leaves the others');
});

test('the city exp cell is an inert spacer that keeps the column aligned', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	const fra = mustRow(ctx._poolListEl, 'Frankfurt');
	assert.ok(has(fra, 'pv-acc-city'), 'city rows carry pv-acc-city');
	const spacer = cell(fra, 'pv-acc-exp');
	assert.ok(spacer, 'the city row keeps the exp column');
	assert.equal(text(spacer), '', 'the spacer stays empty');
	assert.ok(!spacer.attrs.click, 'the spacer is not a click target');
});

// ── chip edit mode ─────────────────────────────────────────────────────────

test('chips render as inspectable elements, and a chip click opens edit mode', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	const chips = findAllClass(ctx.poolChips, 'pv-chip');
	assert.equal(chips.length, 1, 'one chip per picked country');
	assert.ok(text(chips[0]).indexOf('NL') >= 0, 'the chip shows its country');
	assert.equal(typeof chips[0].attrs.click, 'function',
		'the chip is a click target (the edit-mode entry path)');
	chips[0].attrs.click(EV);
	assert.equal(ctx._poolOpen, true, 'the panel opens');
	assert.equal(ctx._poolEdit, true, 'in edit mode');
	assert.equal(ctx._poolCountry, 'NL', 'for the chip country');
	assert.ok(has(mustRow(ctx._poolListEl, 'NL'), 'pv-acc-open'),
		'with that country expanded');
});

test('chip edit mode opens the same accordion with that country expanded', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	ctx.poolOpenCountry('NL', true);
	assert.deepEqual(codes(ctx), [ 'NL' ], 'edit mode does not duplicate the entry');
	assert.ok(has(mustRow(ctx._poolListEl, 'NL'), 'pv-acc-open'),
		'the edited country arrives expanded');
	assert.ok(mustRow(ctx._poolListEl, 'DE'),
		'edit mode renders the whole accordion, not a single country');
	assert.ok(accRows(ctx._poolListEl).some((r) => has(r, 'pv-acc-city')),
		'the edited country shows its cities');
	assert.ok(text(ctx._poolListEl).indexOf('Back to countries') < 0,
		'edit mode has no back head either');
});

test('edit mode on a country outside the set adds it whole', () => {
	const ctx = pickerCtx();
	ctx.poolOpenCountry('DE', true);
	assert.deepEqual(codes(ctx), [ 'DE' ]);
});

test('the remove row keeps the hit+exp structure and removes the country', () => {
	const ctx = pickerCtx({ poolEntries: [ { code: 'NL', kind: 'country' } ] });
	ctx.poolOpenCountry('NL', true);
	const rm = accRows(ctx._poolListEl).filter((r) => has(r, 'pv-pool-remove'));
	assert.equal(rm.length, 1, 'edit mode offers exactly one remove row');
	assert.ok(has(rm[0], 'pv-acc-row'), 'the remove row is an acc row');
	assert.equal((rm[0].children || []).length, 2, 'with the hit+exp structure');
	assert.match(text(cell(rm[0], 'pv-acc-hit')), /Remove this country/);
	cell(rm[0], 'pv-acc-hit').attrs.click(EV);
	assert.deepEqual(codes(ctx), [], 'the remove action drops the country');
	assert.equal(ctx._poolOpen, false, 'and closes the panel');
});

test('the plain add flow offers no remove row', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	assert.equal(accRows(ctx._poolListEl).filter((r) => has(r, 'pv-pool-remove')).length, 0,
		'remove is an edit-mode-only affordance');
});

// ── the filter ─────────────────────────────────────────────────────────────

test('typing in the filter input narrows the list through its own listener', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	const filt = findOneClass(ctx.poolPanel, 'pv-pool-filter');
	assert.ok(filt, 'the panel carries the filter input');
	assert.ok(filt.listeners && filt.listeners.input && filt.listeners.input.length,
		'the filter input has an input listener');
	filt.value = 'nl';
	filt.listeners.input.forEach((fn) => fn());
	assert.ok(mustRow(ctx._poolListEl, 'NL'), 'the matching country stays');
	assert.equal(accRows(ctx._poolListEl).filter((r) => !has(r, 'pv-acc-city')).length, 1,
		'typing narrows the accordion to the match');
});

test('the filter still narrows the accordion to matching countries', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	ctx._poolFilter = 'nl';
	ctx.poolRenderCountryList();
	assert.ok(mustRow(ctx._poolListEl, 'NL'), 'the matching country stays');
	assert.equal(accRows(ctx._poolListEl).filter((r) => !has(r, 'pv-acc-city')).length, 1,
		'only the matching country is listed');
});

test('a filter with no hits keeps the plain no-matches row', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	ctx._poolFilter = 'zzz';
	ctx.poolRenderCountryList();
	const plain = findAllClass(ctx._poolListEl, 'pv-pool-row')
		.filter((r) => !has(r, 'pv-acc-row'));
	assert.equal(plain.length, 1, 'exactly one plain row');
	assert.ok(has(plain[0], 'is-in'), 'it keeps the muted state');
	assert.equal(text(plain[0]), 'No matches');
});

// ── counters and labels that must survive the rework ───────────────────────

test('rows keep the per-hop-mode gateway counters', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'DE'))), /\(4\)/);
	ctx.hopValue = 'secure_core';
	ctx.locations.countries[0].secure_core_count = 9;
	ctx.poolRenderCountryList();
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'DE'))), /\(9\)/,
		'secure_core uses secure_core_count, not standard_count');
});

test('tor mode counts tor gateways on country and city rows', () => {
	const ctx = pickerCtx();
	ctx.hopValue = 'tor';
	ctx.locations.countries[0].tor_count = 7;
	ctx.locations.countries[0].cities[0].tor_count = 5;
	ctx.locations.countries[0].cities[1].tor_count = 2;
	ctx.poolTogglePanel();
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'DE'))), /\(7\)/,
		'the country row shows tor_count');
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'Frankfurt'))), /\(5\)/,
		'city rows count tor gateways too');
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'Berlin'))), /\(2\)/);
});

test('city rows carry their own counter, not the country total', () => {
	const ctx = pickerCtx();
	ctx.locations.countries[0].cities[1].standard_count = 1;
	ctx.poolTogglePanel();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'Frankfurt'))), /\(2\)/);
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'Berlin'))), /\(1\)/,
		'Berlin shows its own count');
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'DE'))), /\(4\)/,
		'the country keeps the total');
});

// ── the metadata sibling and the average load ──────────────────────────────

test('only the name ellipsises; the metadata is a flex:none sibling', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	const hit = cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-hit');
	const grow = findOneClass(hit, 'grow');
	assert.ok(grow, 'the name keeps its grow span');
	assert.ok(!/\(\d+\)/.test(text(grow)),
		'the counter is not inside the ellipsised name');
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'DE'))), /\(4\)/,
		'the counter lives in the metadata sibling');
	assert.ok(/\.pv-pool-acc \.pv-acc-meta\{[^}]*flex:none/.test(src),
		'the metadata never shrinks (flex:none)');
	assert.ok(/\.pv-pool-row \.grow\{[^}]*flex:1[^}]*text-overflow:ellipsis/.test(src),
		'the name span is the one that ellipsises');
	const cityHit = cell((() => {
		cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
		return mustRow(ctx._poolListEl, 'Frankfurt');
	})(), 'pv-acc-hit');
	assert.ok(findOneClass(cityHit, 'pv-acc-meta'),
		'city rows split name and metadata the same way');
	assert.ok(!/\(\d+\)/.test(text(findOneClass(cityHit, 'grow'))),
		'the city name ellipsises alone too');
});

test('rows show the cache average load as a coloured dot and figure', () => {
	const ctx = pickerCtx();
	ctx.locations.countries[0].standard_load = 23;
	ctx.locations.countries[0].cities[0].standard_load = 81;
	ctx.poolTogglePanel();
	const deMeta = metaOf(mustRow(ctx._poolListEl, 'DE'));
	assert.match(text(deMeta), /23%/, 'the country row shows the average load');
	const deDot = findAllClass(deMeta, 'pv-dot')[0];
	assert.ok(deDot && has(deDot, 'pv-dot-lo'), 'a low average takes the green dot');
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	const fraMeta = metaOf(mustRow(ctx._poolListEl, 'Frankfurt'));
	assert.match(text(fraMeta), /81%/, 'city rows carry their own average');
	const fraDot = findAllClass(fraMeta, 'pv-dot')[0];
	assert.ok(fraDot && has(fraDot, 'pv-dot-hi'), 'a high average takes the red dot');
});

test('the load figure follows the hop mode like the counter does', () => {
	const ctx = pickerCtx();
	ctx.hopValue = 'tor';
	ctx.locations.countries[0].tor_count = 7;
	ctx.locations.countries[0].cities[0].tor_count = 5;
	ctx.locations.countries[0].cities[1].tor_count = 2;
	ctx.locations.countries[0].standard_load = 10;
	ctx.locations.countries[0].tor_load = 96;
	ctx.poolTogglePanel();
	const meta = metaOf(mustRow(ctx._poolListEl, 'DE'));
	assert.match(text(meta), /96%/, 'tor mode shows tor_load');
	assert.ok(!/10%/.test(text(meta)), 'not the standard figure');
});

test('every hop mode reads its own load key, on country and city rows', () => {
	const ctx = pickerCtx();
	const de = ctx.locations.countries[0];
	const fra = de.cities[0];
	// Distinct figure per kind and per row, so reading the wrong key (or the
	// wrong row) always shows a number the assertions can name.
	de.standard_count = 4; de.secure_core_count = 4; de.tor_count = 4;
	fra.standard_count = 2; fra.secure_core_count = 2; fra.tor_count = 2;
	de.standard_load = 10; de.secure_core_load = 42; de.tor_load = 96;
	fra.standard_load = 11; fra.secure_core_load = 43; fra.tor_load = 97;
	ctx.poolTogglePanel();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	[ { hop: 'standard', country: 10, city: 11 },
		{ hop: 'secure_core', country: 42, city: 43 },
		{ hop: 'tor', country: 96, city: 97 } ].forEach((m) => {
		ctx.hopValue = m.hop;
		ctx.poolRenderCountryList();
		const all = [10, 42, 96, 11, 43, 97];
		const deMeta = text(metaOf(mustRow(ctx._poolListEl, 'DE')));
		assert.ok(deMeta.indexOf(m.country + '%') >= 0,
			m.hop + ' shows its own country load');
		all.filter((v) => v !== m.country).forEach((v) =>
			assert.ok(deMeta.indexOf(v + '%') < 0,
				m.hop + ' country row never shows ' + v + '%'));
		const fraMeta = text(metaOf(mustRow(ctx._poolListEl, 'Frankfurt')));
		assert.ok(fraMeta.indexOf(m.city + '%') >= 0,
			m.hop + ' shows its own city load');
		all.filter((v) => v !== m.city).forEach((v) =>
			assert.ok(fraMeta.indexOf(v + '%') < 0,
				m.hop + ' city row never shows ' + v + '%'));
	});
});

test('an explicit null load renders like a missing one; a real zero renders 0%', () => {
	const ctx = pickerCtx();
	// The backend emits null for an absent kind, not a missing field.
	ctx.locations.countries[0].standard_load = null;
	ctx.locations.countries[0].cities[0].standard_load = 0;
	ctx.locations.countries[0].cities[1].standard_load = null;
	ctx.poolTogglePanel();
	const deMeta = metaOf(mustRow(ctx._poolListEl, 'DE'));
	assert.equal(findAllClass(deMeta, 'pv-dot').length, 0,
		'explicit null renders no dot');
	assert.ok(!/\d+%/.test(text(deMeta)), 'null is not turned into a 0% figure');
	assert.match(text(deMeta), /\(4\)/, 'the counter still shows');
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	const fraMeta = metaOf(mustRow(ctx._poolListEl, 'Frankfurt'));
	assert.match(text(fraMeta), /0%/, 'a real 0% is data and renders');
	const fraDot = findAllClass(fraMeta, 'pv-dot')[0];
	assert.ok(fraDot && has(fraDot, 'pv-dot-lo'), 'zero load takes the green dot');
	const berMeta = metaOf(mustRow(ctx._poolListEl, 'Berlin'));
	assert.equal(findAllClass(berMeta, 'pv-dot').length, 0,
		'city-level null renders no dot either');
	assert.ok(!/\d+%/.test(text(berMeta)), 'no invented city figure');
});

test('the metadata rule carries no clipping declarations', () => {
	const rule = src.match(/\.pv-pool-acc \.pv-acc-meta\{([^}]*)\}/);
	assert.ok(rule, 'the metadata rule exists');
	assert.ok(/flex:none/.test(rule[1]), 'the metadata never shrinks');
	assert.ok(!/max-width|overflow|text-overflow/.test(rule[1]),
		'the metadata is never width-capped, clipped or ellipsised');
});

test('a cache without load figures renders the count alone, no invented number', () => {
	const ctx = pickerCtx();
	ctx.poolTogglePanel();
	const meta = metaOf(mustRow(ctx._poolListEl, 'DE'));
	assert.equal(findAllClass(meta, 'pv-dot').length, 0, 'no dot without data');
	assert.ok(!/\d+%/.test(text(meta)), 'no percentage is invented');
	assert.match(text(meta), /\(4\)/, 'the counter still shows');
});

test('the IPv6 count label still lands in country and city rows', () => {
	const ctx = pickerCtx({
		v6Only: { checked: true },
		v6Sel: { value: 'auto' },
		autoRouting: { checked: false },
		steerBoxes: { guest: { checked: true } }
	});
	ctx.locations.countries[0].ipv6_count = 1;
	ctx.locations.countries[0].cities[0].ipv6_count = 0;
	ctx.poolTogglePanel();
	// The requirement defaults the IPv6-only filter on, and Frankfurt has no
	// IPv6 gateways: turn the filter off so the zero-IPv6 label can show.
	const v6t = v6Toggle(ctx.poolPanel);
	v6t.box.checked = false;
	v6t.box.attrs.change();
	assert.match(text(mustRow(ctx._poolListEl, 'DE')), /1\/4 IPv6/);
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	assert.match(text(mustRow(ctx._poolListEl, 'Frankfurt')), /no IPv6/);
});

// ── stylesheet, scoped so server-picker rows are untouched ─────────────────

test('the accordion panel geometry is scoped to the picker panel', () => {
	assert.ok(src.includes('.pv-pool-acc{width:100%;max-width:460px}'),
		'the picker panel widens to 460px');
	assert.ok(src.includes(
		'.pv-pool-acc .pv-acc-row{display:flex;align-items:stretch;gap:0;padding:0}'),
		'acc rows switch to stretched, unpadded flex');
	assert.ok(src.includes('.pv-pool-acc .pv-acc-row:hover{background:transparent}'),
		'the base row hover is neutralised inside the panel');
	assert.ok(src.includes('.pv-pool-acc .pv-acc-row.pv-acc-open:hover{'),
		'the expanded row keeps its tint on hover');
	assert.ok(src.includes("class: 'pv-pool-panel pv-pool-acc hidden'"),
		'the location panel element carries pv-pool-acc');
	assert.ok(src.includes("class: 'pv-pool-panel hidden'"),
		'the server panel keeps its plain panel class');
});

test('the hit and exp cells carry their own hover and column geometry', () => {
	assert.ok(/\.pv-pool-acc \.pv-acc-hit\{[^}]*flex:1/.test(src),
		'the hit takes the row width (flex:1)');
	assert.ok(src.includes('.pv-pool-acc .pv-acc-hit:hover{'),
		'the hit has its own hover');
	assert.ok(/\.pv-pool-acc \.pv-acc-exp\{[^}]*width:34px/.test(src) &&
		/\.pv-pool-acc \.pv-acc-exp\{[^}]*border-left/.test(src) &&
		/\.pv-pool-acc \.pv-acc-exp\{[^}]*align-self:stretch/.test(src),
		'the exp cell is the 34px bordered column');
	assert.ok(src.includes('.pv-pool-acc .pv-acc-exp:hover{'),
		'the exp cell has its own hover');
	assert.ok(/\.pv-acc-city \.pv-acc-hit\{[^}]*padding-left:2\.1em/.test(src),
		'city hits are indented to sit under the country name');
});

// ── the "IPv6 only" view filter ─────────────────────────────────────────
// A view filter, not a setting: it narrows what the accordion LISTS, never
// what the backend will connect to (that is require_ipv6's job), and it is
// never silent — the list says how many countries were dropped.

// The toggle's checkbox element inside the panel head.
function v6Toggle(panel) {
	const tog = findOneClass(panel, 'pv-pool-v6only');
	assert.ok(tog, 'the panel head carries the IPv6-only toggle');
	const box = (tog.children || []).find((c) => c && c.tag === 'input');
	assert.ok(box, 'the toggle has no checkbox');
	return { label: tog, box };
}

function v6HiddenLine(el) {
	const n = findOneClass(el, 'pv-pool-v6hidden');
	return n ? text(n) : null;
}

test('IPv6 only drops countries without IPv6 gateways and says how many', () => {
	const ctx = pickerCtx();
	ctx.locations.countries[0].ipv6_count = 2;
	ctx.locations.countries[1].ipv6_count = 0;
	ctx.poolTogglePanel();
	const { box } = v6Toggle(ctx.poolPanel);
	assert.equal(box.checked, false, 'the toggle defaults to off without the requirement');
	box.checked = true;
	box.attrs.change();
	assert.ok(mustRow(ctx._poolListEl, 'DE'), 'the country with IPv6 stays');
	assert.equal(accRows(ctx._poolListEl).filter((r) => !has(r, 'pv-acc-city')).length, 1,
		'the zero-IPv6 country is still listed');
	assert.match(v6HiddenLine(ctx._poolListEl) || '', /1 country hidden/i,
		'the narrowing happens silently — no line says how much is hidden');
	// The user explicitly asked to look at IPv6, so the count shows even
	// though the requirement is off.
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'DE'))), /2\/4 IPv6/,
		'the N/M IPv6 count is gated on the requirement even while filtering by it');
	box.checked = false;
	box.attrs.change();
	assert.ok(mustRow(ctx._poolListEl, 'NL'), 'toggling back off restores the list');
	assert.equal(v6HiddenLine(ctx._poolListEl), null,
		'the hidden-count line outlives the filter');
});

test('IPv6 only drops zero-IPv6 cities inside an expanded country', () => {
	const ctx = pickerCtx();
	ctx.locations.countries[0].ipv6_count = 1;
	ctx.locations.countries[0].cities[0].ipv6_count = 1;
	ctx.locations.countries[0].cities[1].ipv6_count = 0;
	ctx.poolTogglePanel();
	const { box } = v6Toggle(ctx.poolPanel);
	box.checked = true;
	box.attrs.change();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	assert.ok(mustRow(ctx._poolListEl, 'Frankfurt'), 'the city with IPv6 stays');
	assert.equal(accRows(ctx._poolListEl).filter((r) => has(r, 'pv-acc-city')).length, 1,
		'the zero-IPv6 city is still listed');
	assert.match(text(metaOf(mustRow(ctx._poolListEl, 'Frankfurt'))), /1\/2 IPv6/);
});

test('the text filter and IPv6 only compose', () => {
	const ctx = pickerCtx();
	ctx.locations.countries[0].ipv6_count = 2;
	ctx.locations.countries[1].ipv6_count = 0;
	ctx.poolTogglePanel();
	const { box } = v6Toggle(ctx.poolPanel);
	box.checked = true;
	box.attrs.change();
	const filt = findOneClass(ctx.poolPanel, 'pv-pool-filter');
	filt.value = 'nl';
	filt.listeners.input.forEach((fn) => fn());
	// 'nl' matches NL by text, but NL has no IPv6: both conditions narrowed it.
	assert.equal(accRows(ctx._poolListEl).filter((r) => !has(r, 'pv-acc-city')).length, 0,
		'a row survived the combination of text filter and toggle');
	assert.match(text(ctx._poolListEl), /No matches/);
	assert.match(v6HiddenLine(ctx._poolListEl) || '', /1 country hidden/i);
});

test('the toggle is disabled with an explanation in Secure Core and never empties the list', () => {
	const ctx = pickerCtx();
	ctx.hopValue = 'secure_core';
	ctx.locations.countries.forEach((c) => {
		c.secure_core_count = c.standard_count;
		c.ipv6_count = 0;    // counted against the standard kind only
	});
	ctx.poolTogglePanel();
	const { label, box } = v6Toggle(ctx.poolPanel);
	assert.equal(box.disabled, true, 'the toggle stays clickable in Secure Core');
	assert.match(label.attrs.title || '', /Secure Core/i,
		'the disabled toggle does not say why: ' + label.attrs.title);
	// A toggle left on from Standard must not empty the other modes' lists.
	ctx._poolV6Only = true;
	ctx.poolRenderCountryList();
	assert.ok(mustRow(ctx._poolListEl, 'NL'),
		'the carried-over toggle emptied the Secure Core list');
});

test('switching hop mode with the toggle on re-renders the panel without an empty list', () => {
	const ctx = pickerCtx();
	ctx.locations.countries[0].ipv6_count = 2;
	ctx.locations.countries[1].ipv6_count = 0;
	ctx.locations.countries.forEach((c) => { c.secure_core_count = c.standard_count; });
	ctx.poolTogglePanel();
	const { box } = v6Toggle(ctx.poolPanel);
	box.checked = true;
	box.attrs.change();
	assert.equal(accRows(ctx._poolListEl).filter((r) => !has(r, 'pv-acc-city')).length, 1,
		'setup: the toggle is filtering');
	ctx.setHopMode('secure_core');
	assert.ok(mustRow(ctx._poolListEl, 'NL'),
		'the mode switch left the toggle silently filtering an IPv6-less mode');
	const after = v6Toggle(ctx.poolPanel);
	assert.equal(after.box.disabled, true,
		'the toggle is not re-rendered disabled after the mode switch');
});

test('the toggle defaults to on when the IPv6 requirement already applies', () => {
	const ctx = pickerCtx({
		v6Only: { checked: true },
		v6Sel: { value: 'auto' },
		autoRouting: { checked: false },
		steerBoxes: { guest: { checked: true } }
	});
	ctx.locations.countries[0].ipv6_count = 2;
	ctx.locations.countries[1].ipv6_count = 0;
	ctx.poolTogglePanel();
	const { box } = v6Toggle(ctx.poolPanel);
	assert.equal(box.checked, true,
		'the requirement is on but the picker still lists zero-IPv6 countries');
	assert.equal(accRows(ctx._poolListEl).filter((r) => !has(r, 'pv-acc-city')).length, 1);
	box.checked = false;
	box.attrs.change();
	assert.ok(mustRow(ctx._poolListEl, 'NL'), 'the user cannot turn the filter back off');
});

test('IPv6 only says how many cities it hides, even when no country is hidden', () => {
	const ctx = pickerCtx();
	// Both countries have IPv6; only cities inside them lack it, so the
	// narrowing is city-only and a country count could only lie.
	ctx.locations.countries.forEach((c) => { c.ipv6_count = 1; });
	ctx.locations.countries[0].cities[0].ipv6_count = 1; // Frankfurt
	ctx.locations.countries[0].cities[1].ipv6_count = 0; // Berlin
	ctx.locations.countries[1].cities[0].ipv6_count = 0; // Amsterdam
	ctx.poolTogglePanel();
	const { box } = v6Toggle(ctx.poolPanel);
	box.checked = true;
	box.attrs.change();
	cell(mustRow(ctx._poolListEl, 'DE'), 'pv-acc-exp').attrs.click(EV);
	assert.ok(mustRow(ctx._poolListEl, 'Frankfurt'), 'the city with IPv6 stays');
	assert.equal(accRows(ctx._poolListEl).filter((r) => has(r, 'pv-acc-city')).length, 1,
		'the zero-IPv6 city is still listed');
	const line = v6HiddenLine(ctx._poolListEl);
	assert.match(line || '', /1 city hidden/i,
		'Berlin vanished with zero hidden countries and the list says nothing');
	assert.doesNotMatch(line || '', /country hidden/i,
		'a country is reported hidden when none is');
	// Expanding the second country drops its zero-IPv6 city too.
	cell(mustRow(ctx._poolListEl, 'NL'), 'pv-acc-exp').attrs.click(EV);
	assert.match(v6HiddenLine(ctx._poolListEl) || '', /2 cities hidden/i,
		'the hidden-city count stops at one');
	// The opposite order — the cities already expanded when the toggle flips —
	// is the same narrowing and is reported the same.
	box.checked = false;
	box.attrs.change();
	assert.ok(mustRow(ctx._poolListEl, 'Berlin'), 'toggling off restores hidden cities');
	box.checked = true;
	box.attrs.change();
	assert.match(v6HiddenLine(ctx._poolListEl) || '', /2 cities hidden/i,
		'expand-then-enable narrows silently');
	// And the count follows the matched subset when a text filter applies.
	const filt = findOneClass(ctx.poolPanel, 'pv-pool-filter');
	filt.value = 'de';
	filt.listeners.input.forEach((fn) => fn());
	assert.match(v6HiddenLine(ctx._poolListEl) || '', /1 city hidden/i,
		'the hidden-city count does not follow the matched subset');
});

test('the hidden-country count is exact for several countries and follows the text filter', () => {
	const ctx = pickerCtx();
	ctx.locations.countries[0].ipv6_count = 0;
	ctx.locations.countries[1].ipv6_count = 0;
	ctx.poolTogglePanel();
	const { box } = v6Toggle(ctx.poolPanel);
	box.checked = true;
	box.attrs.change();
	assert.equal(v6HiddenLine(ctx._poolListEl), '2 countries hidden — no IPv6 gateways',
		'the plural line does not give the exact count');
	const filt = findOneClass(ctx.poolPanel, 'pv-pool-filter');
	filt.value = 'de';
	filt.listeners.input.forEach((fn) => fn());
	assert.equal(v6HiddenLine(ctx._poolListEl), '1 country hidden — no IPv6 gateways',
		'the count does not follow the matched subset');
});

test('the toggle is disabled with an explanation in Tor and never empties the list', () => {
	const ctx = pickerCtx();
	ctx.locations.countries.forEach((c) => {
		c.tor_count = c.standard_count;
		c.ipv6_count = 0;    // counted against the standard kind only
	});
	ctx.poolTogglePanel();
	// A toggle left on from Standard…
	const { box } = v6Toggle(ctx.poolPanel);
	box.checked = true;
	box.attrs.change();
	ctx.setHopMode('tor');
	// …must go inert there: disabled with the reason, and the Tor rows (which
	// do have gateways) retained rather than filtered by Standard counts.
	const after = v6Toggle(ctx.poolPanel);
	assert.equal(after.box.disabled, true, 'the toggle stays clickable in Tor');
	assert.match(after.label.attrs.title || '', /Tor/i,
		'the disabled toggle does not say why: ' + after.label.attrs.title);
	assert.ok(mustRow(ctx._poolListEl, 'DE'), 'the carried-over toggle emptied the Tor list');
	assert.ok(mustRow(ctx._poolListEl, 'NL'), 'the carried-over toggle emptied the Tor list');
});

test('the view filter is never written to uci', () => {
	const { spec: spec2, uciData } = loadView();
	const ctx = makeCtx(spec2, {
		refs: {},
		autoRouting: { checked: false },
		ksBox: { checked: false },
		v6Sel: { value: 'block' },
		v6Only: { checked: false },
		dnsSel: { value: 'off' },
		steerBoxes: { guest: { checked: true } },
		hopValue: 'standard',
		poolEntries: [],
		_serverChosen: '',
		_poolV6Only: true
	});
	ctx.collectIntoUci();
	const stored = uciData.protonvpn.main;
	assert.equal(stored.ipv6_only, undefined, 'the view filter leaked into uci');
	assert.equal(stored.require_ipv6, '0',
		'the view filter flipped the real requirement');
});

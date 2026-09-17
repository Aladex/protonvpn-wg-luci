// SPDX-License-Identifier: MIT
// Two rendering defects that only show up on the router itself, asserted
// against the real overview.js (see luci-harness.mjs):
//
//  1. The partial-selection mark in the location picker was U+25D0 ("◐").
//     The theme font (Helvetica) on the router has no glyph for it, so the
//     row mark renders as tofu. U+25AA ("▪") is known to be covered. The
//     whole/none marks ("☑"/blank, and "☑"/"☐" in the city panel) do render
//     and must not change.
//  2. Five stylesheet rules carried literal hex colours and so ignored the
//     theme: on a dark theme they showed light-theme green/amber/red/blue.
//     They must sit on the CSS custom properties the rest of the stylesheet
//     already uses, keeping the old literal as the fallback.
//
// Run: node --test luci-app-protonvpn/tests/*.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadView, makeCtx, findClass, El } from './luci-harness.mjs';

const { spec, src } = loadView();

// ── the partial-selection mark ─────────────────────────────────────────────
// The view appends rows with appendChild after dom.content(el, ''), and a
// bare El record has no appendChild — this one tolerates children having
// been reset to a string.

function listEl() {
	const el = El('div', {});
	el.appendChild = function (row) {
		this.children = (Array.isArray(this.children) ? this.children : [])
			.concat(row);
	};
	return el;
}

function renderCountryList(poolEntries) {
	const ctx = makeCtx(spec, {
		locations: { countries: [ {
			code: 'NL', standard_count: 3,
			cities: [ { code: 'NL-AMS', name: 'Amsterdam', standard_count: 3 } ]
		} ] },
		poolEntries: poolEntries
	});
	ctx._poolListEl = listEl();
	ctx.poolRenderCountryList();
	return ctx._poolListEl;
}

test('a partially selected country is marked with ▪, not the tofu ◐', () => {
	// One city of NL picked: whole=false, has=true — the partial state.
	const el = renderCountryList([ { code: 'NL-AMS', kind: 'city' } ]);
	const mark = findClass(el, 'box');
	assert.equal(mark, '▪',
		'partial-selection mark must be ▪ (U+25AA), got ' +
		JSON.stringify(mark));
});

test('a whole country keeps its ☑ mark', () => {
	// Pin: the whole/none marks render fine in the theme font, so only the
	// partial mark changes — this must stay ☑ before and after.
	const el = renderCountryList([ { code: 'NL', kind: 'country' } ]);
	assert.equal(findClass(el, 'box'), '☑');
});

// ── theme colours in the stylesheet ────────────────────────────────────────
// The stylesheet is a string constant inside the view (see luci-harness.mjs),
// so these assert on the source. Each rule is matched whole, so a failure
// names the exact rule that is still hardcoded or malformed.

test('pv-srv-cur takes its green from the theme success colour', () => {
	assert.ok(src.includes(
		'.pv-srv-cur{color:var(--success-color-medium,#3c8c3c);' +
		'font-weight:600;flex:none}'),
	'pv-srv-cur color must be var(--success-color-medium,#3c8c3c)');
});

test('the load dots follow the success/warn/error theme colours', () => {
	assert.ok(src.includes(
		'.pv-dot-lo{background:var(--success-color-medium,#3c8c3c)}'),
	'pv-dot-lo background must be var(--success-color-medium,#3c8c3c)');
	assert.ok(src.includes(
		'.pv-dot-mid{background:var(--warn-color-medium,#c79100)}'),
	'pv-dot-mid background must be var(--warn-color-medium,#c79100)');
	assert.ok(src.includes(
		'.pv-dot-hi{background:var(--error-color-medium,#c0392b)}'),
	'pv-dot-hi background must be var(--error-color-medium,#c0392b)');
});

test('the country chip takes its fill from the theme primary colour', () => {
	assert.ok(src.includes(
		'.pv-chip-country{background:var(--primary-color-medium,#0069d6);' +
		'color:#fff}'),
	'pv-chip-country background must be var(--primary-color-medium,#0069d6)');
});

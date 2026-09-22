// SPDX-License-Identifier: MIT
// Flags: which two-letter codes may become a flag, and what is drawn when a
// code cannot.
//
// countryFlag() used to map ANY two letters onto the regional-indicator pair
// without asking whether the pair is a country. Unicode only assigns a flag
// to codes that exist, so every other pair renders as the fallback glyph —
// the white flag with a question mark on it — which reads as a broken
// picture where a country should be. Proton's server list carries two codes
// that hit this: UK (the ISO code is GB) and XK (Kosovo, which Unicode gives
// no flag at all).
//
// The oracles here are deliberately NOT the view's own table:
//
//   * ICU, through Intl.DisplayNames with fallback:'none', knows which
//     two-letter codes name a region. Its set is a strict SUPERSET of the
//     flag set (it also carries withdrawn codes, EU/UN and the CLDR
//     pseudo-locales), so "ICU does not know this pair" is a sound,
//     independent proof that no flag exists for it. That covers 396 of the
//     676 pairs.
//   * iso-codes, the Debian/Arch package the whole distribution uses for
//     ISO 3166-1, pins the other direction exactly: every officially
//     assigned alpha-2 code must get a flag, and nothing else may.
//
// Run: node --test luci-app-protonvpn/tests/*.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { loadView, makeCtx, text } from './luci-harness.mjs';

const { spec } = loadView();
const ctx = makeCtx(spec, {});

const ISO_JSON = '/usr/share/iso-codes/json/iso_3166-1.json';

// The regional-indicator pair for a code, computed from first principles —
// this is what a flag IS, independent of anything the view does.
function indicators(cc) {
	return String.fromCodePoint(
		0x1F1E6 + cc.charCodeAt(0) - 65,
		0x1F1E6 + cc.charCodeAt(1) - 65);
}

function allPairs() {
	const out = [];
	for (let a = 65; a <= 90; a++)
		for (let b = 65; b <= 90; b++)
			out.push(String.fromCharCode(a) + String.fromCharCode(b));
	return out;
}

const icu = new Intl.DisplayNames([ 'en' ], { type: 'region', fallback: 'none' });
const icuKnows = (cc) => {
	try {
		return icu.of(cc) != null;
	} catch (e) {
		return false;
	}
};

test('Proton sends UK; the flag drawn for it is the one Unicode gives GB', () => {
	// Not a cosmetic alias: 🇺🇰 is not an assigned flag sequence, so the code
	// Proton actually sends is exactly the one that renders broken.
	assert.equal(ctx.countryFlag('UK'), indicators('GB'),
		'UK must render the GB flag, not the UK regional-indicator pair');
});

test('Kosovo gets no phantom flag — XK has no flag sequence at all', () => {
	assert.equal(ctx.countryFlag('XK'), '',
		'XK must not be turned into a regional-indicator pair');
});

test('a code without a flag is drawn as the code itself, not as nothing', () => {
	// The fallback has to be deliberate: the flag sits in its own column and
	// an empty cell in a list of countries reads as a rendering failure.
	const node = ctx.flagNode('XK');
	assert.equal(text(node), 'XK');
	assert.match(String(node.attrs.class), /pv-flag-code/,
		'the fallback must carry its own class so it can be styled as a badge');
});

test('a real country still gets its emoji flag from flagNode()', () => {
	const node = ctx.flagNode('NL');
	assert.equal(text(node), indicators('NL'));
	assert.doesNotMatch(String(node.attrs.class), /pv-flag-code/);
});

test('no pair ICU refuses to name as a region ever becomes a flag', () => {
	// The independent half of the oracle: ICU's region set is a superset of
	// the flag set, so anything outside it definitely has no flag.
	const wrong = allPairs().filter((cc) => !icuKnows(cc) && ctx.countryFlag(cc) !== '');
	assert.deepEqual(wrong, [],
		'these pairs are not regions at all and must not render as flags');
});

test('every officially assigned ISO 3166-1 code gets a flag, and only those', {
	skip: existsSync(ISO_JSON) ? false : 'iso-codes is not installed'
}, () => {
	const assigned = new Set(JSON.parse(readFileSync(ISO_JSON, 'utf8'))['3166-1']
		.map((e) => e.alpha_2));
	// UK is the one code Proton sends that ISO does not assign; it is an
	// alias for GB, which is why it is expected to carry GB's flag.
	const missing = [ ...assigned ].filter((cc) => ctx.countryFlag(cc) !== indicators(cc));
	const extra = allPairs().filter((cc) =>
		cc !== 'UK' && !assigned.has(cc) && ctx.countryFlag(cc) !== '');
	assert.deepEqual(missing, [], 'assigned ISO countries that lost their flag');
	assert.deepEqual(extra, [], 'codes ISO does not assign that still render a flag');
});

test('garbage never reaches the page as a flag', () => {
	for (const bad of [ '', 'A', 'ABC', 'G1', '  ', null, undefined, 42, {} ])
		assert.equal(ctx.countryFlag(bad), '', JSON.stringify(bad));
});

test('the picker draws the fallback badge for a code with no flag', () => {
	// End to end: a country row for XK must not carry a broken glyph.
	const c = makeCtx(spec, {
		locations: { available: true, countries: [
			{ code: 'XK', name: 'Kosovo', gateway_count: 4, standard_count: 4,
			  ipv6_count: 0, cities: [] } ] },
		poolEntries: []
	});
	const el = { tag: 'div', nodeType: 1, attrs: {}, children: [],
		appendChild(n) { this.children.push(n); return n; } };
	c._poolListEl = el;
	c.poolRenderCountryList();
	const flat = JSON.stringify(el.children);
	assert.ok(flat.includes('pv-flag-code'),
		'the XK row must use the code badge');
	assert.ok(!flat.includes(indicators('XK')),
		'the XK row must not contain the XK regional-indicator pair');
});

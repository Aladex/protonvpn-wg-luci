// SPDX-License-Identifier: MIT
// Render the REAL view into a page a browser can lay out.
//
// Nothing here is a mock: every node comes out of overview.js, driven through
// the same node harness the unit suite uses, and serialised. That is the whole
// point — a hand-written mock of the markup measures the mock, and the first
// round of this redesign was very nearly reported off one.
//
// Writes page.html next to this file. See README.md, including the
// max-device-width trap, which will silently invalidate anything you measure.
//
// Usage:  node render.mjs
//         PV_VIEW=/tmp/old-overview.js node render.mjs   # to take a "before"

import { writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadView, makeCtx, El } from '../luci-harness.mjs';

const OUT = dirname(fileURLToPath(import.meta.url));

// Which revision of the view to render. Point this at an older copy to take a
// "before": the numbers only mean something when both sides come out of this
// same rig, and two differently-built pages prove nothing.
//
//   git show <ref>:luci-app-protonvpn/htdocs/luci-static/resources/view/\
//       protonvpn/overview.js > /tmp/old-overview.js
//   PV_VIEW=/tmp/old-overview.js node render.mjs
const PV_VIEW = process.env.PV_VIEW || null;
if (PV_VIEW && !existsSync(PV_VIEW)) {
	process.stderr.write(`PV_VIEW points at ${PV_VIEW}, which does not exist\n`);
	process.exit(2);
}

const VOID = new Set([ 'input', 'br', 'hr', 'img', 'meta', 'link' ]);
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
	.replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function ser(n) {
	if (n == null || n === false)
		return '';
	if (Array.isArray(n))
		return n.map(ser).join('');
	if (typeof n === 'string' || typeof n === 'number')
		return esc(n);
	if (typeof n.__html === 'string')
		return n.__html;
	if (!n.tag)
		return '';
	const at = Object.entries(n.attrs || {})
		// Handlers are not markup, and `false` attributes are absent ones.
		.filter(([ , v ]) => typeof v !== 'function' && v != null && v !== false)
		.map(([ k, v ]) => ` ${k}="${esc(v)}"`).join('');
	return VOID.has(n.tag)
		? `<${n.tag}${at}>`
		: `<${n.tag}${at}>${ser(n.children)}</${n.tag}>`;
}

// The stylesheet is a concatenation of string literals inside the view, so it
// is evaluated out of the source rather than re-typed: a copy would drift.
function extractStyle(src) {
	const a = src.indexOf("var STYLE = ''");
	const END = "'.hidden{display:none!important}';";
	const b = src.indexOf(END, a);
	if (a < 0 || b < 0)
		throw new Error('STYLE block not found — has the view been restructured?');
	const expr = src.slice(a + 'var STYLE = '.length, b + END.length - 1)
		.replace(/^\s*\/\/[^\n]*$/gm, '');
	return new Function('return ' + expr)();
}

// The worst realistic case, on purpose. A short country name and a tidy set
// measure a page that does not exist on anybody's router.
const COUNTRIES = [
	{ code: 'AU', name: 'Australia', gateway_count: 281, standard_count: 281,
	  ipv6_count: 66, standard_load: 28, cities: [] },
	{ code: 'BA', name: 'Bosnia and Herzegovina', gateway_count: 12,
	  standard_count: 12, ipv6_count: 12, standard_load: 9, cities: [
		{ code: 'BA-SJJ', name: 'Sarajevo', standard_count: 6, ipv6_count: 6 } ] },
	// Proton's two non-ISO codes: UK is an alias for GB, XK has no flag at all.
	{ code: 'UK', name: 'United Kingdom', gateway_count: 821, standard_count: 821,
	  ipv6_count: 604, standard_load: 54, cities: [
		{ code: 'UK-LON', name: 'London', standard_count: 700, ipv6_count: 500 } ] },
	{ code: 'XK', name: 'Kosovo', gateway_count: 4, standard_count: 4,
	  ipv6_count: 0, standard_load: 12, cities: [] },
	{ code: 'DE', name: 'Germany', gateway_count: 300, standard_count: 300,
	  ipv6_count: 200, standard_load: 41, cities: [
		{ code: 'DE-BER', name: 'Berlin', standard_count: 100, ipv6_count: 80 },
		{ code: 'DE-FRA', name: 'Frankfurt', standard_count: 120, ipv6_count: 90 },
		{ code: 'DE-DUS', name: 'Düsseldorf', standard_count: 80, ipv6_count: 30 } ] },
	{ code: 'US', name: 'United States', gateway_count: 2143, standard_count: 2143,
	  ipv6_count: 1802, standard_load: 71, cities: [
		{ code: 'US-ATL', name: 'Atlanta', standard_count: 40, ipv6_count: 30 },
		{ code: 'US-CHI', name: 'Chicago', standard_count: 60, ipv6_count: 50 },
		{ code: 'US-DAL', name: 'Dallas', standard_count: 55, ipv6_count: 40 },
		{ code: 'US-LAX', name: 'Los Angeles', standard_count: 90, ipv6_count: 70 },
		{ code: 'US-MIA', name: 'Miami', standard_count: 70, ipv6_count: 55 },
		{ code: 'US-NYC', name: 'New York City', standard_count: 200, ipv6_count: 160 },
		{ code: 'US-SEA', name: 'Seattle', standard_count: 45, ipv6_count: 35 } ] }
];

// ZZ and QQ-OLD are codes the server list no longer knows: the rows that used
// to vanish, leaving no way to edit the set back to something valid.
const SAVED = [ 'UK', 'DE-BER', 'DE-FRA', 'DE-DUS', 'BA', 'XK',
	'US-ATL', 'US-CHI', 'US-DAL', 'US-LAX', 'US-MIA', 'US-NYC', 'US-SEA',
	'ZZ', 'QQ-OLD' ];

const SESSION = { state: 'active', session_expires_at:
	Math.floor(Date.now() / 1000) + 26 * 24 * 3600 };
const STATUS = {
	state: 'connected', configured: true, enabled: true, gateway: 'UK#264',
	location: { country: 'UK', city: 'UK-LON' },
	endpoint: '146.70.204.162:51820', latest_handshake_seconds: 62,
	ipv6: { mode: 'auto', active: true },
	rotation: { enabled: true }, certificate: { present: true, days_left: 311 }
};

function build() {
	const view = loadView({ view: PV_VIEW, uci: { protonvpn: { main: {
		'.type': 'instance', hop_mode: 'standard', locations: SAVED } } } });
	const ctx = makeCtx(view.spec, {
		session: SESSION, status: STATUS,
		locations: { available: true, countries: COUNTRIES,
			stats: { gateways: 3500 }, state: 'fresh' },
		account: { plan: 'Proton Unlimited', max_connect: 11, devices_used: 3 },
		extIp: { key: 'main|UK#264', ip: '146.70.204.166' },
		refs: {}
	});
	// The router runs this in a browser with full ICU, so the picker shows
	// real country names; the node harness has no window.navigator and would
	// otherwise measure two-letter codes — which are exactly the short names
	// that hide the width defects.
	const dn = new Intl.DisplayNames([ 'en' ], { type: 'region', fallback: 'none' });
	ctx.countryLabel = (code) => {
		const cc = String(code || '').toUpperCase();
		return cc ? (dn.of(cc) || cc) : '';
	};
	ctx.bandEl = El('div', { class: 'pv-acct' });
	ctx.stateEl = El('div', { class: 'pv-state' });
	ctx.renderBand();
	ctx.updateStatusBand();
	const conn = ctx.buildConnection();
	// Open the picker with one country expanded, so its rows are measured too.
	ctx._poolOpen = true;
	ctx._poolExpanded = { DE: true };
	ctx.poolRenderPanel();
	if (ctx.poolPanel && ctx.poolPanel.classList)
		ctx.poolPanel.classList.remove('hidden');
	return { css: extractStyle(view.src),
		html: ser(ctx.bandEl) + ser(ctx.stateEl) + ser(conn) };
}

for (const f of [ 'cascade.css', 'mobile.css', 'mobile-emulated.css' ])
	if (!existsSync(join(OUT, f)))
		process.stderr.write(`warning: ${f} is missing — see README.md\n`);

const b = build();
writeFileSync(join(OUT, 'page.html'), `<!doctype html>
<html data-darkmode="true"><head><meta charset="utf-8">
<meta name="viewport" content="initial-scale=1.0">
<link rel="stylesheet" href="cascade.css"><link rel="stylesheet" href="mobile.css">
<link rel="stylesheet" href="mobile-emulated.css">
<style>body{padding:0;margin:0}#view{max-width:100%}</style>
<style>${b.css}</style>
</head><body class="lang_en"><div id="view"><div>
<h2>ProtonVPN</h2>
${b.html}
</div></div></body></html>
`);
process.stdout.write('wrote page.html from ' +
	(PV_VIEW || 'the view in this checkout') + '\n');

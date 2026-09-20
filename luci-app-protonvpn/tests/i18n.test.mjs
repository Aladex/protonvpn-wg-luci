// SPDX-License-Identifier: MIT
// The committed translation template against the sources it was scanned from.
//
// The template is a generated artifact that this repo commits, so it goes
// stale the moment a string is added and nobody reruns the scanner — which is
// exactly what happened: it carried 33 entries for a view with 269 of them,
// and every string added since was invisible to translators. Neither the
// suites nor a mutation run can notice that, because nothing about it is
// executed. So it is checked here instead.
//
// Regenerate with LuCI's own scanner, from a tree with this package at
// applications/luci-app-protonvpn:
//   ./build/i18n-scan.pl applications/luci-app-protonvpn \
//       > applications/luci-app-protonvpn/po/templates/protonvpn.pot
//
// Run: node --test luci-app-protonvpn/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const app = join(here, '..');
const POT = join(app, 'po/templates/protonvpn.pot');

// The file set i18n-scan.pl walks for this package: every .js, plus the
// menu and acl descriptors. The tests are .mjs and are not translated.
function sources(dir, out) {
	out = out || [];
	for (const name of readdirSync(dir)) {
		const full = join(dir, name);
		if (statSync(full).isDirectory()) {
			if (name !== 'po' && name !== 'tests')
				sources(full, out);
		} else if (name.endsWith('.js') ||
		           (name.endsWith('.json') && /menu\.d|acl\.d/.test(full))) {
			out.push(full);
		}
	}
	return out;
}

const src = sources(app).map((f) => readFileSync(f, 'utf8')).join('\n');
const pot = readFileSync(POT, 'utf8');

// The msgids, po-escaped and possibly split over continuation lines:
//
//   msgid ""
//   "The password is turned into a proof in this page and never reaches the "
//   "router."
//
// Reading only the first line — which is what this check did at first — makes
// every long string look absent, which is the opposite of useful here.
function unquote(line) {
	const m = /^"((?:[^"\\]|\\.)*)"$/.exec(line.trim());
	if (!m)
		return null;
	return m[1].replace(/\\n/g, '\n').replace(/\\t/g, '\t')
		.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
}

function msgids(text) {
	const lines = text.split('\n');
	const out = new Set();
	for (let i = 0; i < lines.length; i++) {
		if (!lines[i].startsWith('msgid '))
			continue;
		let v = unquote(lines[i].slice(6)) || '';
		while (i + 1 < lines.length && lines[i + 1].startsWith('"')) {
			v += unquote(lines[++i]) || '';
		}
		if (v !== '')
			out.add(v);
	}
	return out;
}

// _('...') / _("...") on a single line, without concatenation. A subset of
// what the scanner extracts — enough to catch a string nobody rescanned for.
function literals(text) {
	const out = new Set();
	for (const m of text.matchAll(/\b_\('((?:[^'\\]|\\.)*)'\)/g))
		out.add(m[1].replace(/\\'/g, "'").replace(/\\\\/g, '\\'));
	for (const m of text.matchAll(/\b_\("((?:[^"\\]|\\.)*)"\)/g))
		out.add(m[1].replace(/\\"/g, '"').replace(/\\\\/g, '\\'));
	return out;
}

const ids = msgids(pot);
const used = literals(src);

test('the template carries every translatable string in the sources', () => {
	const missing = [ ...used ].filter((s) => !ids.has(s)).sort();
	assert.deepEqual(missing, [],
		'these strings are translatable in the sources but absent from the template — rerun i18n-scan.pl');
});

test('the template carries no string the sources dropped', () => {
	// A msgid whose text is nowhere in the sources any more is left over from
	// an older scan; translators would be working on a string nobody shows.
	const stale = [ ...ids ].filter((s) => {
		if (src.includes(s))
			return false;
		// Source strings quote apostrophes when the literal is single-quoted.
		return !src.includes(s.replace(/'/g, "\\'"));
	}).sort();
	assert.deepEqual(stale, [], 'these template entries no longer exist in the sources');
});

test('the template says how to regenerate it', () => {
	assert.match(pot, /i18n-scan\.pl/,
		'nothing in the file tells the next person how it is produced');
});

test('the template header is the shape LuCI generates', () => {
	assert.match(pot, /^msgid ""\nmsgstr "Content-Type: text\/plain; charset=UTF-8"\n/,
		'the header was hand-edited away from what the scanner writes');
});

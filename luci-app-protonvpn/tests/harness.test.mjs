// SPDX-License-Identifier: MIT
// Tests for the test harness.
//
// Normally the harness is checked by the suites that use it. That failed
// once, expensively: it treated a scalar `dom.content(el, s)` as literal
// children, which is not what LuCI does — luci.js DOM.append() assigns a
// scalar with `node.innerHTML = ...` and only walks an ARRAY into text nodes.
// With the two branches indistinguishable, every rendering test passed while
// the sign-in error was an HTML injection carrying Proton's remote text, and
// 66 mutants died without noticing.
//
// So the modelling itself is pinned here. If these fail, the rendering suite
// has stopped being able to see the difference and its green is worthless.
//
// Run: node --test luci-app-protonvpn/tests/

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { El, text, htmlAssignments, isElem, loadView, fakeDocument, resetFocus } from './luci-harness.mjs';

const { globals } = loadView();
const dom = globals.dom;

test('a scalar child of E() is an innerHTML assignment', () => {
	const el = El('p', {}, 'linux-vpn-gtk@<version>');
	assert.deepEqual(htmlAssignments(el), [ 'linux-vpn-gtk@<version>' ]);
});

test('an array member of E() is a text node', () => {
	const el = El('p', {}, [ 'linux-vpn-gtk@<version>' ]);
	assert.deepEqual(htmlAssignments(el), []);
});

test('a scalar child is rendered the way the HTML parser leaves it', () => {
	// <version> is not a known element; the parser consumes the tag and the
	// text around it is all that remains. This is the user's screenshot.
	assert.equal(text(El('p', {}, 'linux-vpn-gtk@<version>')), 'linux-vpn-gtk@');
	assert.equal(text(El('p', {}, 'a <b>bold</b> word')), 'a bold word');
	assert.equal(text(El('p', {}, '5 &lt; 6 &amp; 7')), '5 < 6 & 7');
});

test('an array member survives verbatim', () => {
	assert.equal(text(El('p', {}, [ 'linux-vpn-gtk@<version>' ])), 'linux-vpn-gtk@<version>');
	assert.equal(text(El('p', {}, [ 'a <b>bold</b> word' ])), 'a <b>bold</b> word');
});

test('dom.content keeps the two branches apart', () => {
	const scalar = El('div', {});
	dom.content(scalar, '<img src=x>');
	assert.deepEqual(htmlAssignments(scalar), [ '<img src=x>' ]);
	assert.equal(text(scalar), '');

	const array = El('div', {});
	dom.content(array, [ '<img src=x>' ]);
	assert.deepEqual(htmlAssignments(array), []);
	assert.equal(text(array), '<img src=x>');
});

test('dom.content replaces what was there', () => {
	const el = El('div', {}, [ 'first' ]);
	dom.content(el, [ 'second' ]);
	assert.equal(text(el), 'second');
});

test('a scalar append wipes the existing children, as innerHTML does', () => {
	// Upstream's scalar branch is an assignment, not an append. Modelling it
	// as an append would hide a real way to lose content.
	const el = El('div', {}, [ 'kept?' ]);
	dom.append(el, 'replaced');
	assert.equal(text(el), 'replaced');
});

test('an array append adds to what was there', () => {
	const el = El('div', {}, [ 'first' ]);
	dom.append(el, [ 'second' ]);
	assert.equal(text(el), 'firstsecond');
});

test('elements pass through both branches untouched', () => {
	const child = El('span', {}, [ 'x' ]);
	const viaArray = El('div', {}, [ child ]);
	const viaScalar = El('div', {}, child);
	assert.deepEqual(htmlAssignments(viaArray), []);
	assert.deepEqual(htmlAssignments(viaScalar), []);
	assert.equal(text(viaArray), 'x');
	assert.equal(text(viaScalar), 'x');
});

test('htmlAssignments finds a scalar nested deep in the tree', () => {
	const tree = El('div', {}, [
		El('section', {}, [ El('p', {}, 'deep <tag> here') ])
	]);
	assert.deepEqual(htmlAssignments(tree), [ 'deep <tag> here' ]);
});

test('htmlAssignments reports nothing for a tree built entirely from arrays', () => {
	const tree = El('div', {}, [
		El('section', {}, [ El('p', {}, [ 'deep <tag> here' ]) ])
	]);
	assert.deepEqual(htmlAssignments(tree), []);
});

test('a value attribute is reflected onto .value once, like a real input', () => {
	const input = El('input', { value: 'from-config' });
	assert.equal(input.value, 'from-config');
	input.value = 'typed';
	assert.equal(input.attrs.value, 'from-config',
		'writing .value must not rewrite the attribute');
});

test('a boxed string is not an element, so it lands in the innerHTML branch', () => {
	// Faithful to luci.js dom.elem(): `typeof e == 'object' && 'nodeType' in e`.
	// A boxed String passes the typeof test and fails the nodeType one, so
	// DOM.append() sends it to `node.innerHTML = ...` like any other scalar.
	// That is precisely why nodes() in the view must not pass objects through
	// on sight — see overview-rendering.test.mjs.
	const el = El('p', {}, new String('a <b>bold</b> word'));
	assert.deepEqual(htmlAssignments(el), [ 'a <b>bold</b> word' ]);
	assert.equal(text(el), 'a bold word');
});

test('an element is recognised by nodeType, the way LuCI recognises one', () => {
	const el = El('div', {});
	assert.equal(el.nodeType, 1);
	assert.equal(isElem(el), true);
	assert.equal(isElem(new String('x')), false);
	assert.equal(isElem({ tag: 'div' }), false,
		'a plain object that merely looks like a node must not count as one');
	assert.equal(isElem(null), false);
	assert.equal(isElem('div'), false);
});

test('a function child is called and its result appended, recursively', () => {
	// luci.js DOM.append(): `return this.append(node, children(node))`. So a
	// function returning a scalar reaches innerHTML exactly like a bare
	// string would — which is why nodes() has to wrap the result too.
	const el = El('p', {}, () => 'a <b>bold</b> word');
	assert.deepEqual(htmlAssignments(el), [ 'a <b>bold</b> word' ]);

	const safe = El('p', {}, () => [ 'a <b>bold</b> word' ]);
	assert.deepEqual(htmlAssignments(safe), []);
	assert.equal(text(safe), 'a <b>bold</b> word');
});

test('a function child receives the node it is appending into', () => {
	let seen = null;
	const el = El('p', {}, (node) => { seen = node; return [ 'x' ]; });
	assert.equal(seen, el, 'the function was not given the target node');
});

// ── loading a different revision of the view ──────────────────────────────
//
// The browser harness takes its "before" numbers by rendering an older
// overview.js through this same rig. That documented path was inert once
// already — README and render.mjs both named PV_VIEW and nothing read it, so
// a before/after comparison that nobody could reproduce was presented as if
// it could be. This is what stops that recurring.

test('loadView reads the source file it is pointed at', () => {
	const dir = mkdtempSync(join(tmpdir(), 'pv-view-'));
	const alt = join(dir, 'overview.js');
	try {
		// A whole view, small enough to assert on: view.extend() hands the
		// spec straight back, exactly as the real one relies on.
		writeFileSync(alt, "return view.extend({ marker: 'from the override' });\n");
		const loaded = loadView({ view: alt });
		assert.equal(loaded.spec.marker, 'from the override',
			'the spec did not come from the file loadView was pointed at');
		assert.match(loaded.src, /from the override/,
			'src must be the overridden file too — the stylesheet is read out of it');
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test('without an override it still reads the view in this checkout', () => {
	const loaded = loadView();
	assert.match(loaded.src, /x-pm-appversion|countryFlag/,
		'the default path must remain the real view');
	assert.equal(typeof loaded.spec.countryFlag, 'function');
});

// ── what can take focus ───────────────────────────────────────────────────
//
// A browser refuses focus to anything that is not rendered, and this page
// hides things with the `hidden` class (display:none!important). Without
// modelling that, a fake DOM cannot tell "un-hide the trigger, then focus it"
// apart from "focus it, then un-hide it" — and the second one loses the
// keyboard on a real router.

test('a hidden element cannot take focus', () => {
	resetFocus();
	const el = El('button', { class: 'cbi-button hidden' });
	el.focus();
	assert.equal(fakeDocument.activeElement, null);
	el.classList.remove('hidden');
	el.focus();
	assert.equal(fakeDocument.activeElement, el);
});

test('nor can anything inside something hidden', () => {
	resetFocus();
	const panel = El('div', { class: 'pv-pool-panel hidden' });
	const row = El('button', {});
	panel.appendChild(row);
	row.focus();
	assert.equal(fakeDocument.activeElement, null,
		'a row inside a closed panel is not a place focus can be');
	panel.classList.remove('hidden');
	row.focus();
	assert.equal(fakeDocument.activeElement, row);
});

test('focus that is refused stays where it already was', () => {
	resetFocus();
	const here = El('input', {});
	here.focus();
	const gone = El('button', { class: 'hidden' });
	gone.focus();
	assert.equal(fakeDocument.activeElement, here,
		'a refused focus() must not blank the document either');
});

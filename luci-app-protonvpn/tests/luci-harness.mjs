// SPDX-License-Identifier: MIT
// Loads the real LuCI view under node so tests can assert what it RENDERS.
//
// Why this exists: a backend field that nothing renders is invisible to the
// user however faithfully it is delivered, and that has happened twice in this
// app (`features` was read in the view but never put in trim_relay; then
// `ipv6_required`/`tunnel_down` were delivered and read by nothing). Transport
// tests cannot catch either shape — only executing the view can.
//
// The view is a LuCI script: it declares its dependencies with 'require ...'
// pragmas and ends in a top-level `return view.extend({...})`. Neither works
// under an ES import, so it is read as text and evaluated in a Function whose
// arguments are the globals LuCI would have injected. `view.extend` hands the
// spec straight back, which is what gives tests access to the real methods.
//
// The stubs are deliberately thin: they record what the view did instead of
// emulating a browser. Anything the view actually needs is here; anything it
// does not is absent on purpose, so a new dependency shows up as a clear
// failure rather than as silently skipped rendering.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const VIEW = join(here, '../htdocs/luci-static/resources/view/protonvpn/overview.js');

// Which source file loadView() reads. Normally the view in this checkout; the
// browser harness points it at an older revision to take a "before"
// measurement through the identical rig, which is the only way a before/after
// comparison means anything. Kept as an explicit option rather than an
// environment variable so the unit suite can never be pointed elsewhere by a
// stray export.
function viewPath(opts) {
	return (opts && opts.view) ? opts.view : VIEW;
}

// LuCI installs String.prototype.format; the view uses it everywhere.
// %s/%d and %% are all this app needs.
function luciFormat(...args) {
	let i = 0;
	return String(this).replace(/%(%|[sd])/g, (m, spec) => {
		if (spec === '%')
			return '%';
		const v = args[i++];
		return spec === 'd' ? String(Math.round(Number(v) || 0)) : String(v);
	});
}
if (!String.prototype.format)
	Object.defineProperty(String.prototype, 'format', { value: luciFormat });

// A node is a plain record; `text()` flattens one the way a reader sees it.
// Elements also carry the small DOM surface the view itself uses when it
// builds panels inline: appends after dom.content(), listeners recorded per
// event (so a test can fire what a click would), and a class list backed by
// attrs.class so visibility toggles stay inspectable.
function childList(el) {
	if (Array.isArray(el.children))
		return el.children;
	return (el.children == null || el.children === '') ? [] : [ el.children ];
}

// ── how LuCI actually puts children into a node ──────────────────────────
//
// luci.js DOM.append() has two branches and they are NOT interchangeable:
//
//   ARRAY   -> each non-element member becomes document.createTextNode(...)
//   SCALAR  -> node.innerHTML = `${children}`
//
// So a bare string is parsed as HTML. A message containing the literal
// `linux-vpn-gtk@<version>` loses `<version>` to a phantom tag, and remote
// text — Proton's own `Error` string — is injected as markup. dom.content()
// delegates to append(), and E()/DOM.create() calls append() with its third
// argument, so `E('p', {}, someString)` is an innerHTML assignment too.
//
// This harness used to treat a scalar as literal children, which made the two
// branches look identical and hid the defect from every test in this suite.
// A scalar is now recorded as an HTML assignment and `text()` renders it the
// way a browser would — through the parser — so the difference is visible.
function htmlAssign(value) {
	return { __html: String(value) };
}

// LuCI's own test for "is this an element", verbatim (luci.js dom.elem):
// it is what DOM.append() uses to choose its branch, so the harness has to
// use the same one or it models a different function. Note what it excludes:
// a boxed `new String(...)` is an object but has no nodeType, so it lands in
// the innerHTML branch like any other scalar.
export function isElem(v) {
	return v != null && typeof v === 'object' && 'nodeType' in v;
}

// What a browser shows for a string assigned to innerHTML: tags are consumed
// (an unknown one like <version> simply disappears) and entities decode.
function renderHtml(src) {
	const stripped = String(src).replace(/<[^>]*>/g, '');
	return stripped
		.replace(/&lt;/g, '<').replace(/&gt;/g, '>')
		.replace(/&quot;/g, '"').replace(/&#0?39;/g, "'")
		.replace(/&amp;/g, '&');
}

// The append() branches, modelled. `replace` is what dom.content() does
// first; note that the SCALAR branch replaces the children even on a plain
// append, because innerHTML is an assignment — that quirk is upstream's, not
// ours.
// Whatever ends up as a child of `el` remembers it, so a test can ask whether
// a node is inside something that is hidden — which is what decides whether
// it can take focus at all.
//
// Non-enumerable, like a real node's: the link points back up the tree, and
// an enumerable one turns every node record into a cycle that JSON.stringify
// and deep-equal both choke on.
function setParent(child, parent) {
	Object.defineProperty(child, 'parentNode',
		{ value: parent, writable: true, enumerable: false, configurable: true });
}

function adopt(el, kids) {
	(Array.isArray(kids) ? kids : [ kids ]).forEach((c) => {
		if (c && typeof c === 'object' && !Array.isArray(c) && c.nodeType === 1)
			setParent(c, el);
	});
	return kids;
}

function appendInto(el, children, replace) {
	if (replace) {
		// A browser blurs whatever it removes from the document, and it does
		// so even when the very same node is put back immediately after —
		// which is exactly what dom.content() does to the controls a card
		// rebuilds. Without this the harness lets a detached node keep
		// focus, and a test asking "did focus survive?" answers yes for a
		// control the user can no longer see.
		if (typeof el.contains === 'function' && fakeDocument.activeElement &&
			el.contains(fakeDocument.activeElement))
			fakeDocument.activeElement = null;
		el.children = [];
	}
	if (Array.isArray(children)) {
		// A non-element member becomes a text node, verbatim. Upstream would
		// stringify a null member into the literal "null"; the harness is
		// lenient about that one case rather than reproducing a bug no test
		// here exercises — do not pass null inside an array.
		el.children = childList(el).concat(adopt(el, children).map(
			(c) => (isElem(c) || c == null || c === false) ? c : String(c)));
	} else if (typeof children === 'function') {
		return appendInto(el, children(el), false);
	} else if (isElem(children)) {
		el.children = childList(el).concat([ adopt(el, children) ]);
	} else if (children != null) {
		el.children = [ htmlAssign(children) ];
	}
	return el;
}

// Every string this node tree had assigned to innerHTML, depth first. A test
// that must not touch innerHTML on a path asserts this is empty; one that
// checks a message survived rendering asserts on text() instead.
export function htmlAssignments(node) {
	const out = [];
	const walk = (n) => {
		if (n == null || typeof n !== 'object')
			return;
		if (Array.isArray(n))
			return n.forEach(walk);
		if (typeof n.__html === 'string')
			return out.push(n.__html);
		walk(n.children);
	};
	walk(node);
	return out;
}

// The one document every El belongs to, so `card.ownerDocument.activeElement`
// resolves the way it does in a browser. Focus is a rendering property like
// any other here: a repaint that throws it away is invisible to a test that
// cannot observe it, and that is exactly the defect being pinned.
export const fakeDocument = { activeElement: null };

export function resetFocus() {
	fakeDocument.activeElement = null;
}

export function El(tag, attrs, children) {
	// nodeType is what makes this record an element to dom.elem() — real
	// elements are nodeType 1.
	const el = { tag, nodeType: 1, attrs: attrs || {}, children: [],
		ownerDocument: fakeDocument };
	// A real input/select reflects its value ATTRIBUTE into the .value
	// property once, at creation; later writes to .value leave the attribute
	// alone. Mirroring it here is what lets a test read back what the view
	// rendered a field with, the same way the view's own code does.
	if (el.attrs.value !== undefined && el.value === undefined)
		el.value = el.attrs.value;
	// A real element's .className IS the class attribute; the view assigns it
	// wholesale on every repaint (`this.stateEl.className = cls`). Without
	// this reflection the record kept its original attrs.class, so classList
	// and every class-based lookup read a value the browser would not have.
	Object.defineProperty(el, 'className', {
		get: () => String(el.attrs.class || ''),
		set: (v) => { el.attrs.class = String(v == null ? '' : v); },
		enumerable: false, configurable: true
	});
	const current = () => String(el.attrs.class || '').split(/\s+/).filter(Boolean);
	const set = (cls, on) => {
		const parts = current();
		const at = parts.indexOf(cls);
		if (on && at < 0) parts.push(cls);
		if (!on && at >= 0) parts.splice(at, 1);
		el.attrs.class = parts.join(' ');
	};
	el.appendChild = (c) => {
		if (c && typeof c === 'object' && c.nodeType === 1)
			setParent(c, el);
		el.children = childList(el).concat([c]);
		return c;
	};
	// DOM.create() ends in DOM.append(elem, data) — same two branches.
	appendInto(el, children, false);
	el.getAttribute = (name) => {
		const v = el.attrs[name];
		return (v === undefined || typeof v === 'function') ? null : v;
	};
	el.setAttribute = (name, v) => { el.attrs[name] = v; };
	// A real element takes focus only if it is rendered. `display:none` is
	// not focusable, and neither is anything inside it — a browser simply
	// ignores the call and leaves focus where it was. Modelling that is what
	// makes the panel-close tests mean something: they only pass if the
	// trigger is un-hidden BEFORE it is focused, which is an ordering a
	// permissive fake cannot tell apart from the correct one.
	//
	// `hidden` is the class this page hides things with (.hidden is
	// display:none!important in its stylesheet); the harness does not
	// evaluate CSS, so that class is the signal.
	el.isRendered = () => {
		for (let n = el; n; n = n.parentNode)
			if (String((n.attrs && n.attrs.class) || '').split(/\s+/).includes('hidden'))
				return false;
		return true;
	};
	el.focus = () => {
		if (!el.isRendered())
			return;
		fakeDocument.activeElement = el;
	};
	el.blur = () => {
		if (fakeDocument.activeElement === el)
			fakeDocument.activeElement = null;
	};
	el.contains = (other) => {
		if (other === el)
			return true;
		const walk = (n) => {
			if (n == null || typeof n !== 'object')
				return false;
			if (Array.isArray(n))
				return n.some(walk);
			if (n === other)
				return true;
			return walk(n.children);
		};
		return walk(childList(el));
	};
	// The two selector shapes the view uses: an option lookup inside a select,
	// and an attribute lookup for the focus keys a repaint restores by.
	el.querySelector = (sel) => {
		const opt = /^([a-z]+)\[value="(.*)"\]$/.exec(sel);
		if (opt)
			return childList(el).find((c) => c && c.tag === opt[1] &&
				String((c.attrs && c.attrs.value) || '') === opt[2]) || null;
		const at = /^\[([a-z-]+)="(.*)"\]$/.exec(sel);
		if (!at)
			return null;
		let hit = null;
		const walk = (n) => {
			if (hit || n == null || typeof n !== 'object')
				return;
			if (Array.isArray(n))
				return n.forEach(walk);
			if (n.attrs && n.attrs[at[1]] === at[2]) {
				hit = n;
				return;
			}
			walk(n.children);
		};
		walk(childList(el));
		return hit;
	};
	el.addEventListener = (ev, fn) => {
		el.listeners = el.listeners || {};
		(el.listeners[ev] = el.listeners[ev] || []).push(fn);
	};
	el.classList = {
		add: (...cs) => cs.forEach((c) => set(c, true)),
		remove: (...cs) => cs.forEach((c) => set(c, false)),
		toggle: (c, on) => set(c, on === undefined ? !current().includes(c) : !!on),
		contains: (c) => current().includes(c)
	};
	return el;
}

export function text(node) {
	if (node == null || node === false)
		return '';
	if (typeof node === 'string' || typeof node === 'number')
		return String(node);
	if (Array.isArray(node))
		return node.map(text).join('');
	// A string that went in through the scalar branch was parsed as HTML, so
	// this is what the user actually reads — not what the view passed.
	if (typeof node.__html === 'string')
		return renderHtml(node.__html);
	let out = '';
	if (node.children !== undefined)
		out += text(node.children);
	return out;
}

// The rendered text of the element with the given CSS class, searched depth
// first. Returns null when the view never produced it, which is a meaningful
// answer: it is what "the user is not told this" looks like.
export function findClass(node, cls) {
	if (node == null || typeof node !== 'object')
		return null;
	if (Array.isArray(node)) {
		for (const c of node) {
			const hit = findClass(c, cls);
			if (hit !== null)
				return hit;
		}
		return null;
	}
	const own = String((node.attrs && node.attrs.class) || '');
	if (own.split(/\s+/).includes(cls))
		return text(node);
	return findClass(node.children, cls);
}

// The element records carrying the given CSS class, depth first. findClass()
// answers "what does the user read"; this one answers "what did the view
// build" — needed where the interesting part is the structure itself (a hit
// target separate from the chevron cell) rather than its text.
export function findAllClass(node, cls) {
	const out = [];
	const walk = (n) => {
		if (n == null || typeof n !== 'object')
			return;
		if (Array.isArray(n))
			return n.forEach(walk);
		const own = String((n.attrs && n.attrs.class) || '');
		if (own.split(/\s+/).includes(cls))
			out.push(n);
		walk(n.children);
	};
	walk(node);
	return out;
}

export function findOneClass(node, cls) {
	return findAllClass(node, cls)[0] || null;
}

export function loadView(opts) {
	opts = opts || {};
	const uciData = opts.uci || {};
	const notices = [];
	const rpcCalls = [];
	// What ui.showModal() was handed, so a test can reach the buttons the view
	// builds outside the panel body — the sign-in Continue button lives there.
	const modals = [];

	const globals = {
		// `view.extend` returning the spec is the whole trick: the tests get
		// the real methods, unbound, and call them on a context they control.
		view: { extend: (spec) => spec },
		baseclass: { extend: (spec) => spec },
		rpc: {
			declare: (decl) => function (...args) {
				rpcCalls.push({ method: decl.method, args });
				const canned = (opts.rpc || {})[decl.method];
				return Promise.resolve(
					typeof canned === 'function' ? canned(...args) : canned);
			}
		},
		uci: {
			get: (cfg, sec, opt) => {
				if (opt === undefined)
					return (uciData[cfg] || {})[sec];
				const s = (uciData[cfg] || {})[sec];
				return s ? s[opt] : undefined;
			},
			set: (cfg, sec, opt, val) => {
				uciData[cfg] = uciData[cfg] || {};
				uciData[cfg][sec] = uciData[cfg][sec] || {};
				uciData[cfg][sec][opt] = val;
			},
			unset: (cfg, sec, opt) => {
				if (uciData[cfg] && uciData[cfg][sec])
					delete uciData[cfg][sec][opt];
			},
			sections: (cfg, type, cb) => {
				const secs = uciData[cfg] || {};
				for (const name of Object.keys(secs))
					if (!type || secs[name]['.type'] === type)
						cb(Object.assign({ '.name': name }, secs[name]), name);
			},
			add: () => 'new', remove: () => {}, save: () => Promise.resolve(),
			apply: () => Promise.resolve(), changes: () => Promise.resolve({})
		},
		ui: {
			addNotification: (_t, node, kind) => {
				const rec = { kind: kind || 'info', text: text(node) };
				notices.push(rec);
				return rec;
			},
			showModal: (title, children) => {
				modals.push({ title, children, open: true });
				return children;
			},
			hideModal: () => {
				if (modals.length)
					modals[modals.length - 1].open = false;
			},
			addValidator: () => {}, createHandlerFn: (_s, fn) => fn
		},
		poll: { add: () => {}, remove: () => {}, start: () => {}, stop: () => {} },
		dom: {
			content: (el, children) => appendInto(el, children, true),
			append: (el, children) => appendInto(el, children, false),
			create: El, parse: (s) => s, isEmpty: () => false
		},
		E: El,
		L: {
			bind: (fn, self, ...pre) => fn.bind(self, ...pre),
			resolveDefault: (p, d) => Promise.resolve(p).catch(() => d),
			error: (e) => { throw new Error(e); },
			env: { requestpath: [], token: 'test' },
			toArray: (v) => Array.isArray(v) ? v : (v == null || v === '' ? [] : [ v ])
		},
		_: (s) => s,
		N_: (_n, s) => s,
		TR: (s) => s,
		fs: { exec: () => Promise.resolve({ code: 0, stdout: '' }) },
		form: {}, network: {}, request: {}, session: {},
		validation: {}, widgets: {}
	};

	const src = readFileSync(viewPath(opts), 'utf8');
	const names = Object.keys(globals);
	// The 'require x' pragmas are string expressions, harmless here; the
	// trailing `return` is why this has to be a Function body and not a module.
	const factory = new Function(...names, src);
	const spec = factory(...names.map((n) => globals[n]));
	// The stylesheet is a plain string constant inside the view, injected by
	// render(); tests that assert on it (theme variables, panel width) read
	// the source rather than standing up the whole form.
	return { spec, globals, notices, rpcCalls, uciData, modals, src };
}

// A view context with the real methods on its prototype and only the state a
// test chooses to set. Built this way so a method reaching for something the
// test did not provide fails loudly instead of reading a leftover default.
export function makeCtx(spec, state) {
	const ctx = Object.create(spec);
	ctx.instance = 'main';
	ctx.instances = [ { instance: 'main' } ];
	ctx.stateEl = El('div', { class: 'pv-state' });
	ctx.status = {};
	ctx.locations = { countries: [] };
	ctx.extIp = null;
	// Nothing in these tests wants a live lookup through the tunnel.
	ctx.maybeFetchExternalIp = () => {};
	ctx.markDirty = () => {};
	ctx.notice = function (t, kind) {
		const rec = { kind: kind || 'info', text: String(t) };
		this._notices = this._notices || [];
		this._notices.push(rec);
		return rec;
	};
	Object.assign(ctx, state || {});
	return ctx;
}

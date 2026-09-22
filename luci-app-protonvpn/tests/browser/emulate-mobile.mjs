// SPDX-License-Identifier: MIT
// Re-key a LuCI theme's mobile stylesheet from max-device-width to max-width.
//
// The theme gates its phone layout on the DEVICE width, which on a desktop is
// the monitor and never the viewport. Nothing you can do to a window or an
// iframe will trigger those blocks, so a measurement taken without this reads
// the desktop form — 180px label column and all — while looking like a phone.
//
// Usage: node emulate-mobile.mjs mobile.css > mobile-emulated.css

import { readFileSync } from 'node:fs';

const src = process.argv[2];
if (!src) {
	process.stderr.write('usage: node emulate-mobile.mjs <mobile.css>\n');
	process.exit(2);
}

const css = readFileSync(src, 'utf8');
const out = css.replace(/max-device-width/g, 'max-width')
	.replace(/min-device-width/g, 'min-width');

if (out === css)
	process.stderr.write(
		'warning: no device-width queries found — either this theme already ' +
		'uses max-width, or you pointed at the wrong file\n');

process.stdout.write(out);

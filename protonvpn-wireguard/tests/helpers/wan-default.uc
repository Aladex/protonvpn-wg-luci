#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Drives the WAN default-route self-heal, or the WAN classification, once
// against the config named by PROTONVPN_MOCK_UCI, and prints the result.
//
//   PVT_MODE=heal (default)
//       The sequence every caller follows: snapshot the main-table default,
//       run the operation's reload, then heal. The "reload" is PVT_RELOAD, a
//       shell command that does to the routing table what the netifd reload
//       is observed to do (or nothing). PVT_SNAPSHOT=unreadable hands the heal
//       no snapshot, as when it could not be read. Prints the heal's result.
//   PVT_MODE=uplinks
//       Prints wan_verdicts() as [ { name, why } ].
//
// Why a separate process: the code under test shells out to `ip` and `ubus`,
// and the test has to decide what those answer. ucode cannot change its own
// PATH, so the fakes can only be put in front of the real commands for a
// child. The caller (test_wan_default.uc) writes the fakes and runs this with
// them first on PATH.
//
// Not named test_*.uc on purpose: run.sh globs that pattern, and this is a
// helper invoked BY a test.

'use strict';

import { cursor } from 'uci';

const _apply = require('protonvpn.apply');
const _routing = require('protonvpn.routing');

if (getenv('PVT_MODE') == 'uplinks') {
	let data = _routing.netifd_dump();
	let out = [];
	for (let v in _routing.wan_verdicts(cursor(), data))
		push(out, { name: v.ifc.interface, why: v.why });
	printf('%J\n', out);
	exit(0);
}

let snap = null;
if (getenv('PVT_SNAPSHOT') != 'unreadable' && _apply.wan_default_snapshot)
	snap = _apply.wan_default_snapshot();
let reload = getenv('PVT_RELOAD');
if (reload)
	system([ '/bin/sh', '-c', reload ]);
printf('%J\n', _apply.restore_wan_default(snap));

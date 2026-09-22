#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Drives the router-advertisement readiness wait to its timeout at the
// PRODUCTION budget, and prints how many milliseconds that took.
//
// Why a separate process: the suite exports a short PROTONVPN_RA_SETTLE_MS so
// the timeout tests do not cost five seconds each, and ucode has no setenv, so
// a test inside that process cannot put the production value back. This is run
// with the variable unset, which is the only honest way to exercise the
// default — the alternative would be asserting against a number the suite
// itself chose, which proves nothing about what ships.
//
// Not named test_*.uc on purpose: run.sh globs that pattern, and this is a
// helper invoked BY a test, not a test.

'use strict';

const _routing = require('protonvpn.routing');

// A network whose addressing never reaches the state asked for, so the wait
// runs the whole budget. The ubus stub answers from the fixture the caller
// wrote; an address outside our hinted /64 is never "ready".
global.MOCK_UCI = { network: {
	globals: { '.type': 'globals', ula_prefix: 'fd7a:1b2c:3d4e::/48' },
	pv_media: { '.type': 'interface', proto: 'wireguard' },
	media: { '.type': 'interface', proto: 'static' }
}, dhcp: {}, firewall: {} };

import { cursor } from 'uci';

function ms_now() {
	let c = clock(true);
	return c[0] * 1000 + int(c[1] / 1000000);
}

let uci = cursor();
let t0 = ms_now();
_routing.ra_refresh(uci, 'pv_media', [ { net: 'media', want: true } ], []);
printf('%d %d\n', ms_now() - t0, _routing.ra_budget_ms());

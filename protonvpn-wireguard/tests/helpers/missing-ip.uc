#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Exercises the `ip`-using code paths on a PATH that has no `ip`, and lets
// the real log() write to stderr so the caller can read what a user would see.
//
// Why a separate process: `ip` is a declared dependency, so it is present on
// the dev machine, and ucode cannot change its own environment. Stripping it
// from PATH is only possible for a child. The caller runs this with a PATH
// that holds the stubs directory and nothing else.
//
// Not named test_*.uc on purpose: run.sh globs that pattern, and this is a
// helper invoked BY a test.

'use strict';

const _routing = require('protonvpn.routing');

global.MOCK_UCI = { network: {
	globals: { '.type': 'globals', ula_prefix: 'fd7a:1b2c:3d4e::/48' }
}, dhcp: {}, firewall: { wanzone: { '.type': 'zone', name: 'wan', network: 'wan' } } };

import { cursor } from 'uci';

// The public entry point, twice: at least one failed `ip` run per pass (the
// WAN IPv6 default-route probe), more when the fixture has WAN devices to
// measure. The user is told once either way, because a missing dependency is
// one fact, not one fact per probe.
let uci = cursor();
_routing.detect(uci, {}, true);
_routing.detect(uci, {}, true);

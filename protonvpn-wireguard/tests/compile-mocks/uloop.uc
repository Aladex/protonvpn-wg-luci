// SPDX-License-Identifier: MIT
// A COMPILE-RESOLUTION stand-in for ucode's 'uloop' module. Not a behavioural
// mock, and deliberately not usable as one.
//
// It lives in tests/compile-mocks and NOT in tests/mocks, and the difference
// is the whole point: run.sh puts tests/mocks on the runtime search path of
// every suite, so anything in there is importable by any test. Only the CI
// compile step puts this directory on its path. tests/test_mocks.uc asserts
// both halves — that the compiler can find this file and that a suite cannot.
//
// Why it exists: the CI interpreter is built without uloop (ULOOP_SUPPORT=OFF
// — it needs libubox, which the offline toolchain does not carry), and
// `ucode -c` RESOLVES imports while compiling. /usr/bin/protonvpn-service
// imports uloop, so without this file that program cannot be syntax-checked
// at all — which is exactly why it sat outside the hand-maintained list of
// compile-checked entry points, uncovered, for as long as the list existed.
//
// Every function here dies if it is ever CALLED. A stand-in that quietly did
// nothing would let a future test of the service loop pass without running a
// loop, which is worse than not having the test: the suite would assert the
// scheduling of jobs that were never scheduled. Resolving the import is the
// whole of what this file is for; if you need to exercise the daemon's timing,
// model uloop properly and measure it against the device first, the way
// mocks/uci.uc and mocks/ubus.uc were.

'use strict';

function unusable(name) {
	die('uloop.' + name + '() was called: mocks/uloop.uc only exists so ' +
		'protonvpn-service can be compile-checked, and models no behaviour');
}

export function init() { unusable('init'); }
export function run() { unusable('run'); }
export function task() { unusable('task'); }
export function interval() { unusable('interval'); }
export function timer() { unusable('timer'); }
export function handle() { unusable('handle'); }
export function process() { unusable('process'); }
export function end() { unusable('end'); }
export function done() { unusable('done'); }

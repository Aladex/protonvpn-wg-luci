// SPDX-License-Identifier: MIT
// Minimal 'ubus' module mock for offline ucode tests. Seed responses keyed by
// "<object>~<method>" via global.MOCK_UBUS:
//   global.MOCK_UBUS = { 'network.interface.protonvpn~status': { up: true, l3_device: 'protonvpn' } };
//
// Connections are counted in global.MOCK_UBUS_OPEN so tests can assert that
// callers close what they open: a connection leaked once per daemon tick
// exhausts ubusd's file descriptors and takes the whole router's ubus down.
//
// Measured against the real module on the device, so the differences that
// remain are deliberate (see tests/test_mocks.uc, which pins both):
//   * the error TEXT is not reproduced. ubusd distinguishes an unknown object
//     ("Not found: Failed to resolve object name ...") from an unknown method
//     ("Method not found: Failed to invoke function ..."); this mock is keyed
//     by object~method and cannot tell them apart without a richer seed
//     format, and nothing in the product reads the text.
//   * connect() always succeeds. The real one answers null when ubusd is
//     unreachable, which is why status.uc guards with `if (ub)` — a guard the
//     suite therefore cannot exercise.

'use strict';

export function connect() {
	let err = null;
	global.MOCK_UBUS_OPEN = (global.MOCK_UBUS_OPEN || 0) + 1;
	let closed = false;
	return {
		call: function(object, method, args) {
			// Measured on the device: a call on a closed connection does not
			// reach ubusd at all, it fails with "Connection is closed". The
			// mock used to answer one, which made a use-after-close — the
			// exact misuse the open-connection count above exists to catch —
			// invisible to the suite.
			if (closed) {
				err = 'Connection failed: Connection is closed';
				return null;
			}
			let key = object + '~' + method;
			let resp = global.MOCK_UBUS ? global.MOCK_UBUS[key] : null;
			if (resp == null) {
				err = 'Method not found';
				return null;
			}
			err = null;
			return resp;
		},
		error: function() { return err; },
		disconnect: function() {
			// The real module answers true for the close that did something
			// and null for a second one; both are ignored rather than fatal.
			if (closed)
				return null;
			closed = true;
			global.MOCK_UBUS_OPEN = (global.MOCK_UBUS_OPEN || 1) - 1;
			return true;
		}
	};
}

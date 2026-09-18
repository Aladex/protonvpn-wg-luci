#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// Skeleton smoke test: require every backend module and assert the exported
// symbols exist, so the scaffold stays compile-checked from day one. Real
// behavior tests land with the implementation. Run via tests/run.sh.

'use strict';

let ok = true;
function check(label, cond) {
	if (!cond) {
		ok = false;
		printf('FAIL %s\n', label);
	} else {
		printf('ok   %s\n', label);
	}
}

// Expected export tables per module. Keep in sync with the modules' return
// blocks when the implementation fills in.
let modules = {
	'protonvpn.common': [
		'VERSION', 'API_BASE', 'LOGICALS_URL', 'CERT_URL',
		'DEFAULT_INTERFACE', 'DEFAULT_PORT', 'FIXED_ADDRESS', 'FIXED_ADDRESS6',
		'SESSION_MAX_AGE', 'SESSION_REFRESH_AGE', 'CERT_MAX_DAYS', 'FEATURE_IPV6',
		'validate_hop_mode', 'validate_dns_mode', 'validate_ipv6_mode',
		'iface_ipv6_capable', 'validate_instance',
		'load_settings', 'list_instances', 'cache_file_path', 'log',
		'atomic_write', 'acquire_lock', 'release_lock', 'run'
	],
	'protonvpn.api': [
		'PM_APPVERSION', 'SESSION_FILE',
		'session_load', 'session_store',
		'auth_info', 'auth_finish', 'totp_submit', 'auth_refresh', 'logout',
		'certificate_create', 'certificate_delete'
	],
	'protonvpn.cache': [
		'write_fetch_status', 'read_fetch_status', 'add_server', 'normalize',
		'locations_tree', 'city_relays', 'pool_relays',
		'fetch_servers', 'read_cache', 'cache_is_stale', 'write_cache',
		'fetch_and_build'
	],
	'protonvpn.select': [
		'candidates', 'location_candidates', 'selection_candidates',
		'by_hostname', 'pick'
	],
	'protonvpn.apply': [
		'ensure_keypair', 'current_peer', 'restore_peer', 'write_relay',
		'bring_up', 'verify_handshake', 'connect_one', 'apply', 'disconnect',
		'create_instance', 'delete_instance', 'restore_wan_default',
		'write_apply_status', 'read_apply_status', 'apply_running',
		'apply_status_report', 'run_apply', 'start_apply'
	],
	'protonvpn.rotate': [
		'shuffle', 'current_key', 'plan_candidates', 'read_state', 'record',
		'last_attempt_ts', 'mark_attempt', 'rotate'
	],
	'protonvpn.routing': [
		'detect', 'enforce', 'reconcile_ipv6', 'ipv6_state',
		'find_wan_zone', 'find_lan_zone',
		'count_user_routes', 'recommend_mtu'
	],
	'protonvpn.service': [
		'should_refresh', 'should_rotate', 'next_rotation', 'should_recover',
		'watchdog_update', 'watchdog_result_update',
		'should_refresh_session', 'should_renew_certificate'
	],
	'protonvpn.status': [
		'status'
	]
};

for (let name in modules) {
	let m = require(name);
	check(name + ' loads', type(m) == 'object');
	if (type(m) != 'object')
		continue;
	for (let sym in modules[name])
		check(sprintf('%s exports %s', name, sym), m[sym] != null);
}

// Proton-specific constants, as verified against the live API.
let common = require('protonvpn.common');
check('client address is 10.2.0.2/32', common.FIXED_ADDRESS == '10.2.0.2/32');
// NOT the address Proton's own web client writes into generated configs —
// see the comment on FIXED_ADDRESS6 for why the published one is one-way.
check('client IPv6 is the in-tunnel ULA Proton actually answers to',
	common.FIXED_ADDRESS6 == 'fd54:20a4:d33b:b10c:0:2:0:2/128');
check('and the in-tunnel resolver is its counterpart',
	common.VPN_DNS6 == 'fd54:20a4:d33b:b10c:0:2:0:1');
// Bit 16 of the logical Features bitmask is what the adaptive IPv6 mode reads
// back off the interface stamp; the value is Proton's, not ours to change.
check('the IPv6 feature bit is 16', common.FEATURE_IPV6 == 16);
check('ipv6 modes validate',
	common.validate_ipv6_mode('block') == 'block' &&
	common.validate_ipv6_mode('auto') == 'auto' &&
	common.validate_ipv6_mode('off') == 'off' &&
	common.validate_ipv6_mode('1') == null);
check('hop modes validate',
	common.validate_hop_mode('standard') == 'standard' &&
	common.validate_hop_mode('secure_core') == 'secure_core' &&
	common.validate_hop_mode('tor') == 'tor' &&
	common.validate_hop_mode('single') == null);

let api = require('protonvpn.api');
// The version gate answers 5003 (legacy) or 2028 (current); both mean the
// stamped client version is no longer accepted. The official client format
// carries a client-type segment: 'linux-vpn-<type>@<version>'.
check('PM_APPVERSION is stamped (Code 5003/2028 guard)',
	match(api.PM_APPVERSION, /^linux-vpn-[a-z0-9-]+@[0-9]+\.[0-9]+\.[0-9]+$/) != null);

exit(ok ? 0 : 1);

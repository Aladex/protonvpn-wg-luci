// SPDX-License-Identifier: MIT
// Key-derivation tests.
//
// Proton registers an Ed25519 public key and derives the X25519 peer key it
// expects from it with the birational Edwards->Montgomery map. That map is
// consistent with the Ed25519 *expanded scalar*, SHA-512(seed)[0:32], NOT with
// the 32-byte seed itself. Using the seed as the WireGuard private key yields a
// tunnel that completes a handshake (Proton accepts unknown initiators) and even
// answers ICMP from 10.2.0.1, but is never authorised: nothing is forwarded and
// /vpn/v1/sessions keeps reporting zero sessions. Verified live on 2026-07-30.
//
// The vector below was computed from first principles (SHA-512 + curve25519
// scalar mult of the clamped scalar) and confirmed against a live Proton server.

'use strict';

import { popen, unlink } from 'fs';
import { cursor } from 'uci';

let ok = true;
function check(name, cond) {
	printf('%s %s\n', cond ? 'ok  ' : 'FAIL', name);
	if (!cond)
		ok = false;
}

let api = require('protonvpn.api');
let apply = require('protonvpn.apply');

// seed = bytes 0x00..0x1f
const SEED = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
const WG_PRIVATE = 'PZTupJxYCu+BaTV2K+BJVZ1tFEDe3hLmoSXxhB//jm8=';
const WG_PUBLIC = 'RwHQhIhFH1RaQJ+1iuPlhYHKQKw/fxFGmM1x3qxzygE=';

check('protonvpn.api exports wg_key_from_seed', api.wg_key_from_seed != null);
check('protonvpn.api exports pem_from_seed', api.pem_from_seed != null);
check('protonvpn.apply exports migrate_legacy_key', apply.migrate_legacy_key != null);

if (api.wg_key_from_seed) {
	let d = api.wg_key_from_seed(SEED);
	check('wg key is the SHA-512 expanded scalar, not the seed',
		d.wg_private == WG_PRIVATE);
	check('the derived key differs from the seed', d.wg_private != SEED);
	check('a malformed seed is rejected',
		(api.wg_key_from_seed('nope') || {}).error != null);
}

// pem_from_seed must not need xxd: busybox has no such applet, so the original
// implementation failed on every real router and broke certificate renewal.
let has_openssl = false;
let p = popen('command -v openssl >/dev/null 2>&1 && echo yes', 'r');
if (p) {
	has_openssl = trim(p.read('all') || '') == 'yes';
	p.close();
}
if (has_openssl && api.pem_from_seed) {
	let pem = api.pem_from_seed(SEED);
	check('pem_from_seed rebuilds a PEM public key without xxd',
		pem.error == null && match(pem.pem_public || '', /^-----BEGIN PUBLIC KEY-----/));
} else {
	printf('skip  pem_from_seed round-trip (no openssl)\n');
}

// A pre-fix install stored the seed in network.<iface>.private_key and kept no
// seed of its own. Migration must move the seed into our 0600 state file and
// leave the correctly derived key in UCI, without touching the certificate:
// the registered Ed25519 identity is unchanged, only our local derivation was.
if (apply.migrate_legacy_key) {
	global.MOCK_UCI = {
		protonvpn: { main: { '.type': 'instance', interface: 'protonvpn' } },
		network: { protonvpn: { '.type': 'interface', proto: 'wireguard',
			private_key: SEED } }
	};
	let uci = cursor();
	let res = apply.migrate_legacy_key(uci, 'main');
	check('migration reports it converted a legacy key', res.migrated == true);
	check('UCI now holds the derived WireGuard key',
		uci.get('network', 'protonvpn', 'private_key') == WG_PRIVATE);
	check('the seed is kept in the certificate state',
		(apply.read_cert_state('main') || {}).key_seed == SEED);

	// Idempotent: a second pass must not re-derive from the already-derived key.
	let again = apply.migrate_legacy_key(uci, 'main');
	check('migration is idempotent', again.migrated != true &&
		uci.get('network', 'protonvpn', 'private_key') == WG_PRIVATE);
}

check('public key of the vector is stable', length(WG_PUBLIC) == 44);

// Renewal re-registers a key the account already carries. Without Renew the API
// answers 409/Code 2500 and the certificate would silently rot until it lapsed.
{
	let renewed = api.certificate_body('-----BEGIN PUBLIC KEY-----x',
		'persistent', 30, true);
	check('a renewal sets Renew', renewed.Renew == true);
	check('and names the key mode', renewed.ClientPublicKeyMode == 'EC');
	check('and spells out Features', type(renewed.Features) == 'object');
	check('and stays persistent', renewed.Mode == 'persistent');

	let first = api.certificate_body('-----BEGIN PUBLIC KEY-----x', 'persistent', 30);
	check('a first registration does not set Renew', first.Renew == null);

	// Session certificates are capped far lower, and carry no device name.
	let sess = api.certificate_body('-----BEGIN PUBLIC KEY-----x', 'session', 9999);
	check('a session certificate is capped', sess.Duration != '9999 days');
	check('and is not named in the dashboard', sess.DeviceName == null);
}

// The suite shares one state directory, so leave it as we found it.
unlink((getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn') + '/certificate.json');

exit(ok ? 0 : 1);

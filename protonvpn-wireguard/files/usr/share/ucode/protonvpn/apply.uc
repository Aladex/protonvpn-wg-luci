// SPDX-License-Identifier: MIT
// Keypair/certificate storage and transactional WireGuard apply. Shared by
// the rpcd `apply`/`certificate_renew` methods and the procd reload path.
//
// Proton difference vs nordvpn: the WireGuard keypair is generated LOCALLY
// and the public key is registered with the API as a "certificate" (see
// protonvpn.api). The certificate is account-wide — one key talks to ANY
// server, so apply/rotation only swap the peer's X25519PublicKey and
// endpoint.

'use strict';

import { rand, srand } from 'math';
import { readfile, unlink, chmod, mkdir, stat } from 'fs';
import { cursor } from 'uci';
const _common = require('protonvpn.common');
const FIXED_ADDRESS = _common.FIXED_ADDRESS,
      FIXED_ADDRESS6 = _common.FIXED_ADDRESS6,
      DEFAULT_PORT = _common.DEFAULT_PORT,
      DEFAULT_KEEPALIVE = _common.DEFAULT_KEEPALIVE,
      CERT_MAX_DAYS = _common.CERT_MAX_DAYS,
      load_settings = _common.load_settings,
      cache_file_path = _common.cache_file_path,
      validate_interface = _common.validate_interface,
      validate_instance = _common.validate_instance,
      validate_wg_key = _common.validate_wg_key,
      iso_ts = _common.iso_ts,
      log = _common.log,
      run = _common.run;
const read_cache = require('protonvpn.cache').read_cache;
const _select = require('protonvpn.select');
const selection_candidates = _select.selection_candidates,
      by_hostname = _select.by_hostname,
      pick = _select.pick;
const _api = require('protonvpn.api');
const enforce_routing = require('protonvpn.routing').enforce;

// Certificate metadata lives next to the session state (same root-only
// directory), NOT in UCI — it must survive a session loss, because the
// certificate outlives the session and its expiry is the real deadline.
// Keyed by instance name: every instance carries its own
// keypair and therefore its own registration.
// PROTONVPN_STATE_DIR relocates it for the offline test suite, which cannot
// write to /etc (same convention as protonvpn.api's session file).
const CERT_STATE_DIR = getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn';
const CERT_STATE_FILE = CERT_STATE_DIR + '/certificate.json';

// One file holds EVERY instance's entry while the daemon forks one task per
// instance, so the read-modify-write below is a genuine race. Losing it does
// not just lose a serial number: key_seed is the only copy of an instance's
// Ed25519 identity, the certificate is registered against it, and it cannot be
// regenerated — so a lost update costs the tunnel permanently. On tmpfs, since
// it is taken on every renewal and flash should not wear out for a lock.
const CERT_STATE_LOCK = '/tmp/protonvpn_cert_state.lock';

// Take the certificate-state lock. The critical section is a read, a merge and
// an atomic write — milliseconds — so a holder that outlives the reclamation
// window is a crashed one; wait that window out rather than drop an update.
// Returns the token or null.
function lock_cert_state() {
	let lock = null;
	for (let i = 0; i < 1550 && !lock; i++) {
		lock = _common.acquire_lock(CERT_STATE_LOCK, 30);
		if (!lock)
			sleep(20);
	}
	return lock;
}

// Locate the managed peer section (type wireguard_<iface>, interface=<iface>).
function find_peer(uci, iface) {
	let found = null;
	uci.foreach('network', null, function(sec) {
		if (sec['.type'] && index(sec['.type'], 'wireguard_') == 0 && sec.interface == iface) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// Stored certificate metadata of one instance ({ serial, expires_at,
// created_at }) or null. Exported so status/service can show/schedule the
// certificate lifetime without knowing the storage layout.
function read_cert_state(instance) {
	let raw = readfile(CERT_STATE_FILE);
	if (!raw)
		return null;
	let all;
	try {
		all = json(raw);
	} catch (e) {
		return null;
	}
	if (type(all) != 'object')
		return null;
	let n = validate_instance(instance) || 'main';
	return all[n] || null;
}

// The merge itself, with the state lock already held.
function record_cert_state_locked(instance, fields) {
	let all = {};
	let raw = readfile(CERT_STATE_FILE);
	if (raw) {
		try {
			all = json(raw) || {};
		} catch (e) {
			all = {};
		}
	}
	if (type(all) != 'object')
		all = {};
	let n = validate_instance(instance) || 'main';
	// Merge rather than replace: the key seed is written once, at generation,
	// and every later certificate renewal must leave it standing.
	let entry = (type(all[n]) == 'object') ? all[n] : {};
	for (let k in fields)
		entry[k] = fields[k];
	all[n] = entry;
	if (!stat(CERT_STATE_DIR))
		mkdir(CERT_STATE_DIR, 0o700);
	if (!_common.atomic_write(CERT_STATE_FILE, sprintf('%J', all)))
		return false;
	chmod(CERT_STATE_FILE, 0o600);
	return true;
}

// Merge the certificate metadata of one instance into the state file
// (atomic write, 0600 — the file sits next to bearer tokens), serialized
// against the other instances' workers.
function record_cert_state(instance, fields) {
	let lock = lock_cert_state();
	if (!lock) {
		log('could not lock the certificate state for ' +
			(validate_instance(instance) || 'main'));
		return false;
	}
	let ok = record_cert_state_locked(instance, fields);
	_common.release_lock(lock);
	return ok;
}

// The removal itself, with the state lock already held.
function forget_cert_state_locked(instance) {
	let raw = readfile(CERT_STATE_FILE);
	if (!raw)
		return true;
	let all;
	try {
		all = json(raw);
	} catch (e) {
		return false;
	}
	if (type(all) != 'object')
		return false;
	let n = validate_instance(instance) || 'main';
	if (all[n] == null)
		return true;
	delete all[n];
	if (!_common.atomic_write(CERT_STATE_FILE, sprintf('%J', all)))
		return false;
	chmod(CERT_STATE_FILE, 0o600);
	return true;
}

// Drop one instance's certificate metadata, leaving the other instances'
// entries intact — the same shared file, so the same lock.
function forget_cert_state(instance) {
	let lock = lock_cert_state();
	if (!lock) {
		log('could not lock the certificate state for ' +
			(validate_instance(instance) || 'main'));
		return false;
	}
	let ok = forget_cert_state_locked(instance);
	_common.release_lock(lock);
	return ok;
}

// Release an instance's Proton-side registration. Certificates live up to a
// year and the per-account limit is unknown, so leaving one behind for an
// instance nobody uses any more slowly consumes a budget we cannot see. Best
// effort throughout — a certificate cannot be revoked with the VPN scope, and
// a dead session must not block the caller.
function retire_certificate(name) {
	let cs = read_cert_state(name);
	if (!cs || !cs.serial)
		return false;

	// Our token cannot revoke (403/9100 — only a web session can), so instead
	// of leaving a year-long registration squatting a device slot, renew it
	// down to the shortest life the API grants: a renewal supersedes the
	// previous registration for the same key, and what is left expires within
	// minutes.
	let done = false;
	if (cs.key_seed) {
		let pem = _api.pem_from_seed(cs.key_seed);
		if (!pem.error) {
			let t = _api.certificate_tombstone(pem.pem_public);
			if (t.ok) {
				done = true;
				log('certificate for ' + name + ' set to expire within minutes');
			} else {
				log('could not shorten the certificate for ' + name + ': ' +
					(t.error || 'unknown error'));
			}
		}
	}
	// No seed (an instance from before the seed was kept): the listing hands
	// back the public key of every certificate, which is all a tombstone needs,
	// so look ours up by serial.
	if (!done) {
		let listed = _api.certificate_list('persistent');
		if (listed.ok) {
			for (let c in listed.certificates) {
				if (c.serial != cs.serial || !length(c.client_key || ''))
					continue;
				let t = _api.certificate_tombstone(c.client_key);
				if (t.ok) {
					done = true;
					log('certificate for ' + name + ' set to expire within minutes');
				}
				break;
			}
		}
	}
	if (!done) {
		// Everything above failed: our token cannot revoke (403/9100 — the
		// dashboard gets there by re-authenticating with the password to obtain
		// the 'locked' scope, which a VPN session does not reach).
		_api.certificate_delete(cs.serial);
		log('certificate ' + cs.serial + ' for ' + name +
			' stays on the account until it expires; remove it under ' +
			'Downloads -> WireGuard configuration at account.protonvpn.com');
	}
	return done;
}

// Repair an instance created before the WireGuard key derivation was fixed.
// Such installs stored the Ed25519 seed itself in network.<iface>.private_key,
// which Proton never authorises (see api.wg_key_from_seed). The registered
// certificate stays valid — only our local derivation was wrong — so the repair
// is purely local: keep the seed in the state file and leave the derived key in
// UCI. Returns { migrated: true } when it changed something.
function migrate_legacy_key(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };

	let stored = read_cert_state(s.name) || {};
	if (stored.key_seed)
		return { migrated: false };

	let legacy = validate_wg_key(uci.get('network', iface, 'private_key'));
	if (!legacy)
		return { migrated: false };

	let derived = _api.wg_key_from_seed(legacy);
	if (derived.error)
		return derived;

	uci.set('network', iface, 'private_key', derived.wg_private);
	uci.commit('network');
	record_cert_state(s.name, { key_seed: legacy });
	log('migrated ' + s.name + ' to the correct WireGuard key derivation');
	return { migrated: true };
}

// Ensure the instance has a local WireGuard keypair and a registered
// certificate: generate the key on first use, store the private key on
// the managed interface (proto wireguard, vpn_type protonvpn, FIXED_ADDRESS
// + FIXED_ADDRESS6), and register the public key via
// _api.certificate_create(). Returns { ok: true } or { error }.
function ensure_keypair(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };

	// Fast path: the instance already has a keypair. Repair the derivation on
	// the way through — an install predating the fix carries a key Proton never
	// authorises, and every apply is a chance to put that right.
	if (validate_wg_key(uci.get('network', iface, 'private_key'))) {
		let mig = migrate_legacy_key(uci, instance);
		if (mig.error)
			return mig;
		return { ok: true };
	}

	// Registration is an authenticated call; without a session there is
	// nothing to apply yet.
	if (!_api.session_load())
		return { error: 'not logged in' };

	// Key generation lives in protonvpn.api next to the call that consumes it:
	// the API rejects a raw wg key (400/Code 2001) and wants a PEM Ed25519 one,
	// from whose seed the WireGuard key is derived (api.wg_key_from_seed).
	// That helper creates the temp file under umask 077 with an unpredictable
	// name, which a fixed /tmp path could not do safely.
	let kp = _api.generate_keypair();
	if (kp.error)
		return kp;
	let private_key = validate_wg_key(kp.wg_private);
	if (!private_key)
		return { error: 'could not derive the WireGuard key from the Ed25519 seed' };

	// Register before persisting: a failed registration must not leave an
	// orphaned private key the fast path would mistake for a working setup.
	let cert = _api.certificate_create(kp.pem_public, 'persistent', CERT_MAX_DAYS);
	if (cert.error)
		return cert;

	if (!uci.get('network', iface))
		uci.set('network', iface, 'interface');
	uci.set('network', iface, 'proto', 'wireguard');
	uci.set('network', iface, 'vpn_type', 'protonvpn');
	uci.set('network', iface, 'private_key', private_key);
	uci.set('network', iface, 'addresses', [ FIXED_ADDRESS, FIXED_ADDRESS6 ]);
	uci.commit('network');

	record_cert_state(s.name, {
		serial: cert.serial || null,
		expires_at: cert.expires_at || 0,
		// RefreshTime is Proton telling us when to renew — keep it so the
		// daemon can prefer it over a guessed threshold.
		refresh_at: cert.refresh_at || 0,
		// The seed is the Ed25519 identity Proton knows us by; renewal has to
		// re-register the very same one. It lives here, in our 0600 state file,
		// rather than in the world-readable /etc/config/network.
		key_seed: kp.key_seed,
		created_at: time()
	});
	log('generated a local keypair and registered a certificate for ' + s.name);
	return { ok: true };
}

// Re-register the instance's EXISTING key before the certificate lapses.
// Deliberately keeps the same key: a new one would mean rewriting the
// interface and bouncing the tunnel, while Proton's own RefreshTime simply
// asks for a fresh registration of what we already have.
function renew_certificate(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };

	// Renewal re-registers the Ed25519 identity, so it needs the seed, not the
	// WireGuard key derived from it. Older instances kept the seed in UCI;
	// migrate them first so the lookup below always finds it in the state file.
	migrate_legacy_key(uci, instance);
	let seed = validate_wg_key((read_cert_state(s.name) || {}).key_seed);
	if (!seed)
		return { error: 'this instance has no keypair yet; apply first' };
	if (!_api.session_load())
		return { error: 'not logged in' };

	let pem = _api.pem_from_seed(seed);
	if (pem.error)
		return pem;

	let cert = _api.certificate_create(pem.pem_public, 'persistent', CERT_MAX_DAYS, true);
	if (cert.error)
		return cert;

	// Drop the superseded registration so a long-lived instance does not
	// accumulate certificates on the account; failure here is not fatal.
	let old = read_cert_state(s.name);
	if (old && old.serial && old.serial != cert.serial) {
		// A renewal with Renew:true supersedes the old registration server-side,
		// so this is belt and braces; it is expected to report `skipped`.
		let rev = _api.certificate_delete(old.serial);
		if (rev.error)
			log('could not drop the superseded certificate ' + old.serial +
				': ' + rev.error);
	}

	record_cert_state(s.name, {
		serial: cert.serial || null,
		expires_at: cert.expires_at || 0,
		refresh_at: cert.refresh_at || 0,
		created_at: time()
	});
	log('renewed the certificate for ' + s.name);
	return { ok: true, serial: cert.serial, expires_at: cert.expires_at,
		refresh_at: cert.refresh_at };
}

// Snapshot the current peer { public_key, endpoint_host, endpoint_port,
// gateway } for rollback, or null.
function current_peer(uci, iface) {
	let peer = find_peer(uci, iface);
	if (!peer)
		return null;
	return {
		public_key: uci.get('network', peer, 'public_key'),
		endpoint_host: uci.get('network', peer, 'endpoint_host'),
		endpoint_port: uci.get('network', peer, 'endpoint_port'),
		gateway: uci.get('network', peer, 'protonvpn_gateway')
	};
}

// Restore a snapshot taken by current_peer() (no commit).
function restore_peer(uci, iface, saved) {
	if (!saved)
		return;
	let peer = find_peer(uci, iface);
	if (!peer)
		peer = uci.add('network', 'wireguard_' + iface);
	uci.set('network', peer, 'interface', iface);
	if (saved.public_key)
		uci.set('network', peer, 'public_key', saved.public_key);
	if (saved.endpoint_host)
		uci.set('network', peer, 'endpoint_host', saved.endpoint_host);
	if (saved.endpoint_port)
		uci.set('network', peer, 'endpoint_port', saved.endpoint_port);
	if (saved.gateway)
		uci.set('network', peer, 'protonvpn_gateway', saved.gateway);
}

// Write interface + peer UCI for the chosen relay (no commit): peer
// public_key = relay.public_key (the server's X25519PublicKey), endpoint =
// relay entry IP + DEFAULT_PORT, allowed_ips 0.0.0.0/0 + ::/0, stamps for
// location/last-applied. The peer pubkey differs per server while OUR
// keypair/certificate stays the same (account-wide).
function write_relay(uci, iface, relay, s) {
	uci.set('network', iface, 'proto', 'wireguard');
	uci.set('network', iface, 'vpn_type', 'protonvpn');
	uci.set('network', iface, 'auto', '1');
	// ProtonVPN assigns the same tunnel addresses to every client (like
	// Nord's 10.5.0.2, unlike Mullvad's per-device addresses).
	uci.set('network', iface, 'addresses', [ FIXED_ADDRESS, FIXED_ADDRESS6 ]);

	if (s.routing_table && s.routing_table != '') {
		uci.set('network', iface, 'ip4table', s.routing_table);
		uci.set('network', iface, 'ip6table', s.routing_table);
	} else {
		uci.delete('network', iface, 'ip4table');
		uci.delete('network', iface, 'ip6table');
	}

	// Optional MTU override; empty falls back to netifd's WireGuard default.
	if (s.mtu)
		uci.set('network', iface, 'mtu', '' + s.mtu);
	else
		uci.delete('network', iface, 'mtu');

	// Stamp the ACTUAL server's country/city: with a location set the
	// connected relay may sit in any of the set's countries, and the status
	// must reflect where the tunnel really exits. cache.uc already groups by
	// the exit country, so country_code IS the exit one (Secure Core included).
	uci.set('network', iface, 'protonvpn_country_code', relay.country_code || s.country_code);
	uci.set('network', iface, 'protonvpn_city_code', relay.city_code || relay.location || s.city_code);
	uci.set('network', iface, 'protonvpn_last_applied', iso_ts());

	let peer = find_peer(uci, iface);
	if (!peer)
		peer = uci.add('network', 'wireguard_' + iface);
	uci.set('network', peer, 'interface', iface);
	// Managed routing stamps the interface; the peer's allowed-IPs routes
	// (netifd-installed, into ip4table when set) follow it.
	if (uci.get('network', iface, 'protonvpn_managed_routing') == '1')
		uci.set('network', peer, 'route_allowed_ips', '1');
	uci.set('network', peer, 'public_key', relay.public_key);
	// Proton endpoints are connected by EntryIP, not by DNS name.
	uci.set('network', peer, 'endpoint_host', relay.ip_address || relay.hostname);
	uci.set('network', peer, 'endpoint_port', '' + (relay.port || DEFAULT_PORT));
	uci.set('network', peer, 'persistent_keepalive', '' + DEFAULT_KEEPALIVE);
	uci.set('network', peer, 'allowed_ips', [ '0.0.0.0/0', '::/0' ]);
	// The logical name ('NL#85') is the identity the user sees and pins, so
	// stamp that rather than the per-server domain; rotation's exclusion and
	// select.by_hostname both accept either form.
	uci.set('network', peer, 'protonvpn_gateway', relay.name || relay.hostname);
}

// ifup the interface. iface is whitelist-validated, so the argv is
// injection-safe (no shell).
function bring_up(iface) {
	return run([ 'ifup', iface ]).code == 0;
}

// Newest WireGuard handshake age (seconds) for the interface. Returns -1 when
// wg cannot be run (off-device), null when it ran but there is no handshake.
function handshake_age(iface) {
	let res = run([ 'wg', 'show', iface, 'latest-handshakes' ]);
	if (res.code != 0)
		return -1;
	let best = 0;
	for (let line in split(trim(res.stdout || ''), '\n')) {
		let parts = split(line, '\t');
		if (length(parts) >= 2) {
			let t = int(parts[1]);
			if (t > best)
				best = t;
		}
	}
	if (best == 0)
		return null;
	let age = time() - best;
	return age < 0 ? 0 : age;
}

// Poll up to `seconds` for a fresh WireGuard handshake. True when connected
// (or when wg is unavailable off-device, so the apply logic is not blocked
// in tests).
function verify_handshake(iface, seconds) {
	for (let i = 0; i < seconds; i++) {
		run([ 'sleep', '1' ]);
		let age = handshake_age(iface);
		if (age == -1)
			return true;
		if (age != null && age < 180)
			return true;
	}
	return false;
}

function shuffle(list) {
	let a = [];
	for (let x in list)
		push(a, x);
	for (let i = length(a) - 1; i > 0; i--) {
		let j = rand() % (i + 1);
		let t = a[i]; a[i] = a[j]; a[j] = t;
	}
	return a;
}

// write_relay + commit + bring_up for one candidate. Bool.
function connect_one(uci, iface, relay, s) {
	write_relay(uci, iface, relay, s);
	uci.commit('network');
	return bring_up(iface);
}

// A global netifd reload has been observed (OpenWrt 24.10) to remove the
// kernel's main IPv4 default route while netifd still reports it as
// installed, cutting WAN connectivity. Self-heal: when the kernel lost the
// default but netifd claims a gateway route on an up interface, re-add it.
function restore_wan_default() {
	// The reload applies asynchronously; the route can disappear a moment
	// after an immediate check passes, so probe a few times.
	for (let attempt = 0; attempt < 3; attempt++) {
		run([ 'sleep', '2' ]);
		let r = run([ 'ip', '-4', 'route', 'show', 'default' ]);
		if (r.code != 0)
			return false;
		if (length(trim(r.stdout || '')) > 0)
			continue;
		let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
		if (d.code != 0)
			return false;
		let data;
		try {
			data = json(d.stdout);
		} catch (e) {
			return false;
		}
		for (let ifc in ((data ? data.interface : null) || [])) {
			if (!ifc.up || !ifc.l3_device)
				continue;
			for (let rt in (ifc.route || [])) {
				if (rt.target == '0.0.0.0' && rt.mask == 0 && rt.nexthop && rt.nexthop != '0.0.0.0') {
					let res = run([ 'ip', 'route', 'add', 'default', 'via', rt.nexthop, 'dev', ifc.l3_device ]);
					if (res.code != 0)
						return false;
					// Only claim success once the route really went in.
					log('restored missing WAN default route via ' + rt.nexthop +
						' on ' + ifc.l3_device);
				}
			}
		}
	}
	return true;
}

// Main transactional apply: settings -> ensure_keypair -> enforce routing ->
// fixed server or shuffled candidates with handshake verify -> rollback on
// total failure. A fixed server is applied once; an automatic selection
// tries several candidates until one completes a handshake, rolling back to
// the previous working peer if none do. Bounded so the rpc call stays
// within timeout. Returns { state, interface, gateway, endpoint, ... }.
function apply_inner(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { state: 'failure', error: 'invalid interface name' };

	// Generate the keypair and register its certificate on first use — that
	// needs a live session, so the error surfaces as 'not logged in'. Called
	// unconditionally: ensure_keypair has its own fast path, and that path is
	// also where an install predating the key-derivation fix gets repaired.
	let kr = ensure_keypair(uci, s.name);
	if (kr.error)
		return { state: 'failure', error: kr.error };

	let cache = read_cache(cache_file_path(s));
	if (!cache)
		return { state: 'failure', error: 'server list not available; refresh the cache first' };

	// Applying implies the user wants the instance on — undo a disable, both
	// in the config and in the already-loaded settings the enforcement uses.
	if (!s.enabled) {
		uci.set('protonvpn', s.name, 'enabled', '1');
		uci.commit('protonvpn');
		s.enabled = true;
	}

	// Reconcile the managed routing/firewall objects with the settings. Only
	// stamped objects are ever touched; a detected manual scheme is left alone.
	let routing = enforce_routing(uci, s);
	if (routing.changed_firewall) {
		uci.commit('firewall');
		run([ '/etc/init.d/firewall', 'reload' ]);
	}
	if (routing.changed_network) {
		uci.commit('network');
		// Steering/prohibit rules are plain netifd config; a reload makes
		// netifd apply the delta (unchanged interfaces are left alone).
		run([ 'ubus', 'call', 'network', 'reload' ]);
	}
	if (routing.changed_network || routing.changed_firewall) {
		// Committing deletions invalidates the cursor's section iteration
		// state (find_peer silently missed sections) — start fresh.
		uci = cursor();
	}
	for (let note in routing.notes)
		_common.log('routing: ' + note);

	srand(time());
	let saved = current_peer(uci, iface);
	let endpoint_of = function(relay) {
		return (relay.ip_address || relay.hostname) + ':' + (relay.port || DEFAULT_PORT);
	};

	if (s.fixed_server && s.fixed_server != '') {
		let relay = by_hostname(cache, s.fixed_server);
		if (!relay)
			return { state: 'failure', error: 'configured server not found in cache' };
		let up = connect_one(uci, iface, relay, s);
		let ok = up && verify_handshake(iface, s.verify_timeout);
		return {
			state: ok ? 'success' : (up ? 'partial_failure' : 'failure'),
			interface: iface, gateway: relay.hostname,
			endpoint: endpoint_of(relay),
			restarted: up,
			error: ok ? null : 'the selected server did not respond'
		};
	}

	let list = selection_candidates(cache, s);
	if (length(list) == 0)
		return { state: 'failure', error: 'no matching server found for the current selection' };
	list = shuffle(list);

	// Honour max_retries like rotation does, but keep a hard ceiling: apply is
	// called from an rpc handler and each attempt costs verify_timeout seconds,
	// so a large setting must not blow the request timeout.
	let budget = s.max_retries || 4;
	if (budget > 4)
		budget = 4;
	let tries = length(list);
	if (tries > budget)
		tries = budget;
	for (let i = 0; i < tries; i++) {
		let relay = list[i];
		if (!connect_one(uci, iface, relay, s))
			continue;
		if (verify_handshake(iface, s.verify_timeout))
			return {
				state: 'success', interface: iface, gateway: relay.hostname,
				endpoint: endpoint_of(relay),
				restarted: true
			};
	}

	if (saved) {
		restore_peer(uci, iface, saved);
		uci.commit('network');
		bring_up(iface);
	}
	return { state: 'failure', restored: saved != null,
		error: 'could not reach any server for the current selection; restored the previous connection' };
}

function apply(uci, instance) {
	let res = apply_inner(uci, instance);
	restore_wan_default();
	return res;
}

// Take the tunnel down and pause rotation: tunnel kept down (auto '0'),
// scheduled rotation stopped, and every managed routing/firewall object
// released so the steered networks return to normal networking — IPv6
// included. The next apply re-enables and recreates everything.
function disconnect(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };
	uci.set('protonvpn', s.name, 'enabled', '0');
	uci.commit('protonvpn');

	s.enabled = false;
	let routing = enforce_routing(uci, s);
	if (routing.changed_firewall) {
		uci.commit('firewall');
		run([ '/etc/init.d/firewall', 'reload' ]);
	}
	if (routing.changed_network) {
		uci.commit('network');
		run([ 'ubus', 'call', 'network', 'reload' ]);
	}
	if (routing.changed_network || routing.changed_firewall)
		uci = cursor();

	if (uci.get('network', iface) != null) {
		uci.set('network', iface, 'auto', '0');
		uci.commit('network');
	}
	run([ 'ifdown', iface ]);
	restore_wan_default();
	return { ok: true, interface: iface };
}

// Forget the instance's WireGuard identity so it goes back to "not
// configured", without deleting it: the location set, rotation schedule and
// routing options stay, so the next apply generates a fresh keypair,
// registers a new certificate and reconnects exactly as before.
//
// Proton-specific: the private key is only half of the identity. The Ed25519
// seed it was derived from lives in the certificate state file and the
// registration lives on the account, so both have to go too — otherwise the
// dropped key keeps occupying a device slot for up to a year (retire it the
// same way delete_instance does).
function clear_credentials(uci, instance) {
	let s = load_settings(uci, instance);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };

	run([ 'ifdown', iface ]);

	retire_certificate(s.name);
	forget_cert_state(s.name);

	let peer = find_peer(uci, iface);
	if (peer)
		uci.delete('network', peer);
	if (uci.get('network', iface) != null) {
		uci.delete('network', iface, 'private_key');
		// Keep the interface itself: the settings that describe it are kept as
		// well, so leave netifd a section to bring back up — just not on boot.
		uci.set('network', iface, 'auto', '0');
	}
	uci.commit('network');
	log('cleared the WireGuard identity of ' + s.name);
	return { ok: true, interface: iface };
}

// Create an additional VPN instance (interface pv_<name>). Committed
// atomically here (not via the UI's staged-apply machinery, whose rollback
// window makes programmatic section creation fragile).
function create_instance(uci, name) {
	let valid = validate_instance(name);
	if (!valid || valid != name)
		return { error: 'invalid instance name' };
	if (name == 'globals')
		return { error: 'this name is reserved' };
	if (uci.get('protonvpn', name) != null)
		return { error: 'an instance with this name already exists' };

	let iface = validate_interface('pv_' + name);
	if (!iface)
		return { error: 'instance name is too long for an interface name' };
	let taken = false;
	for (let other in _common.list_instances(uci))
		if (load_settings(uci, other).interface == iface)
			taken = true;
	if (taken || uci.get('network', iface) != null)
		return { error: 'interface ' + iface + ' already exists' };

	uci.set('protonvpn', name, 'instance');
	uci.set('protonvpn', name, 'interface', iface);
	uci.set('protonvpn', name, 'enabled', '1');
	uci.commit('protonvpn');
	return { ok: true, instance: name, interface: iface };
}

// Delete an instance: stamped routing/firewall objects, the netifd
// interface + peer, and the config section. 'main' is special — it anchors
// the shared cache options and the UI, so instead of deleting the section
// its options are reset to the shipped defaults (the migration stamp is
// kept).
function delete_instance(uci, name) {
	if (uci.get('protonvpn', name) == null)
		return { error: 'no such instance' };

	let s = load_settings(uci, name);
	let iface = validate_interface(s.interface);
	if (!iface)
		return { error: 'invalid interface name' };

	// Remove stamped artifacts by enforcing the all-off state.
	s.auto_routing = false;
	s.killswitch = false;
	s.block_ipv6 = false;
	s.vpn_dns = 'off';
	s.source_networks = [];
	let routing = enforce_routing(uci, s);
	if (routing.changed_firewall) {
		uci.commit('firewall');
		run([ '/etc/init.d/firewall', 'reload' ]);
	}
	if (routing.changed_network) {
		uci.commit('network');
		run([ 'ubus', 'call', 'network', 'reload' ]);
	}
	if (routing.changed_network || routing.changed_firewall)
		uci = cursor(); // see apply(): committed deletions break iteration

	retire_certificate(name);
	forget_cert_state(name);

	run([ 'ifdown', iface ]);
	let peer = find_peer(uci, iface);
	if (peer)
		uci.delete('network', peer);
	if (uci.get('network', iface) != null && uci.get('network', iface, 'vpn_type') == 'protonvpn')
		uci.delete('network', iface);
	uci.commit('network');

	if (name == 'main') {
		let all = uci.get_all('protonvpn', 'main');
		for (let k in all) {
			if (substr(k, 0, 1) == '.' || k == 'config_version')
				continue;
			uci.delete('protonvpn', 'main', k);
		}
		uci.commit('protonvpn');
		restore_wan_default();
		return { ok: true, reset: name, interface: iface };
	}

	uci.delete('protonvpn', name);
	uci.commit('protonvpn');
	restore_wan_default();
	return { ok: true, deleted: name, interface: iface };
}

return {
	ensure_keypair, current_peer, restore_peer, write_relay, bring_up,
	verify_handshake, connect_one, apply, disconnect, clear_credentials,
	create_instance, delete_instance, restore_wan_default,
	renew_certificate, retire_certificate,
	read_cert_state, record_cert_state, forget_cert_state, migrate_legacy_key
};

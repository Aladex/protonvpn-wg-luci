// SPDX-License-Identifier: MIT
// Shared helpers for the protonvpn-wireguard backend: constants, strict input
// validation, /etc/config/protonvpn loading, logging with credential redaction,
// and injection-safe filesystem/process helpers.
//
// Loaded via `require('protonvpn.common')` (resolves to
// /usr/share/ucode/protonvpn/common.uc on the ucode search path). ucode on
// OpenWrt 24.10 does not support ES `export`, so modules use CommonJS return.

'use strict';

import { open, stat, unlink, rename, popen } from 'fs';

// ── Constants ────────────────────────────────────────────────────────────

const VERSION = 'dev';                    // stamped with PKG_VERSION-rPKG_RELEASE at install time by the Makefile
const API_BASE = 'https://api.protonvpn.ch';
const LOGICALS_URL = API_BASE + '/vpn/logicals';
const CERT_URL = API_BASE + '/vpn/v1/certificate';

const DEFAULT_INTERFACE = 'protonvpn';
const DEFAULT_PORT = 51820;               // ProtonVPN WireGuard UDP port
const DEFAULT_KEEPALIVE = 25;
// ProtonVPN assigns the same tunnel addresses to every WireGuard client
// (like Nord's 10.5.0.2, unlike Mullvad's per-device addresses).
const FIXED_ADDRESS = '10.2.0.2/32';

// The IPv6 address below is deliberately NOT the one ProtonVPN publishes, and
// this looks wrong until you measure it. Their web client still writes
// 2a07:b944::2:2/128 into every generated config (live bundle
// VpnSettingsRouter.b1edbc00.chunk.js), and every third-party guide repeats
// it — but that address is one-way. Measured on a live tunnel with no NAT of
// any kind in the path: a request sourced from 2a07:b944::2:2 is forwarded and
// answered — Cloudflare replies in ~25 ms — but the reply comes back addressed
// to fd54:20a4:d33b:b10c:0:2:0:2, which the router does not hold, so nothing
// ever arrives. Sourcing from the fd54 address instead gives a complete
// round trip (0% loss, ~18 ms, TCP sessions reaching ESTABLISHED).
//
// The fd54 prefix is a Proton-side constant, not per-session and not
// per-account: identical across three gateways in two countries here, and
// independently reported by an unrelated user on a different account
// (gist.github.com/mikaeldui/12127c91ccece42ea375c9f42d94aa8a, comments).
//
// So: do not "fix" this back to the documented address. Doing so silently
// breaks IPv6 for every client behind the tunnel, in a way that looks fine in
// the configuration and only shows up as replies that never arrive.
const FIXED_ADDRESS6 = 'fd54:20a4:d33b:b10c:0:2:0:2/128';
// In-tunnel DNS resolvers (pushed by the 'standard' vpn_dns mode). The v6 one
// is the counterpart of the address above, and answers: verified live, it
// resolves A and AAAA records through the tunnel.
const VPN_DNS4 = '10.2.0.1';
const VPN_DNS6 = 'fd54:20a4:d33b:b10c:0:2:0:1';

// Runtime scratch: the status files, the locks and the server-list cache all
// live on tmpfs, under fixed names because separate processes (rpcd, the
// daemon, the detached apply worker) have to find each other's.
//
// PROTONVPN_RUN_DIR relocates the lot, the same convention as
// PROTONVPN_STATE_DIR: the offline suite gives each run its own directory so
// two runs cannot overwrite each other's status files and invent failures.
// Production never sets it.
const RUN_DIR = getenv('PROTONVPN_RUN_DIR') || '/tmp';

const CACHE_FILENAME = 'protonvpn_servers_cache.json';
const DEFAULT_CACHE_DIR = RUN_DIR;
const FETCH_STATUS_FILE = RUN_DIR + '/protonvpn_fetch_status.json';
const CACHE_LOCK_FILE = RUN_DIR + '/protonvpn_cache.lock';
// Progress/outcome of the detached apply worker, polled by the UI — same
// runtime-file convention as the cache fetch status above.
const APPLY_STATUS_FILE = RUN_DIR + '/protonvpn_apply_status.json';
const APPLY_LOCK_FILE = RUN_DIR + '/protonvpn_apply.lock';
const CACHE_MAX_AGE = 86400;          // 24h staleness threshold
const CACHE_SCHEMA_VERSION = 1;

const MIN_ROTATION_INTERVAL = 5;      // minutes
const MAX_ROTATION_INTERVAL = 44640;  // 31 days
const MIN_CACHE_REFRESH = 60;         // seconds
const MAX_CACHE_REFRESH = 604800;     // 7 days
const MIN_VERIFY_TIMEOUT = 2;         // seconds to wait for a handshake
const MAX_VERIFY_TIMEOUT = 30;
// Longest one apply may plausibly take: certificate registration over HTTPS,
// a full cache read and up to four candidates at MAX_VERIFY_TIMEOUT each,
// with slack. Past it a 'running' apply record is an abandoned one.
const APPLY_MAX_RUNTIME = 300;

const WATCHDOG_GRACE = 60;
const WATCHDOG_COOLDOWN_BASE = 120;
const WATCHDOG_COOLDOWN_MAX = 900;

// Credential lifetimes: the session lives 30 days and is
// auto-refreshed by the daemon well before that; a persistent certificate
// lives up to 365 days and is renewed ahead of expiry over the live session.
const SESSION_MAX_AGE = 30 * 86400;       // session hard expiry (30 days)
const SESSION_REFRESH_AGE = 25 * 86400;   // refresh at the latest after 25 days
const CERT_MAX_DAYS = 365;                // persistent certificate max lifetime
const CERT_RENEW_DAYS = 300;              // renew persistent certs after this
const CERT_SESSION_DAYS = 7;              // session-only certificate max lifetime

// Features bitmask of a logical server, decoded from a live /vpn/logicals
// capture (2026-07-30): the paid parc showed 123 Secure Core and 7 Tor
// logicals, and the bits combine freely (28 = IPv6|Streaming|P2P is the most
// common value). They live here rather than in protonvpn.cache because the
// routing and status layers read bit 16 back off the interface stamp, long
// after the cache is out of the picture.
const FEATURE_SECURE_CORE = 1;
const FEATURE_TOR = 2;
const FEATURE_P2P = 4;
const FEATURE_STREAMING = 8;
const FEATURE_IPV6 = 16;

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const DIR_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._/-';

// ── Primitive validators ─────────────────────────────────────────────────
// Each returns a normalized value or null; callers treat null as invalid.

// Coerce to an int within [min, max], else null. Only numbers and numeric
// strings are accepted: int() happily turns a bool, an array or a garbage
// string into 0, which would silently pass a bounds check that spans zero.
function bounded_int(v, min, max) {
	let n;
	let t = type(v);
	if (t == 'int') {
		n = v;
	} else if (t == 'double') {
		n = int(v);
	} else if (t == 'string') {
		if (!match(v, /^-?[0-9]+$/))
			return null;
		n = int(v);
	} else {
		return null;
	}
	if (n < min || n > max)
		return null;
	return n;
}

// Interface name: 1-15 chars, alnum/underscore.
function validate_interface(name) {
	if (type(name) != 'string' || length(name) < 1 || length(name) > 15)
		return null;
	return match(name, /^[A-Za-z0-9_]+$/) ? name : null;
}

// WireGuard key: 44 chars, base64 with '=' padding (char-by-char, no regex).
function validate_wg_key(k) {
	// substr(), not k[i]: ucode strings are not indexable as arrays, and the
	// subscript form throws a reference error on any real 44-char key.
	if (type(k) != 'string' || length(k) != 44 || substr(k, 43, 1) != '=')
		return null;
	for (let i = 0; i < 43; i++)
		if (index(BASE64_ALPHABET, substr(k, i, 1)) < 0)
			return null;
	return k;
}

// Hostname: 1-253 chars of the usual DNS-safe set.
function validate_hostname(h) {
	if (type(h) != 'string' || length(h) < 1 || length(h) > 253)
		return null;
	return match(h, /^[A-Za-z0-9._:-]+$/) ? h : null;
}

// UDP/TCP port number.
function validate_port(p) {
	return bounded_int(p, 1, 65535);
}

// Hop mode: 'standard', 'secure_core' or 'tor'.
function validate_hop_mode(m) {
	return (m == 'standard' || m == 'secure_core' || m == 'tor') ? m : null;
}

// DNS mode: 'off' or 'standard' (ProtonVPN in-tunnel resolver).
function validate_dns_mode(m) {
	return (m == 'off' || m == 'standard') ? m : null;
}

// IPv6 handling for an instance: 'block' (prohibit IPv6 on the steered
// networks), 'auto' (route it through the tunnel when the gateway forwards
// IPv6, prohibit it when it does not) or 'off' (do not touch IPv6 at all).
function validate_ipv6_mode(m) {
	return (m == 'block' || m == 'auto' || m == 'off') ? m : null;
}

// Rotation mode: 'interval' or 'time'.
function validate_rotation_mode(m) {
	return (m == 'interval' || m == 'time') ? m : null;
}

function validate_interval(v) {
	return bounded_int(v, MIN_ROTATION_INTERVAL, MAX_ROTATION_INTERVAL);
}

// "HH:MM" 24-hour local time.
function validate_time(s) {
	return (type(s) == 'string' && match(s, /^([01][0-9]|2[0-3]):[0-5][0-9]$/)) ? s : null;
}

// Two-letter country code, normalized to lowercase.
function validate_country_code(c) {
	if (type(c) != 'string' || !match(c, /^[A-Za-z]{2}$/))
		return null;
	return lc(c);
}

// Location slug like "nl-amsterdam".
function validate_location_code(c) {
	if (type(c) != 'string' || !match(c, /^[A-Za-z0-9-]+$/))
		return null;
	return lc(c);
}

// Instance name: 1-32 chars, alnum/underscore.
function validate_instance(n) {
	if (type(n) != 'string' || length(n) < 1 || length(n) > 32)
		return null;
	return match(n, /^[A-Za-z0-9_]+$/) ? n : null;
}

// Routing table name; empty stays empty.
function validate_routing_table(t) {
	if (t == null || t == '')
		return '';
	if (type(t) != 'string')
		return null;
	return match(t, /^[A-Za-z0-9_]+$/) ? t : null;
}

// Absolute directory path from a safe alphabet; empty stays empty.
function validate_dir(d) {
	if (d == null || d == '')
		return '';
	if (type(d) != 'string' || substr(d, 0, 1) != '/')
		return null;
	for (let i = 0; i < length(d); i++)
		if (index(DIR_ALPHABET, substr(d, i, 1)) < 0)
			return null;
	return d;
}

// ── Relay classification ─────────────────────────────────────────────────

// Classify a normalized relay: 'secure_core', 'tor' or 'standard'. The flags
// are decoded from the API Features bitmask by protonvpn.cache (bit 1 =
// Secure Core, bit 2 = Tor, captured live 2026-07-30).
function relay_kind(r) {
	if (r == null)
		return 'standard';
	if (r.tor)
		return 'tor';
	if (r.secure_core)
		return 'secure_core';
	return 'standard';
}

// True when the gateway currently written on `iface` advertises ProtonVPN's
// IPv6 feature bit. apply.write_relay stamps the raw bitmask on the interface
// so the routing layer can read it back without the cache.
//
// A missing or unparsable stamp deliberately reads as "no IPv6": an interface
// written by an older version carries none, and guessing the other way would
// point a v6 default route at a gateway that silently drops it — a black hole,
// which is worse than no IPv6 at all.
function iface_ipv6_capable(uci, iface) {
	let raw = uci.get('network', iface, 'protonvpn_features');
	if (raw == null)
		return false;
	let v = '' + raw;
	if (!match(v, /^[0-9]+$/))
		return false;
	return (int(v) & FEATURE_IPV6) ? true : false;
}

// True when a normalized relay carries ProtonVPN's IPv6 feature bit. The
// counterpart of iface_ipv6_capable() on the cache side, and it errs the same
// way: a relay from a cache written before `features` was kept has none, and
// reading that as "IPv6 capable" would hand the user a gateway that drops it.
function relay_ipv6_capable(r) {
	if (type(r) != 'object')
		return false;
	let f = r.features;
	if (type(f) == 'string' && match(f, /^[0-9]+$/))
		f = int(f);
	if (type(f) != 'int')
		return false;
	return (f & FEATURE_IPV6) ? true : false;
}

// Whether the "only gateways that forward IPv6" requirement actually applies
// to this instance's server selection.
//
// The option is only meaningful under ipv6_mode 'auto': that is the one mode
// where the bit changes what happens to a client's traffic, so narrowing the
// fleet in 'block'/'off' would cost servers and buy nothing. And it is only
// satisfiable under hop_mode 'standard': measured on the full fleet cache,
// bit 16 appears on 0 of 122 Secure Core and 0 of 7 Tor logicals, so those
// combinations can only ever yield an empty candidate list.
//
// It also has to be routing IPv6 at all. 'auto' hands clients IPv6 only
// through the per-network policy rules that steered routing creates, so with
// auto_routing, with no steered network, or with no routing table to steer
// into, the mode is inert whatever gateway is picked. Requiring IPv6 there
// could only refuse an otherwise usable VPN over an option that changes
// nothing — the same bad trade the ipv6_mode guard above avoids. The three
// conditions mirror protonvpn.routing steering_configured(), read off the
// settings so this stays pure and the selection layer needs no uci cursor.
//
// The raw option stays in UCI whatever any of this says, so flipping hop mode
// or routing out and back does not silently forget what the user asked for;
// this function is the single place that decides whether it bites.
function require_ipv6_active(s) {
	if (!s || !s.require_ipv6)
		return false;
	if (s.ipv6_mode != 'auto' || s.hop_mode != 'standard')
		return false;
	if (s.auto_routing)
		return false;
	return length(s.source_networks || []) > 0 &&
		s.routing_table != null && s.routing_table != '';
}

// Why this instance's IPv6 requirement could not be met, as recorded on the
// managed interface by the apply/rotation paths, or null.
//
// It has to be persisted rather than recomputed because the distinction is
// only knowable at the moment of the refusal: afterwards there is no peer to
// inspect, and telling "the selected locations hold no IPv6 gateway" apart
// from "the IPv6 gateways here could not be reached" would mean re-reading the
// 7.5 MB server cache on a path the UI polls every five seconds.
//
// The distinction matters because the advice differs and the wrong advice is
// worse than none: the first case wants wider locations, while the second
// wants another attempt — the gateways do forward IPv6, they were merely
// unreachable, so widening the locations or dropping the requirement would
// undo a setting that was never the problem.
const IPV6_UNMET_CAUSES = [ 'no_gateway', 'unreachable', 'pinned' ];

function iface_ipv6_unmet(uci, iface) {
	let raw = uci.get('network', iface, 'protonvpn_ipv6_unmet');
	if (raw == null)
		return null;
	let v = '' + raw;
	for (let c in IPV6_UNMET_CAUSES)
		if (v == c)
			return v;
	// An unknown value is treated as "no idea why", which still lets the UI
	// say the requirement is the reason without inventing a cause.
	return null;
}

// ── Settings ─────────────────────────────────────────────────────────────

// All `config instance` section names, 'main' first.
function list_instances(uci) {
	let out = [];
	uci.foreach('protonvpn', 'instance', function(s) {
		if (s['.name'] != 'main')
			push(out, s['.name']);
	});
	sort(out);
	if (uci.get('protonvpn', 'main') == 'instance')
		return [ 'main', ...out ];
	return out;
}

// Section carrying the shared (cache) options: 'globals' when present.
function globals_section(uci) {
	return uci.get('protonvpn', 'globals') ? 'globals' : 'main';
}

// Load and normalize the non-secret settings of one VPN instance from
// /etc/config/protonvpn (`instance` defaults to 'main'). `uci` is a connected
// uci cursor. Numeric/bounded fields fall back to the documented defaults
// when missing or invalid. The server-list cache options are shared between
// instances and always come from the globals/'main' section.
function load_settings(uci, instance) {
	let name = validate_instance(instance) || 'main';
	let g = function(opt, dflt) {
		let v = uci.get('protonvpn', name, opt);
		return (v == null || v == '') ? dflt : v;
	};
	let bi = function(opt, dflt, min, max) {
		let v = bounded_int(g(opt, dflt), min, max);
		return (v == null) ? int(dflt) : v;
	};
	let shared = globals_section(uci);
	let gs = function(opt, dflt) {
		let v = uci.get('protonvpn', shared, opt);
		return (v == null || v == '') ? dflt : v;
	};

	// `list source_network` — logical networks steered through this instance.
	let sn = uci.get('protonvpn', name, 'source_network');
	let source_networks = [];
	if (type(sn) == 'array') {
		for (let x in sn)
			if (validate_interface(x))
				push(source_networks, x);
	} else if (type(sn) == 'string' && validate_interface(sn)) {
		push(source_networks, sn);
	}

	// `list locations` — the instance's location set: countries ('ch') and/or
	// cities ('nl-amsterdam') that both the initial connect and the rotation
	// pick from. Empty = the legacy country_code/city_code selection. A city
	// code always carries its country prefix, so entries without a '-' are
	// only valid as country codes.
	let rp = uci.get('protonvpn', name, 'locations');
	let locations = [];
	let rp_add = function(x) {
		let cc = validate_country_code(x);
		if (cc) {
			push(locations, cc);
			return;
		}
		let loc = validate_location_code(x);
		if (loc && index(loc, '-') > 0)
			push(locations, loc);
	};
	if (type(rp) == 'array') {
		for (let x in rp)
			rp_add(x);
	} else if (type(rp) == 'string') {
		rp_add(rp);
	}

	return {
		name: name,
		source_networks: source_networks,
		locations: locations,
		enabled: g('enabled', '0') == '1',
		interface: validate_interface(g('interface', DEFAULT_INTERFACE)) || DEFAULT_INTERFACE,
		routing_table: g('routing_table', ''),
		// Optional WireGuard interface MTU override; null = keep the netifd
		// default (1420). Clamped to the valid Ethernet/IPv6 range.
		mtu: (function() {
			let v = int(g('mtu', '0'));
			return (v >= 1280 && v <= 1500) ? v : null;
		})(),
		hop_mode: validate_hop_mode(g('hop_mode', 'standard')) || 'standard',
		country_code: g('country_code', ''),
		city_code: g('city_code', ''),
		fixed_server: g('fixed_server', ''),
		rotation_enabled: g('rotation_enabled', '0') == '1',
		rotation_mode: validate_rotation_mode(g('rotation_mode', 'interval')) || 'interval',
		rotation_interval: bi('rotation_interval', '360', MIN_ROTATION_INTERVAL, MAX_ROTATION_INTERVAL),
		rotation_time: validate_time(g('rotation_time', '04:30')) || '04:30',
		// Optional watchdog: auto-reconnect (rotate away) when the tunnel stays
		// unhealthy. Off by default; never fires with a pinned fixed_server.
		watchdog: g('watchdog', '0') == '1',
		verify_timeout: bi('verify_timeout', '8', MIN_VERIFY_TIMEOUT, MAX_VERIFY_TIMEOUT),
		max_retries: bi('max_retries', '10', 1, 50),
		// Automatic traffic routing (zone + default route via the tunnel). The
		// shipped config enables it for fresh installs; the load-time default
		// stays off so upgraded/migrated setups keep their manual scheme.
		auto_routing: g('auto_routing', '0') == '1',
		killswitch: g('killswitch', '0') == '1',
		// IPv6 handling: 'block' (default), 'auto' or 'off'. The boolean
		// block_ipv6 this replaced is converted once by the uci-defaults
		// migration and then gone, so there is a single source of truth.
		ipv6_mode: validate_ipv6_mode(g('ipv6_mode', 'block')) || 'block',
		// Narrow server selection to gateways that forward IPv6 (bit 16).
		// Stored raw; require_ipv6_active() decides whether it applies.
		require_ipv6: g('require_ipv6', '0') == '1',
		// DNS override mode: 'off' keeps the system/WAN resolver, 'standard'
		// pushes the ProtonVPN in-tunnel resolver while the tunnel is up.
		vpn_dns: validate_dns_mode(g('vpn_dns', '')) || 'off',
		cache_dir: gs('cache_dir', ''),
		cache_refresh_interval: (function() {
			let v = bounded_int(gs('cache_refresh_interval', '21600'), MIN_CACHE_REFRESH, MAX_CACHE_REFRESH);
			return (v == null) ? 21600 : v;
		})(),
	};
}

// Absolute path of the shared server-list cache file. Callers reach for this
// on paths where the settings may not have been loaded yet (an unknown
// instance, a failed load), so a missing object must yield the default path
// instead of throwing.
function cache_file_path(settings) {
	let dir = validate_dir(settings ? settings.cache_dir : '');
	if (!dir)
		dir = DEFAULT_CACHE_DIR;
	return dir + '/' + CACHE_FILENAME;
}

// ── Logging ──────────────────────────────────────────────────────────────

// UTC ISO-8601 timestamp for cache/state files.
function iso_ts(ts) {
	let t = gmtime(ts != null ? ts : time());
	return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
		t.year, t.mon, t.mday, t.hour, t.min, t.sec);
}

// Redact anything looking like a token/key before it reaches syslog.
function redact(str) {
	return replace('' + str, /[0-9a-fA-F]{64}/g, '<redacted-token>');
}

function log(msg) {
	warn('protonvpn: ' + redact('' + msg) + '\n');
}

// ── Filesystem helpers ───────────────────────────────────────────────────

// Write via a unique temp file + rename so readers never see a partial file.
function atomic_write(path, data) {
	let fh = null;
	let tmp = null;
	let n = 0;
	while (n < 1000) {
		tmp = path + '.tmp.' + time() + '.' + n;
		fh = open(tmp, 'wx'); // exclusive create; retry on collision
		if (fh)
			break;
		n++;
	}
	if (!fh)
		return false;

	let ok = fh.write(data);
	fh.close();
	if (ok == null) {
		unlink(tmp);
		return false;
	}
	if (!rename(tmp, path)) {
		unlink(tmp);
		return false;
	}
	return true;
}

// O_EXCL lock file with stale-lock reclamation. Returns the path token or
// null when the lock is held by someone else.
function acquire_lock(path, max_age) {
	max_age = max_age || 600;
	let fh = open(path, 'wx');
	if (!fh) {
		// Reclaim a lock left behind by a killed worker; without this a crash
		// would block rotation forever.
		let st = stat(path);
		if (st && st.mtime && (time() - st.mtime) > max_age) {
			unlink(path);
			fh = open(path, 'wx');
		}
	}
	if (!fh)
		return null;
	fh.write(sprintf('%d\n', time()));
	fh.close();
	return path;
}

function release_lock(token) {
	if (token)
		unlink(token);
}

// ── Process helpers ──────────────────────────────────────────────────────

// Single-quote a string for /bin/sh.
function sh_quote(s) {
	return "'" + replace('' + s, /'/g, "'\\''") + "'";
}

// popen() over an argv list with every argument shell-quoted.
function open_cmd(argv, mode) {
	let cmd = join(' ', map(argv, sh_quote));
	return popen(cmd, mode || 'r');
}

// Run an argv list to completion. Returns { code, stdout }; code is -1 when
// the process could not start.
function run(argv) {
	let proc = open_cmd(argv, 'r');
	if (!proc)
		return { code: -1, stdout: '' };
	let out = proc.read('all') || '';
	let code = proc.close();
	return { code: code, stdout: out };
}

// CommonJS export (ucode on OpenWrt 24.10 does not support ES `export`).
return {
	VERSION, API_BASE, LOGICALS_URL, CERT_URL,
	RUN_DIR,
	DEFAULT_INTERFACE, DEFAULT_PORT, DEFAULT_KEEPALIVE, FIXED_ADDRESS, FIXED_ADDRESS6,
	VPN_DNS4, VPN_DNS6,
	CACHE_FILENAME, DEFAULT_CACHE_DIR, FETCH_STATUS_FILE, CACHE_LOCK_FILE,
	APPLY_STATUS_FILE, APPLY_LOCK_FILE, APPLY_MAX_RUNTIME,
	CACHE_MAX_AGE, CACHE_SCHEMA_VERSION,
	MIN_ROTATION_INTERVAL, MAX_ROTATION_INTERVAL, MIN_CACHE_REFRESH, MAX_CACHE_REFRESH,
	MIN_VERIFY_TIMEOUT, MAX_VERIFY_TIMEOUT,
	WATCHDOG_GRACE, WATCHDOG_COOLDOWN_BASE, WATCHDOG_COOLDOWN_MAX,
	SESSION_MAX_AGE, SESSION_REFRESH_AGE, CERT_MAX_DAYS, CERT_RENEW_DAYS, CERT_SESSION_DAYS,
	bounded_int, validate_interface, validate_wg_key, validate_hostname,
	FEATURE_SECURE_CORE, FEATURE_TOR, FEATURE_P2P, FEATURE_STREAMING, FEATURE_IPV6,
	validate_port, validate_hop_mode, validate_dns_mode, validate_ipv6_mode, relay_kind,
	iface_ipv6_capable, relay_ipv6_capable, require_ipv6_active,
	iface_ipv6_unmet, IPV6_UNMET_CAUSES,
	validate_rotation_mode, validate_interval, validate_time,
	validate_country_code, validate_location_code, validate_instance, validate_routing_table, validate_dir,
	load_settings, list_instances, globals_section, cache_file_path, iso_ts, redact, log,
	atomic_write, acquire_lock, release_lock, sh_quote, open_cmd, run
};

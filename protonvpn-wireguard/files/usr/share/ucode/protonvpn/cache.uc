// SPDX-License-Identifier: MIT
// Server-list cache/API module for protonvpn-wireguard. Fetches ProtonVPN
// LogicalServers (AUTHENTICATED — /vpn/logicals returns 401 without a live
// session, verified live 2026-07-30), normalizes them into the same internal
// country/city/relay format the nordvpn backend uses, and maintains the
// atomic cache file with a single-writer lock and a schema version. Shared
// by the cache-update worker, the rotation worker and rpcd.

'use strict';

import { readfile, unlink, stat } from 'fs';
const _common = require('protonvpn.common');
const LOGICALS_URL = _common.LOGICALS_URL,
      CACHE_MAX_AGE = _common.CACHE_MAX_AGE,
      CACHE_SCHEMA_VERSION = _common.CACHE_SCHEMA_VERSION,
      FETCH_STATUS_FILE = _common.FETCH_STATUS_FILE,
      CACHE_LOCK_FILE = _common.CACHE_LOCK_FILE,
      DEFAULT_PORT = _common.DEFAULT_PORT,
      relay_kind = _common.relay_kind,
      atomic_write = _common.atomic_write,
      acquire_lock = _common.acquire_lock,
      release_lock = _common.release_lock,
      iso_ts = _common.iso_ts,
      log = _common.log;
const _api = require('protonvpn.api');

const MAX_RESPONSE = 24 * 1024 * 1024; // hard cap per API response
// The raw logicals body is streamed here, parsed, then removed.
const LOGICALS_TMP = '/tmp/protonvpn_logicals.tmp.json';
const CONNECT_TIMEOUT = 15;
const TOTAL_TIMEOUT = 60;

// Features bitmask of a logical server, decoded from a live /vpn/logicals
// capture (2026-07-30): the paid parc showed 123 Secure Core and 7 Tor
// logicals, and the bits combine freely (28 = IPv6|Streaming|P2P is the most
// common value).
const FEATURE_SECURE_CORE = 1;
const FEATURE_TOR = 2;
const FEATURE_P2P = 4;
const FEATURE_STREAMING = 8;
const FEATURE_IPV6 = 16;

// Proton reports a city NAME ('Tokyo') plus a country CODE ('JP'), while the
// location set and the UI speak 'cc-city' codes — so synthesize one the same
// way nordvpn does.
function city_code_of(country_code, city_name) {
	return country_code + '-' + replace(lc(city_name || 'unknown'), /[^a-z0-9]/g, '');
}

// ── Fetch-status file (progress for the UI) ──────────────────────────────

// Stamp `updated_at` and atomically write the fetch-status file.
function write_fetch_status(status) {
	if (type(status) != 'object')
		return false;
	status.updated_at = iso_ts();
	return atomic_write(FETCH_STATUS_FILE, sprintf('%J', status));
}

// Parsed fetch-status object or null.
function read_fetch_status() {
	let raw = readfile(FETCH_STATUS_FILE);
	if (!raw)
		return null;
	try {
		return json(raw);
	} catch (e) {
		return null;
	}
}

function ensure_country(acc, country_code) {
	if (!acc.country_index[country_code]) {
		let c = {
			code: country_code,
			// Proton sends no country names. The UI resolves the ISO code with
			// Intl.DisplayNames, which localizes for free and spares us a table.
			name: uc(country_code),
			display_name: uc(country_code),
			cities: [],
			gateway_count: 0
		};
		acc.country_index[country_code] = c;
		push(acc.country_list, c);
	}
	return acc.country_index[country_code];
}

function ensure_city(acc, country, city_code, city_name, country_code) {
	if (!acc.location_index[city_code]) {
		let city = {
			code: city_code,
			name: city_name,
			country: country.name,
			country_code: country_code,
			latitude: 0,
			longitude: 0,
			relays: [],
			gateway_count: 0
		};
		acc.location_index[city_code] = city;
		push(country.cities, city);
	}
	return acc.location_index[city_code];
}

// ── Normalization ────────────────────────────────────────────────────────
// Internal cache document (identical shape to nordvpn's):
//   { countries: [ { code, name, display_name, cities: [ {
//       code, name, country, country_code, latitude, longitude,
//       relays: [ <relay> ], gateway_count } ], gateway_count } ],
//     stats: { countries, cities, gateways, servers_seen } }
// Relay (per physical server in a logical's Servers[]):
//   { hostname (logical Name), ip_address (Servers[].EntryIP/ExitIP),
//     name (logical Name), public_key (Servers[].X25519PublicKey),
//     load (Load, %), score (Score — lower is better; Proton's own
//     Quick Connect picks min Score), features (raw Features bitmask),
//     secure_core, tor (decoded flags), tier (0=free), location (city code),
//     port, active (Status != 0), country_code, city_code, city }

// Add one raw logical-server object to the accumulator. Exported for tests.
function add_server(acc, logical) {
	acc.stats.servers_seen++;

	if (type(logical) != 'object' || !logical.Status)
		return;                     // Status 0 = the whole logical is offline
	let servers = logical.Servers;
	if (type(servers) != 'array' || !length(servers))
		return;

	// Group by the EXIT country: that is the visible IP, and for Secure Core
	// the entry country changes between rotations while the exit must not.
	let country_code = lc(logical.ExitCountry || '');
	if (!country_code)
		return;
	let city_name = logical.City || 'Unknown';
	let city_code = city_code_of(country_code, city_name);

	let features = +logical.Features || 0;
	let secure_core = (features & FEATURE_SECURE_CORE) ? true : false;
	let tor = (features & FEATURE_TOR) ? true : false;

	let country = ensure_country(acc, country_code);
	let city = ensure_city(acc, country, city_code, city_name, country_code);

	for (let srv in servers) {
		if (type(srv) != 'object' || !srv.Status)
			continue;               // this physical server is down
		if (!srv.X25519PublicKey)
			continue;               // unusable for WireGuard
		let endpoint = srv.EntryIP || srv.ExitIP || '';
		if (!endpoint)
			continue;

		push(city.relays, {
			// The logical Name ('NL#85', 'SE-JP#1') is what the user sees and
			// what a pinned server is stored as; Domain is per physical server.
			hostname: srv.Domain || logical.Name || '',
			ip_address: endpoint,
			name: logical.Name || '',
			public_key: srv.X25519PublicKey,
			load: +logical.Load || 0,
			// Proton's own Quick Connect picks the LOWEST Score.
			score: +logical.Score || 0,
			features: features,
			secure_core: secure_core,
			tor: tor,
			entry_country: lc(logical.EntryCountry || country_code),
			tier: +logical.Tier || 0,
			location: city_code,
			port: DEFAULT_PORT,
			active: true,
			country_code: country_code,
			city_code: city_code,
			city: city_name
		});
		acc.stats.gateways++;
	}
}

// Normalize an array of raw logical-server objects into the cache structure.
// Exported for fixture tests.
function normalize(list) {
	let acc = {
		country_index: {}, location_index: {}, country_list: [],
		stats: { countries: 0, cities: 0, gateways: 0, servers_seen: 0 }
	};
	if (type(list) == 'array')
		for (let logical in list)
			add_server(acc, logical);

	// Drop empty cities/countries and sort by name so the UI order is stable.
	let filtered = [];
	for (let country in acc.country_list) {
		let valid = [];
		country.gateway_count = 0;
		for (let city in country.cities) {
			if (length(city.relays) > 0) {
				sort(city.relays, function(a, b) {
					return (a.name < b.name) ? -1 : (a.name > b.name) ? 1 : 0;
				});
				city.gateway_count = length(city.relays);
				push(valid, city);
				country.gateway_count += length(city.relays);
				acc.stats.cities++;
			}
		}
		sort(valid, function(a, b) {
			return (a.name < b.name) ? -1 : (a.name > b.name) ? 1 : 0;
		});
		country.cities = valid;
		if (length(valid) > 0)
			push(filtered, country);
	}
	sort(filtered, function(a, b) {
		return (a.name < b.name) ? -1 : (a.name > b.name) ? 1 : 0;
	});
	acc.stats.countries = length(filtered);

	return {
		countries: filtered,
		stats: acc.stats,
		source: LOGICALS_URL,
		generated_at: iso_ts()
	};
}

// Trimmed country/city tree for the UI (no per-relay data).
function locations_tree(cache) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;
	for (let c in cache.countries) {
		let cities = [], totals = { standard: 0, secure_core: 0, tor: 0 };
		for (let city in c.cities) {
			let n = { standard: 0, secure_core: 0, tor: 0 };
			for (let r in city.relays)
				n[relay_kind(r)]++;
			for (let k in [ 'standard', 'secure_core', 'tor' ])
				totals[k] += n[k];
			push(cities, {
				code: city.code, name: city.name,
				gateway_count: length(city.relays),
				standard_count: n.standard,
				secure_core_count: n.secure_core,
				tor_count: n.tor
			});
		}
		push(out, {
			code: c.code, name: c.name, display_name: c.display_name,
			gateway_count: c.gateway_count,
			standard_count: totals.standard,
			secure_core_count: totals.secure_core,
			tor_count: totals.tor,
			cities: cities
		});
	}
	return out;
}

// Relay fields the UI needs; the public key and raw bitmask stay in the cache.
function trim_relay(r) {
	return {
		hostname: r.hostname, name: r.name, city: r.city,
		country_code: r.country_code, city_code: r.city_code,
		load: r.load, score: r.score, tier: r.tier,
		secure_core: r.secure_core, tor: r.tor,
		entry_country: r.entry_country
	};
}

// Map a hop mode onto the relay kind it may use. Unknown/empty = no filter.
function want_kind(hop_mode) {
	return (hop_mode == 'secure_core' || hop_mode == 'tor' || hop_mode == 'standard')
		? hop_mode : null;
}

// Union of relays over a location set (country codes 'ch' and/or 'cc-city'
// codes), deduped, filtered by hop kind ('standard'|'secure_core'|'tor').
function pool_relays(cache, locations, hop_mode) {
	let out = [], seen = {};
	if (!cache || type(cache.countries) != 'array' || type(locations) != 'array')
		return out;
	let want = want_kind(hop_mode);
	let set = {};
	for (let e in locations)
		if (type(e) == 'string' && e != '')
			set[lc(e)] = true;

	for (let c in cache.countries) {
		let whole = set[c.code] ? true : false;
		for (let city in c.cities) {
			// A country code selects all of its cities; a city code selects one.
			if (!whole && !set[city.code])
				continue;
			for (let r in city.relays) {
				if (want && relay_kind(r) != want)
					continue;
				// Dedup on the LOGICAL name, not the domain: Proton runs many
				// logical servers (NL#85, NL#339, ...) on one physical machine,
				// so keying on the domain collapsed ~940 Dutch servers into 73.
				let id = r.name || r.hostname;
				if (seen[id])
					continue;
				seen[id] = true;
				push(out, r);
			}
		}
	}
	return out;
}

// Trimmed relay list for one city; hop_mode null/'' = no filter.
function city_relays(cache, country_code, city_code, hop_mode) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;
	let want = want_kind(hop_mode);
	let cc = lc(country_code || ''), target = lc(city_code || '');
	for (let c in cache.countries) {
		if (cc && c.code != cc)
			continue;
		for (let city in c.cities) {
			if (target && city.code != target)
				continue;
			for (let r in city.relays) {
				if (want && relay_kind(r) != want)
					continue;
				push(out, trim_relay(r));
			}
		}
	}
	return out;
}

// ── Authenticated fetch ──────────────────────────────────────────────────

// GET /vpn/logicals with session headers (via protonvpn.api). Returns the
// normalize()d document or { error }. On 401 attempts one auth_refresh()
// retry before giving up.
function fetch_servers() {
	let session = _api.session_load();
	if (!session)
		return { error: 'not logged in' };

	write_fetch_status({ state: 'running', stage: 'download' });

	// Measured live: the authenticated response is ~13.4 MB for 18k logicals
	// (the unauthenticated one is a fraction of that). It parses in ~2.4s on a
	// 1 GB router, so it is fetched rarely and only the compact normalized
	// document is kept — never the raw body. It is streamed to a temp file
	// because passing that much through a pipe is quadratic in ucode.
	let tmp = LOGICALS_TMP;
	// max_filesize makes curl refuse an oversized body up front: /tmp is RAM on
	// a router, so finding out after the download is already too late.
	let res = _api.api_call({ url: LOGICALS_URL, uid: session.uid,
		token: session.access_token, out_file: tmp, max_filesize: MAX_RESPONSE,
		timeout: 180 });

	// A stale access token is routine (it lives 30 minutes): refresh once and
	// retry before reporting anything to the user.
	if (res.code == 401) {
		let rf = _api.auth_refresh();
		if (!rf.ok) {
			// curl has already written the 401 body here; leaving it behind
			// squats tmpfs until the next successful fetch overwrites it.
			unlink(tmp);
			write_fetch_status({ state: 'error', error: rf.error || 'session expired' });
			return { error: rf.error || 'session expired' };
		}
		session = _api.session_load();
		res = _api.api_call({ url: LOGICALS_URL, uid: session.uid,
			token: session.access_token, out_file: tmp, max_filesize: MAX_RESPONSE,
			timeout: 180 });
	}

	if (res.code != 200) {
		// The error body, if any, is small enough to read back for the message.
		let body = readfile(tmp) || '';
		unlink(tmp);
		let parsed = null;
		try { parsed = json(body); } catch (e) { parsed = null; }
		let msg = _api.api_error({ code: res.code, data: parsed });
		write_fetch_status({ state: 'error', error: msg });
		return { error: msg };
	}

	let st = stat(tmp);
	if (st && st.size > MAX_RESPONSE) {
		unlink(tmp);
		write_fetch_status({ state: 'error', error: 'server list too large' });
		return { error: 'server list too large' };
	}
	let raw = readfile(tmp);
	unlink(tmp);
	if (!raw)
		return { error: 'empty /vpn/logicals response' };
	let doc0 = null;
	try { doc0 = json(raw); } catch (e) { doc0 = null; }
	raw = null;                       // let the 13 MB string go before parsing
	let list = doc0 ? doc0.LogicalServers : null;
	if (type(list) != 'array')
		return { error: 'unexpected /vpn/logicals response' };

	write_fetch_status({ state: 'running', stage: 'normalize',
		servers: length(list) });
	let doc = normalize(list);
	write_fetch_status({ state: 'done', servers: doc.stats.servers_seen,
		gateways: doc.stats.gateways });
	return doc;
}

// ── Cache read/write ─────────────────────────────────────────────────────

// Read the cache; reject a foreign schema_version. Object or null.
function read_cache(path) {
	let raw = readfile(path);
	if (!raw)
		return null;
	let doc;
	try {
		doc = json(raw);
	} catch (e) {
		return null;
	}
	if (type(doc) != 'object' || type(doc.countries) != 'array')
		return null;
	// A cache written by another schema version is not readable — treat it as
	// missing so it gets rebuilt instead of half-understood.
	if (doc.schema_version != CACHE_SCHEMA_VERSION)
		return null;
	return doc;
}

// True when the cache is missing/malformed or older than CACHE_MAX_AGE.
function cache_is_stale(path) {
	let doc = read_cache(path);
	if (!doc || !doc.cached_at_epoch)
		return true;
	return (time() - doc.cached_at_epoch) > CACHE_MAX_AGE;
}

// Stamp cached_at/schema_version/cache_info and atomically write. Bool.
function write_cache(response, path) {
	if (type(response) != 'object' || type(response.countries) != 'array')
		return false;
	response.schema_version = CACHE_SCHEMA_VERSION;
	response.cached_at = iso_ts();
	response.cached_at_epoch = time();
	response.cache_info = {
		countries: response.stats ? response.stats.countries : 0,
		cities: response.stats ? response.stats.cities : 0,
		gateways: response.stats ? response.stats.gateways : 0
	};
	return atomic_write(path, sprintf('%J', response));
}

// Fetch under the single-writer lock; keep the old cache on failure.
function fetch_and_build(path) {
	let lock = acquire_lock(CACHE_LOCK_FILE, 600);
	if (!lock)
		return { skipped: true, reason: 'cache refresh already running' };

	let doc = fetch_servers();
	if (doc.error) {
		release_lock(lock);
		// Keep whatever cache we already have: a stale list still lets rotation
		// work, an empty one does not.
		return { error: doc.error };
	}
	let ok = write_cache(doc, path);
	release_lock(lock);
	if (!ok)
		return { error: 'could not write the cache' };
	log(sprintf('cache updated: %d countries, %d cities, %d gateways',
		doc.stats.countries, doc.stats.cities, doc.stats.gateways));
	return { ok: true, stats: doc.stats };
}

return {
	FEATURE_SECURE_CORE, FEATURE_TOR, FEATURE_P2P, FEATURE_STREAMING, FEATURE_IPV6,
	city_code_of, trim_relay,
	write_fetch_status, read_fetch_status, add_server, normalize,
	locations_tree, city_relays, pool_relays,
	fetch_servers, read_cache, cache_is_stale, write_cache, fetch_and_build
};

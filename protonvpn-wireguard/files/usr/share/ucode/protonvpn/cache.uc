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
      relay_ipv6_capable = _common.relay_ipv6_capable,
      atomic_write = _common.atomic_write,
      acquire_lock = _common.acquire_lock,
      release_lock = _common.release_lock,
      iso_ts = _common.iso_ts,
      log = _common.log;
const _api = require('protonvpn.api');

const MAX_RESPONSE = 24 * 1024 * 1024; // hard cap per API response
// The raw logicals body is streamed here, parsed, then removed.
const LOGICALS_TMP = _common.RUN_DIR + '/protonvpn_logicals.tmp.json';
const CONNECT_TIMEOUT = 15;
const TOTAL_TIMEOUT = 60;

// Features bitmask bits of a logical server. Defined in protonvpn.common,
// because the routing layer reads bit 16 back off the interface stamp without
// ever loading the cache; re-exported here so the decoding stays visible where
// the bitmask is actually parsed.
const FEATURE_SECURE_CORE = _common.FEATURE_SECURE_CORE;
const FEATURE_TOR = _common.FEATURE_TOR;
const FEATURE_P2P = _common.FEATURE_P2P;
const FEATURE_STREAMING = _common.FEATURE_STREAMING;
const FEATURE_IPV6 = _common.FEATURE_IPV6;

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

// Fresh normalization accumulator, shared by normalize() and normalize_body().
function normalize_begin() {
	return {
		country_index: {}, location_index: {}, country_list: [],
		stats: { countries: 0, cities: 0, gateways: 0, servers_seen: 0 }
	};
}

// Drop empty cities/countries, sort by name so the UI order is stable, and
// wrap the accumulator into the cache document.
function normalize_finish(acc) {
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

// Normalize an array of raw logical-server objects into the cache structure.
// Exported for fixture tests. CONSUMES the array: each logical is released
// as it is normalized, so the parsed fleet and the growing document never
// coexist in full (issue #1). Callers must not reuse the array afterwards.
function normalize(list) {
	let acc = normalize_begin();
	if (type(list) == 'array')
		for (let i = 0; i < length(list); i++) {
			add_server(acc, list[i]);
			list[i] = null;
		}
	return normalize_finish(acc);
}

// ── Raw-body parse (issue #1) ──────────────────────────────────────────────

// Parse one logical's piece text (everything after its "Name" key up to and
// including the closing '}'). The text is WRAPPED in two array levels before
// parsing: in the whole document the logical object sits under the root
// object and the LogicalServers array, and the decoder enforces its nesting
// limit on the parser's depth — parsing the piece as its own root would
// apply that limit two levels shallower than json(raw) does, accepting
// documents the monolithic parse rejects with 'nesting too deep'. The
// wrapper restores the exact document offset, whatever the decoder's limit
// happens to be. The result must be exactly [[ logical ]]: anything else
// means the piece held more than one logical's worth of text (e.g. a forged
// array boundary inside it), which the monolith would reject as a syntax
// error — so the strict shape check sends those to the fallback like the
// unwrapped parse did. Returns null when the piece is not one logical
// object.
function parse_logical(text) {
	let w = null;
	try {
		w = json('[[{"Name"' + text + ']]');
	} catch (e) {
		w = null;
	}
	if (type(w) != 'array' || length(w) != 1 ||
	    type(w[0]) != 'array' || length(w[0]) != 1)
		return null;
	return w[0][0];
}

// Trim one split piece back to the end of its logical object. Pieces between
// logicals end with the element separator (ws '{' ws ',' — walk order is
// from the end). Returns the trimmed length, or -1 when the piece does not
// look like a logical boundary at all (then the whole parse falls back to
// the monolith). The FINAL piece is different — it ends with the array
// close and the document tail, see last_piece().
function piece_end(piece) {
	const WS = " \t\n\r";
	let j = length(piece) - 1;
	let skip_ws = function() {
		while (j >= 0 && index(WS, substr(piece, j, 1)) >= 0)
			j--;
	};
	skip_ws();
	if (j < 0 || substr(piece, j, 1) != '{')
		return -1;
	j--;
	skip_ws();
	if (j < 0 || substr(piece, j, 1) != ',')
		return -1;
	j--;
	skip_ws();
	return (j >= 0 && substr(piece, j, 1) == '}') ? j + 1 : -1;
}

// Fold the LAST split piece into the accumulator. It holds the final logical
// plus everything that trails it: the array close and the document tail.
// Proton does NOT end the root with the array — real responses close with
// "ResponseMetadata":{...},"Code":1000} — so the tail is validated, not
// assumed: try each ']' from the end as the array close; the logical before
// it must parse, the tail after it must parse as a document whose array is
// empty, and its decoded root keys must not redefine LogicalServers (the
// monolith would take the LAST duplicate, the walk the first). The piece is
// one logical plus a short tail (~1 KB), so the probes stay cheap. False =
// not walkable, fall back to the monolith.
function last_piece(piece, acc) {
	const WS = " \t\n\r";
	for (let p = length(piece) - 1; p > 0; p--) {
		if (substr(piece, p, 1) != ']')
			continue;
		let q = p - 1;
		while (q >= 0 && index(WS, substr(piece, q, 1)) >= 0)
			q--;
		if (q < 0 || substr(piece, q, 1) != '}')
			continue;
		let logical = parse_logical(substr(piece, 0, q + 1));
		if (type(logical) != 'object')
			continue;
		let tail = null;
		try {
			tail = json('{"LogicalServers":[]' + substr(piece, p + 1));
		} catch (e) {
			tail = null;
		}
		if (type(tail) != 'object')
			continue;
		// A trailing LogicalServers field would REPLACE the walked array in
		// the monolithic parse (duplicate keys: the last occurrence wins),
		// while the walk keeps the first — so this candidate is only valid
		// when the tail does not redefine the selected array. The tail's
		// root keys are validated DECODED, not as raw text: an escaped
		// spelling like "LogicalServers" is invisible to a substring
		// check but decodes to a real duplicate for the parser. Only root
		// keys matter — the monolith reads doc.LogicalServers, and a nested
		// LogicalServers (e.g. inside ResponseMetadata) replaces nothing.
		let fields = substr(piece, p + 1);
		let f = 0;
		while (f < length(fields) && index(WS, substr(fields, f, 1)) >= 0)
			f++;
		if (substr(fields, f, 1) == ',') {
			let tail_keys = null;
			try {
				tail_keys = json('{' + substr(fields, f + 1));
			} catch (e) {
				tail_keys = null;
			}
			if (type(tail_keys) != 'object' || exists(tail_keys, 'LogicalServers'))
				continue;
		}
		add_server(acc, logical);
		return true;
	}
	return false;
}

// Validate the document head up to the first logical's "Name" key: it must
// be a syntactically valid root-object prefix immediately followed by
// "LogicalServers" : [ { — nothing between the array open and the first
// logical's Name key, and the array must be the ROOT LogicalServers one.
// Anything looser would be misparsed silently: fields before the first
// logical's Name would be dropped (JSON key order is free and must never
// change the cache), logicals under another key would be consumed as the
// fleet, and a malformed prefix the real parser would reject would slip
// through. All of those fall back to the monolithic parse instead.
function head_is_logicals_open(head) {
	const WS = " \t\n\r";
	const KEY = '"LogicalServers"';
	let j = length(head) - 1;
	let ws_back = function() {
		while (j >= 0 && index(WS, substr(head, j, 1)) >= 0)
			j--;
	};
	let back = function(ch) {
		ws_back();
		if (j < 0 || substr(head, j, 1) != ch)
			return false;
		j--;
		return true;
	};
	// From the end: ws '{' ws '[' ws ':' ws, then the "LogicalServers" key.
	if (!back('{') || !back('[') || !back(':'))
		return false;
	ws_back();
	if (j < length(KEY) - 1 ||
	    substr(head, j - length(KEY) + 1, length(KEY)) != KEY)
		return false;
	// What precedes the key must be real JSON, not text that merely contains
	// the right substrings: parsed closed with a dummy pair, the prefix must
	// hold. That also pins the key to the ROOT object — the appended pair
	// plus '}' can only complete the document when the prefix sits at depth
	// 1, so a "LogicalServers" nested in something else
	// ({"A":[...,{"LogicalServers":...) cannot validate either.
	let pre = substr(head, 0, j - length(KEY) + 1);
	let probe = null;
	try {
		probe = json(pre + '"LogicalServers":null}');
	} catch (e) {
		probe = null;
	}
	return type(probe) == 'object';
}

// Normalize a raw /vpn/logicals body WITHOUT ever holding the whole parsed
// fleet: the array text is split on the "Name" key (a quoted key cannot
// occur inside a string value unescaped, and Proton's serializer starts
// every logical with it — see the fixture, a trimmed real response), then
// one logical at a time is parsed and folded in — each wrapped at its
// document depth, so the decoder's nesting limit accepts and rejects
// exactly what json(raw) would (see parse_logical()). The peak is the body
// plus one logical plus the growing document, instead of ~14x the body for the
// monolithic parse — which is what got protonvpn-service OOM-killed on
// routers with little free RAM (issue #1). Any structural surprise falls
// back to the monolithic parse; null means the body is not a logicals
// response at all. The result is byte-identical to normalize() over the
// monolithic parse either way.
//
// The fallback must never be SILENT: last_body_mode records which parse the
// last call took ('walk' or 'monolith', see body_parse_mode()), and a walk
// that gives up on a logicals-shaped body is logged — a silent fallback is
// how the fix once shipped while doing nothing on live data (issue #1
// blocker: real responses trail the LogicalServers array with
// ResponseMetadata and Code, which the strict last-piece boundary rejected).
let last_body_mode = null;
function normalize_body(raw) {
	// Cleared up front: a call that rejects its input without parsing must
	// not inherit the previous call's mode.
	last_body_mode = null;
	if (type(raw) != 'string' || raw == '')
		return null;
	let pieces = split(raw, '"Name"');
	// pieces[0] is the document head through the first logical's '{'; the
	// walk only starts when it is exactly the root LogicalServers array open
	// (see head_is_logicals_open), everything else goes to the monolith.
	if (length(pieces) > 2 && head_is_logicals_open(pieces[0])) {
		let acc = normalize_begin();
		let ok = true, fail_at = -1;
		for (let i = 1; i < length(pieces) && ok; i++) {
			if (i == length(pieces) - 1) {
				ok = last_piece(pieces[i], acc);
				pieces[i] = null;
				if (!ok)
					fail_at = i;
				break;
			}
			let end = piece_end(pieces[i]);
			if (end < 0) {
				ok = false;
				fail_at = i;
				break;
			}
			let logical = parse_logical(substr(pieces[i], 0, end));
			pieces[i] = null;
			if (type(logical) != 'object') {
				ok = false;
				fail_at = i;
			} else {
				add_server(acc, logical);
			}
		}
		if (ok) {
			last_body_mode = 'walk';
			return normalize_finish(acc);
		}
		// Structural surprise: re-parse monolithically below. raw is intact.
		log(sprintf('cache: logicals walk gave up at logical %d of %d — ' +
			'using the monolithic parse (peak ~14x the body)', fail_at,
			length(pieces) - 1));
	} else if (length(pieces) > 2) {
		log('cache: logicals head not walkable — ' +
			'using the monolithic parse (peak ~14x the body)');
	}

	last_body_mode = 'monolith';
	let doc0 = null;
	try { doc0 = json(raw); } catch (e) { doc0 = null; }
	let list = (type(doc0) == 'object') ? doc0.LogicalServers : null;
	if (type(list) != 'array')
		return null;
	doc0 = null;                    // the wrapper can go once the array is taken
	return normalize(list);
}

// Which parse the last normalize_body() call took: 'walk' (one logical at a
// time, the whole point of the issue #1 fix) or 'monolith' (the ~14x-peak
// fallback). Null when the last call rejected its input without parsing
// (empty/null/non-string body) or normalize_body() was never called.
// Exported so tests and diagnostics can prove the fast path is actually
// taken on real response shapes.
function body_parse_mode() {
	return last_body_mode;
}

// Rounded mean load, or null when there is nothing to average. The `* 1.0`
// matters: ucode divides int/int as integers (676/8 is 84), which would
// truncate the +0.5 rounding away.
function load_avg(sum, n) {
	return n ? int(sum * 1.0 / n + 0.5) : null;
}

// Trimmed country/city tree for the UI (no per-relay data).
function locations_tree(cache) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;
	for (let c in cache.countries) {
		let cities = [], totals = { standard: 0, secure_core: 0, tor: 0, ipv6: 0 };
		let load_sums = { standard: 0, secure_core: 0, tor: 0 };
		for (let city in c.cities) {
			let n = { standard: 0, secure_core: 0, tor: 0, ipv6: 0 };
			let load = { standard: 0, secure_core: 0, tor: 0 };
			for (let r in city.relays) {
				let kind = relay_kind(r);
				n[kind]++;
				load[kind] += r.load;
				// Counted against the standard kind only, which is the one the
				// IPv6 requirement can apply to. It is also the only place the
				// bit occurs: across the full fleet it is set on 0 of 122
				// Secure Core and 0 of 7 Tor logicals.
				if (kind == 'standard' && relay_ipv6_capable(r))
					n.ipv6++;
			}
			for (let k in [ 'standard', 'secure_core', 'tor', 'ipv6' ])
				totals[k] += n[k];
			for (let k in [ 'standard', 'secure_core', 'tor' ])
				load_sums[k] += load[k];
			push(cities, {
				code: city.code, name: city.name,
				gateway_count: length(city.relays),
				standard_count: n.standard,
				secure_core_count: n.secure_core,
				tor_count: n.tor,
				// Average load per kind, computed here because the tree
				// deliberately carries no per-relay data, so the UI cannot
				// recompute it. Null when the kind is absent: the row then
				// shows the counter alone rather than an invented figure.
				standard_load: load_avg(load.standard, n.standard),
				secure_core_load: load_avg(load.secure_core, n.secure_core),
				tor_load: load_avg(load.tor, n.tor),
				// "N of M", not a yes/no: a city where 3 of 40 gateways carry
				// the bit is not the same offer as one where 38 do, and a
				// boolean would have to call both of them "yes".
				ipv6_count: n.ipv6
			});
		}
		push(out, {
			code: c.code, name: c.name, display_name: c.display_name,
			gateway_count: c.gateway_count,
			standard_count: totals.standard,
			secure_core_count: totals.secure_core,
			tor_count: totals.tor,
			standard_load: load_avg(load_sums.standard, totals.standard),
			secure_core_load: load_avg(load_sums.secure_core, totals.secure_core),
			tor_load: load_avg(load_sums.tor, totals.tor),
			ipv6_count: totals.ipv6,
			cities: cities
		});
	}
	return out;
}

// Relay fields the UI needs; the public key stays in the cache. The raw
// Features bitmask is included because the page decides two things from bit
// 16 — the per-server IPv6 badge and, when the instance requires IPv6, which
// gateways it may offer at all — and it has no other way to see it.
function trim_relay(r) {
	return {
		hostname: r.hostname, name: r.name, city: r.city,
		country_code: r.country_code, city_code: r.city_code,
		load: r.load, score: r.score, tier: r.tier,
		features: r.features, secure_core: r.secure_core, tor: r.tor,
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

	write_fetch_status({ state: 'running', stage: 'normalize' });
	// One logical at a time, never the whole parsed fleet beside the growing
	// document (issue #1 — the monolithic parse peaks at ~14x the body and
	// got the service OOM-killed on a router with ~175 MB FREE RAM).
	// normalize_body falls back to the monolithic parse when the body does
	// not walk cleanly.
	let doc = normalize_body(raw);
	raw = null;
	if (!doc)
		return { error: 'unexpected /vpn/logicals response' };
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
	write_fetch_status, read_fetch_status, add_server, normalize, normalize_body,
	body_parse_mode,
	locations_tree, city_relays, pool_relays,
	fetch_servers, read_cache, cache_is_stale, write_cache, fetch_and_build
};

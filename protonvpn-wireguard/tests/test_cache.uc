// SPDX-License-Identifier: MIT
// Fixture tests for the cache/selection layer. fixtures/logicals_sample.json is
// a trimmed copy of a REAL authenticated /vpn/logicals response (captured
// 2026-07-30), keeping one logical per Features variant plus both tiers, so the
// feature decoding and the Secure Core / Tor split are checked against Proton's
// actual wire format rather than something invented here. Its ROOT shape also
// matches the real wire format: LogicalServers FIRST, then ResponseMetadata
// and Code trailing the array — and JP-FREE#3's city carries a \uXXXX escape
// (São Paulo, written as Proton sends it), so every test runs over the two
// byte classes that once made the raw-body walk give up on live data (the
// issue #1 blocker).
//
// Globals `fixture` and `KEY` come from run.sh.

'use strict';

// Runtime scratch dir of THIS run (tests/run.sh gives each run its own, so
// two suites can execute concurrently); never the shared /tmp.
const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';

import { readfile, writefile, unlink, popen } from 'fs';
const _cache = require('protonvpn.cache');
const normalize = _cache.normalize, locations_tree = _cache.locations_tree,
      pool_relays = _cache.pool_relays, city_relays = _cache.city_relays,
      city_code_of = _cache.city_code_of, write_cache = _cache.write_cache,
      read_cache = _cache.read_cache, cache_is_stale = _cache.cache_is_stale;
const _select = require('protonvpn.select');
const candidates = _select.candidates, location_candidates = _select.location_candidates,
      selection_candidates = _select.selection_candidates,
      by_hostname = _select.by_hostname, pick = _select.pick;
const relay_kind = require('protonvpn.common').relay_kind;

let failures = 0;

function ok(name, cond) {
	print(cond ? 'ok   ' : 'FAIL ', name, '\n');
	if (!cond)
		failures++;
}

function eq(name, got, want) {
	let g = sprintf('%J', got), w = sprintf('%J', want);
	print((g == w) ? 'ok   ' : 'FAIL ', name, '\n');
	if (g != w) {
		print('       got:  ', g, '\n');
		print('       want: ', w, '\n');
		failures++;
	}
}

const raw = json(readfile(fixture));
const doc = normalize(raw.LogicalServers);

// 1. normalization over the real fixture
{
	eq('servers_seen counts every logical', doc.stats.servers_seen, length(raw.LogicalServers));
	ok('countries found', doc.stats.countries > 0);
	ok('gateways found', doc.stats.gateways > 0);

	// Every relay must be usable: a key, an endpoint and a port.
	let bad = 0;
	for (let c in doc.countries)
		for (let city in c.cities)
			for (let r in city.relays)
				if (!r.public_key || !r.ip_address || !r.port)
					bad++;
	eq('every relay has key, endpoint and port', bad, 0);

	// Countries are keyed by the EXIT country: SE-JP#1 (Secure Core, entry SE,
	// exit JP) must live under JP, not SE.
	let jp = null;
	for (let c in doc.countries)
		if (c.code == 'jp')
			jp = c;
	ok('exit country grouping (jp present)', jp != null);
	let sc = null;
	for (let city in jp.cities)
		for (let r in city.relays)
			if (r.name == 'SE-JP#1')
				sc = r;
	ok('secure core logical grouped by exit country', sc != null);
	eq('secure core flag decoded', sc.secure_core, true);
	eq('secure core keeps the entry country', sc.entry_country, 'se');
	eq('secure core is not tor', sc.tor, false);
	eq('relay_kind of a secure core relay', relay_kind(sc), 'secure_core');

	// Tor: FR#13-TOR has Features=2.
	let tor = null;
	for (let c in doc.countries)
		for (let city in c.cities)
			for (let r in city.relays)
				if (r.name == 'FR#13-TOR')
					tor = r;
	ok('tor logical present', tor != null);
	eq('tor flag decoded', tor.tor, true);
	eq('relay_kind of a tor relay', relay_kind(tor), 'tor');

	// A combined bitmask (28 = IPv6|Streaming|P2P) is neither Secure Core nor Tor.
	let plain = null;
	for (let c in doc.countries)
		for (let city in c.cities)
			for (let r in city.relays)
				if (r.name == 'NL#85')
					plain = r;
	ok('combined-feature logical present', plain != null);
	eq('features bitmask preserved', plain.features, 28);
	eq('combined features are standard', relay_kind(plain), 'standard');
	ok('load carried over', plain.load > 0);
	ok('score carried over (lower is better)', plain.score > 0);

	// Free tier is marked so the UI can hide what the account cannot use.
	let free = null;
	for (let c in doc.countries)
		for (let city in c.cities)
			for (let r in city.relays)
				if (r.name == 'JP-FREE#1')
					free = r;
	ok('free-tier logical present', free != null);
	eq('free tier recorded', free.tier, 0);
	eq('paid tier recorded', plain.tier, 2);

	// City codes are synthesized as cc-city because Proton sends a city NAME.
	eq('city code synthesis', city_code_of('jp', 'Tokyo'), 'jp-tokyo');
	eq('city code strips punctuation', city_code_of('us', 'New York City'), 'us-newyorkcity');
	eq('secure core relay city code', sc.city_code, 'jp-tokyo');
}

// 2. offline logicals and dead servers are skipped
{
	let d = normalize([
		{ Name: 'X#1', Status: 0, ExitCountry: 'DE', City: 'Berlin', Features: 0,
		  Servers: [ { Status: 1, EntryIP: '1.2.3.4', X25519PublicKey: 'k' } ] },
		{ Name: 'X#2', Status: 1, ExitCountry: 'DE', City: 'Berlin', Features: 0,
		  Servers: [ { Status: 0, EntryIP: '1.2.3.5', X25519PublicKey: 'k' } ] },
		{ Name: 'X#3', Status: 1, ExitCountry: 'DE', City: 'Berlin', Features: 0,
		  Servers: [ { Status: 1, EntryIP: '1.2.3.6' } ] },
		{ Name: 'X#4', Status: 1, ExitCountry: 'DE', City: 'Berlin', Features: 0,
		  Servers: [ { Status: 1, X25519PublicKey: 'k' } ] }
	]);
	eq('all four logicals seen', d.stats.servers_seen, 4);
	eq('none of them is usable', d.stats.gateways, 0);
	eq('no country survives', length(d.countries), 0);
}

// 3. locations_tree carries per-kind counts for the UI
{
	let tree = locations_tree(doc);
	ok('tree not empty', length(tree) > 0);
	let jp = null;
	for (let c in tree)
		if (c.code == 'jp')
			jp = c;
	ok('tree has jp', jp != null);
	eq('tree country total matches cache', jp.gateway_count,
		jp.standard_count + jp.secure_core_count + jp.tor_count);
	ok('tree cities present', length(jp.cities) > 0);

	// The average load rides next to the counts, per kind, null where the
	// kind is absent: the tree carries no per-relay data, so the UI cannot
	// recompute it and must never invent one.
	let tokyo = null, amsterdam = null;
	for (let c in tree)
		for (let ct in c.cities) {
			if (ct.code == 'jp-tokyo')
				tokyo = ct;
			if (ct.code == 'nl-amsterdam')
				amsterdam = ct;
		}
	ok('tree has tokyo', tokyo != null);
	eq('tokyo standard load averages its gateways', tokyo.standard_load, 89);
	eq('tokyo secure-core load averages its gateways', tokyo.secure_core_load, 50);
	eq('tokyo has no tor load', tokyo.tor_load, null);
	eq('jp standard load averages across cities', jp.standard_load, 85);
	eq('jp secure-core load', jp.secure_core_load, 50);
	eq('amsterdam standard load', amsterdam.standard_load, 38);

	// Tor is a first-class kind like the other two: FR#13-TOR (Load 98) is
	// the only Tor relay in the fixture, so Paris and FR must average to 98 —
	// a present kind must never collapse to 0 — while countries without the
	// kind carry null at the country level too.
	let fr = null, paris = null, nl = null;
	for (let c in tree) {
		if (c.code == 'fr')
			fr = c;
		if (c.code == 'nl')
			nl = c;
		for (let ct in c.cities)
			if (ct.code == 'fr-paris')
				paris = ct;
	}
	ok('tree has fr', fr != null);
	ok('tree has paris', paris != null);
	eq('paris counts its tor gateway', paris.tor_count, 1);
	eq('paris tor load is its gateway load', paris.tor_load, 98);
	eq('fr counts its tor gateway', fr.tor_count, 1);
	eq('fr tor load averages its tor gateways', fr.tor_load, 98);
	eq('paris has no standard load', paris.standard_load, null);
	eq('jp has no country-level tor load', jp.tor_load, null);
	eq('nl has no country-level tor load', nl.tor_load, null);
	eq('nl has no country-level secure-core load', nl.secure_core_load, null);
}

// 4. hop-mode filtering: the same location yields different pools
{
	let std = candidates(doc, 'jp', '', 'standard');
	let sc = candidates(doc, 'jp', '', 'secure_core');
	let tor = candidates(doc, 'jp', '', 'tor');
	ok('jp has standard relays', length(std) > 0);
	ok('jp has a secure core relay', length(sc) > 0);
	eq('jp has no tor relay', length(tor), 0);

	// Secure Core must never leak into the standard pool.
	let leaked = 0;
	for (let r in std)
		if (r.secure_core || r.tor)
			leaked++;
	eq('standard pool holds no secure core or tor', leaked, 0);

	// An unknown hop mode falls back to standard rather than returning nothing.
	eq('unknown hop mode behaves as standard', length(candidates(doc, 'jp', '', 'nonsense')),
		length(std));
}

// 5. location sets: union, dedup, garbage
{
	let jpAll = location_candidates(doc, [ 'jp' ], 'standard');
	let both = location_candidates(doc, [ 'jp', 'nl' ], 'standard');
	ok('two countries give at least as many as one', length(both) >= length(jpAll));

	// A city inside an already-selected country must not double up.
	let dup = location_candidates(doc, [ 'jp', 'jp-tokyo' ], 'standard');
	let seen = {}, dupes = 0;
	for (let r in dup) {
		if (seen[r.hostname])
			dupes++;
		seen[r.hostname] = true;
	}
	eq('country plus its own city does not duplicate', dupes, 0);

	eq('garbage entries contribute nothing',
		length(location_candidates(doc, [ 'zzz', '', '-', 'not a code' ], 'standard')), 0);
	eq('empty set yields nothing', length(location_candidates(doc, [], 'standard')), 0);

	// A location set wins over the legacy single-country selection.
	let viaSet = selection_candidates(doc, { locations: [ 'nl' ], hop_mode: 'standard',
		country_code: 'jp', city_code: '' });
	let nlOnly = candidates(doc, 'nl', '', 'standard');
	eq('location set overrides country_code', length(viaSet), length(nlOnly));
	let viaLegacy = selection_candidates(doc, { locations: [], hop_mode: 'standard',
		country_code: 'jp', city_code: '' });
	eq('empty set falls back to country_code', length(viaLegacy), length(candidates(doc, 'jp', '', 'standard')));
}

// 6. pool_relays mirrors the selection but over the cache document
{
	let pool = pool_relays(doc, [ 'jp', 'nl' ], 'standard');
	ok('pool not empty', length(pool) > 0);
	let wrong = 0;
	for (let r in pool)
		if (r.country_code != 'jp' && r.country_code != 'nl')
			wrong++;
	eq('pool stays inside the requested countries', wrong, 0);
	eq('pool with an empty set is empty', length(pool_relays(doc, [], 'standard')), 0);

	let city = city_relays(doc, 'nl', 'nl-amsterdam', 'standard');
	ok('city relays found', length(city) > 0);
	let outside = 0;
	for (let r in city)
		if (r.city_code != 'nl-amsterdam')
			outside++;
	eq('city relays stay in that city', outside, 0);
	ok('city relays are trimmed (no public key)', city[0].public_key == null);
}

// 6b. many logical servers share ONE physical domain
// Proton runs dozens of logicals (NL#85, NL#339, ...) on the same machine, so
// deduping the pool by domain silently threw away most of the parc: 940 Dutch
// servers collapsed into 73. Dedup must key on the logical name.
{
	let mk = function(name, domain) {
		return { Name: name, Status: 1, ExitCountry: 'NL', City: 'Amsterdam',
			Features: 0, Tier: 2, Load: 10, Score: 1,
			Servers: [ { Status: 1, EntryIP: '1.2.3.4', Domain: domain,
				X25519PublicKey: 'k' + name } ] };
	};
	let doc2 = normalize([
		mk('NL#1', 'node-nl-01.protonvpn.net'),
		mk('NL#2', 'node-nl-01.protonvpn.net'),
		mk('NL#3', 'node-nl-01.protonvpn.net'),
		mk('NL#4', 'node-nl-02.protonvpn.net')
	]);
	eq('all four logicals are cached', doc2.stats.gateways, 4);
	eq('the pool keeps every logical despite the shared domain',
		length(pool_relays(doc2, [ 'nl' ], 'standard')), 4);
	eq('selection keeps them too',
		length(location_candidates(doc2, [ 'nl' ], 'standard')), 4);
	// The country+city overlap must still collapse to one entry each.
	eq('country plus its city still dedups',
		length(location_candidates(doc2, [ 'nl', 'nl-amsterdam' ], 'standard')), 4);
}

// 7. lookup and picking
{
	let r = by_hostname(doc, 'NL#85');
	ok('lookup by logical name', r != null);
	eq('lookup returns the right relay', r.name, 'NL#85');
	ok('lookup by per-server domain also works', by_hostname(doc, r.hostname) != null);
	ok('unknown hostname yields null', by_hostname(doc, 'nope') == null);

	let list = candidates(doc, 'nl', '', 'standard');
	ok('pick returns a member of the list', pick(list) != null);
	eq('pick from an empty list', pick([]), null);

	// Rotation must move away from the current server when there is anywhere
	// to go, and stay put rather than fail when there is not.
	if (length(list) > 1) {
		let cur = list[0].hostname;
		let other = pick(list, cur);
		ok('pick avoids the excluded host', other.hostname != cur);
	}
	let single = [ list[0] ];
	eq('excluding the only candidate falls back to it',
		pick(single, list[0].hostname).hostname, list[0].hostname);

}

// 8. cache file: schema guard, staleness, atomic round-trip
{
	let path = RUN + '/protonvpn_test_cache.json';
	unlink(path);
	eq('missing cache is stale', cache_is_stale(path), true);
	ok('write_cache succeeds', write_cache(doc, path) == true);
	let back = read_cache(path);
	ok('cache reads back', back != null);
	eq('country count survives the round trip', length(back.countries), length(doc.countries));
	ok('cache_info stamped', back.cache_info != null && back.cache_info.gateways > 0);
	eq('fresh cache is not stale', cache_is_stale(path), false);

	// A cache from another schema version must be treated as missing, not
	// half-understood.
	let d2 = read_cache(path);
	d2.schema_version = 'other';
	require('protonvpn.common').atomic_write(path, sprintf('%J', d2));
	eq('foreign schema version is rejected', read_cache(path), null);
	eq('and therefore counts as stale', cache_is_stale(path), true);

	require('protonvpn.common').atomic_write(path, 'not json at all');
	eq('malformed cache is rejected', read_cache(path), null);
	eq('write_cache rejects a non-document', write_cache({ nope: true }, path), false);
	unlink(path);
}

// 9. issue #1 — the OOM: the whole parsed fleet must never exist at once
// beside the normalized document. normalize_body() walks the raw body one
// logical at a time; normalize() releases each logical it consumes.
{
	let body = readfile(fixture);
	let want = normalize(json(body).LogicalServers);
	delete want.generated_at;
	// Excerpt of the real 2026-09-17 response: accented cities as raw
	// <U+XXXX> escapes and root fields trailing the array.
	let esc_fixture = replace(fixture, /[^\/]+$/, 'logicals_escapes.json');

	if (type(_cache.normalize_body) != 'function') {
		ok('normalize_body is exported by protonvpn.cache', false);
	} else {
	// body_parse_mode() reports which parse the LAST normalize_body() call
	// took: the fallback must be rare and visible, so every test below pins
	// the mode, not just the result (byte-identity passes either way).
	let have_mode = type(_cache.body_parse_mode) == 'function';
	ok('body_parse_mode is exported by protonvpn.cache', have_mode);
	let mode = function() { return have_mode ? _cache.body_parse_mode() : null; };
	// Parsing straight from the raw body must be byte-identical to the
	// monolithic parse — on the pretty-printed fixture shape AND on a
	// compact %J serialization (Proton's own responses are compact).
	let pretty = _cache.normalize_body(body);
	delete pretty.generated_at;
	eq('raw-body parse is byte-identical to the monolith (pretty body)', pretty, want);
	eq('and the walk was used', mode(), 'walk');
	let compact = sprintf('%J', json(body));
	let comp = _cache.normalize_body(compact);
	delete comp.generated_at;
	eq('raw-body parse is byte-identical on a compact body', comp, want);
	eq('and the walk was used', mode(), 'walk');

	// A body with root fields AFTER the LogicalServers array is exactly what
	// Proton sends — real responses trail the array with ResponseMetadata
	// and Code. The walk must consume the array and validate the tail, NOT
	// fall back (falling back here is what made the fix useless on live
	// data — the issue #1 blocker).
	let wrapped = '{"Code":1000,"LogicalServers":' +
		sprintf('%J', json(body).LogicalServers) + ',"Trailing":1}';
	let fall = _cache.normalize_body(wrapped);
	ok('a body with trailing root fields parses', fall != null);
	if (fall) {
		delete fall.generated_at;
		eq('and it is byte-identical too', fall, want);
		eq('and the walk handled the trailing fields', mode(), 'walk');
	}

	// The walk must also give up cleanly when the logicals do not START with
	// their Name key: the split pieces then fail the boundary check, and the
	// monolithic fallback parses the reordered keys without noticing.
	let reordered = map(json(body).LogicalServers, function(l) {
		let re = {};
		for (let k in keys(l))
			if (k != 'Name')
				re[k] = l[k];
		re.Name = l.Name;
		return re;
	});
	let rb = _cache.normalize_body(sprintf('%J',
		{ Code: 1000, LogicalServers: reordered }));
	ok('Name-not-first falls back to the monolith', rb != null);
	if (rb) {
		delete rb.generated_at;
		eq('and is byte-identical too', rb, want);
		eq('and the fallback was used', mode(), 'monolith');
	}

	// Key order inside a JSON object is free, so moving one field of ONLY the
	// first logical ahead of its Name key must not change the cache. The walk
	// reconstructs the first logical starting at its Name key, so it must
	// refuse this shape and let the monolith keep the field.
	let first_moved = function(key) {
		let ls = json(body).LogicalServers;
		let re = {};
		re[key] = ls[0][key];
		for (let k in keys(ls[0]))
			if (k != key)
				re[k] = ls[0][k];
		ls[0] = re;
		return sprintf('%J', { Code: 1000, LogicalServers: ls });
	};
	let fc = _cache.normalize_body(first_moved('City'));
	ok('City before Name in the FIRST logical only still parses', fc != null);
	if (fc) {
		delete fc.generated_at;
		eq('and the city is not lost to Unknown', fc, want);
	}
	let fst = _cache.normalize_body(first_moved('Status'));
	ok('Status before Name in the FIRST logical only still parses', fst != null);
	if (fst) {
		delete fst.generated_at;
		eq('and its gateways survive', fst, want);
	}

	// The walk must consume the ROOT LogicalServers array: logicals living
	// under any other key, or a "LogicalServers" key nested inside something
	// else, are not the fleet. The first two variants fall back and yield
	// the real (empty) array's empty document; the last two have no root
	// array at all, so the monolithic parse itself yields null.
	let fleet_j = sprintf('%J', json(body).LogicalServers);
	let want_empty = normalize([]);
	delete want_empty.generated_at;
	let wrong = [
		{ body: '{"LogicalServers":[],"Other":' + fleet_j + '}', want: want_empty },
		{ body: '{"Code":1000,"LogicalServers":[],"Other":' + fleet_j + '}', want: want_empty },
		{ body: '{"Code":1000,"Other":' + fleet_j + '}', want: null },
		{ body: '{"Code":1000,"A":[1,2,{"LogicalServers":' +
			substr(fleet_j, 0, length(fleet_j) - 2) + ',"B":0}]}]}', want: null }
	];
	for (let i = 0; i < length(wrong); i++) {
		let rw = _cache.normalize_body(wrong[i].body);
		if (wrong[i].want == null) {
			eq(sprintf('non-root logicals are rejected, not walked (%d)', i), rw, null);
		} else {
			ok(sprintf('logicals under a non-root key are not walked (%d)', i), rw != null);
			if (rw) {
				delete rw.generated_at;
				eq(sprintf('and only the real LogicalServers counts (%d)', i), rw, want_empty);
			}
		}
		eq(sprintf('and the fallback reported itself (%d)', i), mode(), 'monolith');
	}

	eq('garbage yields null, not a crash', _cache.normalize_body('{ not json'), null);
	eq('a response without the array yields null',
		_cache.normalize_body('{"Code":1000}'), null);
	// A head that merely CONTAINS "LogicalServers" and '[' is not enough: the
	// monolithic parser rejects these bodies, so the walk must not accept them.
	eq('garbage between the array open and the first logical is rejected',
		_cache.normalize_body('{"LogicalServers":[ GARBAGE ' +
			substr(sprintf('%J', json(body).LogicalServers), 1) + '}'), null);
	eq('a syntactically invalid root prefix is rejected',
		_cache.normalize_body('{"Code":,"LogicalServers":' +
			sprintf('%J', json(body).LogicalServers) + '}'), null);

	// The shape that actually broke on live data (issue #1 blocker): real
	// responses carry \uXXXX escapes in city names (São Paulo, San José,
	// Bogotá, Lomé — see the fixture, an excerpt of the 2026-09-17 capture)
	// AND root fields trailing the array. The walk used to give up on the
	// trailing fields and silently fell back to the monolithic parse — peak
	// and all. Byte-identity alone cannot catch that (the fallback produces
	// the same document), so the mode is pinned too.
	let esc_body = readfile(esc_fixture);
	let esc_want = normalize(json(esc_body).LogicalServers);
	delete esc_want.generated_at;
	let esc = _cache.normalize_body(esc_body);
	ok('a body with escapes and trailing root fields parses', esc != null);
	if (esc) {
		delete esc.generated_at;
		eq('and it is byte-identical to the monolith', esc, esc_want);
		eq('and the fast path was taken', mode(), 'walk');
	}

	// Duplicate root keys: ucode's monolithic parser keeps the LAST
	// occurrence, the walk would keep the FIRST array — so a trailing
	// LogicalServers field must force the fallback, or the two paths
	// disagree (the equivalence promise). Case 1: the later empty array must
	// win, like the monolith; case 2: a later null must reject the body.
	let esc_ls = sprintf('%J', json(esc_body).LogicalServers);
	let dup1 = _cache.normalize_body('{"LogicalServers":' + esc_ls +
		',"LogicalServers":[],"Code":1000}');
	ok('a trailing duplicate LogicalServers still parses', dup1 != null);
	if (dup1) {
		delete dup1.generated_at;
		eq('and the LAST array wins, like the monolith', dup1, want_empty);
		eq('and the fallback reported itself', mode(), 'monolith');
	}
	eq('a trailing LogicalServers:null rejects the body',
		_cache.normalize_body('{"LogicalServers":' + esc_ls +
			',"LogicalServers":null,"Code":1000}'), null);
	eq('and the fallback reported itself', mode(), 'monolith');

	// The same hole through the DECODED side: an escaped key spelling is
	// invisible to raw-text checks but decodes to a real duplicate for the
	// monolithic parser. \\u0053 stays a raw six-character escape in the
	// body — a single-backslash \u0053 in a ucode literal would decode to
	// the letter S before the body is even built.
	let dup2 = _cache.normalize_body('{"LogicalServers":' + esc_ls +
		',"Logical\\u0053ervers":[],"Code":1000}');
	ok('an escaped trailing duplicate still parses', dup2 != null);
	if (dup2) {
		delete dup2.generated_at;
		eq('and the LAST array wins, like the monolith', dup2, want_empty);
		eq('and the fallback reported itself', mode(), 'monolith');
	}
	eq('an escaped trailing LogicalServers:null rejects the body',
		_cache.normalize_body('{"LogicalServers":' + esc_ls +
			',"Logical\\u0053ervers":null,"Code":1000}'), null);
	eq('and the fallback reported itself', mode(), 'monolith');

	// body_parse_mode() must never go stale: it describes the LAST call, and
	// a call that rejects its input before parsing is not a parse at all.
	_cache.normalize_body(compact);
	eq('mode after a walk', mode(), 'walk');
	eq('an empty body is rejected', _cache.normalize_body(''), null);
	eq('mode is cleared when nothing was parsed', mode(), null);
	eq('a null body is rejected', _cache.normalize_body(null), null);
	eq('mode stays cleared', mode(), null);
	eq('a non-string body is rejected', _cache.normalize_body(23), null);
	eq('mode stays cleared', mode(), null);

	// The decoder's nesting limit applies to the WHOLE document on the old
	// path: the root object and the LogicalServers array add two levels
	// around every logical, so json(raw) throws 'nesting too deep' for a
	// logical whose fields nest 29-30 levels while the same logical still
	// parses on its own (boundary measured on this ucode build: 28 walks,
	// 29-30 fall back and reject, 31 fails even standalone — kept as a
	// guard). The walk must not accept what the monolith rejects: deep
	// pieces fall back, and the monolith then rejects the body too.
	let nest = function(n) {
		let d = 0;
		for (let i = 0; i < n; i++)
			d = [ d ];
		return d;
	};
	let deep_body = function(n, deep_last) {
		let plain = { Name: 'DE#1', Status: 1, ExitCountry: 'DE',
			City: 'Berlin', Servers: [ { Status: 1, EntryIP: '1.2.3.4',
			X25519PublicKey: 'k' } ] };
		let extra = { Name: 'DE#2', Status: 1, ExitCountry: 'DE',
			City: 'Berlin', Servers: [ { Status: 1, EntryIP: '1.2.3.5',
			X25519PublicKey: 'k' } ], Extra: nest(n) };
		return sprintf('%J', { LogicalServers:
			deep_last ? [ plain, extra ] : [ extra, plain ],
			ResponseMetadata: {}, Code: 1000 });
	};
	let d28 = _cache.normalize_body(deep_body(28, true));
	ok('28 nested levels as the last logical still walks', d28 != null);
	if (d28)
		eq('and both gateways survive', d28.stats.gateways, 2);
	eq('28 nested levels report walk', mode(), 'walk');
	let d28f = _cache.normalize_body(deep_body(28, false));
	ok('28 nested levels as a middle logical still walks', d28f != null);
	if (d28f)
		eq('and both gateways survive', d28f.stats.gateways, 2);
	eq('28 nested middle levels report walk', mode(), 'walk');
	eq('29 nested levels in the last logical reject like the monolith',
		_cache.normalize_body(deep_body(29, true)), null);
	eq('and the fallback reported itself', mode(), 'monolith');
	eq('29 nested levels in a middle logical reject like the monolith',
		_cache.normalize_body(deep_body(29, false)), null);
	eq('and the fallback reported itself', mode(), 'monolith');
	eq('30 nested levels reject like the monolith',
		_cache.normalize_body(deep_body(30, true)), null);
	eq('and the fallback reported itself', mode(), 'monolith');
	eq('31 nested levels fail even standalone (old boundary)',
		_cache.normalize_body(deep_body(31, true)), null);
	eq('and the fallback reported itself', mode(), 'monolith');

	// A forged array boundary inside a logical's text ('}],[{') is a syntax
	// error for the monolith; the walk must not parse around it either.
	eq('a forged array boundary inside a logical rejects the body',
		_cache.normalize_body('{"LogicalServers":[{"Name":"A","Status":1,' +
			'"ExitCountry":"DE","City":"Berlin","Servers":[{"Status":1,' +
			'"EntryIP":"1.2.3.4","X25519PublicKey":"k"}]}],[{"Z":1},{' +
			'"Name":"B","Status":1,"ExitCountry":"DE","City":"Berlin",' +
			'"Servers":[{"Status":1,"EntryIP":"1.2.3.5",' +
			'"X25519PublicKey":"k"}]}],"ResponseMetadata":{},"Code":1000}'),
		null);
	eq('and the fallback reported itself', mode(), 'monolith');
	}

	// normalize() consumes its input: each parsed logical is released as it
	// is normalized, so the parsed fleet and the growing document never
	// coexist in full.
	let fleet = [ { Name: 'T#1', Status: 1, ExitCountry: 'DE', City: 'Berlin',
		Features: 0, Servers: [ { Status: 1, EntryIP: '1.2.3.4',
		X25519PublicKey: 'k' } ] } ];
	normalize(fleet);
	eq('normalize releases each logical as it consumes it', fleet[0], null);
}

// 9b. peak guard: the whole path (read, parse, normalize, serialize) over a
// realistic 18k-logical fleet must stay far below the monolithic parse peak.
// Measured before the fix: ~14x the body size (200-213 MB peak for a 14.5 MB
// body, dev build and router alike). 6x catches a regression to the monolith
// with room for allocator differences. Runs in a CHILD process so the number
// is the child's own VmHWM, not this suite's. The generated fleet carries
// the REAL response shape (\uXXXX city escapes, root fields trailing the
// array), so the guard also fails if the walk ever gives up on live-shaped
// data and silently falls back again (the issue #1 blocker).
{
	let ucode = getenv('UCODE') || 'ucode';
	let measure = getenv('PVT_MEASURE');
	let lflags = getenv('PVT_UCODE_L') || '';
	let fleetfile = RUN + '/peak_fleet.json';
	let gen = popen(sprintf('%s %s -D mode=generate -D fleet=%s -S %s 2>&1',
		ucode, lflags, fleetfile, measure), 'r');
	let gout = gen ? gen.read('all') : '';
	let gcode = gen ? gen.close() : -1;
	ok('fleet generation runs', gcode == 0 && index(gout, 'generated 18000') >= 0);

	let mp = popen(sprintf('%s %s -D mode=measure -D fleet=%s -S %s 2>&1',
		ucode, lflags, fleetfile, measure), 'r');
	let mout = mp ? mp.read('all') : '';
	let mcode = mp ? mp.close() : -1;
	ok('peak measurement runs', mcode == 0 && index(mout, 'gateways 19800') >= 0);
	let bytes = match(mout, /input_bytes (\d+)/);
	let hwm = match(mout, /stage after_serialize rss_kB \d+ hwm_kB (\d+)/);
	ok('measurement reports input size and peak', bytes != null && hwm != null);
	if (bytes && hwm)
		ok(sprintf('peak stays under 6x the body (got %dx)',
			int(hwm[1]) * 1024 / int(bytes[1])),
			int(hwm[1]) * 1024 <= 6 * int(bytes[1]));
	unlink(fleetfile);
}

// 9c. the fallback log must count ALL logical pieces: a body truncated in
// its document tail makes the walk give up on the last of the excerpt's
// five logicals, and the log must say 'of 5' — not one less. Runs in a
// CHILD process so stderr (where log() writes) is capturable.
{
	let ucode = getenv('UCODE') || 'ucode';
	let lflags = getenv('PVT_UCODE_L') || '';
	let esc_fixture = replace(fixture, /[^\/]+$/, 'logicals_escapes.json');
	let probe = RUN + '/fallback_log_probe.uc';
	writefile(probe,
		"import { readfile } from 'fs';\n" +
		"const _c = require('protonvpn.cache');\n" +
		"let raw = readfile(global.fix);\n" +
		"raw = substr(raw, 0, length(raw) - 12);\n" +
		"let doc = _c.normalize_body(raw);\n" +
		"print('doc ', doc ? 'ok' : 'null', ' mode ', _c.body_parse_mode());\n");
	let lp = popen(sprintf('%s %s -D fix=%s -S %s 2>&1',
		ucode, lflags, esc_fixture, probe), 'r');
	let lout = lp ? lp.read('all') : '';
	let lcode = lp ? lp.close() : -1;
	ok('fallback probe runs and falls back',
		lcode == 0 && index(lout, 'doc null mode monolith') >= 0);
	ok('fallback log counts every logical (5 of 5)',
		index(lout, 'gave up at logical 5 of 5') >= 0);
	unlink(probe);
}

print(failures ? sprintf('\nFAILURES: %d\n', failures) : '\nALL CACHE TESTS PASSED\n');
if (failures)
	exit(1);

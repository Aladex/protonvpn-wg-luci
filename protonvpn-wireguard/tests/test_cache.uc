// SPDX-License-Identifier: MIT
// Fixture tests for the cache/selection layer. fixtures/logicals_sample.json is
// a trimmed copy of a REAL authenticated /vpn/logicals response (captured
// 2026-07-30), keeping one logical per Features variant plus both tiers, so the
// feature decoding and the Secure Core / Tor split are checked against Proton's
// actual wire format rather than something invented here.
//
// Globals `fixture` and `KEY` come from run.sh.

'use strict';

// Runtime scratch dir of THIS run (tests/run.sh gives each run its own, so
// two suites can execute concurrently); never the shared /tmp.
const RUN = getenv('PROTONVPN_RUN_DIR') || '/tmp';

import { readfile, unlink } from 'fs';
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

print(failures ? sprintf('\nFAILURES: %d\n', failures) : '\nALL CACHE TESTS PASSED\n');
if (failures)
	exit(1);

// SPDX-License-Identifier: MIT
// Shared server selection over the normalized cache. Pure and testable; used
// by both the apply path (single pick) and the rotation worker (try many).

'use strict';

import { rand } from 'math';
const relay_kind = require('protonvpn.common').relay_kind;

// All relays matching country/city/hop_mode. city_code '' = any city;
// 'secure_core'/'tor' select exactly that kind, anything else selects
// standard servers (tor servers are never picked implicitly).
function candidates(cache, country_code, city_code, hop_mode) {
	let out = [];
	if (!cache || type(cache.countries) != 'array')
		return out;

	// Anything other than an explicit secure_core/tor request means standard,
	// so Tor exits are never picked implicitly (they are slow and often
	// blocked) and Secure Core is never charged for silently.
	let want = (hop_mode == 'secure_core' || hop_mode == 'tor') ? hop_mode : 'standard';
	let cc = (country_code && country_code != '') ? lc(country_code) : null;

	for (let country in cache.countries) {
		if (cc && lc(country.code) != cc)
			continue;
		for (let city in country.cities) {
			if (city_code && city_code != '' && city.code != city_code)
				continue;
			for (let relay in city.relays) {
				if (relay_kind(relay) == want)
					push(out, relay);
			}
		}
	}
	return out;
}

// Union of candidates() over a location set (country codes 'ch' or city
// codes 'ch-zurich'), deduped by hostname.
function location_candidates(cache, locations, hop_mode) {
	let out = [], seen = {};
	if (type(locations) != 'array')
		return out;
	for (let entry in locations) {
		let list = [];
		if (type(entry) == 'string' && match(entry, /^[A-Za-z]{2}$/))
			list = candidates(cache, entry, '', hop_mode);
		else if (type(entry) == 'string' && index(entry, '-') > 0)
			list = candidates(cache, split(entry, '-')[0], lc(entry), hop_mode);
		// Anything else is garbage and contributes nothing, by design.
		for (let r in list) {
			// A city inside an already-selected country must appear once. Key
			// on the logical name: one physical domain hosts many logical
			// servers, so deduping by domain would throw most of them away and
			// leave rotation picking from a fraction of the pool.
			let id = r.name || r.hostname;
			if (seen[id])
				continue;
			seen[id] = true;
			push(out, r);
		}
	}
	return out;
}

// The location set wins when non-empty; otherwise the legacy
// country_code/city_code selection applies.
function selection_candidates(cache, settings) {
	if (!settings)
		return [];
	let loc = settings.locations;
	if (loc && length(loc) > 0)
		return location_candidates(cache, loc, settings.hop_mode);
	return candidates(cache, settings.country_code, settings.city_code, settings.hop_mode);
}

// One relay by hostname (logical server name) or null.
function by_hostname(cache, hostname) {
	if (!cache || type(cache.countries) != 'array' || !hostname)
		return null;
	for (let country in cache.countries)
		for (let city in country.cities)
			for (let relay in city.relays)
				// A pinned server is stored by the logical name, which the UI
				// shows; the per-server Domain is matched too so an older pin
				// written as a domain keeps working.
				if (relay.name == hostname || relay.hostname == hostname)
					return relay;
	return null;
}

// Random pick, optionally excluding a hostname (falls back to the full list
// when the exclusion would empty it).
function pick(list, exclude_hostname) {
	if (type(list) != 'array' || length(list) == 0)
		return null;
	let pool = list;
	if (exclude_hostname) {
		pool = filter(list, function(r) {
			return r.hostname != exclude_hostname && r.name != exclude_hostname;
		});
		// Excluding everything means there is nothing else to move to; the
		// caller decides whether keeping the current server is acceptable.
		if (length(pool) == 0)
			pool = list;
	}
	return pool[rand() % length(pool)];
}

// Lowest-Score relay, i.e. what Proton's own Quick Connect would choose.
// Kept separate from pick() so rotation stays random (predictable rotation
// would defeat the point) while the UI can offer a deliberate best pick.
function pick_best(list, exclude_hostname) {
	if (type(list) != 'array' || length(list) == 0)
		return null;
	let best = null;
	for (let r in list) {
		if (exclude_hostname && (r.hostname == exclude_hostname || r.name == exclude_hostname))
			continue;
		if (!best || (+r.score || 0) < (+best.score || 0))
			best = r;
	}
	return best;
}

return { candidates, location_candidates, selection_candidates, by_hostname, pick, pick_best };

// SPDX-License-Identifier: MIT
// Shared server selection over the normalized cache. Pure and testable; used
// by both the apply path (single pick) and the rotation worker (try many).

'use strict';

import { rand } from 'math';
const _common = require('protonvpn.common');
const relay_kind = _common.relay_kind,
      relay_ipv6_capable = _common.relay_ipv6_capable,
      require_ipv6_active = _common.require_ipv6_active;

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

// Everything geography and hop mode allow, before the IPv6 requirement gets a
// say. The location set wins when non-empty; otherwise the legacy
// country_code/city_code selection applies.
function geographic_candidates(cache, settings) {
	if (!settings)
		return [];
	let loc = settings.locations;
	if (loc && length(loc) > 0)
		return location_candidates(cache, loc, settings.hop_mode);
	return candidates(cache, settings.country_code, settings.city_code, settings.hop_mode);
}

// The candidate list plus enough context to explain an empty one.
//
// `matched` counts what the location set and hop mode alone select, so a
// caller can tell "you picked nowhere" apart from "you picked somewhere with
// no IPv6 gateway in it" — two very different things to tell a user, and the
// second one must never be answered by connecting anyway. `ipv6_filtered`
// says whether the requirement was applied at all, so the message is only
// ever blamed on IPv6 when IPv6 is what narrowed the list.
function selection_report(cache, settings) {
	let all = geographic_candidates(cache, settings);
	if (!require_ipv6_active(settings))
		return { list: all, matched: length(all), ipv6_filtered: false };
	return { list: filter(all, relay_ipv6_capable), matched: length(all),
		ipv6_filtered: true };
}

// The servers this instance may connect to, narrowed to gateways that forward
// IPv6 when the instance requires it. Every selection path — the initial
// apply, scheduled rotation and the watchdog's recovery rotation — goes
// through here, so the requirement cannot be honoured on one and forgotten on
// another.
function selection_candidates(cache, settings) {
	return selection_report(cache, settings).list;
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

return { candidates, location_candidates, geographic_candidates,
	selection_report, selection_candidates, by_hostname, pick };

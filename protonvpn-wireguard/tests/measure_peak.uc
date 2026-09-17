// SPDX-License-Identifier: MIT
// Peak-RSS measurement for the /vpn/logicals -> normalize() path (issue #1:
// protonvpn-service OOM-killed on routers with little free RAM).
//
// Not part of run.sh; invoked directly, and by the peak regression test in
// test_cache.uc. Three concerns, one script so they stay in lockstep:
//
//   generate: synthesize a realistic fleet of N logicals (default 18000, the
//     live fleet size) with exactly the field shape of the committed fixture
//     (a trimmed real /vpn/logicals response) — a 13 MB fixture must never
//     be committed — and write it as one JSON document, the same shape curl
//     leaves on disk for fetch_servers().
//   measure: read that document back the way fetch_servers() does, parse it,
//     run the REAL normalize() from protonvpn.cache over it, and print VmHWM
//     (/proc/self/status) after each stage.
//   -D out=<path>: also write the normalized document (sans the volatile
//     generated_at stamp) so two builds can be diffed byte for byte.
//
// Usage:
//   ucode -L "mocks/*.uc" -L "../files/usr/share/ucode/*.uc" \
//     -D fixture=fixtures/logicals_sample.json -D mode=generate \
//     -D fleet=/tmp/fleet.json -S measure_peak.uc
//   ucode -L ... -D mode=measure -D fleet=/tmp/fleet.json [-D out=/tmp/norm.json] \
//     -S measure_peak.uc

'use strict';

import { readfile, writefile, unlink, stat } from 'fs';
const _cache = require('protonvpn.cache');

const mode = getenv('MODE') || global.mode || 'measure';
const fleet_path = getenv('FLEET') || global.fleet ||
	(getenv('PROTONVPN_RUN_DIR') || '/tmp') + '/measure_fleet.json';
const N = int(getenv('N') || global.n || 18000);

// Peak and current RSS of this process in kB, Linux and the router alike.
function probe(stage) {
	let s = readfile('/proc/self/status') || '';
	let r = match(s, /VmRSS:\s*(\d+) kB/), h = match(s, /VmHWM:\s*(\d+) kB/);
	printf('stage %s rss_kB %d hwm_kB %d\n', stage,
		r ? int(r[1]) : -1, h ? int(h[1]) : -1);
}

function b64(chars) {
	const abc = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
	let out = '';
	for (let i = 0; i < chars; i++)
		out += substr(abc, (i * 37 + chars) % 64, 1);
	return out;
}

// One synthetic logical with exactly the field set Proton sends (see
// fixtures/logicals_sample.json). `i` drives every varying field, so the
// output is deterministic.
function mk_logical(i) {
	const ccs = [ 'NL', 'DE', 'JP', 'US', 'CH', 'SE', 'FR', 'GB', 'CA', 'AU',
		'PL', 'LV', 'IL', 'FI', 'NZ', 'BR', 'IN', 'SG', 'HK', 'AT',
		'BE', 'CZ', 'DK', 'ES', 'IT', 'NO', 'PT', 'RO', 'IE', 'IS' ];
	const feats = [ 0, 1, 2, 28, 12, 16, 4, 8 ];
	let cc = ccs[i % length(ccs)];
	let f = feats[i % length(feats)];
	let sc = (f & 1) ? true : false;
	let entry = sc ? ccs[(i + 7) % length(ccs)] : cc;
	// Live is ~750 bytes/logical (13.4 MB / 18k), i.e. barely over one physical
	// server per logical — most Proton logicals wrap exactly one.
	let nservers = 1 + ((i % 10 == 0) ? 1 : 0);
	let servers = [];
	for (let s = 0; s < nservers; s++) {
		let ip = sprintf('10.%d.%d.%d', (i >> 8) & 255, i & 255, s + 2);
		push(servers, {
			EntryIP: ip, ExitIP: ip,
			Domain: sprintf('node-%s-%d.protonvpn.net', lc(cc), (i * 4 + s) % 100),
			ID: b64(86) + '==',
			Label: '',
			X25519PublicKey: b64(42) + '=',
			Generation: 0,
			Status: 1,
			ServicesDown: 0,
			ServicesDownReason: null
		});
	}
	// A share of the fleet gets accented cities — Proton sends those as
	// \uXXXX escapes on the wire (450 in the 2026-09 capture), so the
	// generator must produce that byte class too (issue #1 blocker).
	let city = sprintf('City%d', i % 250);
	if (i % 7 == 3)
		city = sprintf('São Paulo %d', i % 50);
	else if (i % 11 == 5)
		city = sprintf('San José %d', i % 40);
	else if (i % 13 == 6)
		city = sprintf('Bogotá %d', i % 30);
	return {
		Name: sc ? sprintf('%s-%s#%d', entry, cc, i) : sprintf('%s#%d', cc, i),
		EntryCountry: entry,
		ExitCountry: cc,
		Domain: sprintf('%s-%d.protonvpn.net', lc(cc), i % 1000),
		Tier: (i % 11 == 0) ? 0 : 2,
		Features: f,
		Region: null,
		City: city,
		Score: (i % 300) / 100.0 + 0.5,
		HostCountry: null,
		OrganizationID: null,
		VPNGatewayID: null,
		ID: b64(86) + '==',
		Location: { Lat: 35.65, Long: 139.83 },
		Servers: servers,
		Status: 1,
		Load: i % 100
	};
}

if (mode == 'generate') {
	let fleet = [];
	for (let i = 0; i < N; i++)
		push(fleet, mk_logical(i));
	// The real response shape: LogicalServers FIRST, then trailing root
	// fields (ResponseMetadata, Code) — the walk must handle both (issue #1
	// blocker: real bodies silently fell back to the monolithic parse).
	let body = sprintf('%J', { LogicalServers: fleet,
		ResponseMetadata: { ListIsTruncated: false }, Code: 1000 });
	fleet = null;
	// %J emits raw UTF-8, but Proton escapes non-ASCII as XXXX on the
	// wire (\u00e3/\u00e9/\u00e1 in the 2026-09 capture) — match that, so the
	// raw-body walk is measured against the byte sequences it will really
	// see. Only city names contain these characters. The doubled backslash
	// keeps the replacement a literal six-character escape sequence: ucode
	// string literals interpret \uXXXX in either quote style.
	body = replace(body, 'ã', '\\u00e3');
	body = replace(body, 'é', '\\u00e9');
	body = replace(body, 'á', '\\u00e1');
	if (!writefile(fleet_path, body))
		die(sprintf('could not write %s (directory missing?)\n', fleet_path));
	printf('generated %d logicals, %d bytes -> %s\n', N, length(body), fleet_path);
	exit(0);
}

// ── measure ──────────────────────────────────────────────────────────────
// The same path fetch_servers() takes after the download lands: read the
// body, then normalize straight from it (one logical at a time — the point
// of the issue #1 fix — with the monolithic parse as normalize_body()'s own
// fallback).
let st = stat(fleet_path);
if (!st)
	die(sprintf('fleet file %s missing — run mode=generate first\n', fleet_path));
printf('input_bytes %d\n', st.size);
probe('start');

let raw = readfile(fleet_path);
probe('after_read');

let doc = _cache.normalize_body(raw);
raw = null;
if (!doc)
	die('normalize_body returned null for the synthetic fleet\n');
probe('after_normalize');
printf('logicals %d gateways %d countries %d cities %d\n',
	doc.stats.servers_seen, doc.stats.gateways, doc.stats.countries,
	doc.stats.cities);

// write_cache() serializes the whole document in one sprintf; that string is
// part of the real peak, so measure it too.
let ser = sprintf('%J', doc);
probe('after_serialize');
printf('serialized_bytes %d\n', length(ser));
ser = null;
gc();
probe('after_release');

if (global.out) {
	// The stamp differs between runs; everything else must not.
	delete doc.generated_at;
	writefile(global.out, sprintf('%J', doc));
	printf('normalized_written %s\n', global.out);
}

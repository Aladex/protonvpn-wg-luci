#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// The client-version picker: what client_versions() fetches from the official
// Linux client's repository, what it does when a source is unreachable, and
// the one thing it must never do — decide. The app_version override is a
// header Proton gates sign-ins on; offering a list is help, changing the
// setting behind the user's back is not. Run via tests/run.sh.

'use strict';

import { open, unlink, mkdir, rmdir } from 'fs';

let ok = true;
function check(label, cond) {
	if (!cond) {
		ok = false;
		printf('FAIL %s\n', label);
	} else {
		printf('ok   %s\n', label);
	}
}

let api = require('protonvpn.api');

// tests/stubs/curl answers per URL from files named after a piece of it.
let dir = getenv('PROTONVPN_RUN_DIR') + '/curl-responses';
mkdir(dir);
function answer(key, code, body) {
	let f = open(dir + '/' + key, 'w');
	f.write('' + code + '\n' + body + '\n');
	f.close();
}
function silence(key) {
	unlink(dir + '/' + key);
}
function reset() {
	silence('versions.yml');
	silence('tags');
}

// The upstream shapes, as they really are: versions.yml is a stream of YAML
// documents newest first, and the tags endpoint answers with a JSON array.
const YML = 'version: 4.18.2\n' +
	'stable: true\n' +
	'---\n' +
	'version: 3.0.0\n';
// Deliberately NOT in version order: the tags endpoint does not promise one,
// and a fixture that happens to be sorted cannot tell a sorted list from an
// unsorted one.
const TAGS = '[{"name":"v4.9.0"},{"name":"v4.18.2"},{"name":"v4.17.0"},' +
	'{"name":"v4.18.2"},{"name":"not-a-version"},{"name":"v4.10.0-rc1"}]';

function has(list, v) {
	for (let x in list)
		if (x == v)
			return true;
	return false;
}

// ── both sources answer ──────────────────────────────────────────────────
reset();
answer('versions.yml', 200, YML);
answer('tags', 200, TAGS);
let r = api.client_versions();
check('both sources answering is not an error', !r.error);
check('the current release comes from the first versions.yml document',
	r.current == 'linux-vpn-gtk@4.18.2');
check('the released versions come from the repository tags',
	has(r.versions, 'linux-vpn-gtk@4.17.0') && has(r.versions, 'linux-vpn-gtk@4.9.0'));
check('the newest version is offered first',
	r.versions[0] == 'linux-vpn-gtk@4.18.2');
// 4.9.0 is listed first upstream and sorts LAST by number, and a string
// comparison would put it above 4.17.0 — so this fails for an unsorted list
// and for a lexicographic one alike.
check('versions are ordered by number, not by the order upstream listed them',
	index(r.versions, 'linux-vpn-gtk@4.10.0') < 0 &&
	index(r.versions, 'linux-vpn-gtk@4.17.0') <
		index(r.versions, 'linux-vpn-gtk@4.9.0'));
check('the oldest version is offered last',
	r.versions[length(r.versions) - 1] == 'linux-vpn-gtk@4.9.0');
check('a duplicate tag is offered once',
	length(filter(r.versions, function (v) { return v == 'linux-vpn-gtk@4.18.2'; })) == 1);
check('a tag that is not a plain version is dropped',
	!has(r.versions, 'linux-vpn-gtk@not-a-version') &&
	!has(r.versions, 'linux-vpn-gtk@4.10.0-rc1'));

// Everything offered must be a value app_version() would actually accept —
// an entry the user can pick and that is then ignored is worse than no list.
let all_valid = true;
for (let v in r.versions)
	if (!match(v, /^linux-vpn-[a-z0-9-]+@[0-9]+\.[0-9]+\.[0-9]+$/))
		all_valid = false;
check('every offered value is one app_version() accepts', all_valid);

// ── it offers, it never decides ──────────────────────────────────────────
global.MOCK_UCI = { protonvpn: { main: { '.type': 'instance', '.name': 'main' } } };
let before = api.app_version();
reset();
answer('versions.yml', 200, YML);
answer('tags', 200, TAGS);
api.client_versions();
check('fetching the list does not change the stamped version',
	api.app_version() == before);
check('fetching the list writes nothing into uci',
	global.MOCK_UCI.protonvpn.main.app_version == null &&
	global.MOCK_UCI.protonvpn.globals == null);

// The user has to be able to see what is set right now to judge the list.
reset();
answer('versions.yml', 200, YML);
answer('tags', 200, TAGS);
r = api.client_versions();
check('the reply says which version is stamped today',
	r.configured == api.app_version());

// ── a source that does not answer ────────────────────────────────────────
reset();
answer('versions.yml', 200, YML);
// tags unreachable: curl cannot connect.
r = api.client_versions();
check('an unreachable tags endpoint is reported, not hidden',
	r.error != null && r.error != '');
check('the current release still survives a failed tags fetch',
	r.current == 'linux-vpn-gtk@4.18.2');

reset();
answer('tags', 200, TAGS);
r = api.client_versions();
check('an unreachable versions.yml is reported', r.error != null && r.error != '');
check('the list still survives a failed versions.yml fetch',
	has(r.versions, 'linux-vpn-gtk@4.17.0'));
check('no current release is invented when versions.yml did not answer',
	!r.current);

reset();
r = api.client_versions();
check('both sources failing is reported as a failure',
	r.error != null && r.error != '');
check('both sources failing offers nothing rather than something made up',
	length(r.versions) == 0 && !r.current);

// An HTTP error is as much a failure as an unreachable host.
reset();
answer('versions.yml', 500, 'oops');
answer('tags', 403, '{"message":"API rate limit exceeded"}');
r = api.client_versions();
check('an HTTP error from both sources is a failure',
	r.error != null && length(r.versions) == 0 && !r.current);

// And an error body that happens to parse is still an error body: a proxy,
// a captive portal or a rate-limit page can return anything, and reading it
// as an answer would offer the user versions nobody published.
reset();
answer('versions.yml', 500, 'version: 9.9.9\n');
answer('tags', 500, TAGS);
r = api.client_versions();
check('a parseable body behind an HTTP error is not read as the version list',
	length(r.versions) == 0);
check('a parseable body behind an HTTP error names no current release',
	!r.current);
check('a parseable body behind an HTTP error is still reported as a failure',
	r.error != null);

// ── versions.yml shapes that must not be guessed at ──────────────────────
reset();
answer('tags', 200, TAGS);
answer('versions.yml', 200, 'version: 4.18.2\nversion: 9.9.9\n---\nversion: 1.0.0\n');
r = api.client_versions();
check('two version keys in the first document name no current release',
	!r.current && r.error != null);

reset();
answer('tags', 200, TAGS);
answer('versions.yml', 200, '---\nversion: 2.2.2\n');
r = api.client_versions();
check('only the first document is read for the current release', !r.current);

reset();
answer('tags', 200, TAGS);
answer('versions.yml', 200, 'version: 4.18.2beta\n');
r = api.client_versions();
check('a version that is not X.Y.Z is not accepted', !r.current);

// Upstream ships a release before it tags it; that value is the one most
// users want, so it belongs in the list even when no tag carries it yet.
reset();
answer('versions.yml', 200, 'version: 5.1.0\n');
answer('tags', 200, TAGS);
r = api.client_versions();
check('the current release is offered even when no tag carries it yet',
	r.current == 'linux-vpn-gtk@5.1.0' && has(r.versions, 'linux-vpn-gtk@5.1.0'));

// ── the rpcd surface ─────────────────────────────────────────────────────
// A backend function the page cannot call is not a feature.
let rpcd_src = open(RPCD, 'r').read('all');
check('rpcd exposes client_versions under that name',
	index(rpcd_src, 'methods.client_versions = {') >= 0);
check('the exposed method is the one in protonvpn.api',
	index(rpcd_src, '_api.client_versions()') >= 0);

reset();
rmdir(dir);
exit(ok ? 0 : 1);

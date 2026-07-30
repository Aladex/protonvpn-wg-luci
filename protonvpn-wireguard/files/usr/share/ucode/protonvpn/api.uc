// SPDX-License-Identifier: MIT
// ProtonVPN API client: SRP-6a login relay, session refresh, TOTP 2FA and
// WireGuard certificate registration. This module owns every authenticated
// HTTP call to api.protonvpn.ch.
//
// Design (see RECON.md): SRP needs 2048-bit modexp, which ucode cannot do —
// so the browser computes the SRP proof (native BigInt in LuCI JS) and rpcd
// only relays the HTTP steps:
//
//   1. rpcd  POST /auth/info (username)        -> SRP params to the browser
//   2. JS    computes clientEphemeral+proof    (password never leaves it)
//   3. rpcd  POST /auth (proof)                -> session tokens
//   4. rpcd  POST /2fa/totp (optional 2FA step)
//
// The session (UID/AccessToken/RefreshToken) lives 30 days; the daemon
// refreshes it via POST /auth/refresh (the refresh token rotates). Re-login
// (SRP, manual) is only needed after >30 days offline. Session state is kept
// in a root-only state file (0600), NEVER in UCI.

'use strict';

import { open, stat, chmod, unlink, mkdir, pipe, readfile, popen } from 'fs';
const _common = require('protonvpn.common');
const API_BASE = _common.API_BASE,
      open_cmd = _common.open_cmd,
      run = _common.run,
      atomic_write = _common.atomic_write,
      log = _common.log,
      sh_quote = _common.sh_quote,
      SESSION_MAX_AGE = _common.SESSION_MAX_AGE,
      CERT_MAX_DAYS = _common.CERT_MAX_DAYS,
      CERT_SESSION_DAYS = _common.CERT_SESSION_DAYS;

// ── Constants ────────────────────────────────────────────────────────────

// REQUIRED on every request: Proton rejects outdated app versions with HTTP
// 422 / error Code 5003 ("app version outdated"). Community tooling stamps
// the version of the current official Linux client; when the API starts
// rejecting this constant it must be bumped (checked live 2026-07-30).
const PM_APPVERSION = 'linux-vpn@4.9.0';

const AUTH_INFO_URL = API_BASE + '/auth/info';
const AUTH_URL = API_BASE + '/auth';
const AUTH_REFRESH_URL = API_BASE + '/auth/refresh';
// Verified live 2026-07-30: /auth/2fa answers 8002 for a wrong code (the path
// exists); the versioned /auth/v4/2fa is an alias. A wrong path returns 404.
const TOTP_URL = API_BASE + '/auth/2fa';
const LOGICALS_URL = _common.LOGICALS_URL;
const CERT_URL = _common.CERT_URL;

// Session state file: UID, AccessToken, RefreshToken, expiry, scope.
// Root-only (0600), outside UCI on purpose — UCI diffs/backups must not
// carry bearer tokens.
//
// PROTONVPN_STATE_DIR relocates it for the offline test suite, which cannot
// write under /etc. Production never sets it; anyone who could would already
// be root on the router.
const SESSION_DIR = getenv('PROTONVPN_STATE_DIR') || '/etc/protonvpn';
const SESSION_FILE = SESSION_DIR + '/session.json';

// Access token TTL fallback when the API omits ExpiresIn. Measured live: the
// API returns 1800s. The session (refresh token) horizon is SESSION_MAX_AGE.
const ACCESS_TOKEN_TTL = 1800;
// Refresh this long before the access token expires, so a slow tick or a brief
// WAN outage cannot leave us with a dead token.
const ACCESS_REFRESH_MARGIN = 300;

// Page size for the certificate listing; Proton accepts up to 50.
const CERT_PAGE_SIZE = 50;

const CONNECT_TIMEOUT = 15;
const TOTAL_TIMEOUT = 60;

// ── HTTP plumbing ────────────────────────────────────────────────────────

// One HTTP call to the Proton API. Secrets (bearer token) are never passed in
// argv — they would show up in `ps` — but written into an anonymous pipe that
// curl reads as a config file. The request body travels the same way, so a
// password-adjacent proof never lands on disk either.
//
// Returns { code: <http status>, data: <parsed json or null>, raw: <body> }.
// `code` is 0 when curl itself could not run.
function api_call(opts) {
	let p = pipe();
	if (!p)
		return { code: 0, data: null, raw: '', error: 'failed to create config pipe' };
	let r = p[0], w = p[1];
	let rfd = r.fileno();

	// The body goes through a SECOND pipe, referenced as a file. curl unescapes
	// backslash sequences inside quoted config values, so an inline body would
	// have its JSON \n mangled — a PEM key made the API answer 6001. Passing it
	// as a file removes the whole escaping problem.
	let bp = null, br = null, bw = null;
	if (opts.body != null) {
		bp = pipe();
		if (!bp) {
			r.close();
			return { code: 0, data: null, raw: '', error: 'failed to create body pipe' };
		}
		br = bp[0];
		bw = bp[1];
	}

	let conf = '';
	conf += 'header = "x-pm-appversion: ' + PM_APPVERSION + '"\n';
	conf += 'header = "Accept: application/vnd.protonmail.v1+json"\n';
	if (opts.token && opts.uid) {
		conf += 'header = "x-pm-uid: ' + opts.uid + '"\n';
		conf += 'header = "Authorization: Bearer ' + opts.token + '"\n';
	}
	if (opts.body != null) {
		conf += 'header = "Content-Type: application/json"\n';
		conf += 'data-binary = "@/proc/self/fd/' + br.fileno() + '"\n';
	}
	if (opts.method)
		conf += 'request = "' + opts.method + '"\n';
	w.write(conf);
	w.close();

	if (bw) {
		// Bodies here are small (proofs, a PEM key), so the pipe buffer holds
		// them and curl never blocks waiting for a writer.
		bw.write(sprintf('%J', opts.body));
		bw.close();
	}

	// -w appends the status code on its own last line; --fail is deliberately
	// NOT used so error bodies (Proton's Code/Error JSON) stay readable.
	//
	// out_file streams the body straight to disk instead of through this pipe.
	// /vpn/logicals is ~13 MB: pulling that through ucode meant O(n^2) string
	// concatenation (20+ seconds of CPU) and, once the read loop hit its cap,
	// curl died with "Failure writing output" because nothing drained the pipe.
	let argv = [
		'curl', '-g', '-s', '-S',
		'--connect-timeout', '' + CONNECT_TIMEOUT,
		'--max-time', '' + (opts.timeout || TOTAL_TIMEOUT),
		'-w', opts.out_file ? '%{http_code}' : '\n%{http_code}',
		'--config', '/proc/self/fd/' + rfd
	];
	if (opts.out_file)
		push(argv, '-o', opts.out_file);
	push(argv, opts.url);
	let proc = open_cmd(argv, 'r');
	if (!proc) {
		r.close();
		if (br) br.close();
		return { code: 0, data: null, raw: '', error: 'failed to start curl' };
	}
	// Collect chunks and join once: repeated string concatenation is quadratic.
	let chunks = [];
	while (true) {
		let chunk = proc.read(65536);
		if (chunk == null || chunk == '')
			break;
		push(chunks, chunk);
	}
	let out = join('', chunks);
	proc.close();
	r.close();
	if (br)
		br.close();

	// With out_file the body is on disk and stdout holds just the status code.
	if (opts.out_file)
		return { code: +trim(out) || 0, data: null, raw: '', file: opts.out_file };

	// Split the trailing status line back off the body.
	let nl = 0;
	for (let i = length(out) - 1; i >= 0; i--) {
		if (substr(out, i, 1) == '\n') {
			nl = i;
			break;
		}
	}
	let body = nl ? substr(out, 0, nl) : '';
	let status = +trim(nl ? substr(out, nl + 1) : out) || 0;

	let data = null;
	try {
		data = json(body);
	} catch (e) {
		data = null;
	}
	return { code: status, data: data, raw: body };
}

// Turn a Proton error response into one readable message. Code 5003 means the
// stamped client version is too old and PM_APPVERSION needs bumping.
function api_error(res) {
	if (res.error)
		return res.error;
	let d = res.data;
	if (d && d.Code == 5003)
		return 'Proton rejected the client version (Code 5003) — PM_APPVERSION needs updating';
	// Anti-abuse gate: Proton demands a CAPTCHA, which cannot be solved from
	// LuCI. Seen after several login attempts in quick succession from one IP.
	// Retrying immediately makes it worse; the message tells the user what to do.
	if (d && d.Code == 9001)
		return 'Proton requires a CAPTCHA for this login (Code 9001). ' +
			'Wait a while before retrying — repeated attempts prolong it. ' +
			'An existing session keeps working; if you have none, sign in with an ' +
			'official Proton client once and import that session (see README).';
	if (d && d.Code == 8002)
		return 'Wrong or already-used two-factor code (Code 8002)';
	if (d && d.Error)
		return d.Error + ' (Code ' + (d.Code || '?') + ', HTTP ' + res.code + ')';
	return 'HTTP ' + res.code;
}

// ── Session state ────────────────────────────────────────────────────────

// Load the persisted session. Returns { uid, access_token, refresh_token,
// expires_at, scope, twofa } or null when missing/malformed.
function session_load() {
	let raw = readfile(SESSION_FILE);
	if (!raw)
		return null;
	let s;
	try {
		s = json(raw);
	} catch (e) {
		return null;
	}
	if (type(s) != 'object' || !s.uid || !s.access_token || !s.refresh_token)
		return null;
	// Migrate the single `expires_at` written before access and session
	// horizons were split apart.
	if (s.access_expires_at == null) {
		s.access_expires_at = s.expires_at || 0;
		s.session_expires_at = s.session_expires_at || s.expires_at || 0;
	}
	return s;
}

// Persist the session atomically with 0600 permissions. `session` is the
// object described above; null deletes the state file (logout).
function session_store(session) {
	if (session == null) {
		unlink(SESSION_FILE);
		return true;
	}
	if (!stat(SESSION_DIR))
		mkdir(SESSION_DIR, 0o700);
	if (!atomic_write(SESSION_FILE, sprintf('%J', session)))
		return false;
	// Tokens are bearer credentials: keep them root-only.
	chmod(SESSION_FILE, 0o600);
	return true;
}

// Authorization headers for an authenticated call, from session_load().
// Returns a curl-ready header list or null when there is no live session.
function auth_headers() {
	let s = session_load();
	if (!s)
		return null;
	return [
		'x-pm-appversion: ' + PM_APPVERSION,
		'x-pm-uid: ' + s.uid,
		'Authorization: Bearer ' + s.access_token
	];
}

// ── SRP login relay (step 1 and 3; step 2 happens in the browser) ────────

// SRP step 1: POST /auth/info { Username } -> SRP parameters for the
// browser: { Modulus (PGP-signed), ServerEphemeral, Salt, SRPSession,
// Version }. The browser derives the client proof from these with BigInt.
// NOTE: optionally verify the PGP signature on Modulus, or pin a known
// modulus (see RECON.md "Верификация PGP-подписи modulus").
function auth_info(username) {
	if (!username || length(username) > 128)
		return { error: 'invalid username' };

	let res = api_call({ url: AUTH_INFO_URL, body: { Username: username } });
	if (res.code != 200)
		return { error: api_error(res) };
	let d = res.data;
	if (!d || !d.Modulus || !d.ServerEphemeral || !d.SRPSession)
		return { error: 'incomplete SRP parameters in the /auth/info response' };

	// Modulus is a PGP clear-signed message; the browser strips the armor and
	// validates the group mathematically (2048-bit safe prime, 3 mod 8, Lucas).
	return {
		modulus: d.Modulus,
		server_ephemeral: d.ServerEphemeral,
		salt: d.Salt || '',
		srp_session: d.SRPSession,
		version: d.Version != null ? d.Version : 4
	};
}

// SRP step 3: POST /auth { Username, SRPSession, ClientEphemeral,
// ClientProof } -> session: { UID, AccessToken, RefreshToken, ExpiresIn,
// Scope }. Persists via session_store(). When the account has 2FA enabled
// the scope is limited and totp_submit() must follow.
function auth_finish(proof) {
	if (!proof || !proof.username || !proof.srp_session ||
	    !proof.client_ephemeral || !proof.client_proof)
		return { error: 'incomplete SRP proof' };

	let res = api_call({ url: AUTH_URL, body: {
		Username: proof.username,
		SRPSession: proof.srp_session,
		ClientEphemeral: proof.client_ephemeral,
		ClientProof: proof.client_proof
	} });
	if (res.code != 200)
		return { error: api_error(res) };
	let d = res.data;
	if (!d || !d.UID || !d.AccessToken || !d.RefreshToken)
		return { error: 'incomplete session in the /auth response' };

	// A non-zero 2FA field means the scope is limited until totp_submit().
	let twofa = false;
	if (d['2FA'] && d['2FA'].Enabled)
		twofa = true;
	else if (d.TwoFactor)
		twofa = true;

	// Two horizons, and conflating them is a bug: ExpiresIn is the ACCESS token
	// TTL — measured live at 1800s (30 minutes) — while the refresh token, and
	// therefore the session, lasts ~30 days. Treating ExpiresIn as the session
	// lifetime would tell the user to log in again every half hour.
	let now = time();
	let session = {
		uid: d.UID,
		access_token: d.AccessToken,
		refresh_token: d.RefreshToken,
		access_expires_at: now + (d.ExpiresIn || ACCESS_TOKEN_TTL),
		session_expires_at: now + SESSION_MAX_AGE,
		scope: d.Scope || '',
		twofa: twofa,
		created_at: now
	};
	if (!session_store(session))
		return { error: 'could not persist the session' };

	log('logged in' + (twofa ? ' (2FA code still required)' : ''));
	// ServerProof goes back to the browser, which checks it against what it
	// derived — that is how we authenticate the server, so never drop it.
	return { ok: true, twofa: twofa, server_proof: d.ServerProof || '' };
}

// Submit a TOTP 2FA code after auth_finish() returned a limited scope.
// Upgrades the session to the full scope.
function totp_submit(code) {
	let s = session_load();
	if (!s)
		return { error: 'no session; log in first' };
	if (!code || !match('' + code, /^[0-9]{6,8}$/))
		return { error: 'invalid TOTP code' };

	let res = api_call({ url: TOTP_URL, uid: s.uid, token: s.access_token,
		body: { TwoFactorCode: '' + code } });
	if (res.code != 200)
		return { error: api_error(res) };

	// Scope is upgraded server-side; reflect that locally so the UI stops
	// asking. The wrong-code path leaves the session alone on purpose, so the
	// user can retype the code without redoing SRP.
	s.twofa = false;
	if (res.data && res.data.Scope)
		s.scope = res.data.Scope;
	session_store(s);
	return { ok: true };
}

// ── Session maintenance ──────────────────────────────────────────────────

// POST /auth/refresh { RefreshToken, UID } -> rotated token pair. The
// refresh token is single-use: always persist the rotated pair on success.
// Called by the daemon (should_refresh_session) and by any API call that
// met a 401.
function auth_refresh() {
	let s = session_load();
	if (!s)
		return { error: 'no session to refresh' };

	let res = api_call({ url: AUTH_REFRESH_URL, uid: s.uid, token: s.access_token,
		body: { UID: s.uid, RefreshToken: s.refresh_token, ResponseType: 'token',
			GrantType: 'refresh_token', RedirectURI: 'http://protonmail.ch' } });

	// Only a definitive authentication refusal kills the session. Network
	// trouble (code 0) or a 5xx must NOT log the user out — see the watchdog
	// lesson: a dead WAN is not a dead credential.
	if (res.code == 400 || res.code == 401 || res.code == 422) {
		session_store(null);
		return { error: api_error(res), expired: true };
	}
	if (res.code != 200)
		return { error: api_error(res) };

	let d = res.data;
	if (!d || !d.AccessToken || !d.RefreshToken)
		return { error: 'incomplete refresh response' };

	// The refresh token is single-use: persist the rotated pair or the next
	// refresh fails permanently.
	let now = time();
	s.access_token = d.AccessToken;
	s.refresh_token = d.RefreshToken;
	s.uid = d.UID || s.uid;
	s.access_expires_at = now + (d.ExpiresIn || ACCESS_TOKEN_TTL);
	// A fresh refresh token was issued, so the 30-day horizon starts over.
	s.session_expires_at = now + SESSION_MAX_AGE;
	if (d.Scope)
		s.scope = d.Scope;
	if (!session_store(s))
		return { error: 'could not persist the refreshed session' };
	return { ok: true };
}

// Forget the session locally (optionally best-effort revoke server-side).
function logout() {
	let s = session_load();
	if (s)
		// Best effort: a failure here still drops the local session.
		api_call({ url: AUTH_URL, method: 'DELETE', uid: s.uid, token: s.access_token });
	session_store(null);
	return { ok: true };
}

// ── WireGuard certificate registration ───────────────────────────────────

// POST /vpn/v1/certificate { ClientPublicKey, Mode, Duration }: register a
// locally generated WireGuard public key. `mode` is 'persistent' (named,
// visible in the Proton dashboard, up to CERT_MAX_DAYS days) or 'session'
// (up to CERT_SESSION_DAYS days). The certificate is account-wide: one key
// works on ANY server, only the peer pubkey/endpoint changes per server.
// Derive the WireGuard private key from an Ed25519 seed.
//
// Proton stores the Ed25519 public key we register and derives the X25519 peer
// key it expects with the birational Edwards->Montgomery map. That map matches
// the Ed25519 *expanded scalar*, SHA-512(seed)[0:32] — NOT the seed itself.
// Handing the raw seed to WireGuard produces a tunnel that looks healthy (the
// handshake completes, 10.2.0.1 answers ICMP) but is never authorised: nothing
// is forwarded and /vpn/v1/sessions reports zero sessions. Verified live.
//
// The scalar is left unclamped on purpose: both `wg pubkey` and the kernel
// clamp a private key on use, so storing it verbatim round-trips exactly.
//
// Returns { wg_private } or { error }.
function wg_key_from_seed(seed_b64) {
	if (!seed_b64 || length(seed_b64) != 44)
		return { error: 'invalid key seed' };
	let script =
		'printf %s "$1" | openssl enc -base64 -d -A | ' +
		'openssl dgst -sha512 -binary | head -c 32 | openssl enc -base64 -A';
	let proc = popen('sh -c ' + sh_quote(script) + ' sh ' + sh_quote(seed_b64), 'r');
	if (!proc)
		return { error: 'could not run openssl' };
	let out = trim(proc.read('all') || '');
	let code = proc.close();
	if (code != 0 || length(out) != 44)
		return { error: 'could not derive the WireGuard key from the Ed25519 seed' };
	return { wg_private: out };
}

// Generate the client keypair locally. Verified live: Proton wants an Ed25519
// SPKI in PEM (OID 1.3.101.112) — a raw WireGuard key is rejected with
// 400/Code 2001. The 32-byte seed is the tail of the 48-byte PKCS#8 DER; the
// WireGuard key is derived from it by wg_key_from_seed() above. Proton also
// offers to generate the pair server-side, which we deliberately do NOT use: it
// would hand our private key to the API. Requires openssl-util (Ed25519 support
// verified on OpenWrt's OpenSSL 3.0).
//
// Returns { pem_public, key_seed, wg_private, wg_public } or { error }.
function generate_keypair() {
	// The private material moves through pipes and a 0600 temp file, never
	// through argv. busybox has no base64(1), hence `openssl enc`.
	let script =
		'umask 077; t=$(mktemp) || exit 1; ' +
		'openssl genpkey -algorithm ED25519 -out "$t" 2>/dev/null || { rm -f "$t"; exit 1; }; ' +
		'echo "---PEM---"; openssl pkey -in "$t" -pubout 2>/dev/null; ' +
		'echo "---SEED---"; ' +
		'openssl pkey -in "$t" -outform DER 2>/dev/null | tail -c 32 | openssl enc -base64 -A; ' +
		'echo; rm -f "$t"';
	let proc = popen(script, 'r');
	if (!proc)
		return { error: 'could not run openssl' };
	let out = proc.read('all') || '';
	let code = proc.close();
	if (code != 0)
		return { error: 'openssl failed to generate an Ed25519 key (is openssl-util installed?)' };

	let parts = split(out, '---SEED---');
	if (length(parts) != 2)
		return { error: 'unexpected openssl output' };
	let pem = trim(replace(parts[0], '---PEM---', ''));
	let seed = trim(parts[1]);
	if (!match(pem, /^-----BEGIN PUBLIC KEY-----/) || !length(seed))
		return { error: 'could not read the generated key' };

	let derived = wg_key_from_seed(seed);
	if (derived.error)
		return derived;

	// The matching WireGuard public key is informational: netifd derives it
	// from the private key, and Proton derives it from the Ed25519 key we
	// registered. Report it when wireguard-tools is around, but never fail the
	// generation over it — the key itself is already complete.
	let pub = run([ 'sh', '-c',
		'echo ' + sh_quote(derived.wg_private) + ' | wg pubkey 2>/dev/null' ]);
	let wg_public = trim(pub.stdout || '');

	return { pem_public: pem, key_seed: seed, wg_private: derived.wg_private,
		wg_public: length(wg_public) ? wg_public : null };
}

// Rebuild the Ed25519 public key PEM from the stored 32-byte seed (the value
// we keep as the WireGuard private key). Renewal must re-register the SAME
// key, otherwise the tunnel would have to be torn down and reapplied. The
// PKCS#8 wrapper is fixed for Ed25519, so prefixing the seed with it and
// asking openssl for the public half round-trips exactly (verified).
function pem_from_seed(seed_b64) {
	if (!seed_b64 || length(seed_b64) != 44)
		return { error: 'invalid key seed' };
	let script =
		'umask 077; t=$(mktemp) || exit 1; ' +
		// 302e020100300506032b657004220420 = PKCS#8 header for an Ed25519 key,
		// spelled in octal because busybox has neither xxd nor `printf \xNN`.
		'printf "\\060\\056\\002\\001\\000\\060\\005\\006\\003\\053\\145\\160\\004\\042\\004\\040" > "$t"; ' +
		'printf %s "$1" | openssl enc -base64 -d -A >> "$t"; ' +
		'openssl pkey -inform DER -in "$t" -pubout 2>/dev/null; rm -f "$t"';
	let proc = popen('sh -c ' + sh_quote(script) + ' sh ' + sh_quote(seed_b64), 'r');
	if (!proc)
		return { error: 'could not run openssl' };
	let out = proc.read('all') || '';
	let code = proc.close();
	let pem = trim(out);
	if (code != 0 || !match(pem, /^-----BEGIN PUBLIC KEY-----/))
		return { error: 'could not rebuild the public key from the stored seed' };
	return { pem_public: pem };
}

// Request body for /vpn/v1/certificate. Split out from the call below so the
// exact shape can be asserted offline — every field here was learned the hard
// way against the live API.
//
// ClientPublicKeyMode/Features mirror what Proton's own clients send: with
// Features omitted the API echoes back an empty array instead of the settings
// object. NetShield stays off — it is a DNS-level filter we do not expose yet;
// RandomNAT=true is Proton's inverted flag for "no Moderate NAT"; SplitTCP is
// the VPN Accelerator. `renew` re-registers a key the account already carries:
// without it the API answers 409/Code 2500 ("ClientPublicKey conflict"), which
// is what every renewal of a still-registered key would hit.
//
// Session certificates are capped much lower than persistent ones, and a
// persistent one shows up in the Proton dashboard under DeviceName.
function certificate_body(pubkey, mode, days, renew, duration) {
	let want = (mode == 'persistent') ? 'persistent' : 'session';
	let cap = (want == 'persistent') ? CERT_MAX_DAYS : CERT_SESSION_DAYS;
	let d = +days || cap;
	if (d < 1)
		d = 1;
	if (d > cap)
		d = cap;

	let body = {
		ClientPublicKey: pubkey,
		ClientPublicKeyMode: 'EC',
		Duration: duration ? duration : ('' + d + ' days'),
		Features: { NetShieldLevel: 0, RandomNAT: true,
			PortForwarding: false, SplitTCP: true }
	};
	if (want == 'persistent') {
		body.Mode = 'persistent';
		body.DeviceName = 'OpenWrt';
	}
	if (renew)
		body.Renew = true;
	return body;
}

function certificate_create(pubkey, mode, days, renew, duration) {
	let s = session_load();
	if (!s)
		return { error: 'not logged in' };
	if (!pubkey || !match(pubkey, /^-----BEGIN PUBLIC KEY-----/))
		return { error: 'certificate needs a PEM Ed25519 public key' };

	let want = (mode == 'persistent') ? 'persistent' : 'session';
	let body = certificate_body(pubkey, mode, days, renew, duration);

	let res = api_call({ url: CERT_URL, uid: s.uid, token: s.access_token, body: body });
	if (res.code == 401) {
		let rf = auth_refresh();
		if (!rf.ok)
			return { error: rf.error || 'session expired' };
		s = session_load();
		res = api_call({ url: CERT_URL, uid: s.uid, token: s.access_token, body: body });
	}
	if (res.code != 200)
		return { error: api_error(res) };

	let dd = res.data;
	if (!dd || !dd.SerialNumber)
		return { error: 'unexpected certificate response' };
	// RefreshTime is Proton telling us when to renew — prefer it over guessing
	// a threshold from ExpirationTime.
	return {
		ok: true,
		serial: '' + dd.SerialNumber,
		mode: dd.Mode || want,
		expires_at: +dd.ExpirationTime || 0,
		refresh_at: +dd.RefreshTime || 0,
		server_public_key: dd.ServerPublicKey || '',
		fingerprint: dd.ClientKeyFingerprint || ''
	};
}

// GET /vpn/v1/certificate/all: the certificates registered on the account,
// newest page first, walked through with BeginID. For WireGuard this is the
// only honest measure of how much of the plan's device allowance is spoken for
// — /vpn/v1/sessions counts the legacy OpenVPN/IKEv2 sessions and stays empty
// no matter how many tunnels are up (verified live with 4.7 MB flowing).
//
// Returns { ok: true, certificates: [ { serial, device_name, expires_at } ] }.
function certificate_list(mode) {
	let s = session_load();
	if (!s)
		return { error: 'not logged in' };
	let want = (mode == 'session') ? 'session' : 'persistent';
	let out = [];
	let begin = '';
	// Bounded: an account cannot hold enough certificates to need more, and an
	// API that never shrinks a page must not spin us forever.
	for (let page = 0; page < 20; page++) {
		let url = CERT_URL + '/all?Mode=' + want + '&Limit=' + CERT_PAGE_SIZE;
		if (length(begin))
			url += '&BeginID=' + begin;
		let res = api_call({ url: url, uid: s.uid, token: s.access_token });
		if (res.code == 401) {
			let rf = auth_refresh();
			if (!rf.ok)
				return { error: rf.error || 'session expired' };
			s = session_load();
			res = api_call({ url: url, uid: s.uid, token: s.access_token });
		}
		if (res.code != 200)
			return { error: api_error(res) };
		let list = (res.data && type(res.data.Certificates) == 'array')
			? res.data.Certificates : [];
		for (let c in list)
			push(out, {
				serial: '' + (c.SerialNumber || ''),
				device_name: c.DeviceName || '',
				expires_at: +c.ExpirationTime || 0,
				// The PEM public key comes back with every entry, and a
				// tombstone needs nothing else — so any certificate on the
				// account can be retired, including ones this router never
				// created and has no seed for.
				client_key: c.ClientKey || ''
			});
		if (length(list) < CERT_PAGE_SIZE)
			break;
		begin = out[length(out) - 1].serial;
	}
	return { ok: true, certificates: out };
}

// Shrink a registration we are done with down to the shortest life the API
// grants, so it drops off the account on its own.
//
// This is the way out of the revocation dead end below: we cannot DELETE, but
// we CAN renew, and a renewal supersedes the previous registration for the same
// key. Renewing a doomed certificate to ten minutes turns "squats a device slot
// for a year" into "gone before anyone notices". Verified live.
const CERT_MIN_DURATION = '10 minutes';

function certificate_tombstone(pubkey) {
	return certificate_create(pubkey, 'persistent', 1, true, CERT_MIN_DURATION);
}

// DELETE /vpn/v1/certificate: revoke a registered certificate by serial.
//
// Verified live: this ALWAYS fails with 403/Code 9100 ("the access token has
// no access") for the VPN scope — session-mode and persistent alike, and no
// URL shape helps (a path segment is a plain 404). Only a full web session on
// account.protonvpn.com can revoke. The call is kept because the scope may
// widen, but callers must treat `skipped` as "this certificate will sit on the
// account until it expires", not as "cleaned up".
function certificate_delete(id) {
	let s = session_load();
	if (!s)
		return { error: 'not logged in' };
	let res = api_call({ url: CERT_URL, method: 'DELETE', uid: s.uid,
		token: s.access_token, body: { SerialNumber: '' + (id || '') } });
	if (res.code == 200)
		return { ok: true };
	if (res.code == 403)
		return { ok: false, skipped: true,
			reason: 'the VPN scope cannot revoke certificates; this one stays on the account until it expires' };
	return { error: api_error(res) };
}

// True when the access token is expired or about to be, i.e. the daemon should
// call auth_refresh() on this tick. Not a user-facing condition.
function access_token_stale(session, now) {
	let s = session || session_load();
	if (!s)
		return false;
	return (s.access_expires_at || 0) - (now || time()) <= ACCESS_REFRESH_MARGIN;
}

return {
	PM_APPVERSION, SESSION_FILE, ACCESS_TOKEN_TTL, ACCESS_REFRESH_MARGIN,
	api_call, api_error, auth_headers, access_token_stale,
	generate_keypair, pem_from_seed, wg_key_from_seed,
	session_load, session_store,
	auth_info, auth_finish, totp_submit, auth_refresh, logout,
	certificate_body, certificate_create, certificate_delete, certificate_list,
	certificate_tombstone
};

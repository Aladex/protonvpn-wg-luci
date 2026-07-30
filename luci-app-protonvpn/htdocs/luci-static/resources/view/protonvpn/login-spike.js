// SPDX-License-Identifier: MIT
// Throwaway page that exercises one thing: the browser-side SRP login relayed
// through rpcd. It exists to validate the architecture before the real UI is
// built, and should be deleted once overview.js owns the login modal.
//
// The form is a stepper on purpose: only what the user must fill in right now
// is on screen, with a single primary button per step. Asking for a TOTP code
// up front is misleading — most accounts do not need one, and the API only
// tells us after the password step. Every step is also logged so a failure
// points at a specific layer (rpcd relay, Proton API, SRP maths, proof check).

'use strict';
'require view';
'require rpc';
'require ui';
'require dom';

var callSessionState = rpc.declare({ object: 'protonvpn', method: 'session_state' });
var callAuthInfo = rpc.declare({
	object: 'protonvpn', method: 'auth_info', params: [ 'username' ]
});
var callAuthFinish = rpc.declare({
	object: 'protonvpn', method: 'auth_finish',
	params: [ 'username', 'srp_session', 'client_ephemeral', 'client_proof' ]
});
var callSetTotp = rpc.declare({ object: 'protonvpn', method: 'set_totp', params: [ 'code' ] });
var callRefreshSession = rpc.declare({ object: 'protonvpn', method: 'refresh_session' });
var callLogout = rpc.declare({ object: 'protonvpn', method: 'logout' });
var callLocations = rpc.declare({ object: 'protonvpn', method: 'locations' });
var callServers = rpc.declare({
	object: 'protonvpn', method: 'servers', params: [ 'locations', 'hop_mode' ]
});
var callRefreshLocations = rpc.declare({ object: 'protonvpn', method: 'refresh_locations' });

// Proton sends country CODES only, so let the browser localize them instead of
// shipping a 148-entry table on the router.
var countryNames = null;
function countryName(code) {
	if (countryNames === null) {
		try {
			countryNames = new Intl.DisplayNames([ navigator.language || 'en' ], { type: 'region' });
		} catch (e) {
			countryNames = false;
		}
	}
	var cc = String(code || '').toUpperCase();
	if (!countryNames)
		return cc;
	try {
		return countryNames.of(cc) || cc;
	} catch (e) {
		return cc;
	}
}

var STYLE =
	'.pv-card{max-width:34em;padding:1.2em;border:1px solid var(--border-color-medium,#444);' +
	'border-radius:6px;margin-bottom:1em}' +
	'.pv-field{margin-bottom:.9em}' +
	'.pv-field label{display:block;margin-bottom:.3em;font-weight:bold}' +
	'.pv-field input{width:100%;box-sizing:border-box}' +
	'.pv-hint{font-size:90%;opacity:.75;margin-top:.25em}' +
	'.pv-err{color:#c0392b;margin-bottom:.8em;font-weight:bold}' +
	'.pv-who{opacity:.8;margin-bottom:.9em}' +
	'.pv-actions{display:flex;gap:.6em;align-items:center;flex-wrap:wrap}' +
	'.pv-state{margin-bottom:1em}' +
	'.pv-srv{width:100%;border-collapse:collapse;font-size:92%}' +
	'.pv-srv th,.pv-srv td{text-align:left;padding:.25em .5em;border-bottom:1px solid var(--border-color-low,#333)}' +
	'.pv-srv td.num{text-align:right;font-variant-numeric:tabular-nums}' +
	'.pv-dot{display:inline-block;width:.62em;height:.62em;border-radius:50%;margin-right:.4em}' +
	'.pv-lo{background:#3c8c3c}.pv-mid{background:#c79100}.pv-hi{background:#c0392b}' +
	'.pv-tag{font-size:85%;padding:.05em .4em;border-radius:3px;margin-left:.4em;' +
	'border:1px solid var(--border-color-medium,#555);opacity:.85}' +
	'.pv-scroll{max-height:20em;overflow:auto;margin-top:.6em}' +
	'.pv-log{font-family:monospace;font-size:12px;white-space:pre-wrap;' +
	'background:var(--background-color-medium,#2b2b2b);padding:.7em;border-radius:4px;' +
	'max-height:18em;overflow:auto}' +
	'.pv-ok{color:#3c8c3c;font-weight:bold}' +
	'.pv-bad{color:#c0392b;font-weight:bold}';

// LuCI's loader cannot pull in a UMD bundle, so inject the two crypto files as
// plain scripts once and wait for them to define their globals.
function loadScript(url) {
	return new Promise(function (resolve, reject) {
		var el = document.createElement('script');
		el.src = url;
		el.onload = function () { resolve(); };
		el.onerror = function () { reject(new Error('failed to load ' + url)); };
		document.head.appendChild(el);
	});
}

function loadCrypto() {
	if (window.ProtonSRP)
		return Promise.resolve(window.ProtonSRP);
	return loadScript(L.resource('view/protonvpn/vendor/bcrypt.js'))
		.then(function () { return loadScript(L.resource('view/protonvpn/srp.js')); })
		.then(function () {
			if (!window.ProtonSRP)
				throw new Error('srp.js loaded but ProtonSRP is undefined');
			return window.ProtonSRP;
		});
}

function fmtTime(epoch) {
	return epoch ? new Date(epoch * 1000).toLocaleString() : '?';
}

return view.extend({
	load: function () {
		return callSessionState().catch(function (e) {
			return { state: 'error', error: '' + e };
		});
	},

	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	log: function (msg, cls) {
		this.logEl.appendChild(E('div', cls ? { class: cls } : {}, msg));
		this.logEl.scrollTop = this.logEl.scrollHeight;
	},

	setError: function (msg) {
		dom.content(this.errEl, msg || '');
	},

	// Single source of truth for what the form shows.
	setStep: function (step) {
		this.step = step;
		this.renderForm();
	},

	refreshState: function () {
		return callSessionState().then(L.bind(function (st) {
			this.session = st || {};
			dom.content(this.stateEl, [
				E('strong', {}, _('Session: ')),
				E('span', { class: st && st.state === 'active' ? 'pv-ok' : '' },
					(st && st.state) || '?'),
				st && st.session_expires_at
					? E('span', {}, ' · ' + _('valid until') + ' ' + fmtTime(st.session_expires_at))
					: '',
				st && st.access_expires_at && st.state === 'active'
					? E('span', { class: 'pv-hint' }, ' · ' + _('access token until') + ' ' +
						fmtTime(st.access_expires_at) + _(' (refreshed automatically)'))
					: ''
			]);
			// A session can persist in a half-authenticated state, so trust the
			// backend over whatever step we happened to be on.
			if (st && st.state === 'active')
				this.setStep('done');
			else if (st && st.state === 'needs_2fa')
				this.setStep('totp');
			else
				this.setStep('credentials');
		}, this));
	},

	renderForm: function () {
		var self = this;
		var kids = [];

		if (this.step === 'credentials') {
			this.userEl = E('input', { type: 'text', class: 'cbi-input-text',
				placeholder: 'user@proton.me', autocomplete: 'username',
				value: this.lastUser || '',
				keydown: function (ev) { if (ev.key === 'Enter') self.handlePrimary(); } });
			this.passEl = E('input', { type: 'password', class: 'cbi-input-password',
				autocomplete: 'current-password',
				keydown: function (ev) { if (ev.key === 'Enter') self.handlePrimary(); } });
			kids = [
				E('div', { class: 'pv-field' }, [ E('label', {}, _('Proton username')), this.userEl ]),
				E('div', { class: 'pv-field' }, [ E('label', {}, _('Password')), this.passEl ]),
				E('div', { class: 'pv-actions' }, [
					E('button', { class: 'cbi-button cbi-button-apply',
						click: ui.createHandlerFn(this, 'handlePrimary') }, _('Log in'))
				]),
				E('div', { class: 'pv-hint' },
					_('The password is turned into a proof in this page and never reaches the router.'))
			];
			setTimeout(function () { try { (self.lastUser ? self.passEl : self.userEl).focus(); } catch (e) {} }, 50);
		} else if (this.step === 'totp') {
			// Second step only exists because the API asked for it.
			this.totpEl = E('input', { type: 'text', class: 'cbi-input-text',
				placeholder: '123456', inputmode: 'numeric', maxlength: '8',
				autocomplete: 'one-time-code', style: 'max-width:9em;letter-spacing:.2em',
				keydown: function (ev) { if (ev.key === 'Enter') self.handlePrimary(); } });
			kids = [
				E('div', { class: 'pv-who' },
					_('Password accepted for %s. This account has two-factor authentication.')
						.format(this.lastUser || '')),
				E('div', { class: 'pv-field' }, [
					E('label', {}, _('Two-factor code')), this.totpEl
				]),
				E('div', { class: 'pv-actions' }, [
					E('button', { class: 'cbi-button cbi-button-apply',
						click: ui.createHandlerFn(this, 'handlePrimary') }, _('Confirm code')),
					E('button', { class: 'cbi-button',
						click: ui.createHandlerFn(this, 'handleStartOver') }, _('Start over'))
				]),
				E('div', { class: 'pv-hint' },
					_('A wrong code can simply be retyped — the password step is not repeated.'))
			];
			setTimeout(function () { try { self.totpEl.focus(); } catch (e) {} }, 50);
		} else {
			kids = [
				E('div', { class: 'pv-who' }, _('Signed in. The router keeps the session and refreshes it on its own.')),
				E('div', { class: 'pv-actions' }, [
					E('button', { class: 'cbi-button',
						click: ui.createHandlerFn(this, 'handleRefresh') }, _('Refresh session')),
					E('button', { class: 'cbi-button cbi-button-remove',
						click: ui.createHandlerFn(this, 'handleLogout') }, _('Log out'))
				])
			];
		}

		dom.content(this.formEl, kids);
	},

	handlePrimary: function () {
		return this.step === 'totp' ? this.submitTotp() : this.submitCredentials();
	},

	handleStartOver: function () {
		this.setError('');
		this.log('starting over — the half-authenticated session is dropped');
		return callLogout().then(L.bind(function () {
			return this.refreshState();
		}, this));
	},

	handleRefresh: function () {
		var self = this;
		return callRefreshSession().then(function (r) {
			if (r && r.error) {
				self.setError(r.error);
				self.log('refresh failed: ' + r.error, 'pv-bad');
			} else {
				self.log('session refreshed; access token until ' + fmtTime(r && r.access_expires_at), 'pv-ok');
			}
			return self.refreshState();
		});
	},

	handleLogout: function () {
		var self = this;
		return callLogout().then(function () {
			self.log('logged out');
			return self.refreshState();
		});
	},

	// Step 1: password -> proof in this page, HTTP via the router, then check
	// the server's own proof back.
	submitCredentials: function () {
		var username = (this.userEl.value || '').trim();
		var password = this.passEl.value || '';
		this.setError('');
		if (!username || !password) {
			this.setError(_('Enter the username and password'));
			return;
		}
		this.lastUser = username;

		var self = this;
		var SRP, params;
		this.log('--- ' + new Date().toLocaleTimeString() + ' login attempt ---');

		return loadCrypto().then(function (srp) {
			SRP = srp;
			self.log('crypto loaded (bcrypt + SRP)');
			self.log('POST /auth/info via rpcd ...');
			return callAuthInfo(username);
		}).then(function (res) {
			if (!res || res.error)
				throw new Error((res && res.error) || 'no response from auth_info');
			params = res;
			self.log('auth_info OK — version=' + res.version +
				', modulus=' + (String(res.modulus).indexOf('PGP') >= 0 ? 'clear-signed' : 'bare'));
			self.log('computing SRP proof in the browser (password stays here) ...');
			return SRP.prepareLogin({
				version: params.version,
				username: username,
				password: password,
				saltBase64: params.salt,
				modulusBase64: params.modulus,
				serverEphemeralBase64: params.server_ephemeral
			});
		}).then(function (proofs) {
			self.log('proof computed; modulus validated (2048-bit safe prime, 3 mod 8, Lucas)');
			self.expected = proofs.expectedServerProof;
			self.log('POST /auth via rpcd ...');
			return callAuthFinish(username, params.srp_session,
				proofs.clientEphemeral, proofs.clientProof);
		}).then(function (res) {
			if (!res || res.error)
				throw new Error((res && res.error) || 'no response from auth_finish');

			// Mutual authentication: a mismatch means the peer did not know the
			// verifier, so the session must not be trusted.
			if (res.server_proof) {
				var ok = SRP.verifyServerProof(self.expected, res.server_proof);
				self.log('server proof ' + (ok ? 'VERIFIED' : 'MISMATCH'), ok ? 'pv-ok' : 'pv-bad');
				if (!ok)
					throw new Error('server proof did not verify — aborting');
			} else {
				self.log('server returned no ServerProof (cannot authenticate the server)', 'pv-bad');
			}

			self.log(res.twofa ? 'two-factor code required' : 'LOGIN OK — session stored on the router',
				res.twofa ? '' : 'pv-ok');
			return self.refreshState().then(function () { return self.loadLocations(); });
		}).catch(function (err) {
			var msg = err.message || ('' + err);
			self.setError(msg);
			self.log('FAILED: ' + msg, 'pv-bad');
		});
	},

	// Step 2: only reached when the API said 2FA is needed.
	submitTotp: function () {
		var self = this;
		var code = (this.totpEl.value || '').trim();
		this.setError('');
		if (!/^[0-9]{6,8}$/.test(code)) {
			this.setError(_('Enter the 6-digit code from your authenticator'));
			return;
		}
		return callSetTotp(code).then(function (res) {
			if (!res || res.error) {
				var msg = (res && res.error) || 'no response';
				self.setError(msg);
				self.log('two-factor failed: ' + msg, 'pv-bad');
				self.totpEl.value = '';
				try { self.totpEl.focus(); } catch (e) {}
				return;
			}
			self.log('two-factor accepted — session upgraded', 'pv-ok');
			return self.refreshState();
		});
	},

	// ── Server browser: proves the data layer end to end (13 MB fetch ->
	// normalized cache -> ubus -> UI) and previews what the real picker shows.

	loadLocations: function () {
		var self = this;
		return callLocations().then(function (res) {
			self.locations = res || {};
			self.renderLocations();
		});
	},

	handleRefreshLocations: function () {
		var self = this;
		self.log('refreshing the server list (13 MB download, a few seconds) ...');
		return callRefreshLocations().then(function (r) {
			if (r && r.error) {
				self.log('refresh failed: ' + r.error, 'pv-bad');
				return;
			}
			if (r && r.already_running) {
				self.log('a refresh is already running');
				return;
			}
			// The worker is detached, so poll until the cache reappears.
			var tries = 0;
			var poll = function () {
				return callLocations().then(function (res) {
					if (res && res.available) {
						self.locations = res;
						self.renderLocations();
						self.log('server list updated: ' + res.stats.gateways + ' gateways', 'pv-ok');
						return;
					}
					if (++tries > 30)
						return self.log('refresh did not finish in time', 'pv-bad');
					return new Promise(function (r2) { setTimeout(r2, 2000); }).then(poll);
				});
			};
			return poll();
		});
	},

	renderLocations: function () {
		var self = this;
		var loc = this.locations || {};
		if (!loc.available) {
			dom.content(this.srvEl, [
				E('p', {}, _('No server list cached yet.')),
				E('button', { class: 'cbi-button',
					click: ui.createHandlerFn(this, 'handleRefreshLocations') },
					_('Download server list'))
			]);
			return;
		}

		var countries = (loc.countries || []).slice();
		// Order by name the way the user reads them, not by ISO code.
		countries.sort(function (a, b) {
			return countryName(a.code).localeCompare(countryName(b.code));
		});

		var sel = E('select', { class: 'cbi-input-select', change: function () {
			self.showServers(this.value, self.hopEl.value);
		} });
		sel.appendChild(E('option', { value: '' }, _('-- pick a country --')));
		countries.forEach(function (c) {
			sel.appendChild(E('option', { value: c.code },
				'%s — %d (%s: %d, Tor: %d)'.format(countryName(c.code), c.gateway_count,
					_('Secure Core'), c.secure_core_count, c.tor_count)));
		});
		this.countryEl = sel;

		this.hopEl = E('select', { class: 'cbi-input-select', change: function () {
			self.showServers(self.countryEl.value, this.value);
		} });
		[ [ 'standard', _('Standard') ], [ 'secure_core', _('Secure Core') ], [ 'tor', _('Tor') ] ]
			.forEach(function (o) {
				self.hopEl.appendChild(E('option', { value: o[0] }, o[1]));
			});

		this.srvListEl = E('div', { class: 'pv-scroll' });

		dom.content(this.srvEl, [
			E('div', {}, [
				E('strong', {}, _('Server list: ')),
				E('span', {}, '%d %s · %d %s · %d %s'.format(
					loc.stats.countries, _('countries'), loc.stats.cities, _('cities'),
					loc.stats.gateways, _('gateways'))),
				E('span', { class: 'pv-hint' }, ' · ' + _('cached') + ' ' + (loc.cached_at || '?') +
					(loc.state === 'stale' ? ' (' + _('stale') + ')' : ''))
			]),
			E('div', { class: 'pv-actions', style: 'margin:.7em 0' }, [
				this.hopEl, sel,
				E('button', { class: 'cbi-button',
					click: ui.createHandlerFn(this, 'handleRefreshLocations') }, _('Re-download'))
			]),
			this.srvListEl
		]);
	},

	showServers: function (cc, hop) {
		var self = this;
		if (!cc) {
			dom.content(this.srvListEl, '');
			return;
		}
		return callServers([ cc ], hop || 'standard').then(function (res) {
			var relays = (res && res.relays) || [];
			// Lowest Score first: that is exactly Proton's Quick Connect order.
			relays.sort(function (a, b) { return (a.score || 0) - (b.score || 0); });
			if (!relays.length) {
				dom.content(self.srvListEl,
					E('p', {}, _('No servers of this kind in %s.').format(countryName(cc))));
				return;
			}
			var rows = relays.map(function (r, i) {
				var cls = r.load < 50 ? 'pv-lo' : (r.load < 80 ? 'pv-mid' : 'pv-hi');
				return E('tr', {}, [
					E('td', {}, [
						E('span', { class: 'pv-dot ' + cls }),
						E('span', {}, r.name || r.hostname),
						i === 0 ? E('span', { class: 'pv-tag' }, _('best')) : '',
						r.secure_core ? E('span', { class: 'pv-tag' },
							countryName(r.entry_country) + ' → ') : '',
						r.tor ? E('span', { class: 'pv-tag' }, 'Tor') : '',
						r.tier === 0 ? E('span', { class: 'pv-tag' }, _('free')) : ''
					]),
					E('td', {}, r.city || ''),
					E('td', { class: 'num' }, '%d%%'.format(r.load)),
					E('td', { class: 'num' }, (r.score || 0).toFixed(2))
				]);
			});
			dom.content(self.srvListEl, E('table', { class: 'pv-srv' }, [
				E('tr', {}, [
					E('th', {}, _('Server')), E('th', {}, _('City')),
					E('th', { class: 'num' }, _('Load')), E('th', { class: 'num' }, _('Score'))
				])
			].concat(rows)));
		});
	},

	render: function (state) {
		this.session = state || {};
		this.step = 'credentials';
		this.lastUser = '';
		this.logEl = E('div', { class: 'pv-log' });
		this.stateEl = E('div', { class: 'pv-state' });
		this.errEl = E('div', { class: 'pv-err' });
		this.formEl = E('div', {});
		this.srvEl = E('div', {}, E('em', {}, _('Log in to browse the server list.')));

		var body = E('div', {}, [
			E('style', { type: 'text/css' }, STYLE),
			E('h2', {}, _('ProtonVPN login (spike)')),
			E('p', {}, _('Validates the SRP login end to end: the password is turned into a proof in this page and never reaches the router; the router only relays the HTTP calls to Proton.')),
			E('div', { class: 'pv-card' }, [ this.stateEl, this.errEl, this.formEl ]),
			E('div', { class: 'pv-card', style: 'max-width:none' }, [ this.srvEl ]),
			this.logEl
		]);

		// Derive the initial step from the real session state.
		if (state && state.state === 'active')
			this.step = 'done';
		else if (state && state.state === 'needs_2fa')
			this.step = 'totp';
		this.renderForm();
		dom.content(this.stateEl, [
			E('strong', {}, _('Session: ')),
			E('span', {}, (state && state.state) || '?')
		]);

		this.log('ready — page served over ' + window.location.protocol);
		// The list needs a session only to be (re)downloaded; a cached one is
		// readable regardless, so always try.
		this.loadLocations().catch(L.bind(function (e) {
			this.log('could not read the server list: ' + e, 'pv-bad');
		}, this));
		return body;
	}
});

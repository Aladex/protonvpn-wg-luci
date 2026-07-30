// SPDX-License-Identifier: MIT
// ProtonVPN LuCI view. The location-set widget and the server picker are ported
// from luci-app-nordvpn, adapted to Proton's data model: hop modes are
// Standard / Secure Core / Tor, servers carry a Score (Proton's own Quick
// Connect order) besides load, and country names are resolved in the browser
// because the API only sends ISO codes.
//
// Login runs here: the password is turned into an SRP proof in this page and
// never reaches the router (see srp.js); rpcd only relays the HTTP calls.

'use strict';
'require view';
'require rpc';
'require uci';
'require ui';
'require poll';
'require dom';

var callStatus = rpc.declare({ object: 'protonvpn', method: 'status', params: [ 'instance' ] });
var callInstances = rpc.declare({ object: 'protonvpn', method: 'instances' });
var callSessionState = rpc.declare({ object: 'protonvpn', method: 'session_state' });
var callLocations = rpc.declare({ object: 'protonvpn', method: 'locations' });
var callServers = rpc.declare({
	object: 'protonvpn', method: 'servers', params: [ 'locations', 'hop_mode' ]
});
var callAuthInfo = rpc.declare({ object: 'protonvpn', method: 'auth_info', params: [ 'username' ] });
var callAuthFinish = rpc.declare({
	object: 'protonvpn', method: 'auth_finish',
	params: [ 'username', 'srp_session', 'client_ephemeral', 'client_proof' ]
});
var callSetTotp = rpc.declare({ object: 'protonvpn', method: 'set_totp', params: [ 'code' ] });
var callLogout = rpc.declare({ object: 'protonvpn', method: 'logout' });
var callRefreshLocations = rpc.declare({ object: 'protonvpn', method: 'refresh_locations' });
var callAccount = rpc.declare({ object: 'protonvpn', method: 'account' });
var callExternalIp = rpc.declare({
	object: 'protonvpn', method: 'external_ip', params: [ 'instance' ]
});
var callApply = rpc.declare({ object: 'protonvpn', method: 'apply', params: [ 'instance' ] });
var callDisconnect = rpc.declare({ object: 'protonvpn', method: 'disconnect', params: [ 'instance' ] });
var callRotateNow = rpc.declare({ object: 'protonvpn', method: 'rotate_now', params: [ 'instance' ] });

var STYLE = '' +
	'.pv-status-main{display:flex;flex-wrap:wrap;align-items:baseline;gap:.75em;font-size:1.05em}' +
	'.pv-state{font-weight:700}' +
	'.pv-status-details{color:var(--text-color-medium,#666);font-size:.9em;margin-top:.3em}' +
	'.pv-status-actions{margin-top:.7em;display:flex;gap:.5em;flex-wrap:wrap}' +
	'.pv-mono{font-family:monospace}' +
	'.pv-inline-note{font-style:italic;color:var(--text-color-medium,#666)}' +
	'.pv-inline{display:flex;align-items:center;gap:.75em;flex-wrap:wrap}' +
	'.pv-radio-group{display:flex;align-items:center;gap:1.25em;flex-wrap:wrap;min-height:1.9em}' +
	'.pv-radio-group label{display:inline-flex;align-items:center;gap:.4em;margin:0;font-weight:normal}' +
	'.pv-check{display:inline-flex;align-items:center;gap:.4em;font-weight:normal}' +
	'.pv-seg{display:inline-flex;flex-wrap:wrap;max-width:100%;border:1px solid #0069d6;border-radius:1.2em;overflow:hidden}' +
	'.pv-seg button{border:0;background:transparent;margin:0;padding:.3em 1.1em;cursor:pointer;font:inherit;color:inherit;line-height:1.3;white-space:nowrap;flex:1 1 auto}' +
	'.pv-seg button+button{border-left:1px solid #0069d6}' +
	'.pv-seg button.active{background:#0069d6;color:#fff}' +
	// Rotation pool chips: a country is filled (like the active segment), a
	// Location chips: one filled pill per country, with borderless edit/remove
	// buttons inside. A stale code (no longer in the server list) is dashed.
	'.pv-pool{display:flex;flex-direction:column;align-items:flex-start;gap:.4em;margin-top:.45em}' +
	'.pv-chip{display:inline-flex;align-items:center;gap:.35em;border:1px solid #0069d6;border-radius:1.2em;padding:.15em .55em;line-height:1.4;white-space:nowrap}' +
	'.pv-chip-country{background:#0069d6;color:#fff}' +
	'.pv-chip-click{cursor:pointer}' +
	'.pv-chip-stale{border-style:dashed;color:var(--text-color-medium,#666)}' +
	'.pv-chip button{border:0;background:transparent;color:inherit;cursor:pointer;padding:0 .1em;margin:0;font:inherit;font-weight:700;line-height:1}' +
	'.pv-pool-count{color:var(--text-color-medium,#666);font-size:.9em}' +
	// Custom location picker: the trigger opens an inline panel that walks
	// countries -> cities (checkbox narrowing) in place. The trigger hides
	// while the panel is open, so there is no duplicate "add" affordance.
	'.pv-pool-wrap{display:block;margin-top:.5em}' +
	'.pv-pool-trigger::after{content:" \\25be"}' +
	'.pv-pool-panel{display:block;margin-top:.35em;width:320px;max-width:100%;max-height:340px;overflow:auto;background:var(--background-color-high,#fff);color:var(--text-color-high,inherit);border:1px solid var(--border-color-medium,#ccc);border-radius:.4em;box-shadow:0 4px 14px rgba(0,0,0,.18);padding:.25em}' +
	'.pv-pool-panel.hidden{display:none}' +
	'.pv-pool-head{display:flex;align-items:center;justify-content:space-between;gap:.5em;padding:.1em .3em .3em;font-weight:600}' +
	'.pv-pool-x{border:0;background:transparent;cursor:pointer;font:inherit;font-weight:700;color:inherit;padding:0 .2em}' +
	'.pv-pool-filter{width:100%;box-sizing:border-box;margin:0 0 .3em 0}' +
	'.pv-pool-row{display:flex;align-items:center;gap:.55em;padding:.34em .5em;border-radius:.3em;cursor:pointer;white-space:nowrap}' +
	'.pv-pool-row:hover{background:rgba(0,105,214,.14)}' +
	'.pv-pool-row.is-in{opacity:.55}' +
	'.pv-pool-row .grow{flex:1;overflow:hidden;text-overflow:ellipsis}' +
	'.pv-pool-row .chev{color:var(--text-color-medium,#888);font-weight:700}' +
	'.pv-pool-row .box{font-weight:700;width:1.15em;text-align:center;flex:none}' +
	'.pv-pool-back{font-weight:600}' +
	'.pv-pool-remove{color:#c0392b;font-weight:600}' +
	'.pv-pool-remove:hover{background:rgba(192,57,43,.12)}' +
	'.pv-pool-sep{border-top:1px solid var(--border-color-medium,#ddd);margin:.25em 0}' +
	'.pv-chip-add{font-weight:700;padding:0 .15em}' +
	// Server picker: same panel, plus a load dot (green/amber/red), a group
	// header per country and quick "Automatic / Lowest load" rows at the top.
	'.pv-srv-trigger{max-width:100%;overflow:hidden;text-overflow:ellipsis;text-align:left}' +
	'.pv-srv-x{border:0;background:transparent;cursor:pointer;font:inherit;font-weight:700;color:inherit;padding:0 .2em;margin-left:.3em}' +
	'.pv-dot{display:inline-block;width:.7em;height:.7em;border-radius:50%;flex:none}' +
	'.pv-dot-lo{background:#3c8c3c}' +
	'.pv-dot-mid{background:#c79100}' +
	'.pv-dot-hi{background:#c0392b}' +
	'.pv-srv-load{color:var(--text-color-medium,#888);font-variant-numeric:tabular-nums;flex:none}' +
	'.pv-srv-cur{color:#3c8c3c;font-weight:600;flex:none}' +
	'.pv-srv-grp{font-weight:600;padding:.35em .5em .15em;color:var(--text-color-medium,#888)}' +
	'.pv-pool-row.pv-srv-quick{font-weight:600}' +
	// Plain flex rows (no LuCI .table classes), so the theme's own responsive
	// table stacking can never apply; wraps naturally down to ~340 px.
	'.pv-inst-row{display:flex;align-items:center;gap:.8em;padding:.55em 0;border-bottom:1px solid var(--border-color-medium,#ccc);cursor:pointer}' +
	'.pv-inst-row:last-child{border-bottom:none}' +
	'.pv-inst-info{display:flex;flex-wrap:wrap;align-items:center;gap:.25em .8em;flex:1;min-width:0}' +
	'.pv-inst-name{font-weight:bold}' +
	'.pv-inst-dim{color:var(--text-color-medium,#666);font-size:.92em}' +
	'.pv-inst-act{flex:none;margin-left:auto}' +
	'.pv-token-field>div{display:block;width:100%}' +
	'.pv-token-field .control-group{display:flex;width:100%}' +
	'.pv-token-field .control-group input{flex:1 1 auto;width:100%}' +
	'details.pv-advanced>summary{cursor:pointer;font-weight:700;padding:.3em 0}' +
	// ── ProtonVPN account card ───────────────────────────────────────────
	// A real card, not a bare paragraph: the credential state is the first
	// thing to read on the page, and its actions must not collide with the
	// form below.
	'.pv-acct{display:flex;flex-wrap:wrap;align-items:center;gap:1em;' +
	'padding:.85em 1.1em;margin-bottom:1.2em;border-radius:6px;' +
	'border:1px solid var(--border-color-medium,#444);' +
	'background:var(--background-color-medium,rgba(127,127,127,.06))}' +
	'.pv-acct-main{flex:1 1 22em;min-width:16em}' +
	'.pv-acct-title{font-weight:700;display:flex;align-items:center;gap:.5em}' +
	'.pv-acct-sub{font-size:90%;opacity:.75;margin-top:.25em}' +
	// Actions sit on the right on wide screens and wrap underneath on narrow
	// ones, always with real spacing between the buttons.
	'.pv-acct-actions{display:flex;gap:.6em;flex-wrap:wrap;margin-left:auto}' +
	'.pv-acct-warn{border-color:#c79100}' +
	'.pv-acct-bad{border-color:#c0392b}' +
	'.pv-led{display:inline-block;width:.7em;height:.7em;border-radius:50%;flex:none}' +
	'.pv-led-ok{background:#3c8c3c}.pv-led-warn{background:#c79100}.pv-led-bad{background:#c0392b}' +
	'.pv-tagline{font-size:85%;opacity:.8;margin-left:.4em}' +
	'.pv-err{color:#c0392b;font-weight:bold;margin-bottom:.6em}' +
	'.pv-field{margin-bottom:.9em}' +
	'.pv-field label{display:block;margin-bottom:.3em;font-weight:bold}' +
	'.pv-field input{width:100%;box-sizing:border-box}' +
	'.pv-state{display:flex;flex-wrap:wrap;align-items:center;gap:1em;' +
	'padding:.85em 1.1em;margin-bottom:1.2em;border-radius:6px;' +
	'border:1px solid var(--border-color-medium,#444)}' +
	'.pv-state-main{flex:1 1 24em;min-width:16em}' +
	'.pv-state-title{font-weight:700;display:flex;align-items:center;gap:.5em}' +
	'.pv-state-sub{font-size:90%;opacity:.8;margin-top:.3em;line-height:1.5}' +
	'.pv-state-actions{display:flex;gap:.6em;flex-wrap:wrap;margin-left:auto}' +
	'.pv-quota{font-size:85%;opacity:.75}' +
	'.hidden{display:none!important}';

// Proton sends ISO country codes only, so the browser localizes them instead
// of the router shipping a 148-entry name table.
var regionNames = null;

function loadScript(url) {
	return new Promise(function (resolve, reject) {
		var el = document.createElement('script');
		el.src = url;
		el.onload = function () { resolve(); };
		el.onerror = function () { reject(new Error('failed to load ' + url)); };
		document.head.appendChild(el);
	});
}

// LuCI's loader cannot pull in a UMD bundle, so the crypto files are injected
// as plain scripts the first time a login is attempted.
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
	handleSave: null,
	handleSaveApply: null,
	handleReset: null,

	load: function () {
		return Promise.all([
			uci.load('protonvpn'),
			callSessionState().catch(function () { return { state: 'error' }; }),
			callLocations().catch(function () { return { available: false }; }),
			callStatus('main').catch(function () { return {}; })
			// NOTE: the account/limits call is deliberately NOT here. It makes
			// two live HTTPS round-trips to Proton, which would sit in the
			// critical path of every page load. It is fetched after render and
			// the card updates when it arrives.
		]);
	},

	// ── small helpers ────────────────────────────────────────────────────

	countryFlag: function (code) {
		if (typeof code !== 'string' || !/^[A-Za-z]{2}$/.test(code))
			return '';
		var c = code.toLowerCase();
		return String.fromCodePoint(
			0x1F1E6 + (c.charCodeAt(0) - 97),
			0x1F1E6 + (c.charCodeAt(1) - 97));
	},

	// Localized country name for an ISO code, falling back to the code itself.
	countryLabel: function (code) {
		var cc = String(code || '').toUpperCase();
		if (!cc)
			return '';
		if (regionNames === null) {
			try {
				regionNames = new Intl.DisplayNames([ navigator.language || 'en' ],
					{ type: 'region' });
			} catch (e) {
				regionNames = false;
			}
		}
		if (!regionNames)
			return cc;
		try {
			return regionNames.of(cc) || cc;
		} catch (e) {
			return cc;
		}
	},

	hopMode: function () {
		return this.hopValue || 'standard';
	},

	// Key of the per-kind gateway counters in the locations tree.
	hopCountKey: function () {
		var m = this.hopMode();
		return m === 'secure_core' ? 'secure_core_count'
			: (m === 'tor' ? 'tor_count' : 'standard_count');
	},

	setHopMode: function (mode) {
		if (this.hopValue === mode)
			return;
		this.hopValue = mode;
		this.markDirty();
		this.updateHopButtons();
		// Entries that do not exist in the new mode are hidden, not deleted, so
		// switching back restores the previous selection.
		this.rebuildPoolWidget();
		this.refreshServerList();
	},

	updateHopButtons: function () {
		var mode = this.hopMode();
		for (var k in this.hopButtons)
			this.hopButtons[k].classList.toggle('active', k === mode);
		var notes = {
			secure_core: _('Traffic enters through a Proton-owned server in a privacy-friendly country before exiting in the country you pick. Slower, fewer servers.'),
			tor: _('Traffic leaves the VPN server through the Tor network. Noticeably slower, and some sites block Tor exits.')
		};
		if (this.hopNote) {
			dom.content(this.hopNote, notes[mode] || '');
			this.hopNote.classList.toggle('hidden', !notes[mode]);
		}
	},

	// Countries that actually have servers of the current kind.
	filteredCountries: function () {
		var l = this.locations || {};
		if (!Array.isArray(l.countries))
			return [];
		var key = this.hopCountKey();
		var self = this;
		var out = [];
		l.countries.forEach(function (c) {
			var cities = (c.cities || []).filter(function (city) {
				return (city[key] || 0) > 0;
			});
			var count = c[key] || 0;
			if (cities.length && count > 0)
				out.push(Object.assign({}, c, {
					cities: cities, gateway_count: count,
					name: self.countryLabel(c.code)
				}));
		});
		out.sort(function (a, b) { return a.name.localeCompare(b.name); });
		return out;
	},

	// Fetch the union server list for the location set and repaint the picker.
	// A pin the user cannot reach any more is dropped, but only when they
	// changed the locations themselves: on a plain repaint the persisted pin is
	// restored as-is, so a slow or empty response never silently unpins.
	refreshServerList: function () {
		if (!this.srvTrigger)
			return;
		var codes = (this.poolEntries || []).map(function (e) { return e.code; });
		var req = ++this._serversReq;
		var userEdit = !this._building;
		this._serverData = null;
		this.srvTrigger.disabled = !codes.length;
		if (!codes.length) {
			this.srvRenderTrigger();
			return;
		}
		callServers(codes, this.hopMode()).then(L.bind(function (res) {
			if (req !== this._serversReq)
				return;                 // a newer rebuild superseded this response
			this._serverData = { relays: ((res && res.relays) || []).slice() };
			// Restoring the persisted pin is not a user edit.
			var pinned = uci.get('protonvpn', this.instance, 'fixed_server') || '';
			var reachable = !pinned || this._serverData.relays.some(function (r) {
				return r.name === pinned || r.hostname === pinned;
			});
			if (userEdit && !reachable) {
				// The user moved to another region; a server from the old one
				// would keep the tunnel where it was.
				this._serverChosen = '';
				this.markDirty();
			} else {
				this._serverChosen = pinned;
			}
			this.srvRenderTrigger();
			if (this._srvOpen)
				this.srvRenderPanel();
			this._building = true;
			this.updateRotationAvailability();
			this._building = false;
		}, this)).catch(function () {});
	},

	markDirty: function () {
		if (this._building)
			return;
		this._dirty = true;
		if (this.saveBtn)
			this.saveBtn.disabled = false;
		if (this.discardBtn)
			this.discardBtn.disabled = false;
	},

	notice: function (text, kind) {
		ui.addNotification(null, E('p', {}, text), kind || 'info');
	},

	// ── login (SRP happens in this page) ─────────────────────────────────

	// Stepper: credentials first, and the two-factor field only once the API
	// says it is needed. Asking for a code up front misleads the majority of
	// accounts that have none.
	showLoginModal: function (step) {
		var self = this;
		this.loginStep = step || 'credentials';
		this.loginErr = E('div', { class: 'pv-err' });
		var body = E('div', {});

		var render = function () {
			var kids = [];
			if (self.loginStep === 'totp') {
				self.totpEl = E('input', { type: 'text', class: 'cbi-input-text',
					placeholder: '123456', inputmode: 'numeric', maxlength: '8',
					autocomplete: 'one-time-code', style: 'max-width:9em;letter-spacing:.2em',
					keydown: function (ev) { if (ev.key === 'Enter') submit(); } });
				kids = [
					E('p', {}, _('Password accepted for %s. This account has two-factor authentication.')
						.format(self.loginUser || '')),
					E('div', { class: 'pv-field' }, [ E('label', {}, _('Two-factor code')), self.totpEl ]),
					E('div', { class: 'cbi-value-description' },
						_('A wrong code can simply be retyped — the password step is not repeated.'))
				];
			} else {
				self.userEl = E('input', { type: 'text', class: 'cbi-input-text',
					placeholder: 'user@proton.me', autocomplete: 'username',
					value: self.loginUser || '',
					keydown: function (ev) { if (ev.key === 'Enter') submit(); } });
				self.passEl = E('input', { type: 'password', class: 'cbi-input-password',
					autocomplete: 'current-password',
					keydown: function (ev) { if (ev.key === 'Enter') submit(); } });
				kids = [
					E('div', { class: 'pv-field' }, [ E('label', {}, _('Proton username')), self.userEl ]),
					E('div', { class: 'pv-field' }, [ E('label', {}, _('Password')), self.passEl ]),
					E('div', { class: 'cbi-value-description' },
						_('The password is turned into a proof in this page and never reaches the router.'))
				];
			}
			dom.content(body, [ self.loginErr ].concat(kids));
			setTimeout(function () {
				try {
					(self.loginStep === 'totp' ? self.totpEl :
						(self.loginUser ? self.passEl : self.userEl)).focus();
				} catch (e) {}
			}, 60);
		};

		var fail = function (msg) {
			dom.content(self.loginErr, msg);
			self.loginBusy = false;
		};

		var submit = function () {
			if (self.loginBusy)
				return;
			self.loginBusy = true;
			dom.content(self.loginErr, '');
			if (self.loginStep === 'totp')
				return self.submitTotp(fail, render);
			return self.submitCredentials(fail, render);
		};

		render();
		ui.showModal(_('Sign in to Proton'), [
			body,
			E('div', { class: 'right' }, [
				E('button', { class: 'cbi-button', click: ui.hideModal }, _('Cancel')),
				' ',
				E('button', { class: 'cbi-button cbi-button-apply',
					click: function () { submit(); } }, _('Continue'))
			])
		]);
	},

	submitCredentials: function (fail, render) {
		var self = this;
		var username = (this.userEl.value || '').trim();
		var password = this.passEl.value || '';
		if (!username || !password)
			return fail(_('Enter the username and password'));
		this.loginUser = username;

		var SRP, params;
		return loadCrypto().then(function (srp) {
			SRP = srp;
			return callAuthInfo(username);
		}).then(function (res) {
			if (!res || res.error)
				throw new Error((res && res.error) || _('no response'));
			params = res;
			return SRP.prepareLogin({
				version: params.version, username: username, password: password,
				saltBase64: params.salt, modulusBase64: params.modulus,
				serverEphemeralBase64: params.server_ephemeral
			});
		}).then(function (proofs) {
			self._expectedProof = proofs.expectedServerProof;
			return callAuthFinish(username, params.srp_session,
				proofs.clientEphemeral, proofs.clientProof);
		}).then(function (res) {
			if (!res || res.error)
				throw new Error((res && res.error) || _('no response'));
			// Mutual authentication: if the server cannot prove it knows the
			// verifier, the session must not be trusted.
			if (res.server_proof &&
			    !SRP.verifyServerProof(self._expectedProof, res.server_proof))
				throw new Error(_('The server proof did not verify — aborting.'));
			self.loginBusy = false;
			if (res.twofa) {
				self.loginStep = 'totp';
				render();
				return;
			}
			ui.hideModal();
			self.notice(_('Signed in.'), 'info');
			return self.afterLogin();
		}).catch(function (err) {
			fail(err.message || ('' + err));
		});
	},

	submitTotp: function (fail) {
		var self = this;
		var code = (this.totpEl.value || '').trim();
		if (!/^[0-9]{6,8}$/.test(code))
			return fail(_('Enter the 6-digit code from your authenticator'));
		return callSetTotp(code).then(function (res) {
			self.loginBusy = false;
			if (!res || res.error) {
				self.totpEl.value = '';
				return fail((res && res.error) || _('no response'));
			}
			ui.hideModal();
			self.notice(_('Signed in.'), 'info');
			return self.afterLogin();
		});
	},

	// After a successful login the server list is usually missing, so pull it
	// once; the download is a few seconds and everything else depends on it.
	afterLogin: function () {
		var self = this;
		return callSessionState().then(function (st) {
			self.session = st || {};
			// Limits become knowable again; a failure here must not derail login.
			return self.loadAccount();
		}).then(function () {
			return callLocations();
		}).then(function (loc) {
			self.locations = loc || {};
			if (!loc || !loc.available)
				return self.handleRefreshLocations();
			self.rebuildPoolWidget();
			self.refreshServerList();
			self.renderBand();
		});
	},

	handleLogout: function () {
		var self = this;
		return callLogout().then(function () {
			// Without a session the plan and the connection quota are no longer
			// knowable, so drop them instead of showing a stale figure.
			self.account = null;
			self.externalIp = null;
			return callSessionState();
		}).then(function (st) {
			self.session = st || {};
			self.renderBand();
			return self.refreshStatus();
		});
	},

	handleRefreshLocations: function () {
		var self = this;
		return callRefreshLocations().then(function (r) {
			if (r && r.error) {
				self.notice(r.error, 'warning');
				return;
			}
			self.notice(_('Downloading the server list…'), 'info');
			var tries = 0;
			var poll_ = function () {
				return callLocations().then(function (res) {
					if (res && res.available) {
						self.locations = res;
						self.rebuildPoolWidget();
						self.refreshServerList();
						self.renderBand();
						self.notice(_('Server list updated: %d servers.')
							.format(res.stats.gateways), 'info');
						return;
					}
					if (++tries > 40)
						return self.notice(_('The server list did not arrive in time.'), 'warning');
					return new Promise(function (r2) { setTimeout(r2, 2000); }).then(poll_);
				});
			};
			return poll_();
		});
	},
	poolResolve: function(code) {
		if (typeof code !== 'string' || !code)
			return null;
		var key = this.hopCountKey();
		var isCountry = /^[A-Za-z]{2}$/.test(code);
		var flag = this.countryFlag(code.slice(0, 2));
		var countries = this.filteredCountries();
		for (var i = 0; i < countries.length; i++) {
			var c = countries[i];
			if (isCountry && c.code === code)
				return { code: code, kind: 'country', name: c.name, count: c.gateway_count || 0, flag: flag };
			var cities = isCountry ? [] : (c.cities || []);
			for (var j = 0; j < cities.length; j++)
				if (cities[j].code === code)
					return { code: code, kind: 'city', name: cities[j].name, count: cities[j][key] || 0, flag: flag };
		}
		return { code: code, kind: isCountry ? 'country' : 'city', name: null, count: null, flag: flag };
	},

	/* ---- country-first set mutations ---------------------------------- */

	poolCitiesOf: function(cc) {
		return (((this._ccData || {})[cc]) || {}).cities || [];
	},

	// Current state of a country in the set: whole, or a map of picked cities.
	poolCountryHas: function(cc) {
		var whole = false, cities = {};
		(this.poolEntries || []).forEach(function(e) {
			if (e.code === cc) whole = true;
			else if (e.kind === 'city' && e.code.indexOf(cc + '-') === 0) cities[e.code] = true;
		});
		return { whole: whole, cities: cities, has: whole || Object.keys(cities).length > 0 };
	},

	poolStripCountry: function(cc) {
		this.poolEntries = (this.poolEntries || []).filter(function(e) {
			return !(e.code === cc || (e.kind === 'city' && e.code.indexOf(cc + '-') === 0));
		});
	},

	_poolCommit: function() {
		this.markDirty();
		this.rebuildPoolWidget();
		this.refreshServerList();
	},

	// Whole country in the set (stored as the bare country code).
	poolSetWhole: function(cc) {
		this.poolStripCountry(cc);
		var e = this.poolResolve(cc);
		if (e)
			this.poolEntries.push(e);
		this._poolCommit();
	},

	poolRemoveCountry: function(cc) {
		this.poolStripCountry(cc);
		this._poolCommit();
	},

	// Narrow a country to specific city codes. All cities selected collapses
	// back to the whole country; none removes it entirely.
	poolSetCities: function(cc, codes) {
		var all = this.poolCitiesOf(cc).map(function(c) { return c.code; });
		if (!codes.length)
			return this.poolRemoveCountry(cc);
		if (all.length && codes.length >= all.length)
			return this.poolSetWhole(cc);
		this.poolStripCountry(cc);
		codes.forEach(L.bind(function(code) {
			var e = this.poolResolve(code);
			if (e)
				this.poolEntries.push(e);
		}, this));
		this._poolCommit();
	},

	// Toggle one city. From a whole country, the first uncheck expands to
	// "every city except this one".
	poolToggleCity: function(cc, code) {
		var st = this.poolCountryHas(cc);
		var all = this.poolCitiesOf(cc).map(function(c) { return c.code; });
		var sel;
		if (st.whole) {
			sel = all.filter(function(x) { return x !== code; });
		} else {
			sel = Object.keys(st.cities);
			if (sel.indexOf(code) >= 0)
				sel = sel.filter(function(x) { return x !== code; });
			else
				sel.push(code);
		}
		this.poolSetCities(cc, sel);
	},

	// The "whole country" master toggle.
	poolToggleWhole: function(cc) {
		if (this.poolCountryHas(cc).whole)
			this.poolRemoveCountry(cc);
		else
			this.poolSetWhole(cc);
	},

	// Repaint the cascade picker, chips and the counter. Re-resolves entries,
	// so it is also the hop-mode/locations change hook. Also maintains the
	// country-code → name/data maps used by the cascade and server labels.
	rebuildPoolWidget: function() {
		if (!this.poolChips)
			return;
		this.poolEntries = (this.poolEntries || []).map(L.bind(function(e) {
			return this.poolResolve(e.code);
		}, this)).filter(function(e) { return e != null; });

		this._ccData = {};
		this.filteredCountries().forEach(L.bind(function(c) {
			this._ccData[c.code] = c;
		}, this));
		// Keep an open panel in sync with the set (✓ marks, counts, city lists).
		if (this._poolOpen)
			this.poolRenderPanel();

		dom.content(this.poolChips, '');
		// One chip per country (country-first model). A whole-country chip shows
		// just the country; a narrowed one lists its picked cities. Remove drops
		// the whole country; the pencil opens its city checklist.
		// Entries not available in the current hop mode are hidden (shown as "not
		// selected") rather than as broken raw codes; switching modes therefore
		// reads as an empty set until valid locations are picked. They stay in
		// poolEntries so a round-trip mode switch does not lose them, and are
		// dropped from what gets saved (collectIntoUci filters the same way).
		var groups = [], byCc = {};
		this.poolEntries.forEach(function(e) {
			if (e.count == null)
				return;
			var cc = e.kind === 'country' ? e.code : e.code.split('-')[0];
			var g = byCc[cc];
			if (!g) {
				g = { cc: cc, flag: e.flag, whole: null, cities: [] };
				byCc[cc] = g;
				groups.push(g);
			}
			if (e.kind === 'country')
				g.whole = e;
			else
				g.cities.push(e);
		});

		var total = 0;
		groups.forEach(function(g) {
			if (g.whole) {
				if (g.whole.count != null) total += g.whole.count;
			} else {
				g.cities.forEach(function(e) { if (e.count != null) total += e.count; });
			}
		});

		groups.forEach(L.bind(function(g) {
			var cname = this.countryLabel(g.cc);
			var flag = g.flag || '';
			var label, stale;
			if (g.whole) {
				stale = g.whole.name == null;
				label = (flag ? flag + ' ' : '') + cname +
					(g.whole.count != null ? ' (%d)'.format(g.whole.count) : '');
			} else {
				stale = g.cities.some(function(e) { return e.name == null; });
				var cities = g.cities.map(function(e) { return e.name || e.code; }).join(', ');
				label = (flag ? flag + ' ' : '') + cname + ' · ' + cities;
			}
			// The whole chip opens this country's editor (cities + remove); no
			// separate ×/pencil buttons.
			this.poolChips.appendChild(E('span', {
				class: 'pv-chip pv-chip-country pv-chip-click' + (stale ? ' pv-chip-stale' : ''),
				title: _('Edit or remove'),
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolOpenCountry(g.cc, true); }, this) },
				label));
		}, this));

		var summary = '';
		if (groups.length)
			summary = total ? _('set: %d countries, ~%d servers').format(groups.length, total)
				: _('set: %d countries').format(groups.length);
		this.poolChips.appendChild(this.poolCount);
		dom.content(this.poolCount, summary);

		// Guidance: the server list drives the picker, and the set must not be
		// empty — the connection picks within it.
		var note = '';
		if (!(this.locations || {}).available)
			note = _('Loading server list… use "Refresh server list" in Advanced settings if it does not appear.');
		else if (!groups.length)
			note = _('Add at least one country or city.');
		dom.content(this.poolNote, note);
		this.poolNote.classList.toggle('hidden', !note);
		if (this.poolTrigger)
			this.poolTrigger.disabled = !(this.locations || {}).available;
	},

	/* ---- location picker panel --------------------------------------- */

	poolTogglePanel: function() {
		if (this._poolOpen)
			return this.poolClosePanel();
		this._poolLevel = 'country';
		this._poolCountry = null;
		this._poolFilter = '';
		this._poolOpen = true;
		if (this.poolTrigger) this.poolTrigger.classList.add('hidden');
		this.poolPanel.classList.remove('hidden');
		this.poolRenderPanel();
	},

	poolClosePanel: function() {
		this._poolOpen = false;
		if (this.poolPanel) this.poolPanel.classList.add('hidden');
		if (this.poolTrigger) this.poolTrigger.classList.remove('hidden');
	},

	// Open a country's city checklist. Entering a country selects it whole
	// ("pick a country = whole country in the set"); checkboxes then narrow it.
	// edit=true means we came from a chip (editing that country): no "back to
	// countries", but a "remove this country" action instead. edit=false is the
	// add flow from the country list (keeps a back step).
	poolOpenCountry: function(cc, edit) {
		if (!this.poolCountryHas(cc).has)
			this.poolSetWhole(cc);
		this._poolLevel = 'city';
		this._poolCountry = cc;
		this._poolEdit = !!edit;
		this._poolFilter = '';
		this._poolOpen = true;
		if (this.poolTrigger) this.poolTrigger.classList.add('hidden');
		this.poolPanel.classList.remove('hidden');
		this.poolRenderPanel();
	},

	// City level: a back row, a "Whole country" master toggle, then a checkbox
	// per city. Country level: a header with close, a filter, the country list.
	poolRenderPanel: function() {
		var panel = this.poolPanel;
		if (!panel)
			return;
		dom.content(panel, '');

		if (this._poolLevel === 'city') {
			var cc = this._poolCountry;
			var c = (this._ccData || {})[cc];
			if (this._poolEdit) {
				var cflag = this.countryFlag(cc);
				panel.appendChild(E('div', { class: 'pv-pool-head' }, [
					E('span', {}, (cflag ? cflag + ' ' : '') + (this.countryLabel(cc))),
					E('button', { type: 'button', class: 'pv-pool-x', title: _('Done'),
						click: L.bind(function(ev) { ev.stopPropagation(); this.poolClosePanel(); }, this) }, '✕')
				]));
			} else {
				panel.appendChild(E('div', { class: 'pv-pool-head' }, [
					E('span', { class: 'pv-pool-back', style: 'cursor:pointer',
						click: L.bind(function(ev) {
							ev.stopPropagation();
							this._poolLevel = 'country';
							this._poolCountry = null;
							this._poolFilter = '';
							this.poolRenderPanel();
						}, this) }, '‹ ' + _('Back to countries')),
					E('button', { type: 'button', class: 'pv-pool-x', title: _('Close'),
						click: L.bind(function(ev) { ev.stopPropagation(); this.poolClosePanel(); }, this) }, '✕')
				]));
			}
			panel.appendChild(E('div', { class: 'pv-pool-sep' }));
			if (!c) {
				panel.appendChild(E('div', { class: 'pv-pool-row is-in' }, _('No cities available')));
				return;
			}
			var st = this.poolCountryHas(cc);
			panel.appendChild(E('div', { class: 'pv-pool-row',
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolToggleWhole(cc); }, this) }, [
					E('span', { class: 'box' }, st.whole ? '☑' : '☐'),
					E('span', { class: 'grow' }, _('Whole country (%d)').format(c.gateway_count || 0))
				]));
			panel.appendChild(E('div', { class: 'pv-pool-sep' }));
			var key = this.hopCountKey();
			(c.cities || []).forEach(L.bind(function(city) {
				var on = st.whole || !!st.cities[city.code];
				panel.appendChild(E('div', { class: 'pv-pool-row',
					click: L.bind(function(ev) { ev.stopPropagation(); this.poolToggleCity(cc, city.code); }, this) }, [
						E('span', { class: 'box' }, on ? '☑' : '☐'),
						E('span', { class: 'grow' }, '%s (%d)'.format(city.name, city[key] || 0))
					]));
			}, this));
			if (this._poolEdit) {
				panel.appendChild(E('div', { class: 'pv-pool-sep' }));
				panel.appendChild(E('div', { class: 'pv-pool-row pv-pool-remove',
					click: L.bind(function(ev) {
						ev.stopPropagation();
						this.poolRemoveCountry(cc);
						this.poolClosePanel();
					}, this) }, [
						E('span', { class: 'box' }, '🗑'),
						E('span', { class: 'grow' }, _('Remove this country'))
					]));
			}
			return;
		}

		panel.appendChild(E('div', { class: 'pv-pool-head' }, [
			E('span', {}, _('Add a location')),
			E('button', { type: 'button', class: 'pv-pool-x', title: _('Close'),
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolClosePanel(); }, this) }, '✕')
		]));
		var filt = E('input', { type: 'text', class: 'cbi-input-text pv-pool-filter',
			placeholder: _('Filter') + '…', value: this._poolFilter });
		filt.addEventListener('input', L.bind(function() {
			this._poolFilter = filt.value;
			this.poolRenderCountryList();
		}, this));
		filt.addEventListener('click', function(ev) { ev.stopPropagation(); });
		panel.appendChild(filt);
		this._poolListEl = E('div', {});
		panel.appendChild(this._poolListEl);
		this.poolRenderCountryList();
		setTimeout(function() { try { filt.focus(); } catch (e) {} }, 0);
	},

	// Country rows, filtered. Mark: whole = check, partial = half, none = blank.
	// Clicking a row opens that country (adding it whole, then narrow-able).
	poolRenderCountryList: function() {
		var el = this._poolListEl;
		if (!el)
			return;
		dom.content(el, '');
		var f = (this._poolFilter || '').toLowerCase();
		var any = false;
		this.filteredCountries().forEach(L.bind(function(c) {
			if (f && c.name.toLowerCase().indexOf(f) < 0 && c.code.toLowerCase().indexOf(f) < 0)
				return;
			any = true;
			var st = this.poolCountryHas(c.code);
			var mark = st.whole ? '☑' : (st.has ? '◐' : '');
			var flag = this.countryFlag(c.code);
			el.appendChild(E('div', { class: 'pv-pool-row' + (st.has ? ' is-in' : ''),
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolOpenCountry(c.code); }, this) }, [
					E('span', { class: 'box' }, mark),
					E('span', { class: 'grow' }, (flag ? flag + ' ' : '') +
						'%s (%d)'.format(c.name, c.gateway_count || 0)),
					E('span', { class: 'chev' }, '›')
				]));
		}, this));
		if (!any)
			el.appendChild(E('div', { class: 'pv-pool-row is-in' }, _('No matches')));
	},
	srvLoadClass: function(load) {
		if (typeof load !== 'number')
			return '';
		return load < 50 ? 'pv-dot-lo' : (load < 80 ? 'pv-dot-mid' : 'pv-dot-hi');
	},

	// The gateway the tunnel is on right now (live status), to flag it.
	srvCurrentGateway: function() {
		return (this.status && this.status.gateway) || '';
	},

	srvRelayByHost: function(host) {
		var found = null;
		((this._serverData && this._serverData.relays) || []).forEach(function(r) {
			if (r.name === host || r.hostname === host) found = r;
		});
		return found;
	},

	// Proton publishes a Score per server and its own Quick Connect takes the
	// lowest one, so the quick pick follows that rather than raw load.
	srvBestScore: function() {
		var best = null;
		((this._serverData && this._serverData.relays) || []).forEach(function(r) {
			if (typeof r.score !== 'number') return;
			if (!best || r.score < best.score) best = r;
		});
		return best;
	},

	// The trigger shows the current pin richly (load dot / flag / city / name),
	// or "Automatic server", with an inline clear when pinned.
	srvRenderTrigger: function() {
		var t = this.srvTrigger;
		if (!t)
			return;
		var host = this._serverChosen;
		if (!host) {
			dom.content(t, _('Automatic server'));
			return;
		}
		var r = this.srvRelayByHost(host);
		var kids;
		if (r) {
			var flag = this.countryFlag(r.country_code);
			kids = [
				E('span', { class: 'pv-dot ' + this.srvLoadClass(r.load) }),
				E('span', {}, ' ' + (flag ? flag + ' ' : '') +
					'%s / %s'.format(r.city || '?', r.name || r.hostname) +
					(r.load != null ? ' (%d%%)'.format(r.load) : ''))
			];
		} else {
			kids = [ E('span', {}, host + ' ' + _('(not in the set)')) ];
		}
		kids.push(E('button', { type: 'button', class: 'pv-srv-x', title: _('Clear (back to automatic)'),
			click: L.bind(function(ev) { ev.preventDefault(); ev.stopPropagation(); this.srvSetChosen(''); }, this) }, '×'));
		dom.content(t, kids);
	},

	srvTogglePanel: function() {
		if (this._srvOpen)
			return this.srvClosePanel();
		this._srvFilter = '';
		this._srvOpen = true;
		if (this.srvTrigger) this.srvTrigger.classList.add('hidden');
		this.srvPanel.classList.remove('hidden');
		this.srvRenderPanel();
	},

	srvClosePanel: function() {
		this._srvOpen = false;
		if (this.srvPanel) this.srvPanel.classList.add('hidden');
		if (this.srvTrigger) this.srvTrigger.classList.remove('hidden');
	},

	srvSetChosen: function(host) {
		this._serverChosen = host || '';
		this.markDirty();
		this.updateRotationAvailability();
		this.srvRenderTrigger();
		this.srvClosePanel();
	},

	// Panel: header + filter, quick "Automatic" and "Lowest load" rows, then
	// servers grouped by country and sorted by load (lowest first).
	srvRenderPanel: function() {
		var panel = this.srvPanel;
		if (!panel)
			return;
		dom.content(panel, '');
		panel.appendChild(E('div', { class: 'pv-pool-head' }, [
			E('span', {}, _('Pick a server')),
			E('button', { type: 'button', class: 'pv-pool-x', title: _('Close'),
				click: L.bind(function(ev) { ev.stopPropagation(); this.srvClosePanel(); }, this) }, '✕')
		]));
		var filt = E('input', { type: 'text', class: 'cbi-input-text pv-pool-filter',
			placeholder: _('Filter servers') + '…', value: this._srvFilter });
		filt.addEventListener('input', L.bind(function() {
			this._srvFilter = filt.value;
			this.srvRenderList();
		}, this));
		filt.addEventListener('click', function(ev) { ev.stopPropagation(); });
		panel.appendChild(filt);
		this._srvListEl = E('div', {});
		panel.appendChild(this._srvListEl);
		this.srvRenderList();
		setTimeout(function() { try { filt.focus(); } catch (e) {} }, 0);
	},

	srvRenderList: function() {
		var el = this._srvListEl;
		if (!el)
			return;
		dom.content(el, '');
		var chosen = this._serverChosen;
		var current = this.srvCurrentGateway();
		var f = (this._srvFilter || '').toLowerCase();

		el.appendChild(E('div', { class: 'pv-pool-row pv-srv-quick',
			click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(''); }, this) }, [
				E('span', { class: 'box' }, chosen ? '' : '☑'),
				E('span', { class: 'grow' }, _('Automatic (rotation picks)'))
			]));
		var best = this.srvBestScore();
		if (best) {
			var bn = this.countryLabel(best.country_code);
			el.appendChild(E('div', { class: 'pv-pool-row pv-srv-quick',
				click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(best.name || best.hostname); }, this) }, [
					E('span', { class: 'box' }, '⚡'),
					E('span', { class: 'grow' }, _('Best (Quick Connect)') + ' · ' + (best.city || bn) +
						(best.load != null ? ' (%d%%)'.format(best.load) : '')),
					E('span', { class: 'pv-dot ' + this.srvLoadClass(best.load) })
				]));
		}
		el.appendChild(E('div', { class: 'pv-pool-sep' }));

		var groups = [], byCode = {};
		((this._serverData && this._serverData.relays) || []).forEach(L.bind(function(r) {
			var cname = this.countryLabel(r.country_code);
			var hay = (cname + ' / ' + (r.city || '') + ' / ' + (r.name || r.hostname)).toLowerCase();
			if (f && r.hostname !== chosen && hay.indexOf(f) < 0)
				return;
			var g = byCode[r.country_code];
			if (!g) {
				g = { name: cname, flag: this.countryFlag(r.country_code), rows: [] };
				byCode[r.country_code] = g;
				groups.push(g);
			}
			g.rows.push(r);
		}, this));
		groups.forEach(L.bind(function(g) {
			// Score first (Proton's own ordering), load only as a tiebreak.
			g.rows.sort(function(a, b) {
				var as = typeof a.score === 'number' ? a.score : 1e9;
				var bs = typeof b.score === 'number' ? b.score : 1e9;
				if (as !== bs)
					return as - bs;
				return (a.load || 0) - (b.load || 0);
			});
			el.appendChild(E('div', { class: 'pv-srv-grp' }, (g.flag ? g.flag + ' ' : '') +
				'%s (%d)'.format(g.name, g.rows.length)));
			g.rows.forEach(L.bind(function(r) {
				var isCur = current && (r.name === current || r.hostname === current);
				var isPin = (r.name || r.hostname) === chosen;
				el.appendChild(E('div', { class: 'pv-pool-row' + (isPin ? ' is-in' : ''),
					click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(r.name || r.hostname); }, this) }, [
						E('span', { class: 'pv-dot ' + this.srvLoadClass(r.load) }),
						E('span', { class: 'grow' }, '%s / %s'.format(r.city || '?', r.name || r.hostname)),
						r.secure_core ? E('span', { class: 'pv-tagline' },
							this.countryLabel(r.entry_country) + ' → ') : '',
						r.tier === 0 ? E('span', { class: 'pv-tagline' }, _('free')) : '',
						isCur ? E('span', { class: 'pv-srv-cur' }, '● ' + _('current')) : '',
						E('span', { class: 'pv-srv-load' }, r.load != null ? '%d%%'.format(r.load) : '')
					]));
			}, this));
		}, this));

		if (chosen && !this.srvRelayByHost(chosen))
			el.appendChild(E('div', { class: 'pv-pool-row is-in' }, chosen + ' ' + _('(not in the set)')));
		else if (!groups.length)
			el.appendChild(E('div', { class: 'pv-pool-row is-in' }, _('No matches')));
	},

	onHopChange: function() {
		this.markDirty();
		this.updateHopButtons();
		this.rebuildPoolWidget();
		this.refreshServerList();
	},

	// ── credential banner ────────────────────────────────────────────────

	// Session expiry is NOT an outage: the tunnel and rotation keep working
	// from the cache, so the banner stays calm until the certificate — the
	// real deadline — is at risk.
	renderBand: function () {
		if (!this.bandEl)
			return;
		var st = this.session || {};
		var title, sub, led, actions, cls = 'pv-acct';

		if (st.state === 'active') {
			led = 'pv-led-ok';
			title = _('Signed in to Proton');
			// The 30-minute access token is refreshed silently, so only the
			// session horizon is worth showing here.
			sub = _('Session valid until %s. The router keeps it alive on its own — you will not be asked again unless it stays offline for weeks.')
				.format(fmtTime(st.session_expires_at));
			actions = [
				E('button', { class: 'cbi-button',
					click: ui.createHandlerFn(this, 'handleRefreshLocations') },
					_('Update server list')),
				E('button', { class: 'cbi-button cbi-button-remove',
					click: ui.createHandlerFn(this, 'handleLogout') }, _('Sign out'))
			];
		} else if (st.state === 'needs_2fa') {
			cls += ' pv-acct-warn';
			led = 'pv-led-warn';
			title = _('Two-factor code required');
			sub = _('The password was accepted; enter the code from your authenticator to finish.');
			actions = [
				E('button', { class: 'cbi-button cbi-button-apply',
					click: ui.createHandlerFn(this, 'showLoginModal', 'totp') }, _('Enter code'))
			];
		} else if (st.state === 'expired') {
			cls += ' pv-acct-warn';
			led = 'pv-led-warn';
			title = _('Proton session expired');
			// Deliberately calm: an expired session does not drop the tunnel.
			sub = _('The tunnel keeps running, but the server list cannot be updated and the certificate cannot be renewed. Sign in again to restore that.');
			actions = [
				E('button', { class: 'cbi-button cbi-button-apply',
					click: ui.createHandlerFn(this, 'showLoginModal', 'credentials') },
					_('Sign in again'))
			];
		} else {
			cls += ' pv-acct-bad';
			led = 'pv-led-bad';
			title = _('Not signed in');
			sub = _('ProtonVPN needs your account to fetch the server list and register this router as a device.');
			actions = [
				E('button', { class: 'cbi-button cbi-button-apply',
					click: ui.createHandlerFn(this, 'showLoginModal', 'credentials') }, _('Sign in'))
			];
		}

		this.bandEl.className = cls;
		dom.content(this.bandEl, [
			E('div', { class: 'pv-acct-main' }, [
				E('div', { class: 'pv-acct-title' }, [
					E('span', { class: 'pv-led ' + led }), E('span', {}, title)
				]),
				E('div', { class: 'pv-acct-sub' }, sub)
			]),
			E('div', { class: 'pv-acct-actions' }, actions)
		]);
	},

	// ── connection status ────────────────────────────────────────────────

	// What the tunnel is doing right now, plus the actions that change it.
	// Kept separate from the account card above: one is about credentials,
	// this one is about the link.
	updateStatusBand: function () {
		if (!this.stateEl)
			return;
		var st = this.status || {};
		var led = 'pv-led-bad', title, sub = [], cls = 'pv-state';

		if (st.state === 'connected') {
			led = 'pv-led-ok';
			title = _('Connected');
		} else if (st.state === 'degraded') {
			led = 'pv-led-warn';
			cls += ' pv-acct-warn';
			title = _('Degraded — no recent handshake');
		} else if (st.state === 'connecting') {
			led = 'pv-led-warn';
			title = _('Connecting…');
		} else if (st.state === 'not_configured') {
			title = _('Not set up yet');
		} else if (!st.enabled) {
			title = _('Disabled');
		} else {
			title = _('Disconnected');
		}

		if (st.gateway)
			sub.push(_('Server %s').format(st.gateway));
		if (st.location && st.location.country)
			sub.push(this.countryFlag(st.location.country) + ' ' +
				this.countryLabel(st.location.country));
		if (st.endpoint)
			sub.push(st.endpoint);
		if (st.latest_handshake_seconds != null)
			sub.push(_('handshake %ds ago').format(st.latest_handshake_seconds));
		if (this.externalIp)
			sub.push(_('external IP %s').format(this.externalIp));
		if (st.certificate && st.certificate.present && st.certificate.days_left != null)
			sub.push(_('certificate %d days left').format(st.certificate.days_left));

		// The connection budget is shared with every other device on the
		// account, so a refused tunnel is often just "all slots taken".
		var quota = '';
		if (this.account && this.account.max_connect)
			quota = _('%s · %s of %s connections in use').format(
				this.account.plan || '', this.account.sessions_used != null
					? this.account.sessions_used : '?', this.account.max_connect);

		var actions = [];
		var configured = st.configured;
		if (st.state === 'connected' || st.state === 'degraded' || st.enabled) {
			actions.push(E('button', { class: 'cbi-button cbi-button-remove',
				click: ui.createHandlerFn(this, 'handleDisconnect') }, _('Disconnect')));
		}
		actions.push(E('button', { class: 'cbi-button cbi-button-apply',
			click: ui.createHandlerFn(this, 'handleConnect') },
			configured ? _('Reconnect') : _('Connect')));
		// Rotation makes no sense on a pinned server; the backend refuses it
		// anyway, so do not offer a button that cannot work.
		if (!st.fixed && st.state === 'connected')
			actions.push(E('button', { class: 'cbi-button',
				click: ui.createHandlerFn(this, 'handleRotateNow') }, _('Rotate now')));

		this.stateEl.className = cls;
		dom.content(this.stateEl, [
			E('div', { class: 'pv-state-main' }, [
				E('div', { class: 'pv-state-title' }, [
					E('span', { class: 'pv-led ' + led }), E('span', {}, title)
				]),
				E('div', { class: 'pv-state-sub' }, sub.join(' · ') || _('No tunnel yet.')),
				quota ? E('div', { class: 'pv-quota' }, quota) : ''
			]),
			E('div', { class: 'pv-state-actions' }, actions)
		]);
	},

	// Plan and connection quota. Two live API calls, so this is refreshed only
	// on demand (page load, login, connect) rather than on the status poll.
	loadAccount: function () {
		var self = this;
		return callAccount().then(function (acct) {
			self.account = (acct && !acct.error) ? acct : null;
			self.updateStatusBand();
		}).catch(function () {});
	},

	refreshStatus: function () {
		var self = this;
		return Promise.all([
			callStatus(this.instance).catch(function () { return null; }),
			callSessionState().catch(function () { return null; })
		]).then(function (res) {
			if (res[0] && !res[0].error)
				self.status = res[0];
			if (res[1])
				self.session = res[1];
			self.updateStatusBand();
			self.renderBand();
		});
	},

	handleConnect: function () {
		var self = this;
		this.notice(_('Connecting… this verifies a real WireGuard handshake and can take a few seconds.'), 'info');
		return callApply(this.instance).then(function (res) {
			if (!res || res.error) {
				self.notice((res && res.error) || _('apply failed'), 'warning');
			} else if (res.state === 'success') {
				self.notice(_('Connected via %s.').format(res.gateway || '?'), 'info');
				// Only worth asking once the tunnel is actually up.
				callExternalIp(self.instance).then(function (ip) {
					if (ip && ip.ip) {
						self.externalIp = ip.ip;
						self.updateStatusBand();
					}
				}).catch(function () {});
			} else {
				self.notice(res.error || _('the tunnel did not come up'), 'warning');
			}
			return self.refreshStatus().then(function () { return self.loadAccount(); });
		});
	},

	handleDisconnect: function () {
		var self = this;
		this.externalIp = null;
		return callDisconnect(this.instance).then(function () {
			return self.refreshStatus();
		});
	},

	handleRotateNow: function () {
		var self = this;
		this.notice(_('Rotating…'), 'info');
		return callRotateNow(this.instance).then(function (res) {
			if (res && res.error)
				self.notice(res.error, 'warning');
			else if (res && res.skipped)
				self.notice(res.reason || _('nothing to rotate to'), 'info');
			else if (res && res.server)
				self.notice(_('Rotated to %s.').format(res.server), 'info');
			self.externalIp = null;
			return self.refreshStatus();
		});
	},

	// ── sections ─────────────────────────────────────────────────────────

	// LuCI's own two-column form markup, so the page lines up with every other
	// LuCI page instead of inventing a private layout.
	row: function (labelText, fieldNodes, descText) {
		var field = E('div', { class: 'cbi-value-field' }, fieldNodes);
		if (descText)
			field.appendChild(E('div', { class: 'cbi-value-description' }, descText));
		return E('div', { class: 'cbi-value' }, [
			E('label', { class: 'cbi-value-title' }, labelText),
			field
		]);
	},

	buildConnection: function () {
		var self = this;
		// The persisted state is (re)read here rather than in render(), because
		// the whole form is rebuilt on discard and must start from UCI again.
		this.hopValue = uci.get('protonvpn', this.instance, 'hop_mode') || 'standard';
		this._serverChosen = uci.get('protonvpn', this.instance, 'fixed_server') || '';
		this.poolEntries = [];
		var seed = uci.get('protonvpn', this.instance, 'locations') || [];
		if (typeof seed === 'string')
			seed = seed.length ? [ seed ] : [];
		seed.forEach(L.bind(function (code) {
			var e = this.poolResolve(code);
			if (e)
				this.poolEntries.push(e);
		}, this));

		this.hopButtons = {};
		var seg = E('div', { class: 'pv-seg' }, [
			[ 'standard', _('Standard') ],
			[ 'secure_core', _('Secure Core') ],
			[ 'tor', _('Tor') ]
		].map(L.bind(function (o) {
			var b = E('button', { type: 'button', click: L.bind(this.setHopMode, this, o[0]) }, o[1]);
			this.hopButtons[o[0]] = b;
			return b;
		}, this)));
		this.hopNote = E('div', { class: 'cbi-value-description' });

		this.poolChips = E('div', { class: 'pv-pool' });
		this.poolCount = E('span', { class: 'pv-pool-count' });
		this.poolNote = E('div', { class: 'cbi-value-description' });
		this.poolTrigger = E('button', { class: 'cbi-button',
			click: ui.createHandlerFn(this, 'poolTogglePanel') }, '+ ' + _('Add a location'));
		this.poolPanel = E('div', { class: 'pv-pool-panel hidden' });
		this.poolWrap = E('div', { class: 'pv-pool-wrap' }, [ this.poolTrigger, this.poolPanel ]);

		this.srvTrigger = E('button', { class: 'cbi-button pv-srv-trigger',
			click: ui.createHandlerFn(this, 'srvTogglePanel') }, _('Automatic server'));
		this.srvPanel = E('div', { class: 'pv-pool-panel hidden' });

		this.srvWrap = E('span', { class: 'pv-pool-wrap' }, [ this.srvTrigger, this.srvPanel ]);

		// Initial repaint: the same hooks a user edit would trigger.
		this.updateHopButtons();
		this.rebuildPoolWidget();
		this.refreshServerList();

		return E('fieldset', { class: 'cbi-section' }, [
			E('legend', {}, _('Connection')),
			E('div', { class: 'cbi-section-node' }, [
				this.row(_('Hop mode'), [ seg, this.hopNote ]),
				this.row(_('Locations'), [
					E('div', {}, [ this.poolChips ]),
					this.poolWrap,
					this.poolNote
				], _('Countries this instance connects between. Picking a country adds the whole country; open its chip to narrow it to specific cities. The initial connect and the rotation both pick within this set.')),
				this.row(_('Server'), [
					this.srvWrap
				], _('Automatic picks a server from the set (rotation-friendly). Pin a specific one to lock it; pinning disables automatic rotation.'))
			])
		]);
	},

	buildFormSections: function () {
		this.refs = {};
		// Building the form fires the same change paths as user input; the
		// guard keeps programmatic construction from marking the form dirty.
		this._building = true;
		var sections = [ this.buildConnection(), this.buildRoutingSection(), this.buildRotation(), this.buildAdvanced() ];
		// Sync the pin-dependent rows once every section exists (Connection is
		// built before the rotation and advanced ones).
		this.updateRotationAvailability();
		this._building = false;
		return sections;
	},

	input: function (key, type, value, attrs) {
		var el = E('input', Object.assign({
			type: type || 'text',
			class: 'cbi-input-text',
			value: (value != null ? value : '')
		}, attrs || {}));
		el.addEventListener('input', L.bind(this.markDirty, this));
		el.addEventListener('change', L.bind(this.markDirty, this));
		this.refs[key] = el;
		return el;
	},

	// Traffic-routing panel. In a detected manual scheme it is purely
	// informational; otherwise it drives the backend's stamped auto-routing.
	buildRoutingSection: function () {
		var self = this;
		var g = function (o, d) { return uci.get('protonvpn', self.instance, o) || d; };
		var rt = (this.status || {}).routing || {};
		var body = E('div', { class: 'cbi-section-node' });
		this.autoRouting = null;
		this.steerBoxes = {};
		this.steerRow = null;

		// Read-only context: the interface and table this instance uses, so the
		// firewall/routing wiring is visible right here — not only in Advanced.
		var iface = (this.status || {}).interface || g('interface', 'protonvpn');
		var tbl = g('routing_table', '') || iface;
		body.appendChild(this.row(_('Interface / table'), [
			E('span', { class: 'pv-inline-note' },
				_('Interface %s · routing table %s — edit under Advanced settings.').format(iface, tbl))
		]));

		if (rt.mode === 'manual') {
			var what = [];
			if (rt.user_routes)
				what.push(_('%d custom route(s)/rule(s)').format(rt.user_routes));
			var table = g('routing_table', '');
			if (table)
				what.push(_('routing table "%s"').format(table));
			body.appendChild(this.row(_('Mode'), [
				E('div', {}, [
					E('span', {}, _('Manual — %s detected. The app leaves routing and firewall untouched.')
						.format(what.join(' + ') || _('custom configuration'))),
					E('div', { class: 'cbi-value-description' },
						_('Remove your own routes/rules that reference this interface to manage routing from here.'))
				])
			]));
			if (rt.ipv6_wan)
				body.appendChild(this.row('', [ E('span', { class: 'pv-inline-note' },
					_('⚠ IPv6 is active on the WAN and bypasses the VPN unless your rules cover it.')) ]));
		} else {
			this.autoRouting = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
			this.autoRouting.checked = (g('auto_routing', '1') === '1');
			this.ksBox = E('input', { type: 'checkbox', change: L.bind(this.markDirty, this) });
			this.ksBox.checked = (g('killswitch', '0') === '1');
			this.v6Box = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
			this.v6Box.checked = (g('block_ipv6', '1') === '1');
			this.v6Warn = E('div', { class: 'cbi-value-description pv-inline-note hidden' },
				_('⚠ IPv6 stays outside the tunnel and can leak your address.'));

			this.steerBoxes = {};
			var current = uci.get('protonvpn', this.instance, 'source_network');
			var currentList = Array.isArray(current) ? current : (current ? [ current ] : []);
			var nets = rt.networks || [];
			this.steerWrap = E('div', { class: 'pv-inline', style: 'gap:1em' }, nets.map(L.bind(function (n) {
				var cb = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
				cb.checked = currentList.indexOf(n) >= 0;
				this.steerBoxes[n] = cb;
				return E('label', { class: 'pv-check' }, [ cb, n ]);
			}, this)));

			body.appendChild(this.row(_('Traffic routing'), [
				E('label', { class: 'pv-check' }, [ this.autoRouting, _('Route all LAN traffic through the VPN') ])
			], _('Creates a firewall zone and a default route via the tunnel; disabling removes exactly what was created.')));
			this.steerRow = this.row(_('Steered networks'), [ this.steerWrap ],
				_('Or route only these networks through this instance — policy rules send their traffic into its routing table.'));
			if (nets.length)
				body.appendChild(this.steerRow);
			this.ksRow = this.row(_('Kill switch'), [
				E('label', { class: 'pv-check' }, [ this.ksBox, _('Block LAN internet access while the VPN is down') ])
			]);
			this.v6Row = this.row(_('IPv6'), [
				E('label', { class: 'pv-check' }, [ this.v6Box, _('Block direct IPv6 to prevent leaks') ]),
				this.v6Warn
			]);
			body.appendChild(this.ksRow);
			body.appendChild(this.v6Row);
			this.onRoutingToggle(true);
		}

		return E('fieldset', { class: 'cbi-section' }, [
			E('legend', {}, _('Traffic routing')),
			body
		]);
	},

	steeredNetworks: function () {
		var out = [];
		for (var k in (this.steerBoxes || {}))
			if (this.steerBoxes[k].checked)
				out.push(k);
		return out;
	},

	onRoutingToggle: function (init) {
		if (init !== true)
			this.markDirty();
		var auto = this.autoRouting && this.autoRouting.checked;
		var on = auto || this.steeredNetworks().length > 0;
		if (this.steerRow) this.steerRow.classList.toggle('hidden', !!auto);
		if (this.ksRow) this.ksRow.classList.toggle('hidden', !on);
		if (this.v6Row) this.v6Row.classList.toggle('hidden', !on);
		var rt = (this.status || {}).routing || {};
		if (this.v6Warn)
			this.v6Warn.classList.toggle('hidden', !(on && this.v6Box && !this.v6Box.checked && rt.ipv6_wan));
	},

	buildRotation: function () {
		var enabled = (uci.get('protonvpn', this.instance, 'rotation_enabled') === '1');
		var mode = uci.get('protonvpn', this.instance, 'rotation_mode') || 'interval';
		var interval = uci.get('protonvpn', this.instance, 'rotation_interval') || '360';
		var time = uci.get('protonvpn', this.instance, 'rotation_time') || '04:30';

		this.rotEnable = E('input', { type: 'checkbox', change: L.bind(this.onRotationToggle, this) });
		this.rotEnable.checked = enabled;

		this.rotModeInterval = E('input', { type: 'radio', name: 'pv-rotmode', value: 'interval', change: L.bind(this.onRotationToggle, this) });
		this.rotModeTime = E('input', { type: 'radio', name: 'pv-rotmode', value: 'time', change: L.bind(this.onRotationToggle, this) });
		(mode === 'time' ? this.rotModeTime : this.rotModeInterval).checked = true;

		this.rotInterval = E('select', { class: 'cbi-input-select', change: L.bind(this.markDirty, this) });
		[ [ '60', _('Every hour') ], [ '180', _('Every 3 hours') ], [ '360', _('Every 6 hours') ],
		  [ '720', _('Every 12 hours') ], [ '1440', _('Every 24 hours') ] ].forEach(L.bind(function (o) {
			this.rotInterval.appendChild(E('option', { value: o[0], selected: (o[0] === interval) || null }, o[1]));
		}, this));

		this.rotTime = E('input', { type: 'time', class: 'cbi-input-text', value: time, style: 'width:auto', change: L.bind(this.markDirty, this) });
		this.refs.rotation_interval = this.rotInterval;
		this.refs.rotation_time = this.rotTime;

		this.rotFixedNote = E('div', { class: 'cbi-value-description pv-inline-note hidden' }, _('Automatic rotation is unavailable while a specific server is selected.'));
		this.rotModeRow = this.row(_('Schedule'), [
			E('div', { class: 'pv-radio-group' }, [
				E('label', {}, [ this.rotModeInterval, _('Every N hours') ]),
				E('label', {}, [ this.rotModeTime, _('At specific time') ])
			])
		]);
		this.rotIntervalRow = this.row(_('Rotation interval'), [ this.rotInterval ]);
		this.rotTimeRow = this.row(_('Rotation time'), [ this.rotTime ], _('Router local time'));
		this.rotNextSpan = E('span', {}, this.nextRotationText());
		this.rotNextRow = this.row(_('Next rotation'), [ this.rotNextSpan ]);

		var section = E('fieldset', { class: 'cbi-section', id: 'pv-rotation' }, [
			E('legend', {}, _('Automatic rotation')),
			E('div', { class: 'cbi-section-node' }, [
				this.row(_('Automatic rotation'), [
					E('label', { class: 'pv-check' }, [ this.rotEnable, _('Change server automatically on a schedule') ]),
					this.rotFixedNote
				]),
				this.rotModeRow, this.rotIntervalRow, this.rotTimeRow, this.rotNextRow
			])
		]);

		this.onRotationToggle();
		return section;
	},

	nextRotationText: function () {
		var r = ((this.status || {}).rotation) || {};
		if (!r.enabled)
			return _('Disabled');
		if (!r.next_run)
			return _('On schedule');
		var d = new Date(r.next_run * 1000);
		var diff = Math.floor((d.getTime() - Date.now()) / 1000);
		if (diff < 90)
			return '%s (%s)'.format(d.toLocaleString(), _('due now'));
		var h = Math.floor(diff / 3600), m = Math.floor((diff % 3600) / 60);
		var rel = h > 0 ? _('in %dh %dm').format(h, m) : _('in %dm').format(m);
		return '%s (%s)'.format(d.toLocaleString(), rel);
	},

	onRotationToggle: function () {
		this.markDirty();
		var on = this.rotEnable && this.rotEnable.checked && !this._serverChosen;
		var timeMode = this.rotModeTime && this.rotModeTime.checked;
		if (this.rotModeRow) this.rotModeRow.classList.toggle('hidden', !on);
		if (this.rotIntervalRow) this.rotIntervalRow.classList.toggle('hidden', !on || timeMode);
		if (this.rotTimeRow) this.rotTimeRow.classList.toggle('hidden', !on || !timeMode);
		if (this.rotNextRow) this.rotNextRow.classList.toggle('hidden', !on);
	},

	// Pin↔rotation coupling: with a pinned server there is nothing to rotate
	// between and the watchdog never fires, so those controls are disabled or
	// hidden instead of silently ignored.
	updateRotationAvailability: function () {
		var fixed = this._serverChosen;
		if (this.rotEnable) {
			this.rotEnable.disabled = !!fixed;
			if (fixed)
				this.rotEnable.checked = false;
		}
		if (this.rotFixedNote)
			this.rotFixedNote.classList.toggle('hidden', !fixed);
		// With a pinned server there are no candidates to try.
		if (this.maxRetriesRow)
			this.maxRetriesRow.classList.toggle('hidden', !!fixed);
		// The watchdog never fires with a pinned server either.
		if (this.wdRow)
			this.wdRow.classList.toggle('hidden', !!fixed);
		this.onRotationToggle();
	},

	buildAdvanced: function () {
		var self = this;
		var g = function (o, d) { return uci.get('protonvpn', self.instance, o) || d; };
		// The server-list cache is shared between instances (owned by 'main').
		var gm = function (o, d) { return uci.get('protonvpn', 'main', o) || d; };
		this.cacheRow = E('span', {}, this.cacheSummary());

		// MTU with a WAN-derived recommendation (backend computes WAN_MTU - 80).
		var rtx = (this.status || {}).routing || {};
		var recMtu = rtx.recommended_mtu;
		var curMtu = g('mtu', '');
		var atRec = recMtu && curMtu !== '' && parseInt(curMtu, 10) === recMtu;
		var mtuInput = this.input('mtu', 'number', g('mtu', ''),
			{ min: 1280, max: 1500, style: 'width:90px', placeholder: recMtu ? ('' + recMtu) : '1420' });
		var mtuCtl = [ mtuInput ];
		if (atRec) {
			mtuCtl.push(' ');
			mtuCtl.push(E('span', { style: 'color:var(--success-color-medium,#3c8c3c);font-weight:600' },
				_('✓ recommended value')));
		} else if (recMtu) {
			mtuCtl.push(' ');
			mtuCtl.push(E('button', { class: 'cbi-button', click: L.bind(function (ev) {
				ev.preventDefault();
				mtuInput.value = recMtu;
				this.markDirty();
			}, this) }, _('Use recommended')));
		}
		var mtuDesc = atRec
			? _('You are on the recommended MTU for your WAN (MTU %d). Empty = the netifd default (1420).').format(rtx.wan_mtu || 0)
			: (recMtu
				? _('Recommended %d for your WAN (MTU %d). Empty = the default (1420). Lower it if sites hang or throughput is poor — LTE/5G often need less.').format(recMtu, rtx.wan_mtu || 0)
				: _('WireGuard interface MTU. Empty = the netifd default (1420).'));

		this.wdBox = E('input', { type: 'checkbox', change: L.bind(this.markDirty, this) });
		this.wdBox.checked = (g('watchdog', '0') === '1');

		// Proton runs a single in-tunnel resolver, so the DNS mode has no
		// filtering tier — only off/standard.
		var dnsMode = g('vpn_dns', 'off');
		if (dnsMode !== 'standard')
			dnsMode = 'off';
		this.dnsSel = E('select', { class: 'cbi-input-select', change: L.bind(this.markDirty, this) }, [
			E('option', { value: 'off' }, _('Off — use system DNS')),
			E('option', { value: 'standard' }, _('ProtonVPN — in-tunnel resolver (10.2.0.1)'))
		]);
		this.dnsSel.value = dnsMode;

		var body = E('div', { class: 'cbi-section-node' }, [
			this.row(_('Interface name'), [ this.input('interface', 'text', g('interface', 'protonvpn')) ],
				_('Name of the managed WireGuard interface. ⚠ Changing it after setup recreates the tunnel under the new name and orphans the old interface’s firewall/routing objects.')),
			this.row(_('Routing table'), [ this.input('routing_table', 'text', g('routing_table', ''), { placeholder: 'main' }) ],
				_('Custom routing table (empty = the interface name when steering, otherwise the main table).')),
			this.row(_('MTU'), mtuCtl, mtuDesc),
			this.row(_('Connection wait (seconds)'), [ this.input('verify_timeout', 'number', g('verify_timeout', '8'), { min: 2, max: 30, style: 'width:80px' }) ],
				_('How long to wait for a WireGuard handshake before giving up on a server')),
			this.maxRetriesRow = this.row(_('Max server attempts'), [ this.input('max_retries', 'number', g('max_retries', '10'), { min: 1, max: 50, style: 'width:80px' }) ],
				_('How many candidate servers a rotation may try')),
			this.wdRow = this.row(_('Auto-reconnect (watchdog)'), [
				E('label', { class: 'pv-check' }, [ this.wdBox, _('Reconnect automatically when the tunnel goes stale') ])
			], _('Auto-reconnect when the tunnel goes stale (handshake-based; no external probe; off when a specific server is pinned)')),
			this.row(_('Cache directory'), [ this.input('cache_dir', 'text', gm('cache_dir', ''), { placeholder: '/tmp' }) ],
				_('Where to store the downloaded server list, shared by all instances (leave empty for /tmp)')),
			this.row(_('Server cache'), [
				E('div', { class: 'pv-inline' }, [
					this.cacheRow,
					E('button', { class: 'cbi-button', click: L.bind(this.refreshCache, this) }, _('Refresh server list'))
				])
			]),
			this.row(_('DNS'), [ this.dnsSel ],
				_('Which resolver to use while connected. Proton runs a single in-tunnel resolver (10.2.0.1); it only works through the tunnel.'))
		]);

		// The connection section is built (and may restore a pinned server)
		// before this row exists — sync the initial visibility.
		if (this._serverChosen) {
			this.maxRetriesRow.classList.add('hidden');
			this.wdRow.classList.add('hidden');
		}

		return E('details', { class: 'pv-advanced cbi-section' }, [
			E('summary', {}, _('Advanced settings')),
			body
		]);
	},

	cacheSummary: function () {
		var l = this.locations || {};
		if (!l.available)
			return _('Server list not loaded');
		var when = (l.cache_info && l.cache_info.created) ? l.cache_info.created : '';
		var count = (l.stats && l.stats.gateways) ? l.stats.gateways : 0;
		var txt = _('%d servers').format(count);
		if (when)
			txt += ' · ' + _('updated %s').format(when);
		if (l.state === 'stale')
			txt += ' · ' + _('stale');
		return txt;
	},

	// The backend has no refresh-progress method, so the button reuses the
	// banner's flow and additionally reports back into the cache summary row.
	refreshCache: function (ev) {
		var btn = ev.target;
		btn.disabled = true;
		dom.content(this.cacheRow, _('Refreshing…'));
		return this.handleRefreshLocations().then(L.bind(function () {
			btn.disabled = false;
			if (this.cacheRow)
				dom.content(this.cacheRow, this.cacheSummary());
		}, this)).catch(L.bind(function (e) {
			btn.disabled = false;
			if (this.cacheRow)
				dom.content(this.cacheRow, this.cacheSummary());
			this.notice(_('Refresh failed: %s').format(e), 'error');
		}, this));
	},

	buildActions: function () {
		this.saveBtn = E('button', {
			class: 'cbi-button cbi-button-save',
			disabled: true,
			click: L.bind(this.save, this)
		}, _('Save and reconnect'));
		this.discardBtn = E('button', {
			class: 'cbi-button',
			disabled: true,
			click: L.bind(this.discard, this)
		}, _('Discard changes'));
		return E('div', { class: 'cbi-page-actions' }, [ this.saveBtn, ' ', this.discardBtn ]);
	},

	discard: function () {
		// uci.load() is cached, so unload first or the rebuild would render the
		// very changes that are being discarded.
		uci.unload('protonvpn');
		return uci.load('protonvpn').then(L.bind(function () {
			dom.content(this.formNode, this.buildFormSections());
			this._dirty = false;
			if (this.saveBtn) this.saveBtn.disabled = true;
			if (this.discardBtn) this.discardBtn.disabled = true;
		}, this));
	},

	// ── save ─────────────────────────────────────────────────────────────

	collectIntoUci: function () {
		var inst = this.instance;
		var setv = function (o, v, section) {
			var sec = section || inst;
			if (v == null || v === '')
				uci.unset('protonvpn', sec, o);
			else
				uci.set('protonvpn', sec, o, v);
		};
		[ 'interface', 'routing_table', 'verify_timeout', 'max_retries', 'mtu' ].forEach(L.bind(function (k) {
			if (this.refs[k]) setv(k, (this.refs[k].value || '').trim());
		}, this));
		// The cache directory is shared and lives on the 'main' section.
		if (this.refs.cache_dir)
			setv('cache_dir', (this.refs.cache_dir.value || '').trim(), 'main');

		uci.set('protonvpn', inst, 'hop_mode', this.hopMode());

		// The location set is the single source of truth; the legacy
		// country/city options are cleared so both paths agree.
		var codes = (this.poolEntries || []).map(function (e) { return e.code; });
		if (codes.length)
			uci.set('protonvpn', inst, 'locations', codes);
		else
			uci.unset('protonvpn', inst, 'locations');
		uci.unset('protonvpn', inst, 'country_code');
		uci.unset('protonvpn', inst, 'city_code');

		var fixed = this._serverChosen || '';
		setv('fixed_server', fixed);

		// Routing toggles exist only when no manual scheme was detected; a
		// manual setup's options are never written.
		if (this.autoRouting) {
			var autoOn = this.autoRouting.checked;
			var steered = autoOn ? [] : this.steeredNetworks();
			uci.set('protonvpn', inst, 'auto_routing', autoOn ? '1' : '0');
			uci.set('protonvpn', inst, 'killswitch', (this.ksBox && this.ksBox.checked) ? '1' : '0');
			uci.set('protonvpn', inst, 'block_ipv6', (this.v6Box && this.v6Box.checked) ? '1' : '0');
			uci.set('protonvpn', inst, 'vpn_dns', (this.dnsSel && this.dnsSel.value) || 'off');
			if (steered.length) {
				uci.set('protonvpn', inst, 'source_network', steered);
				// Steering needs a routing table; default to the interface name.
				var rtb = this.refs.routing_table ? (this.refs.routing_table.value || '').trim()
					: (uci.get('protonvpn', inst, 'routing_table') || '');
				if (!rtb) {
					var ifn = this.refs.interface ? (this.refs.interface.value || '').trim() : '';
					ifn = ifn || uci.get('protonvpn', inst, 'interface') || 'protonvpn';
					uci.set('protonvpn', inst, 'routing_table', ifn);
					if (this.refs.routing_table)
						this.refs.routing_table.value = ifn;
				}
			} else {
				uci.unset('protonvpn', inst, 'source_network');
			}
		}

		var rotOn = this.rotEnable && this.rotEnable.checked && !fixed;
		uci.set('protonvpn', inst, 'rotation_enabled', rotOn ? '1' : '0');
		if (rotOn) {
			var timeMode = this.rotModeTime && this.rotModeTime.checked;
			setv('rotation_mode', timeMode ? 'time' : 'interval');
			setv('rotation_interval', this.rotInterval ? this.rotInterval.value : '360');
			setv('rotation_time', this.rotTime ? this.rotTime.value : '04:30');
		}

		// Written unconditionally (not tied to the routing block); the backend
		// ignores it while a server is pinned.
		uci.set('protonvpn', inst, 'watchdog', (this.wdBox && this.wdBox.checked) ? '1' : '0');
	},

	save: function () {
		var self = this;
		// A location set that resolves to nothing in the current mode would
		// leave the backend with no candidates at all.
		var valid = (this.poolEntries || []).filter(function (e) { return e.count != null; });
		if (!valid.length) {
			this.notice(_('Pick at least one location that has servers in this mode.'), 'warning');
			return;
		}
		this.collectIntoUci();
		return uci.save().then(function () {
			return uci.apply();
		}).then(function () {
			self._dirty = false;
			if (self.saveBtn)
				self.saveBtn.disabled = true;
			if (self.discardBtn)
				self.discardBtn.disabled = true;
			self.notice(_('Saved. Applying…'), 'info');
			return callApply(self.instance);
		}).then(function (res) {
			if (res && res.error)
				self.notice(res.error, 'warning');
		});
	},

	render: function (data) {
		var session = data[1] || {};
		var locations = data[2] || {};
		this.status = (data[3] && !data[3].error) ? data[3] : {};
		this.account = null;
		this.instance = 'main';
		this.session = session;
		this.locations = locations;
		this.externalIp = null;
		this._serversReq = 0;
		this._dirty = false;

		this.bandEl = E('div', { class: 'pv-acct' });
		this.stateEl = E('div', { class: 'pv-state' });
		this.formNode = E('div', {});
		dom.content(this.formNode, this.buildFormSections());

		var body = E('div', {}, [
			E('style', { type: 'text/css' }, STYLE),
			E('h2', {}, _('ProtonVPN')),
			this.bandEl,
			this.stateEl,
			this.formNode,
			this.buildActions()
		]);

		this.renderBand();
		this.updateStatusBand();
		// Limits arrive out of band; the quota line simply appears once known.
		this.loadAccount();
		// Live status: the same 5-second cadence the reference uses, so a
		// connect/rotate reflects without the user reloading.
		poll.add(L.bind(this.refreshStatus, this), 5);
		return body;
	}
});

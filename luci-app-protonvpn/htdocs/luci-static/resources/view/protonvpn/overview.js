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
// Reaches out to the official client's repository, so it is called from the
// Advanced-settings button ONLY — never on page load and never as part of a
// sign-in.
var callClientVersions = rpc.declare({ object: 'protonvpn', method: 'client_versions' });
var callRefreshLocations = rpc.declare({ object: 'protonvpn', method: 'refresh_locations' });
var callAccount = rpc.declare({ object: 'protonvpn', method: 'account' });
var callExternalIp = rpc.declare({
	object: 'protonvpn', method: 'external_ip', params: [ 'instance' ]
});
// An apply is key generation, a certificate registration over HTTPS and then a
// real handshake probe per candidate server — routinely 20s and more. Called
// synchronously it holds the single rpcd worker for that whole time, so every
// other LuCI page on the router stalls behind it. The page therefore starts the
// job and watches it; `apply` itself stays in the backend for the CLI only.
var callApplyStart = rpc.declare({ object: 'protonvpn', method: 'apply_start', params: [ 'instance' ] });
var callApplyStatus = rpc.declare({ object: 'protonvpn', method: 'apply_status' });
var callDisconnect = rpc.declare({ object: 'protonvpn', method: 'disconnect', params: [ 'instance' ] });
var callRotateNow = rpc.declare({ object: 'protonvpn', method: 'rotate_now', params: [ 'instance' ] });
// LuCI's uci.apply() always arms a rollback (10s by default) and confirms it
// from a timer that the returned promise does NOT wait for. We then start a
// long backend apply, rpcd is busy serving it, the confirmation never lands in
// time and the router restores /etc/config/protonvpn from the snapshot —
// silently discarding the settings the user just saved while the routing
// objects the backend created stay in place. Observed live: settings written,
// gone again exactly 10s later, config checksum back to its previous value.
//
// The protection was illusory here anyway: what can lock an admin out is the
// routing and firewall state, and the backend commits that itself, outside the
// transaction — a rollback of the settings file would not restore access.
var callUciApply = rpc.declare({
	object: 'uci', method: 'apply', params: [ 'timeout', 'rollback' ]
});

var callCreateInstance = rpc.declare({
	object: 'protonvpn', method: 'create_instance', params: [ 'instance' ]
});
var callDeleteInstance = rpc.declare({
	object: 'protonvpn', method: 'delete_instance', params: [ 'instance' ]
});

// Cadence of the apply watcher. The whole point of the asynchronous apply is to
// leave rpcd free, so the probe must stay rare compared to the work it watches;
// two seconds still shows the outcome as soon as it lands.
var APPLY_POLL_MS = 2000;
// Hard ceiling for that watch. The backend's own worst case is a 60s credential
// call plus four candidates at up to 30s of handshake verification each, so
// anything past four minutes is a wedged job, not a slow one — say so instead of
// spinning forever.
var APPLY_TIMEOUT_MS = 240000;
var STATUS_POLL_S = 5;

var STYLE = '' +
	'.pv-inline-note{font-style:italic;color:var(--text-color-medium,#666)}' +
	'.pv-inline{display:flex;align-items:center;gap:.75em;flex-wrap:wrap}' +
	'.pv-radio-group{display:flex;align-items:center;gap:1.25em;flex-wrap:wrap;min-height:1.9em}' +
	'.pv-radio-group label{display:inline-flex;align-items:center;gap:.4em;margin:0;font-weight:normal}' +
	'.pv-check{display:inline-flex;align-items:center;gap:.4em;font-weight:normal}' +
	'.pv-seg{display:inline-flex;flex-wrap:wrap;max-width:100%;border:1px solid #0069d6;border-radius:1.2em;overflow:hidden}' +
	'.pv-seg button{border:0;background:transparent;margin:0;padding:.3em 1.1em;cursor:pointer;font:inherit;color:inherit;line-height:1.3;white-space:nowrap;flex:1 1 auto}' +
	'.pv-seg button+button{border-left:1px solid #0069d6}' +
	'.pv-seg button.active{background:#0069d6;color:#fff}' +
	'.pv-pool{display:flex;flex-direction:column;align-items:flex-start;gap:.4em;margin-top:.45em}' +
	'.pv-pool-count{color:var(--text-color-medium,#666);font-size:.9em}' +
	// Custom location picker: the trigger opens an inline accordion — the
	// country rows expand to their cities in place. The trigger hides
	// while the panel is open, so there is no duplicate "add" affordance.
	'.pv-pool-wrap{display:block;margin-top:.5em}' +
	'.pv-pool-trigger::after{content:" \\25be"}' +
	'.pv-pool-panel{display:block;margin-top:.35em;width:320px;max-width:100%;max-height:340px;overflow:auto;background:var(--background-color-high,#fff);color:var(--text-color-high,inherit);border:1px solid var(--border-color-medium,#ccc);border-radius:.4em;box-shadow:0 4px 14px rgba(0,0,0,.18);padding:.25em}' +
	'.pv-pool-panel.hidden{display:none}' +
	'.pv-pool-head{display:flex;align-items:center;justify-content:space-between;gap:.5em;padding:.1em .3em .3em;font-weight:600}' +
	'.pv-pool-x{border:0;background:transparent;cursor:pointer;font:inherit;font-weight:700;color:inherit;padding:0 .2em}' +
	'.pv-pool-filter{width:100%;box-sizing:border-box;margin:0 0 .3em 0}' +
	// The filter input and the IPv6-only toggle share one row in the panel
	// head: the input keeps the width, the toggle never wraps mid-label.
	'.pv-pool-filterrow{display:flex;align-items:center;gap:.6em;margin:0 0 .3em 0}' +
	'.pv-pool-filterrow .pv-pool-filter{margin:0}' +
	'.pv-pool-v6only{flex:none;white-space:nowrap;font-weight:normal}' +
	'.pv-pool-row{display:flex;align-items:center;gap:.55em;padding:.34em .5em;border-radius:.3em;cursor:pointer;white-space:nowrap;width:100%;box-sizing:border-box}' +
	'.pv-pool-row:hover{background:rgba(0,105,214,.14)}' +
	'.pv-pool-row.is-in{opacity:.55}' +
	'.pv-pool-row .grow{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis}' +
	'.pv-pool-row .chev{color:var(--text-color-medium,#888);font-weight:700}' +
	'.pv-pool-row .box{font-weight:700;width:1.15em;text-align:center;flex:none}' +
	'.pv-pool-remove{color:#c0392b;font-weight:600}' +
	'.pv-pool-remove:hover{background:rgba(192,57,43,.12)}' +
	'.pv-pool-sep{border-top:1px solid var(--border-color-medium,#ddd);margin:.25em 0}' +
	// The location picker accordion, scoped to its own panel so the server
	// picker's rows keep the base .pv-pool-row look. Each row is two cells:
	// the hit cell takes the width and does the selecting, the 34px expand
	// cell opens the country's cities inline — the country list is never
	// swapped for a city page.
	'.pv-pool-acc{width:100%;max-width:460px}' +
	'.pv-pool-acc .pv-acc-row{display:flex;align-items:stretch;gap:0;padding:0}' +
	'.pv-pool-acc .pv-acc-row:hover{background:transparent}' +
	'.pv-pool-acc .pv-acc-row.pv-acc-open{background:rgba(0,105,214,.08)}' +
	'.pv-pool-acc .pv-acc-row.pv-acc-open:hover{background:rgba(0,105,214,.08)}' +
	'.pv-pool-acc .pv-acc-hit{flex:1;min-width:0;display:flex;align-items:center;gap:.55em;padding:.34em .5em;border-radius:.3em;cursor:pointer;white-space:nowrap}' +
	'.pv-pool-acc .pv-acc-hit:hover{background:rgba(0,105,214,.14)}' +
	// The metadata (load dot + figure, gateway count, IPv6 count) is a sibling
	// of the name, never inside it: .grow alone flexes and ellipsises, so a
	// long country name can never eat these.
	'.pv-pool-acc .pv-acc-meta{flex:none;display:flex;align-items:center;gap:.4em;color:var(--text-color-medium,#888);font-variant-numeric:tabular-nums}' +
	'.pv-pool-acc .pv-acc-exp{flex:none;width:34px;padding:0;align-self:stretch;display:flex;align-items:center;justify-content:center;border-left:1px solid var(--border-color-medium,#ddd);color:var(--text-color-medium,#888);font-weight:700;cursor:pointer}' +
	'.pv-pool-acc .pv-acc-exp:hover{background:rgba(0,105,214,.14)}' +
	'.pv-acc-city .pv-acc-hit{padding-left:2.1em}' +
	'.pv-pool-acc .pv-acc-city .pv-acc-exp{cursor:default}' +
	'.pv-pool-acc .pv-acc-city .pv-acc-exp:hover{background:transparent}' +
	// Server picker: same panel, plus a load dot (green/amber/red), a group
	// header per country and quick "Automatic / Lowest load" rows at the top.
	'.pv-srv-trigger{max-width:100%;overflow:hidden;text-overflow:ellipsis;text-align:left}' +
	'.pv-srv-x{border:0;background:transparent;cursor:pointer;font:inherit;font-weight:700;color:inherit;padding:0 .2em;margin-left:.3em}' +
	'.pv-dot{display:inline-block;width:.7em;height:.7em;border-radius:50%;flex:none}' +
	'.pv-dot-lo{background:var(--success-color-medium,#3c8c3c)}' +
	'.pv-dot-mid{background:var(--warn-color-medium,#c79100)}' +
	'.pv-dot-hi{background:var(--error-color-medium,#c0392b)}' +
	'.pv-srv-load{color:var(--text-color-medium,#888);font-variant-numeric:tabular-nums;flex:none}' +
	'.pv-srv-cur{color:var(--success-color-medium,#3c8c3c);font-weight:600;flex:none}' +
	// Deliberately muted and theme-driven, unlike pv-srv-cur's success
	// green: it marks a capability, not a state, and it shares a narrow row
	// with the load figure — which must never be pushed off.
	'.pv-srv-v6{flex:none;font-size:78%;font-weight:600;line-height:1.5;' +
		'padding:0 .3em;border:1px solid var(--border-color-medium,#ccc);' +
		'border-radius:3px;color:var(--text-color-medium,#888);white-space:nowrap}' +
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
	'details.pv-advanced>summary{cursor:pointer;font-weight:700;padding:.3em 0}' +
	// A disabled Continue button has to LOOK unavailable: the whole defect
	// was a button that answered a press with nothing visible.
	'button.pv-login-go[disabled]{opacity:.55;cursor:not-allowed}' +
	// ── ProtonVPN account card ───────────────────────────────────────────
	// A real card, not a bare paragraph: the credential state is the first
	// thing to read on the page, and its actions must not collide with the
	// form below.
	// The account card carries a tint so it reads as the page's first block;
	// everything else about its box comes from .pv-card.
	'.pv-acct{background:var(--background-color-medium,rgba(127,127,127,.06))}' +
	'.pv-acct-sub{font-size:90%;opacity:.8;margin-top:.35em}' +
	'.pv-state-note{font-size:90%;opacity:.85;margin-top:.35em}' +
	'.pv-acct-warn{border-color:#c79100}' +
	'.pv-acct-bad{border-color:#c0392b}' +
	'.pv-led{display:inline-block;width:.7em;height:.7em;border-radius:50%;flex:none}' +
	'.pv-led-ok{background:#3c8c3c}.pv-led-warn{background:#c79100}.pv-led-bad{background:#c0392b}' +
	'.pv-err{color:#c0392b;font-weight:bold;margin-bottom:.6em}' +
	'.pv-field{margin-bottom:.9em}' +
	'.pv-field label{display:block;margin-bottom:.3em;font-weight:bold}' +
	'.pv-field input{width:100%;box-sizing:border-box}' +
	// ── the layout rule for this whole page ──────────────────────────────
	//
	// Never rely on flex-wrap for a "text + action" pair. Use an explicit
	// grid where ONLY the text column flexes, and carry min-width:0 all the
	// way up. Every complaint the owner raised about this page was the same
	// mistake: the client-version button wrapped onto its own line, a
	// location chip grew without bound, and a long country name in the picker
	// widened the form until the page scrolled sideways. A flex item defaults
	// to min-width:auto, so the min-content width of a nowrap descendant
	// propagates outward one ancestor at a time until something stops it.
	//
	// THE root cause of the horizontal scroll on phones: a <fieldset> carries
	// a UA default of min-width:min-content, so .cbi-section cannot shrink
	// below the widest nowrap thing inside it and drags the document with it.
	// Measured: this one line took the document from 518px to the viewport
	// width at 320, 360 and 390.
	'fieldset.cbi-section{min-width:0}' +
	'.cbi-value-field,.pv-pool-wrap,.pv-pool-panel,.pv-sel{min-width:0}' +
	'.pv-card{border-radius:6px;padding:.6em .8em;margin-bottom:.9em;' +
		'border:1px solid var(--border-color-medium,#444)}' +
	// led · label · detail · primary actions · secondary actions. The detail
	// is the only column allowed to flex, so the header can never break onto
	// a second row.
	//
	// Five columns, not four: grid-template-columns fixes the column count,
	// so a fifth item on a four-column template wraps to a second ROW —
	// measured, that is exactly what the secondary actions did at 820px, and
	// it is the same wrapping-header defect in a new place.
	'.pv-line{display:grid;grid-template-columns:auto auto minmax(0,1fr) auto auto;' +
		'align-items:center;gap:.35em .5em;min-height:1.9em}' +
	'.pv-line .pv-grow{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
	'.pv-line-label{font-weight:700;white-space:nowrap}' +
	'.pv-acts{display:flex;gap:.35em;align-items:center;justify-self:end}' +
	// Secondary actions are hidden only where they do not fit. The kebab is
	// the narrow-screen fallback, not the design: with room, every action is
	// one click, which is the whole point of having a toolbar.
	'.pv-sec{display:none;gap:.35em;align-items:center;justify-self:end}' +
	'.pv-card.pv-acts-open .pv-sec{display:flex;grid-column:1/-1;' +
		'flex-wrap:wrap;justify-content:flex-end}' +
	'.pv-kebab{border:1px solid var(--border-color-medium,#888);background:none;' +
		'color:inherit;border-radius:4px;padding:0 .45em;cursor:pointer;font:inherit;' +
		'line-height:1.6;margin:0}' +
	'@media (min-width:34em){.pv-sec{display:flex}' +
		'.pv-card.pv-acts-open .pv-sec{grid-column:auto;flex-wrap:nowrap}' +
		'.pv-kebab{display:none}}' +
	// Facts as labelled pairs rather than a middot run-on.
	//
	// Narrow: ONE column, and the values may wrap. Two columns at 320px give
	// each value about 140px, which is where the external IP lost its tail —
	// and an IPv4 address has no space to wrap at, so a narrower column can
	// only cut it. One column costs three more rows and truncates nothing,
	// which is the better trade on a card that went from 248px to about 100.
	// Wide: let them flow and go nowrap, because forcing a column grid there
	// truncated that same IP while empty space sat beside it.
	'.pv-facts{display:grid;grid-template-columns:minmax(0,1fr);' +
		'gap:.1em .9em;margin-top:.4em;font-size:92%}' +
	'@media (min-width:34em){.pv-facts{display:flex;flex-wrap:wrap;gap:.1em 1.5em}' +
		'.pv-facts .pv-fact span{white-space:nowrap}}' +
	'.pv-fact{display:flex;gap:.4em;min-width:0}' +
	'.pv-fact b{font-weight:600;color:var(--text-color-medium,#888);flex:none}' +
	'.pv-fact span{min-width:0;overflow:hidden;text-overflow:ellipsis}' +
	'details.pv-more{margin-top:.45em}' +
	'details.pv-more>summary{cursor:pointer;color:var(--text-color-medium,#888);font-size:90%}' +
	// Same rule as the header row: the control that can shrink does, the
	// button never wraps. A <select> will not go below its longest option
	// without min-width:0, which is why this row used to break in two.
	'.pv-verrow{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:.4em;' +
		'align-items:center;margin-top:.4em}' +
	'.pv-verrow select{min-width:0;width:100%}' +
	'.pv-verrow button{white-space:nowrap;margin:0}' +
	// The selected locations, as an aligned list rather than chips. Chips put
	// one pill per row anyway (the container was a column flex) and a
	// narrowed country concatenated every city name into a single nowrap pill
	// with no width bound. Measured row minimum here is 103-127px whatever the
	// name, against 304-361px for the picker rows it replaced.
	// 460px matches the picker directly below it, so the two blocks line up;
	// on a wide screen the cap is raised, because a name ellipsised while
	// empty space sits beside it is the mistake this list was built to fix.
	'.pv-sel{margin-top:.45em;max-width:460px;border-radius:.4em;' +
		'border:1px solid var(--border-color-medium,#888)}' +
	'.pv-selrow{display:grid;grid-template-columns:auto minmax(0,1fr) auto auto;' +
		'gap:.5em;align-items:center;padding:.3em .5em;cursor:pointer;' +
		'border-bottom:1px solid var(--border-color-medium,#888)}' +
	'.pv-selrow:last-child{border-bottom:0}' +
	'.pv-selrow:hover{background:rgba(0,105,214,.14)}' +
	'.pv-selrow .pv-selname{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
	'.pv-selrow .pv-seldetail{color:var(--text-color-medium,#888);font-size:88%;white-space:nowrap}' +
	'.pv-selrow .pv-selx{border:0;background:transparent;font:inherit;font-weight:700;' +
		'cursor:pointer;padding:0 .25em;margin:0;color:var(--error-color-medium,#c0392b)}' +
	'.pv-selrow .pv-selx:hover{background:rgba(192,57,43,.14);border-radius:.25em}' +
	'@media (min-width:34em){.pv-sel{max-width:640px}}' +
	// The dashed border is the meaning the old chip carried: this entry is
	// in the saved set but the server list does not know it, so nothing
	// will ever be connected to through it.
	'.pv-selrow.pv-sel-stale{border-style:dashed;border-width:1px;' +
		'border-color:var(--warn-color-medium,#c79100)}' +
	'.pv-sel-stale .pv-selname{font-style:italic;color:var(--text-color-medium,#888)}' +
	'.pv-flag{flex:none}' +
	// The no-flag fallback: the country code itself, set as a badge so the
	// flag column keeps its width and nothing looks like a missing glyph.
	'.pv-flag-code{font-size:76%;font-weight:600;letter-spacing:.04em;line-height:1.6;' +
		'padding:0 .28em;border-radius:3px;border:1px solid var(--border-color-medium,#888);' +
		'color:var(--text-color-medium,#888)}' +
	// ── keyboard ─────────────────────────────────────────────────────────
	//
	// Every row that acts is a real <button>. A <div> with a click handler is
	// not reachable by Tab, is not activated by Enter or Space, and draws no
	// focus ring — and this page was built entirely out of those. Using the
	// element the browser already gives keyboard behaviour to is both less
	// code and more correct than re-implementing it with role/tabindex and a
	// keydown handler.
	//
	// The theme styles bare buttons heavily, so each one is reset back to
	// looking exactly like the row it replaced. What is deliberately NOT
	// reset is the outline: a focus ring is the only thing telling a
	// keyboard user where they are.
	'.pv-rowbtn{appearance:none;-webkit-appearance:none;border:0;background:transparent;' +
		'color:inherit;font:inherit;line-height:inherit;text-align:left;margin:0;' +
		'box-shadow:none;border-radius:inherit;min-width:0}' +
	// :focus first, then withdrawn for pointer focus. A browser too old for
	// :focus-visible drops the second rule as an unknown selector and keeps
	// the ring on every focus — the wrong trade-off in the safe direction.
	'.pv-rowbtn:focus,.pv-selx:focus,.pv-kebab:focus,.pv-pool-x:focus,' +
		'.pv-more-summary:focus{outline:2px solid var(--primary-color-medium,#0069d6);' +
		'outline-offset:-2px}' +
	'.pv-rowbtn:focus:not(:focus-visible),.pv-selx:focus:not(:focus-visible),' +
		'.pv-kebab:focus:not(:focus-visible),.pv-pool-x:focus:not(:focus-visible),' +
		'.pv-more-summary:focus:not(:focus-visible){outline:none}' +
	'.pv-rowbtn[disabled]{cursor:default}' +
	// The picked-location name is the keyboard handle for its row, so it is a
	// button; it still has to lay out as the one ellipsising grid cell.
	'button.pv-selname{display:block;width:100%;padding:0}' +
	'.hidden{display:none!important}';

// Every officially assigned ISO 3166-1 alpha-2 code. Unicode's flag sequences
// are keyed on exactly this list, so it is also the set of codes that can be
// drawn as a flag at all — see countryFlag(). Shipped as a string and split
// once, because 249 array literals cost more source than they save.
var FLAG_CODES =
	'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI ' +
	'BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN ' +
	'CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK ' +
	'FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM ' +
	'HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN ' +
	'KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ' +
	'ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP ' +
	'NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW ' +
	'SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF ' +
	'TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI ' +
	'VN VU WF WS YE YT ZA ZM ZW';
var flagCodes = null;

// Codes Proton uses that ISO 3166-1 does not assign, and the country they
// actually mean. Verified against the live server list: UK is the only one
// with an ISO equivalent — XK (Kosovo) has none, and deliberately gets the
// no-flag fallback rather than an invented mapping.
var CODE_ALIASES = { UK: 'GB' };

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

// ── putting text on the page ─────────────────────────────────────────────
//
// LuCI's DOM.append() (luci.js) has two branches and they are NOT
// interchangeable:
//
//   ARRAY  -> every non-element member becomes document.createTextNode(...)
//   SCALAR -> node.innerHTML = `${children}`
//
// dom.content() delegates to append(), and E()/DOM.create() calls append()
// with its third argument — so `E('p', {}, s)` and `dom.content(el, s)` both
// parse `s` as HTML. Two things go wrong. Our own 5003 hint contains the
// literal `linux-vpn-gtk@<version>`, and `<version>` is swallowed as a
// phantom tag, so the page tells the user to type a string it does not show.
// And every message that came from the API, from uci or from the user is
// markup in the router's admin page.
//
// nodes() wraps a child so it always lands as text. Arrays, elements and
// the function form pass through untouched, which is what lets it sit on
// every E() and dom.content() call in this file rather than on the handful
// someone remembered. There is a test that renders the whole page and fails
// if anything reached innerHTML.
function nodes(v) {
	if (v == null)
		return [];
	// Arrays are already the safe branch. An "element" is whatever LuCI's own
	// dom.elem() accepts — `typeof e == 'object' && 'nodeType' in e`,
	// luci.js:1186 — which is the same test append() applies when it picks
	// its branch, so the two agree by construction.
	if (Array.isArray(v))
		return v;
	if (typeof v === 'object' && 'nodeType' in v)
		return v;
	// The function form is kept, because append() calls it with the target
	// node, but its RESULT goes back through here: append() appends that
	// result recursively (`return this.append(node, children(node))`), so a
	// function returning a string reaches innerHTML exactly like a bare
	// string would.
	if (typeof v === 'function')
		return function (node) { return nodes(v(node)); };
	// Everything else becomes text. Spelling that out rather than passing
	// every object through is what closes `new String(markup)`: it is an
	// object, it is not an element, and a blanket passthrough would hand it
	// to the innerHTML branch and have its tags eaten. Nothing in this view
	// produces a boxed string or a function child today — the point is that
	// nothing can.
	return [ '' + v ];
}

function fmtTime(epoch) {
	return epoch ? new Date(epoch * 1000).toLocaleString() : '?';
}

// Day and month only. The account card's one line has to fit next to its
// actions at 320px, and the hour a ~30-day session lapses at is not something
// anybody acts on; the full stamp is still in the tooltip.
function fmtDay(epoch) {
	if (!epoch)
		return '?';
	var d = new Date(epoch * 1000);
	try {
		return d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
	} catch (e) {
		return d.toLocaleDateString();
	}
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
			callStatus('main').catch(function () { return {}; }),
			callInstances().catch(function () { return { instances: [] }; })
			// NOTE: the account/limits call is deliberately NOT here. It makes
			// two live HTTPS round-trips to Proton, which would sit in the
			// critical path of every page load. It is fetched after render and
			// the card updates when it arrives.
		]);
	},

	// ── small helpers ────────────────────────────────────────────────────

	// ── instances ────────────────────────────────────────────────────────

	// One account, many tunnels: every instance carries its own key,
	// certificate, interface and schedule, and they run side by side.
	statusOf: function (name) {
		var found = null;
		(this.instances || []).forEach(function (st) {
			if (st.instance === name)
				found = st;
		});
		return found;
	},

	// An instance that exists but is switched off reads as "disabled" rather
	// than whatever its last tunnel state happened to be.
	dispState: function (s) {
		if (s && s.configured && s.enabled === false)
			return 'disabled';
		return (s && s.state) || 'not_configured';
	},

	stateInfo: function (state) {
		var map = {
			connected:      { label: _('Connected'),      color: 'var(--success-color,#2d8f4e)' },
			connecting:     { label: _('Connecting'),     color: 'var(--warning-color,#b8860b)' },
			degraded:       { label: _('Degraded'),       color: 'var(--warning-color,#b8860b)' },
			disconnected:   { label: _('Disconnected'),   color: 'var(--error-color,#c0392b)' },
			disabled:       { label: _('Disabled'),       color: 'var(--text-color-medium,#666)' },
			error:          { label: _('Error'),          color: 'var(--error-color,#c0392b)' },
			not_configured: { label: _('Not configured'), color: 'var(--text-color-medium,#666)' }
		};
		return map[state] || { label: _('Unknown'), color: 'var(--text-color-medium,#666)' };
	},

	// A raw second count is unreadable past a minute or two ("3600s ago"), so
	// anything but a fresh handshake is expressed in minutes.
	// The minutes branch starts at 90s, so it renders "1 minute" for a whole
	// half-minute window — singular is worth spelling out rather than shipping
	// "1 minutes ago" on the most visible line of the page.
	// How long ago the last handshake was, as a VALUE. It used to carry the
	// word "Handshake" itself, which was right for a middot run-on and says
	// it twice next to a label.
	fmtHandshake: function (sec) {
		if (sec == null)
			return null;
		if (sec < 90)
			return (sec == 1) ? _('1 second ago') : _('%d seconds ago').format(sec);
		var min = Math.floor(sec / 60);
		return (min == 1) ? _('1 minute ago') : _('%d minutes ago').format(min);
	},

	// Display names for the country/city pair the tunnel reports. The country
	// name comes from the browser (Proton only sends ISO codes); the city name
	// only exists in the locations tree, so a missing or not-yet-loaded tree
	// falls back to the raw 'cc-city' code rather than dropping the city.
	locationNames: function (cc, cityCode) {
		var countries = Array.isArray((this.locations || {}).countries)
			? this.locations.countries : [];
		var city = cityCode || '';
		countries.forEach(function (c) {
			if (c.code !== cc)
				return;
			(c.cities || []).forEach(function (ct) {
				if (ct.code === cityCode)
					city = ct.name || cityCode;
			});
		});
		return [ cc ? this.countryLabel(cc) : '', city ];
	},

	updateInstancesTable: function () {
		if (!this.instancesNode)
			return;
		var rows = [];

		(this.instances || []).forEach(L.bind(function (st) {
			var info = this.stateInfo(this.dispState(st));
			var loc = st.location || {};
			var flag = this.countryFlag(loc.country);
			var selected = (st.instance === this.instance);
			var r = st.rotation || {};
			var next = '';
			if (r.enabled && r.next_run)
				next = new Date(r.next_run * 1000).toLocaleTimeString();
			else if (r.enabled)
				next = _('on schedule');

			rows.push(E('div', {
				class: 'pv-inst-row',
				click: L.bind(this.selectInstance, this, st.instance)
			}, nodes([
				E('div', { class: 'pv-inst-info' }, nodes([
					E('span', { class: 'pv-inst-name' }, nodes((selected ? '▸ ' : '') + st.instance)),
					E('span', { style: 'color:' + info.color }, nodes(info.label)),
					E('span', {}, nodes((flag ? flag + ' ' : '') + (st.gateway || '—'))),
					next ? E('span', { class: 'pv-inst-dim' }, nodes('⟳ ' + next)) : ''
				])),
				E('span', { class: 'pv-inst-act' }, nodes(E('button', {
					class: 'cbi-button cbi-button-remove',
					click: L.bind(this.showDeleteInstanceModal, this, st.instance)
				}, nodes(st.instance === 'main' ? _('Reset') : _('Delete')))))
			])));
		}, this));

		dom.content(this.instancesNode, nodes(E('fieldset', { class: 'cbi-section' }, nodes([
			E('legend', {}, nodes(_('VPN instances'))),
			E('div', { class: 'cbi-section-node' }, nodes([
				E('div', {}, nodes(rows)),
				E('div', { style: 'margin-top:.6em' }, nodes([
					E('button', {
						class: 'cbi-button cbi-button-add',
						click: L.bind(this.showAddInstanceModal, this)
					}, nodes(_('Add instance')))
				]))
			]))
		]))));
	},

	selectInstance: function (name) {
		if (name === this.instance)
			return;
		if (this._dirty && !window.confirm(_('Discard unsaved changes?')))
			return;
		this.instance = name;
		this._dirty = false;
		if (this.saveBtn)
			this.saveBtn.disabled = true;
		if (this.discardBtn)
			this.discardBtn.disabled = true;
		this.status = this.statusOf(name) || {};
		// Belongs to the tunnel we just left.
		this.forgetExternalIp();
		this.updateInstancesTable();
		this.updateStatusBand();
		dom.content(this.formNode, nodes(this.buildFormSections()));
	},

	showAddInstanceModal: function () {
		var input = E('input', { type: 'text', class: 'cbi-input-text',
			placeholder: _('e.g. media') });
		var err = E('div', { class: 'cbi-value-description',
			style: 'color:var(--error-color,#c0392b)' });
		ui.showModal(_('Add VPN instance'), [
			E('p', {}, nodes(_('A new instance runs its own tunnel on its own WireGuard interface, with its own locations and schedule. It uses the same Proton account — no separate credentials — but registers a certificate of its own.'))),
			E('div', { class: 'cbi-value' }, nodes([ input ])),
			err,
			E('div', { class: 'right' }, nodes([
				E('button', { class: 'cbi-button', click: ui.hideModal }, nodes(_('Cancel'))),
				' ',
				E('button', { class: 'cbi-button cbi-button-action',
					click: L.bind(this.addInstance, this, input, err) }, nodes(_('Add')))
			]))
		]);
	},

	addInstance: function (input, err) {
		var name = (input.value || '').trim();
		// The backend prefixes the interface with 'pv_', which netifd caps.
		if (!/^[A-Za-z0-9_]{1,12}$/.test(name)) {
			dom.content(err, nodes(_('Use 1-12 letters, digits or underscores.')));
			return;
		}
		return callCreateInstance(name).then(L.bind(function (res) {
			if (res && res.error) {
				dom.content(err, nodes(res.error));
				return;
			}
			ui.hideModal();
			uci.unload('protonvpn');
			return uci.load('protonvpn').then(L.bind(function () {
				return this.refreshStatus();
			}, this)).then(L.bind(function () {
				this.selectInstance(name);
				this.notice(_('Instance "%s" created. Pick its locations, then save.')
					.format(name), 'info', 6000);
			}, this));
		}, this)).catch(L.bind(function (e) {
			dom.content(err, nodes('' + e));
		}, this));
	},

	showDeleteInstanceModal: function (name, ev) {
		// The row underneath is a selector; the button must not trigger it.
		if (ev)
			ev.stopPropagation();
		var main = (name === 'main');
		ui.showModal(main ? _('Reset "main" to defaults?')
			: _('Delete instance "%s"?').format(name), [
			E('p', {}, nodes(main
				? _('The tunnel is taken down, its certificate is revoked, the key, interface and firewall objects are removed, and every setting returns to its default. Other instances are not affected.')
				: _('The tunnel is taken down, its certificate is revoked, and its interface, firewall objects and settings are removed. Networks routed through it fall back to your other routes.'))),
			E('div', { class: 'right' }, nodes([
				E('button', { class: 'cbi-button', click: ui.hideModal }, nodes(_('Cancel'))),
				' ',
				E('button', { class: 'cbi-button cbi-button-negative',
					click: L.bind(this.deleteInstance, this, name) },
					nodes(main ? _('Reset') : _('Delete')))
			]))
		]);
	},

	deleteInstance: function (name) {
		ui.hideModal();
		var n = this.notice(_('Deleting instance "%s"…').format(name), 'info');
		return callDeleteInstance(name).then(L.bind(function (res) {
			this.dismiss(n);
			if (res && res.error) {
				this.notice(_('Delete failed: %s').format(res.error), 'error');
				return;
			}
			this.notice(res && res.reset
				? _('Instance "%s" was reset to defaults.').format(name)
				: _('Instance "%s" deleted.').format(name), 'info', 6000);
			uci.unload('protonvpn');
			return uci.load('protonvpn').then(L.bind(function () {
				// The selected instance may be the one that just went away.
				if (!this.statusOf(this.instance))
					this.instance = 'main';
				this._dirty = false;
				return this.refreshStatus();
			}, this)).then(L.bind(function () {
				this.status = this.statusOf(this.instance) || {};
				this.forgetExternalIp();
				this.updateInstancesTable();
				this.updateStatusBand();
				dom.content(this.formNode, nodes(this.buildFormSections()));
			}, this));
		}, this)).catch(L.bind(function (e) {
			this.dismiss(n);
			this.notice(_('Delete failed: %s').format(e), 'error');
		}, this));
	},

	// The emoji flag for a country code, or '' when there is no flag to draw.
	//
	// Unicode only assigns a regional-indicator sequence to codes that name a
	// country; every other pair falls back to the white flag with a question
	// mark on it, which reads as a broken picture rather than as "unknown".
	// This used to map ANY two letters, so both non-ISO codes in Proton's own
	// server list came out broken: UK (ISO assigns GB) and XK (Kosovo, which
	// has no flag sequence at all). The membership test is what makes that
	// general — a code Proton invents tomorrow gets the honest fallback
	// instead of a phantom flag.
	countryFlag: function (code) {
		var cc = this.isoCode(code);
		if (!cc)
			return '';
		return String.fromCodePoint(
			0x1F1E6 + (cc.charCodeAt(0) - 65),
			0x1F1E6 + (cc.charCodeAt(1) - 65));
	},

	// The assigned country this code stands for, or '' when it stands for
	// none. Proton's UK is resolved to GB here rather than in the flag
	// function, because the alias is about the code, not about the picture.
	isoCode: function (code) {
		if (typeof code !== 'string' || !/^[A-Za-z]{2}$/.test(code))
			return '';
		var cc = code.toUpperCase();
		if (Object.prototype.hasOwnProperty.call(CODE_ALIASES, cc))
			cc = CODE_ALIASES[cc];
		if (flagCodes === null)
			flagCodes = new Set(FLAG_CODES.split(' '));
		return flagCodes.has(cc) ? cc : '';
	},

	// What goes in the flag column. An emoji when Unicode has one, otherwise
	// the code itself in a small badge.
	//
	// The badge, rather than an empty cell: the flag has its own column in the
	// selected-location list and in the picker, and a blank there reads as a
	// font that failed to load. Kosovo is the live case — Proton lists it as
	// XK, ISO 3166-1 does not assign that code, and no emoji exists for it at
	// any Unicode version — so what is drawn is exactly what the server list
	// said, "XK", and nothing is invented.
	flagNode: function (code) {
		var f = this.countryFlag(code);
		if (f)
			return E('span', { class: 'pv-flag' }, nodes(f));
		var raw = String(code == null ? '' : code).toUpperCase();
		return E('span', { class: 'pv-flag pv-flag-code',
			title: _('Unicode has no flag for this country code') },
			nodes(raw || '??'));
	},

	// Localized country name for an ISO code, falling back to the code itself.
	countryLabel: function (code) {
		var cc = String(code || '').toUpperCase();
		if (!cc)
			return '';
		if (regionNames === null) {
			try {
				regionNames = new Intl.DisplayNames([ window.navigator.language || 'en' ],
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

	// Bit 16 of the logical server's Features bitmask is ProtonVPN's IPv6
	// flag (protonvpn.common FEATURE_IPV6); cache.uc keeps the raw mask on
	// every trimmed relay. A relay out of a cache written before the mask was
	// carried has none, and must read as "no IPv6" rather than be guessed at.
	relayHasV6: function (r) {
		return !!r && (Number(r.features) & 16) !== 0;
	},

	// Whether "only gateways that forward IPv6" is currently narrowing server
	// selection. Mirrors protonvpn.common require_ipv6_active() exactly: the
	// backend refuses to connect on anything this predicate excludes, so a
	// page that disagreed would offer servers the router then rejects.
	//
	// Read from the live widgets when they exist, so the picker follows the
	// IPv6 mode and hop mode the user is editing rather than what was last
	// saved; falls back to UCI on the paths that run before the form is built.
	requireV6Active: function () {
		var want = this.v6Only ? this.v6Only.checked
			: (uci.get('protonvpn', this.instance, 'require_ipv6') === '1');
		if (!want)
			return false;
		var mode = this.v6Sel ? this.v6Sel.value
			: (uci.get('protonvpn', this.instance, 'ipv6_mode') || 'block');
		if (mode !== 'auto' || this.hopMode() !== 'standard')
			return false;
		// And it must be steering, because that is the only shape in which
		// 'auto' hands clients IPv6 at all. The routing table the backend also
		// requires is not checked here: collectIntoUci fills it in from the
		// interface name whenever steering is saved without one, so demanding
		// it now would show the control as inert right up until save.
		if (this.autoRouting)
			return !this.autoRouting.checked && this.steeredNetworks().length > 0;
		var sn = uci.get('protonvpn', this.instance, 'source_network');
		return (uci.get('protonvpn', this.instance, 'auto_routing') !== '1') &&
			(Array.isArray(sn) ? sn.length > 0 : !!sn);
	},

	// The picker's "IPv6 only" view filter: on only when the user asked AND
	// the hop mode can have IPv6 gateways at all. ipv6_count is counted
	// against the standard kind only (cache.uc locations_tree: 0 of 122
	// Secure Core and 0 of 7 Tor logicals carry the bit), so filtering in
	// the other modes would empty the list — the toggle is rendered
	// disabled there instead, and a state carried over from Standard goes
	// inert rather than taking the list with it. This is a view filter: it
	// narrows what the accordion lists, never what the backend may connect
	// to, and nothing of it is written to uci.
	v6FilterOn: function () {
		return !!this._poolV6Only && this.hopMode() === 'standard';
	},

	// " · N/M IPv6" for a country or city row in the location picker, or ''
	// when neither the requirement nor the view filter is on.
	//
	// A count rather than a yes/no on purpose. The bit is per gateway while a
	// location set is per country or city, so a city can hold both kinds: a
	// "yes" on a city where 3 of 40 gateways qualify promises something it
	// barely delivers, and the only honest boolean — "zero or not" — makes a
	// country that mostly works look identical to one that mostly does not.
	//
	// Unlike the server picker, a zero row is shown rather than hidden. This
	// is where the set is chosen, and a country that silently disappeared
	// would make the backend's later "no IPv6 gateways in the selected
	// locations" impossible to act on. The "IPv6 only" toggle is the one
	// sanctioned exception, and it holds to the same rule: the list ends in
	// a line saying how many countries and cities were dropped, and this
	// label shows while it is on — a user looking at IPv6 needs the number
	// even without the requirement.
	v6CountLabel: function (row) {
		if (!row || (!this.requireV6Active() && !this.v6FilterOn()))
			return '';
		var n = row.ipv6_count || 0;
		var m = row.standard_count || 0;
		return ' · ' + (n ? _('%d/%d IPv6').format(n, m) : _('no IPv6'));
	},

	// What to tell the user about an IPv6 requirement that could not be met,
	// derived from STATUS alone — one short line for the band, one sentence for
	// the routing note, and whether the steered networks are exposed.
	//
	// Status-only is the whole point. The reply to a Save/Connect/Rotate is
	// seen only by whoever was watching the page at that moment, while a
	// reload, the five-second poll and a background rotation all rebuild from
	// status; those are the normal case, not the exception. Anything the user
	// must see therefore has to be derivable from here.
	//
	// The cause drives the wording because the advice differs, and the wrong
	// advice is worse than none: 'unreachable' means these gateways DO forward
	// IPv6 and were merely out of reach, so telling the user to widen their
	// locations or drop the requirement would have them undo a setting that
	// was never the problem.
	ipv6Unmet: function (st) {
		st = st || this.status || {};
		var v6 = st.ipv6 || {};
		if (v6.reason !== 'ipv6_required_unavailable')
			return null;
		var rt = st.routing || {};
		var by = {
			no_gateway: {
				line: _('IPv6 required — none of the gateways in these locations support it'),
				note: _('None of the gateways in the selected locations forward IPv6, and this instance requires it. Add a location that has IPv6 gateways, or turn the requirement off.')
			},
			unreachable: {
				line: _('IPv6 required — the IPv6 gateways here could not be reached'),
				note: _('The IPv6 gateways in the selected locations could not be reached. They do forward IPv6, so this may simply work on the next attempt — reconnect rather than changing the locations.')
			},
			pinned: {
				line: _('IPv6 required — the pinned server does not support it'),
				note: _('The pinned server does not forward IPv6 and this instance requires it. Pick a different server, or turn the requirement off.')
			}
		};
		var pick = by[v6.required_cause] || {
			line: _('IPv6 required — no IPv6 gateway is available'),
			note: _('This instance requires IPv6 and no gateway providing it is available, so the tunnel stays down.')
		};
		// The second half of the same situation. Only for steered routing:
		// with auto_routing the requirement is inactive and there are no
		// steered networks to expose, so the sentence would be false.
		var steered = (rt.mode === 'steered') || (rt.mode == null && v6.require_ipv6_active);
		var exposed = steered && !rt.killswitch;
		return {
			line: pick.line,
			note: pick.note,
			exposed: exposed,
			// Said on the band, because someone told only that IPv6 is
			// unavailable will not realise their networks stopped being
			// protected at the same moment.
			exposure: exposed
				? _('steered traffic is leaving through your provider — turn the kill switch on to block it instead')
				: null
		};
	},

	// Key of the per-kind gateway counters in the locations tree.
	hopCountKey: function () {
		var m = this.hopMode();
		return m === 'secure_core' ? 'secure_core_count'
			: (m === 'tor' ? 'tor_count' : 'standard_count');
	},

	// Key of the matching per-kind average load. cache.uc computes it next to
	// the counters because the locations tree carries no per-relay data;
	// caches written before the field existed simply have none, and the row
	// then shows the counter alone rather than an invented figure.
	hopLoadKey: function () {
		var m = this.hopMode();
		return m === 'secure_core' ? 'secure_core_load'
			: (m === 'tor' ? 'tor_load' : 'standard_load');
	},

	setHopMode: function (mode) {
		if (this.hopValue === mode)
			return;
		this.hopValue = mode;
		this.onHopChange();
	},

	// The single hop-mode transition. It used to live here AND inline in
	// setHopMode, which quietly won — so edits to this one changed nothing.
	onHopChange: function () {
		this.markDirty();
		this.updateHopButtons();
		// Start the set empty. The three modes are different products, not
		// filters over one list: in Secure Core the country is the *exit*
		// country reached through a partner country, and a Tor exit is a
		// different machine again. Carrying a Standard pick across reads as
		// "still selected" when it now means something else — and a country
		// that exists in both modes would quietly survive with a completely
		// different server behind it. The cost is that a round trip through
		// another mode no longer restores the old set.
		this.poolEntries = [];
		this._serverChosen = '';
		this.rebuildPoolWidget();
		this.refreshServerList();
		// Whether the IPv6 requirement may apply turns on the hop mode, so the
		// control's availability and its explanation are stale until this
		// runs. Nothing else on this path repaints them.
		this.onRoutingToggle();
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
			dom.content(this.hopNote, nodes(notes[mode] || ''));
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
			// Listed whenever the country has gateways of the current kind,
			// even when the cache carries no per-city counts for it: the row
			// shows the country's own counter, and the expand cell simply has
			// no cities to offer. Demanding city counts here would drop whole
			// countries from the secure-core/tor lists.
			if (count > 0)
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
			// Nothing to pin any more, so the rotation rows this gates must be
			// re-evaluated here too — the early return skips the one below.
			this._building = true;
			this.updateRotationAvailability();
			this._building = false;
			return;
		}
		callServers(codes, this.hopMode()).then(L.bind(function (res) {
			if (req !== this._serversReq)
				return;                 // a newer rebuild superseded this response
			this._serverData = { relays: ((res && res.relays) || []).slice() };
			// Restoring the persisted pin is not a user edit.
			var pinned = uci.get('protonvpn', this.instance, 'fixed_server') || '';
			// A pin the requirement excludes is as unreachable as one in a
			// region the user just left: the backend refuses to connect to it,
			// so carrying it forward would save a configuration that cannot
			// come up. Dropped on the same terms — only when the user is
			// editing, never when the persisted value is merely being restored.
			var onlyV6 = this.requireV6Active();
			var reachable = !pinned || this._serverData.relays.some(L.bind(function (r) {
				if (r.name !== pinned && r.hostname !== pinned)
					return false;
				return !onlyV6 || this.relayHasV6(r);
			}, this));
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

	// Returns the node so a progress banner can be taken down again: LuCI's
	// notifications are sticky, and "Applying…" left on screen reads as a hang.
	// `timeout` is for terminal good news only — errors stay until dismissed.
	notice: function (text, kind, timeout) {
		var node = ui.addNotification(null, E('p', {}, nodes(text)), kind || 'info');
		if (timeout)
			setTimeout(L.bind(this.dismiss, this, node), timeout);
		return node;
	},

	dismiss: function (node) {
		try {
			if (node && node.parentNode)
				node.parentNode.removeChild(node);
		} catch (e) {}
	},

	// We call uci.apply() ourselves (the framework's own apply would reload the
	// page and abort the reconnect), so the global "Unsaved Changes" indicator
	// has to be cleared by hand once our commit lands.
	clearChangeIndicator: function () {
		try {
			if (L.ui && L.ui.changes)
				L.ui.changes.setIndicator(0);
		} catch (e) {}
	},

	// ── login (SRP happens in this page) ─────────────────────────────────

	// Stepper: credentials first, and the two-factor field only once the API
	// says it is needed. Asking for a code up front misleads the majority of
	// accounts that have none.
	showLoginModal: function (step) {
		this.loginStep = step || 'credentials';
		this.loginErr = E('div', { class: 'pv-err' });
		// Everything the dialog is made of lives on the view, and nothing here
		// is captured in a closure. That is not tidiness: the sign-in outlives
		// the window it started in, so a step still pending when the user
		// closes and reopens has to render into whatever modal is on screen
		// WHEN IT RESOLVES, not into the one that happened to start it. A
		// captured body meant the two-factor field was drawn into a detached
		// node while the visible dialog still asked for the password — with
		// loginStep already 'totp', so its Continue button could only answer
		// "enter the 6-digit code" for a field that was nowhere on screen.
		this.loginBody = E('div', {});
		this.loginBtn = E('button', { class: 'cbi-button cbi-button-apply pv-login-go',
			click: L.bind(this.submitLogin, this) }, nodes(_('Continue')));
		this.resumeLoginState();
		this.renderLoginBody();

		ui.showModal(_('Sign in to Proton'), [
			this.loginBody,
			E('div', { class: 'right' }, nodes([
				E('button', { class: 'cbi-button pv-login-cancel',
					click: L.bind(this.cancelLogin, this) }, nodes(_('Cancel'))),
				' ',
				this.loginBtn
			]))
		]);
	},

	// Draw the current step into the current body. Called on open and again
	// whenever the step changes, including from a resolution that arrives
	// after the dialog was closed and reopened — which is why it reads
	// this.loginBody rather than closing over one.
	renderLoginBody: function () {
		var self = this;
		var enter = function (ev) { if (ev.key === 'Enter') self.submitLogin(); };
		var kids = [];
		if (this.loginStep === 'totp') {
			this.totpEl = E('input', { type: 'text', class: 'cbi-input-text',
				placeholder: '123456', inputmode: 'numeric', maxlength: '8',
				autocomplete: 'one-time-code', style: 'max-width:9em;letter-spacing:.2em',
				keydown: enter });
			kids = [
				E('p', {}, nodes(_('Password accepted for %s. This account has two-factor authentication.')
					.format(this.loginUser || ''))),
				E('div', { class: 'pv-field' }, nodes([ E('label', {}, nodes(_('Two-factor code'))), this.totpEl ])),
				E('div', { class: 'cbi-value-description' },
					nodes(_('A wrong code can simply be retyped — the password step is not repeated.')))
			];
		} else {
			this.userEl = E('input', { type: 'text', class: 'cbi-input-text',
				placeholder: 'user@proton.me', autocomplete: 'username',
				value: this.loginUser || '', keydown: enter });
			this.passEl = E('input', { type: 'password', class: 'cbi-input-password',
				autocomplete: 'current-password', keydown: enter });
			kids = [
				E('div', { class: 'pv-field' }, nodes([ E('label', {}, nodes(_('Proton username'))), this.userEl ])),
				E('div', { class: 'pv-field' }, nodes([ E('label', {}, nodes(_('Password'))), this.passEl ])),
				E('div', { class: 'cbi-value-description' },
					nodes(_('The password is turned into a proof in this page and never reaches the router.')))
			];
		}
		dom.content(this.loginBody, nodes([ this.loginErr ].concat(kids)));
		setTimeout(function () {
			try {
				(self.loginStep === 'totp' ? self.totpEl :
					(self.loginUser ? self.passEl : self.userEl)).focus();
			} catch (e) {}
		}, 60);
	},

	submitLogin: function (ev) {
		var self = this;
		if (ev && ev.preventDefault)
			ev.preventDefault();
		if (this.loginBusy)
			return;
		// Every callback this attempt hands out is stamped with its own
		// number, so a resolution that arrives after the view has moved on
		// cannot speak for a newer attempt.
		var attempt = this.loginInFlight = ++this.loginAttempt;
		this.setLoginState('busy');
		dom.content(this.loginErr, []);
		var failFor = function (msg, local) {
			return self.failLogin(attempt, msg, local);
		};
		return this.runLoginAttempt(attempt, failFor, function () {
			if (self.loginStep === 'totp')
				return self.submitTotp(failFor);
			return self.submitCredentials(failFor);
		});
	},

	// Closing the dialog is not abandoning the sign-in. The request is still
	// on the wire and the pause is still owed, so only the visible countdown
	// is stopped here — the deadline itself lives on the view and is picked
	// up again when the modal reopens.
	cancelLogin: function () {
		clearTimeout(this.loginCooldownTimer);
		ui.hideModal();
	},

	// What the button shows when a modal opens. The sign-in outlives the
	// window it was started from: closing and reopening used to clear the
	// cooldown timer and force the button back to 'ready', which handed the
	// user a second real attempt for the price of one Cancel — and a burst of
	// real attempts is what gets the account temporarily limited in the first
	// place.
	resumeLoginState: function () {
		clearTimeout(this.loginCooldownTimer);
		if (this.loginInFlight)
			return this.setLoginState('busy');
		if (this.loginCooldownUntil > Date.now())
			return this.tickLoginCooldown();
		this.setLoginState('ready');
	},

	// Run one sign-in step under a guarantee: the attempt it started always
	// ends. This is here rather than in each step because submit() is the only
	// place that marks an attempt in flight, and an attempt that is never
	// settled is permanent — loginBusy stays true, Continue stays disabled
	// reading "Signing in…", and resumeLoginState() faithfully restores that,
	// so reopening the modal reproduces the dead button instead of clearing
	// it. Nothing short of reloading the page gets the user out.
	//
	// submitTotp() had exactly that hole: a .then() with no .catch(), so a
	// rejected LuCI RPC — a transport failure, an rpcd restart, the router
	// dropping the connection mid-2FA — settled nothing at all.
	//
	// Three ways a step can end without settling, all covered here: it
	// rejects, it throws on its way to returning a promise, or it resolves
	// having simply forgotten. failLogin() ignores an attempt that is no
	// longer the one on the wire, so a step that DID settle is untouched by
	// the net below.
	runLoginAttempt: function (attempt, failFor, step) {
		var self = this;
		var running;
		try {
			running = step();
		} catch (e) {
			failFor(self.loginErrorText(e));
			return Promise.resolve();
		}
		return Promise.resolve(running).catch(function (e) {
			failFor(self.loginErrorText(e));
		}).then(function () {
			if (self.loginInFlight === attempt)
				failFor(_('The sign-in did not finish and it is not clear why. Please try again.'));
		});
	},

	// What to show the user for a thrown or rejected value. LuCI rejects with
	// an Error for a transport failure and with a plain value elsewhere.
	loginErrorText: function (e) {
		return (e && e.message) || ('' + e);
	},

	// A sign-in attempt that failed. `attempt` is the number submit() stamped
	// on this callback, and only the attempt actually on the wire may settle
	// — once. That covers both ways a stale resolution arrives: one belonging
	// to an attempt the user has already moved past (a late catch after a
	// close and reopen), and a second settle for an attempt that has already
	// finished (afterLogin() rejecting behind a sign-in that succeeded, which
	// would otherwise open a pause nobody earned).
	//
	// `local` marks a refusal that never left the browser: an empty field, a
	// malformed code. Nothing was attempted, so there is nothing to pace and
	// the user may fix the typo at once.
	failLogin: function (attempt, msg, local) {
		if (attempt !== this.loginInFlight)
			return;
		this.loginInFlight = 0;
		dom.content(this.loginErr, nodes(msg));
		if (local)
			this.setLoginState('ready');
		else
			this.beginLoginCooldown();
	},

	// A sign-in attempt that got through, under the same rule. Returns false
	// when the caller should stop: it is speaking for an attempt that is no
	// longer the one on the wire.
	settleLogin: function (attempt) {
		if (attempt !== this.loginInFlight)
			return false;
		this.loginInFlight = 0;
		this.setLoginState('ready');
		return true;
	},

	// How long the Continue button stays out of reach after a failed sign-in.
	// Each press after a failure is a real new attempt, and a burst of them is
	// what Proton's anti-abuse answers by temporarily limiting the account —
	// which then reaches the user as an error about their account rather than
	// about a button that looked like it had done nothing.
	LOGIN_RETRY_PAUSE_MS: 5000,

	// Sign-in state that belongs to the sign-in, not to the dialog showing it:
	// the attempt counter, which attempt is still on the wire, and when the
	// pause after the last failure runs out. All three survive a close.
	loginAttempt: 0,
	loginInFlight: 0,
	loginCooldownUntil: 0,

	// The Continue button has three states: 'ready' (usable), 'busy' (a
	// sign-in is in flight: disabled, with a spinner) and 'cooldown' (an
	// attempt just failed: disabled, counting the pause down in its label).
	// Anything but 'ready' also stops submit(), so a click a disabled button
	// would not have delivered cannot get through another way either.
	setLoginState: function (state, label) {
		this.loginState = state;
		this.loginBusy = (state !== 'ready');
		var btn = this.loginBtn;
		if (!btn)
			return;
		btn.disabled = (state !== 'ready');
		btn.classList.toggle('pv-busy', state !== 'ready');
		if (state === 'busy')
			dom.content(btn, nodes([ E('span', { class: 'spinning' }), ' ', _('Signing in…') ]));
		else if (state === 'cooldown')
			dom.content(btn, nodes(label || _('Please wait…')));
		else
			dom.content(btn, nodes(_('Continue')));
	},

	// Hold the button after a failed attempt and count the pause down in its
	// label, so the wait is something the user can watch rather than presses
	// that silently do nothing.
	//
	// The deadline is kept on the view rather than in the timer's closure,
	// because it has to outlive both the timer and the modal: a Cancel stops
	// the countdown, and reopening must resume the same pause rather than
	// grant a fresh button.
	beginLoginCooldown: function () {
		this.loginCooldownUntil = Date.now() + (this.LOGIN_RETRY_PAUSE_MS || 0);
		this.tickLoginCooldown();
	},

	tickLoginCooldown: function () {
		var self = this;
		clearTimeout(this.loginCooldownTimer);
		var tick = function () {
			var left = (self.loginCooldownUntil || 0) - Date.now();
			if (left <= 0) {
				self.loginCooldownUntil = 0;
				return self.setLoginState('ready');
			}
			self.setLoginState('cooldown',
				_('Try again in %ds').format(Math.ceil(left / 1000)));
			self.loginCooldownTimer = setTimeout(tick, Math.min(250, left));
		};
		tick();
	},

	submitCredentials: function (fail) {
		var self = this;
		var attempt = this.loginAttempt;
		var username = (this.userEl.value || '').trim();
		var password = this.passEl.value || '';
		if (!username || !password)
			return fail(_('Enter the username and password'), true);
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
			if (!self.settleLogin(attempt))
				return;
			if (res.twofa) {
				self.loginStep = 'totp';
				self.renderLoginBody();
				return;
			}
			ui.hideModal();
			self.notice(_('Signed in.'), 'info', 4000);
			return self.afterLoginReported();
		}).catch(function (err) {
			fail(self.loginErrorText(err));
		});
	},

	submitTotp: function (fail) {
		var self = this;
		var attempt = this.loginAttempt;
		var code = (this.totpEl.value || '').trim();
		if (!/^[0-9]{6,8}$/.test(code))
			return fail(_('Enter the 6-digit code from your authenticator'), true);
		return callSetTotp(code).then(function (res) {
			if (!res || res.error) {
				self.totpEl.value = '';
				return fail((res && res.error) || _('no response'));
			}
			if (!self.settleLogin(attempt))
				return;
			ui.hideModal();
			self.notice(_('Signed in.'), 'info', 4000);
			return self.afterLoginReported();
		}).catch(function (err) {
			fail(self.loginErrorText(err));
		});
	},

	// The sign-in is over by the time this runs: the session exists and the
	// modal is closed. What follows it can still fail, and that has to read as
	// what it is. Left to flow back into the sign-in's own error handling it
	// would either open a retry pause on a sign-in that worked, or — where
	// there is no catch at all — become an unhandled rejection the user never
	// sees while the server list quietly stays empty.
	afterLoginReported: function () {
		var self = this;
		return this.afterLogin().catch(function (e) {
			self.notice(_('Signed in, but loading the server list failed: %s')
				.format((e && e.message) || e), 'warning');
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
		var n = this.notice(_('Signing out…'), 'info');
		return callLogout().then(function (res) {
			self.dismiss(n);
			if (res && res.error)
				self.notice(_('Sign-out failed: %s').format(res.error), 'error');
			else
				// Signing out takes every tunnel down (the backend disconnects
				// them before dropping the session), which is a big enough
				// consequence to spell out rather than leave to be discovered.
				self.notice(_('Signed out. Every tunnel was taken down and its networks are back on normal routing — sign in again to restore them.'), 'info', 6000);
			// Without a session the plan and the connection quota are no longer
			// knowable, so drop them instead of showing a stale figure.
			self.account = null;
			self.forgetExternalIp();
			return callSessionState();
		}).then(function (st) {
			self.session = st || {};
			self.renderBand();
			return self.refreshStatus();
		}).catch(function (e) {
			self.dismiss(n);
			self.notice(_('Sign-out failed: %s').format(e), 'error');
		});
	},

	handleRefreshLocations: function () {
		var self = this;
		return callRefreshLocations().then(function (r) {
			if (r && r.error) {
				self.notice(r.error, 'warning');
				return;
			}
			var n = self.notice(_('Downloading the server list…'), 'info');
			var tries = 0;
			var poll_ = function () {
				return callLocations().then(function (res) {
					if (res && res.available) {
						self.dismiss(n);
						self.locations = res;
						self.rebuildPoolWidget();
						self.refreshServerList();
						self.renderBand();
						self.notice(_('Server list updated: %d servers.')
							.format(res.stats.gateways), 'info', 4000);
						return;
					}
					if (++tries > 40) {
						self.dismiss(n);
						return self.notice(_('The server list did not arrive in time.'), 'warning');
					}
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
		// Kept for callers that still want a plain string; the picked-location
		// list and the picker rows draw their own flag through flagNode(),
		// which falls back to a code badge where Unicode has no flag.
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

	// Whether the server list knows this code AT ALL, in any hop mode.
	//
	// poolResolve() searches the CURRENT mode only, so it answers null for
	// two very different situations: a code that exists but is not offered
	// here (a Secure Core country while Standard is selected), and a code the
	// cache has never heard of. The first is a filter and the entry is kept
	// and hidden; the second is a dead entry that the user has to be able to
	// delete, and telling them apart is the whole point of this function.
	//
	// While the list has not loaded, nothing is known and nothing is
	// condemned: every code would look dead against an empty cache, and a
	// slow page load is the worst possible moment to say so.
	poolCodeOffered: function (code) {
		var l = this.locations || {};
		if (!l.available || !Array.isArray(l.countries))
			return true;
		var cc = String(code || '').split('-')[0];
		for (var i = 0; i < l.countries.length; i++) {
			var c = l.countries[i];
			if (c.code !== cc)
				continue;
			if (c.code === code)
				return true;
			var cities = c.cities || [];
			for (var j = 0; j < cities.length; j++)
				if (cities[j].code === code)
					return true;
			return false;
		}
		return false;
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
		// Keep an open panel in sync with the set (✓ marks, counts, city
		// lists) AND with the hop mode, whose change disables the IPv6-only
		// toggle in the panel head. poolRenderPanel() carries focus and the
		// filter text across, so repainting the whole thing under the user's
		// hands is safe.
		if (this._poolOpen)
			this.poolRenderPanel();

		// The row a user just removed cannot be restored by key, so focus
		// lands on the control that adds a new one rather than on <body>.
		this.repaintKeepingFocus(this.poolChips, L.bind(function () {
			this.rebuildPoolRows();
		}, this), this.poolTrigger);
	},

	rebuildPoolRows: function() {
		dom.content(this.poolChips, nodes(''));
		// One row per country (country-first model). A whole-country row names
		// the country; a narrowed one lists its picked cities in the same
		// column.
		//
		// An entry that does not resolve in the current hop mode is one of
		// two things, and they must not be treated alike:
		//
		//  * still offered in another mode — hidden, and kept in poolEntries
		//    so a round-trip mode switch does not lose it. Switching modes
		//    therefore reads as an empty set until valid locations are picked.
		//  * not in the server list at all — SHOWN, marked, and removable.
		//    It used to be dropped from the display while collectIntoUci went
		//    on writing it back on every save, so the set could not be edited
		//    to something valid from this page: the only way out was uci.
		var groups = [], byCc = {}, unknown = [], byDead = {};
		this.poolEntries.forEach(L.bind(function(e) {
			var cc = e.kind === 'country' ? e.code : e.code.split('-')[0];
			if (e.count == null) {
				if (this.poolCodeOffered(e.code))
					return;
				var d = byDead[cc];
				if (!d) {
					d = { cc: cc, codes: [] };
					byDead[cc] = d;
					unknown.push(d);
				}
				d.codes.push(e.code);
				return;
			}
			var g = byCc[cc];
			if (!g) {
				g = { cc: cc, whole: null, cities: [] };
				byCc[cc] = g;
				groups.push(g);
			}
			if (e.kind === 'country')
				g.whole = e;
			else
				g.cities.push(e);
		}, this));

		var total = 0;
		groups.forEach(function(g) {
			if (g.whole) {
				if (g.whole.count != null) total += g.whole.count;
			} else {
				g.cities.forEach(function(e) { if (e.count != null) total += e.count; });
			}
		});

		// An aligned list, not chips. Chips put one pill per row anyway (their
		// container was a column flex), and a narrowed country concatenated
		// every city name into a single nowrap pill with no width bound —
		// "Germany · Berlin, Frankfurt, Düsseldorf" simply ran off the screen.
		// Here the columns line up, and only the name column may lose text:
		// the measured row minimum is 103-127px whatever the name is, against
		// 304-361px for the picker rows the chips sat under.
		var list = (groups.length || unknown.length) ? E('div', { class: 'pv-sel' }) : null;
		groups.forEach(L.bind(function(g) {
			var cname = this.countryLabel(g.cc);
			var name, detail;
			if (g.whole) {
				name = cname;
				detail = _('%d servers').format(g.whole.count);
			} else {
				name = cname + ' · ' +
					g.cities.map(function(e) { return e.name || e.code; }).join(', ');
				detail = g.cities.length === 1 ? _('1 city')
					: _('%d cities').format(g.cities.length);
			}
			list.appendChild(this.selRow(g.cc, name, detail, false));
		}, this));
		// The rows for codes the server list has never heard of. Same shape as
		// the rest so the columns still line up, dashed and italic so it is
		// obvious at a glance which is which — the meaning the old chip
		// carried with its dashed border — and with the same × as everything
		// else, because being able to delete it is the entire point.
		unknown.forEach(L.bind(function(d) {
			list.appendChild(this.selRow(d.cc, d.codes.join(', '),
				_('not in the server list'), true));
		}, this));
		if (list)
			this.poolChips.appendChild(list);

		var summary = '';
		if (groups.length)
			summary = total ? _('set: %d countries, ~%d servers').format(groups.length, total)
				: _('set: %d countries').format(groups.length);
		this.poolChips.appendChild(this.poolCount);
		dom.content(this.poolCount, nodes(summary));

		// Guidance: the server list drives the picker, and the set must not be
		// empty — the connection picks within it.
		var note = '';
		if (!(this.locations || {}).available)
			note = _('Loading server list… use "Refresh server list" in Advanced settings if it does not appear.');
		else if (!groups.length)
			note = _('Add at least one country or city.');
		dom.content(this.poolNote, nodes(note));
		this.poolNote.classList.toggle('hidden', !note);
		if (this.poolTrigger)
			this.poolTrigger.disabled = !(this.locations || {}).available;
	},

	// One row of the picked-location list: flag · name · detail · remove.
	//
	// The row keeps its own click so the mouse gets the whole row as a hit
	// target, while the NAME is the button a keyboard reaches. The name
	// rather than the row itself, because the row also holds the remove
	// button and a button inside a button is not a thing; both handlers stop
	// propagation so a click on the name cannot also fire the row.
	//
	// `dead` is for a code the server list no longer knows: same shape, so
	// the columns still line up, plus the dashed styling the chip this list
	// replaced used to carry for exactly this case.
	selRow: function (cc, name, detail, dead) {
		return E('div', {
			class: 'pv-selrow' + (dead ? ' pv-sel-stale' : ''),
			title: _('Edit or remove'),
			click: L.bind(function(ev) { ev.stopPropagation(); this.poolOpenCountry(cc, true); }, this) },
			nodes([
				this.flagNode(cc),
				E('button', { type: 'button', class: 'pv-rowbtn pv-selname',
					title: name, 'data-pv-focus': 'sel:' + cc,
					click: L.bind(function(ev) {
						ev.stopPropagation();
						if (ev.preventDefault)
							ev.preventDefault();
						this.poolOpenCountry(cc, true);
					}, this) }, nodes(name)),
				E('span', { class: 'pv-seldetail' }, nodes(detail)),
				E('button', { class: 'pv-selx', type: 'button',
					title: _('Remove'), 'data-pv-focus': 'selx:' + cc,
					'aria-label': _('Remove %s').format(name),
					click: L.bind(function(ev) {
						ev.stopPropagation();
						if (ev.preventDefault)
							ev.preventDefault();
						this.poolRemoveCountry(cc);
					}, this) }, nodes('\u00D7'))
			]));
	},

	/* ---- pickers ------------------------------------------------------ */

	// Escape closes a panel, from anywhere inside it.
	//
	// The mouse has the ✕ and a click outside; this is the keyboard's way out,
	// and without it a picker could be opened from the keyboard and not
	// closed from it. Bound to the panel element, which is built once and
	// outlives every rebuild of its contents, so the handler survives the
	// repaints that replace the rows under it.
	//
	// ONE rule, wherever focus is — including in the filter box. Escape
	// meaning "clear the field" there and "close the panel" everywhere else
	// is two behaviours behind one key, and the filter is reset on every open
	// anyway, so closing costs nothing anybody would want to keep.
	//
	// The event is stopped: an Escape that closed this panel must not also
	// reach whatever is behind it.
	bindPanelEscape: function (panel, closer) {
		// Bound on the way in rather than at construction, so every path that
		// opens a panel gets it; the flag keeps that to a single listener.
		if (!panel || panel._pvEscapeBound)
			return;
		panel._pvEscapeBound = true;
		panel.addEventListener('keydown', L.bind(function (ev) {
			if (!ev || ev.key !== 'Escape')
				return;
			ev.preventDefault();
			ev.stopPropagation();
			this[closer]();
		}, this));
	},

	// Both pickers are inline panels rather than modals, so nothing dismisses
	// them on its own: without this they could only be closed through their own
	// ✕, which is not how a dropdown is expected to behave. One document-level
	// listener serves both.
	//
	// Capture phase on purpose: it runs BEFORE the trigger's own handler, so
	// the click that opens a panel is still seen while that panel is closed and
	// cannot immediately shut it again. Clicks on a panel or on its trigger are
	// left alone; everything else closes whatever is open — including opening
	// one picker while the other is still up.
	bindOutsideClose: function () {
		if (this._outsideBound)
			return;
		this._outsideBound = true;
		document.addEventListener('click', L.bind(function (ev) {
			var t = ev.target;
			var inside = function (node) {
				return node && node.contains && node.contains(t);
			};
			if (this._poolOpen && !inside(this.poolPanel) && !inside(this.poolTrigger))
				this.poolClosePanel();
			if (this._srvOpen && !inside(this.srvPanel) && !inside(this.srvTrigger))
				this.srvClosePanel();
		}, this), true);
	},

	/* ---- location picker panel --------------------------------------- */

	// Opens the panel. NOT a toggle, however much the trigger looks like one:
	// the trigger hides while the panel is open, so its own click — the only
	// caller — can never arrive to close it again. The close branch that used
	// to sit here was unreachable, and a dismissal path that cannot be
	// reached is worse than no path, because it reads as one. Dismissal is
	// Escape, the ✕ and a click outside; see poolClosePanel().
	poolOpenPanel: function() {
		if (this._poolOpen)
			return;
		this._poolEdit = false;
		this._poolCountry = null;
		this._poolExpanded = {};
		this._poolFilter = '';
		// View filter, not a setting: it only defaults from the requirement
		// (the user already said IPv6 gateways are what they want) and can be
		// turned right back off; nothing of it reaches uci.
		this._poolV6Only = this.requireV6Active();
		this._poolOpen = true;
		this.bindPanelEscape(this.poolPanel, 'poolClosePanel');
		if (this.poolTrigger) this.poolTrigger.classList.add('hidden');
		this.poolPanel.classList.remove('hidden');
		this.poolRenderPanel();
	},

	poolClosePanel: function() {
		// Decided BEFORE the panel is hidden: once it is, the element that
		// held focus is no longer rendered and the answer is already lost.
		var handBack = this.focusInside(this.poolPanel);
		this._poolOpen = false;
		if (this.poolPanel) this.poolPanel.classList.add('hidden');
		if (this.poolTrigger) this.poolTrigger.classList.remove('hidden');
		if (handBack && this.poolTrigger && this.poolTrigger.focus)
			this.poolTrigger.focus();
	},

	// Open the picker from a chip: the same accordion as the plain add flow,
	// but that one country arrives expanded and the list ends in a "remove
	// this country" row. The country is added whole when it was not in the
	// set yet ("pick a country = whole country in the set").
	poolOpenCountry: function(cc, edit) {
		if (!this.poolCountryHas(cc).has)
			this.poolSetWhole(cc);
		this._poolEdit = !!edit;
		this._poolCountry = cc;
		this._poolExpanded = {};
		this._poolExpanded[cc] = true;
		this._poolFilter = '';
		this._poolV6Only = this.requireV6Active();
		this._poolOpen = true;
		this.bindPanelEscape(this.poolPanel, 'poolClosePanel');
		if (this.poolTrigger) this.poolTrigger.classList.add('hidden');
		this.poolPanel.classList.remove('hidden');
		this.poolRenderPanel();
	},

	// The chevron hit: expand or collapse one country's cities in place. Pure
	// presentation — it never touches the set and never swaps the list.
	poolToggleExpand: function(cc) {
		this._poolExpanded = this._poolExpanded || {};
		if (this._poolExpanded[cc])
			delete this._poolExpanded[cc];
		else
			this._poolExpanded[cc] = true;
		this.poolRenderCountryList();
	},

	// The panel: a head with close, a filter, then the accordion list. Edit
	// mode (reached from a chip) is the same accordion, headed by the country
	// being edited.
	poolRenderPanel: function() {
		var panel = this.poolPanel;
		if (!panel)
			return;
		// Two different events reach this function. A genuine OPEN, where
		// focus is somewhere else on the page and belongs in the filter box;
		// and a repaint under the user's hands — a country toggled, the hop
		// mode changed — where focus is already inside the panel and must
		// stay on the control it is on. Focusing the filter on the second
		// would drag a keyboard user out of the list on every pick.
		var doc = panel.ownerDocument;
		var act = doc && doc.activeElement;
		var hadFocus = !!(act && panel.contains && panel.contains(act));
		var filt = null;
		this.repaintKeepingFocus(panel, L.bind(function () {
			filt = this.poolRenderPanelBody(panel);
		}, this));
		if (!hadFocus && filt)
			setTimeout(function() { try { filt.focus(); } catch (e) {} }, 0);
	},

	// Builds the panel's contents and hands back the filter input, which is
	// the control an open focuses.
	poolRenderPanelBody: function(panel) {
		dom.content(panel, nodes([]));

		var title;
		if (this._poolEdit && this._poolCountry) {
			var cflag = this.countryFlag(this._poolCountry);
			title = (cflag ? cflag + ' ' : '') + this.countryLabel(this._poolCountry);
		} else {
			title = _('Add a location');
		}
		panel.appendChild(E('div', { class: 'pv-pool-head' }, nodes([
			E('span', {}, nodes(title)),
			E('button', { type: 'button', class: 'pv-pool-x', title: _('Close'),
				'data-pv-focus': 'panel-close', 'aria-label': _('Close'),
				click: L.bind(function(ev) { ev.stopPropagation(); this.poolClosePanel(); }, this) }, nodes('✕'))
		])));
		var filt = E('input', { type: 'text', class: 'cbi-input-text pv-pool-filter',
			'data-pv-focus': 'panel-filter',
			placeholder: _('Filter') + '…', value: this._poolFilter });
		filt.addEventListener('input', L.bind(function() {
			this._poolFilter = filt.value;
			this.poolRenderCountryList();
		}, this));
		filt.addEventListener('click', function(ev) { ev.stopPropagation(); });
		// "IPv6 only": a view filter over the accordion. Disabled with the
		// reason in Secure Core/Tor rather than hidden — ipv6_count is
		// standard-only, so there the filter could only empty the list, and
		// a control that vanishes without a word teaches nothing. The box
		// keeps its checked state while disabled, so a mode round trip
		// restores it.
		var hop = this.hopMode();
		var v6box = E('input', { type: 'checkbox', 'data-pv-focus': 'panel-v6only',
			change: L.bind(function() {
			this._poolV6Only = v6box.checked;
			this.poolRenderCountryList();
		}, this) });
		v6box.checked = this.v6FilterOn();
		if (hop !== 'standard') {
			v6box.disabled = true;
			v6box.checked = !!this._poolV6Only;
		}
		var v6title = (hop === 'secure_core')
			? _('No Secure Core gateway forwards IPv6, so this would empty the list.')
			: (hop === 'tor'
				? _('No Tor gateway forwards IPv6, so this would empty the list.')
				: _('Show only locations whose gateways forward IPv6'));
		panel.appendChild(E('div', { class: 'pv-pool-filterrow' }, nodes([
			filt,
			E('label', { class: 'pv-check pv-pool-v6only', title: v6title }, nodes([
				v6box, _('IPv6 only') ]))
		])));
		this._poolListEl = E('div', {});
		panel.appendChild(this._poolListEl);
		this.poolRenderCountryList();
		return filt;
	},

	// The metadata half of an accordion row: the average-load dot and figure
	// (only when the cache carries them — see hopLoadKey), then the gateway
	// counter and the IPv6 count label. Lives outside the .grow name span so
	// a long name ellipsises alone and never eats these.
	poolMetaKids: function (count, avg, v6row) {
		var kids = [];
		if (typeof avg === 'number') {
			kids.push(E('span', { class: 'pv-dot ' + this.srvLoadClass(avg),
				title: _('Average load of these gateways') }));
			kids.push(E('span', {}, nodes('%d%%'.format(avg))));
		}
		kids.push(E('span', {}, nodes('(%d)'.format(count) + this.v6CountLabel(v6row))));
		return kids;
	},

	// The accordion: one row per country, two cells each. The hit cell (name
	// side) toggles the whole country in the set; the exp cell (the 34px
	// chevron column) expands that country's city rows inline. Mark: whole =
	// check, partial = small square, none = blank. The square (U+25AA) renders
	// in the theme font, unlike the half-circle that used to be here and came
	// out as tofu on the router. City rows repeat the two cells but their exp
	// cell is an inert spacer, so the chevron column stays aligned.
	poolRenderCountryList: function() {
		var el = this._poolListEl;
		if (!el)
			return;
		// Activating a row re-renders the whole list under the finger that
		// pressed it. Without carrying focus across, the first Enter throws
		// it to the document and a second country cannot be picked without
		// reaching for the mouse.
		this.repaintKeepingFocus(el, L.bind(function () {
			this.poolRenderCountryRows(el);
		}, this));
	},

	poolRenderCountryRows: function(el) {
		dom.content(el, nodes([]));
		var f = (this._poolFilter || '').toLowerCase();
		var any = false;
		var key = this.hopCountKey();
		var loadKey = this.hopLoadKey();
		var v6only = this.v6FilterOn();
		var v6hidden = 0;
		var v6chidden = 0;
		this.filteredCountries().forEach(L.bind(function(c) {
			if (f && c.name.toLowerCase().indexOf(f) < 0 && c.code.toLowerCase().indexOf(f) < 0)
				return;
			if (v6only && !(c.ipv6_count > 0)) {
				// Dropped, but never silently: counted here, reported under
				// the list — see the comment above v6CountLabel.
				v6hidden++;
				return;
			}
			any = true;
			var cc = c.code;
			var st = this.poolCountryHas(cc);
			var mark = st.whole ? '☑' : (st.has ? '▪' : '');
			var open = !!(this._poolExpanded || {})[cc];
			// Two buttons, not two spans with handlers: Tab reaches them,
			// Enter and Space activate them, and the focus ring is drawn.
			// aria-pressed carries what the ☑ in the box cell says visually,
			// which a screen reader never sees; aria-expanded does the same
			// for the chevron.
			el.appendChild(E('div', { class: 'pv-pool-row pv-acc-row' +
				(st.has ? ' is-in' : '') + (open ? ' pv-acc-open' : '') }, nodes([
				E('button', { type: 'button', class: 'pv-rowbtn pv-acc-hit',
					'data-pv-focus': 'cc:' + cc,
					// "mixed" is what ARIA has for exactly this: some of the
					// country's cities are picked and not the whole of it.
					// The ▪ in the box cell is the sighted cue for it and a
					// screen reader never sees that.
					'aria-pressed': st.whole ? 'true' : (st.has ? 'mixed' : 'false'),
					click: L.bind(function(ev) { ev.stopPropagation(); this.poolToggleWhole(cc); }, this) }, nodes([
						E('span', { class: 'box' }, nodes(mark)),
						E('span', { class: 'grow' }, nodes([ this.flagNode(cc), ' ' + c.name ])),
						E('span', { class: 'pv-acc-meta' },
							nodes(this.poolMetaKids(c.gateway_count || 0, c[loadKey], c)))
					])),
				E('button', { type: 'button', class: 'pv-rowbtn pv-acc-exp',
					'data-pv-focus': 'exp:' + cc,
					'aria-expanded': open ? 'true' : 'false',
					'aria-label': _('Show the cities of %s').format(c.name),
					click: L.bind(function(ev) { ev.stopPropagation(); this.poolToggleExpand(cc); }, this) },
					nodes(open ? '▾' : '›'))
			])));
			if (!open)
				return;
			(c.cities || []).forEach(L.bind(function(city) {
				if (v6only && !(city.ipv6_count > 0)) {
					// Dropped cities count too: only expanded countries reach
					// this loop, so every drop here is a row the user would
					// otherwise see — the same no-silent-narrowing rule as for
					// countries, reported under the list.
					v6chidden++;
					return;
				}
				var on = st.whole || !!st.cities[city.code];
				// The city's expand cell stays an inert <span>: it is a
				// spacer that keeps the chevron column aligned, and making it
				// a button would put a tab stop on something that does
				// nothing.
				el.appendChild(E('div', { class: 'pv-pool-row pv-acc-row pv-acc-city' +
					(on ? ' is-in' : '') }, nodes([
					E('button', { type: 'button', class: 'pv-rowbtn pv-acc-hit',
						'data-pv-focus': 'city:' + city.code,
						'aria-pressed': on ? 'true' : 'false',
						click: L.bind(function(ev) { ev.stopPropagation(); this.poolToggleCity(cc, city.code); }, this) }, nodes([
							E('span', { class: 'box' }, nodes(on ? '☑' : '☐')),
							E('span', { class: 'grow' }, nodes(city.name)),
							E('span', { class: 'pv-acc-meta' },
								nodes(this.poolMetaKids(city[key] || 0, city[loadKey], city)))
						])),
					E('span', { class: 'pv-acc-exp' })
				])));
			}, this));
		}, this));
		if (!any)
			el.appendChild(E('div', { class: 'pv-pool-row is-in' }, nodes(_('No matches'))));
		// The narrowing is always said out loud: a location that silently
		// disappeared would make the backend's later "no IPv6 gateways in the
		// selected locations" impossible to act on. Countries and cities get
		// their own lines — reporting a country as hidden when only cities
		// were dropped would be its own kind of lie.
		if (v6hidden > 0)
			el.appendChild(E('div', { class: 'pv-pool-row is-in pv-pool-v6hidden' },
				nodes(v6hidden === 1
					? _('1 country hidden — no IPv6 gateways')
					: _('%d countries hidden — no IPv6 gateways').format(v6hidden))));
		if (v6chidden > 0)
			el.appendChild(E('div', { class: 'pv-pool-row is-in pv-pool-v6hidden' },
				nodes(v6chidden === 1
					? _('1 city hidden — no IPv6 gateways')
					: _('%d cities hidden — no IPv6 gateways').format(v6chidden))));
		if (this._poolEdit) {
			var rmcc = this._poolCountry;
			el.appendChild(E('div', { class: 'pv-pool-sep' }));
			el.appendChild(E('div', { class: 'pv-pool-row pv-acc-row pv-pool-remove' }, nodes([
				E('button', { type: 'button', class: 'pv-rowbtn pv-acc-hit',
					'data-pv-focus': 'rm:' + rmcc,
					click: L.bind(function(ev) {
						ev.stopPropagation();
						this.poolRemoveCountry(rmcc);
						this.poolClosePanel();
					}, this) }, nodes([
						E('span', { class: 'box' }, nodes('🗑')),
						E('span', { class: 'grow' }, nodes(_('Remove this country')))
					])),
				E('span', { class: 'pv-acc-exp' })
			])));
		}
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
	srvLowestLoad: function() {
		var best = null;
		var v6 = this.requireV6Active();
		((this._serverData && this._serverData.relays) || []).forEach(L.bind(function(r) {
			if (typeof r.load !== 'number') return;
			// The quick action is a pin like any other, so it has to draw from
			// the same pool the list shows — otherwise one click hands the
			// backend a server it will refuse to connect to.
			if (v6 && !this.relayHasV6(r)) return;
			if (!best || r.load < best.load) best = r;
		}, this));
		return best;
	},

	// The trigger shows the current pin richly (load dot / flag / city / name),
	// or "Automatic server", with an inline clear when pinned.
	srvRenderTrigger: function() {
		var t = this.srvTrigger;
		if (!t)
			return;
		// The × lives inside this trigger and rebuilds itself away when it is
		// pressed — clearing the pin leaves no × at all. The trigger itself
		// is the fallback: it is what the × was attached to and what now
		// offers to pick a server again.
		this.repaintKeepingFocus(t, L.bind(function () {
			this.srvRenderTriggerBody(t);
		}, this), t);
	},

	srvRenderTriggerBody: function(t) {
		var host = this._serverChosen;
		if (!host) {
			dom.content(t, nodes(_('Automatic server')));
			return;
		}
		var r = this.srvRelayByHost(host);
		var kids;
		if (r) {
			var flag = this.countryFlag(r.country_code);
			kids = [
				E('span', { class: 'pv-dot ' + this.srvLoadClass(r.load) }),
				E('span', {}, nodes(' ' + (flag ? flag + ' ' : '') +
					'%s / %s'.format(r.city || '?', r.name || r.hostname) +
					(r.load != null ? ' (%d%%)'.format(r.load) : '')))
			];
		} else {
			kids = [ E('span', {}, nodes(host + ' ' + _('(not in the set)'))) ];
		}
		kids.push(E('button', { type: 'button', class: 'pv-srv-x',
			title: _('Clear (back to automatic)'), 'data-pv-focus': 'srv-clear',
			'aria-label': _('Clear the pinned server'),
			click: L.bind(function(ev) { ev.preventDefault(); ev.stopPropagation(); this.srvSetChosen(''); }, this) }, nodes('×')));
		dom.content(t, nodes(kids));
	},

	// Opens the panel; see poolOpenPanel() for why this is not a toggle.
	srvOpenPanel: function() {
		if (this._srvOpen)
			return;
		this._srvFilter = '';
		this._srvOpen = true;
		this.bindPanelEscape(this.srvPanel, 'srvClosePanel');
		if (this.srvTrigger) this.srvTrigger.classList.add('hidden');
		this.srvPanel.classList.remove('hidden');
		this.srvRenderPanel();
	},

	srvClosePanel: function() {
		// Same as the location panel: read it before hiding, hand the
		// keyboard to the trigger that is reappearing. This is also the path
		// a keyboard pick takes — srvSetChosen() ends here, and the row that
		// was just activated stops existing.
		var handBack = this.focusInside(this.srvPanel);
		this._srvOpen = false;
		if (this.srvPanel) this.srvPanel.classList.add('hidden');
		if (this.srvTrigger) this.srvTrigger.classList.remove('hidden');
		if (handBack && this.srvTrigger && this.srvTrigger.focus)
			this.srvTrigger.focus();
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
		// Same two events as the location panel: a genuine OPEN, where the
		// filter should take the keyboard, and a repaint under the user's
		// hands — refreshServerList() re-renders an open panel whenever its
		// answer arrives — where focus has to stay on the control it is on.
		var hadFocus = this.focusInside(panel);
		var filt = null;
		this.repaintKeepingFocus(panel, L.bind(function () {
			filt = this.srvRenderPanelBody(panel);
		}, this));
		if (!hadFocus && filt)
			setTimeout(function() { try { filt.focus(); } catch (e) {} }, 0);
	},

	// Builds the panel's contents and hands back the filter input, which is
	// the control an open focuses.
	srvRenderPanelBody: function(panel) {
		dom.content(panel, nodes(''));
		panel.appendChild(E('div', { class: 'pv-pool-head' }, nodes([
			E('span', {}, nodes(_('Pick a server'))),
			E('button', { type: 'button', class: 'pv-pool-x', title: _('Close'),
				'data-pv-focus': 'srv-panel-close', 'aria-label': _('Close'),
				click: L.bind(function(ev) { ev.stopPropagation(); this.srvClosePanel(); }, this) }, nodes('✕'))
		])));
		var filt = E('input', { type: 'text', class: 'cbi-input-text pv-pool-filter',
			'data-pv-focus': 'srv-panel-filter',
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
		return filt;
	},

	srvRenderList: function() {
		var el = this._srvListEl;
		if (!el)
			return;
		dom.content(el, nodes(''));
		var chosen = this._serverChosen;
		var current = this.srvCurrentGateway();
		var f = (this._srvFilter || '').toLowerCase();

		// Same rule as the location picker: a row that picks is a button, so
		// Tab reaches it and Enter fires it. The rows that only report
		// something (group headers, "no matches") stay plain divs — a tab
		// stop on a sentence is noise.
		el.appendChild(E('button', { type: 'button', class: 'pv-rowbtn pv-pool-row pv-srv-quick',
			'data-pv-focus': 'srv:auto', 'aria-pressed': chosen ? 'false' : 'true',
			click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(''); }, this) }, nodes([
				E('span', { class: 'box' }, nodes(chosen ? '' : '☑')),
				E('span', { class: 'grow' }, nodes(_('Automatic (rotation picks)')))
			])));
		var best = this.srvLowestLoad();
		if (best) {
			var bn = this.countryLabel(best.country_code);
			el.appendChild(E('button', { type: 'button', class: 'pv-rowbtn pv-pool-row pv-srv-quick',
				'data-pv-focus': 'srv:lowest',
				click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(best.name || best.hostname); }, this) }, nodes([
					E('span', { class: 'box' }, nodes('⚡')),
					E('span', { class: 'grow' }, nodes(_('Lowest load') + ' · ' + (best.city || bn) +
						(best.load != null ? ' (%d%%)'.format(best.load) : ''))),
					E('span', { class: 'pv-dot ' + this.srvLoadClass(best.load) })
				])));
		}
		el.appendChild(E('div', { class: 'pv-pool-sep' }));

		// The badge only means something under ipv6_mode 'auto': that is the
		// one mode where the bit changes what happens to a client's traffic.
		// In 'block'/'off' IPv6 is not routed whichever server is picked, so
		// labelling servers would be noise — and an invitation to ask why the
		// label lies.
		var showV6 = (this.v6Sel ? this.v6Sel.value
			: (uci.get('protonvpn', this.instance, 'ipv6_mode') || 'block')) === 'auto';
		// With the requirement on, an ineligible gateway is not merely
		// unlabelled — it is not on offer, because the backend would refuse
		// it. Groups are built from the surviving rows, so a country with
		// nothing left simply does not appear: an empty group header would
		// promise servers that are not there, and its count — computed from
		// the whole fleet — would be a number the list cannot justify.
		var onlyV6 = this.requireV6Active();

		var groups = [], byCode = {};
		((this._serverData && this._serverData.relays) || []).forEach(L.bind(function(r) {
			if (onlyV6 && !this.relayHasV6(r))
				return;
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
			// Sort by the number the row actually shows. Proton's own `score`
			// ranks servers better — it appears to fold in distance, since a
			// German server scores ~1.5 against ~2.9 for Slovenia from the same
			// router — but it is invisible here, and ordering by an invisible
			// field makes the visible percentages look shuffled. Within one
			// country its resolution also collapses (all 64 Slovenian servers
			// sit inside 0.15) so the order it produces there is close to
			// arbitrary anyway.
			//
			// The tiebreak is numeric-aware on purpose: a plain string compare
			// puts SI#27 before SI#5, which reads as broken when a whole page
			// of servers shares the same load.
			g.rows.sort(function(a, b) {
				var al = typeof a.load === 'number' ? a.load : 999;
				var bl = typeof b.load === 'number' ? b.load : 999;
				if (al !== bl)
					return al - bl;
				return (a.name || a.hostname || '').localeCompare(
					b.name || b.hostname || '', undefined, { numeric: true });
			});
			el.appendChild(E('div', { class: 'pv-srv-grp' }, nodes((g.flag ? g.flag + ' ' : '') +
				'%s (%d)'.format(g.name, g.rows.length))));
			g.rows.forEach(L.bind(function(r) {
				var isCur = current && (r.name === current || r.hostname === current);
				var isPin = (r.name || r.hostname) === chosen;
				el.appendChild(E('button', { type: 'button',
					class: 'pv-rowbtn pv-pool-row' + (isPin ? ' is-in' : ''),
					'data-pv-focus': 'srv:' + (r.name || r.hostname),
					'aria-pressed': isPin ? 'true' : 'false',
					click: L.bind(function(ev) { ev.stopPropagation(); this.srvSetChosen(r.name || r.hostname); }, this) }, nodes([
						E('span', { class: 'pv-dot ' + this.srvLoadClass(r.load) }),
						E('span', { class: 'grow' }, nodes('%s / %s'.format(r.city || '?', r.name || r.hostname))),
						r.secure_core ? E('span', { class: 'pv-tagline' },
							nodes(this.countryLabel(r.entry_country) + ' → ')) : '',
						r.tier === 0 ? E('span', { class: 'pv-tagline' }, nodes(_('free'))) : '',
						// Bit 16 of the logical server's Features bitmask is
						// ProtonVPN's IPv6 flag (protonvpn.common FEATURE_IPV6);
						// cache.uc keeps the raw mask on every relay.
						(showV6 && this.relayHasV6(r)) ? E('span', { class: 'pv-srv-v6',
							title: _('This server forwards IPv6 through the tunnel') }, nodes(_('IPv6'))) : '',
						isCur ? E('span', { class: 'pv-srv-cur' }, nodes('● ' + _('current'))) : '',
						E('span', { class: 'pv-srv-load' }, nodes(r.load != null ? '%d%%'.format(r.load) : ''))
					])));
			}, this));
		}, this));

		if (chosen && !this.srvChosenOfferable())
			el.appendChild(E('div', { class: 'pv-pool-row is-in' }, nodes(chosen + ' ' +
				(this.srvRelayByHost(chosen) ? _('(does not forward IPv6)')
					: _('(not in the set)')))));
		else if (!groups.length)
			// Say which emptiness this is. "No matches" under an active
			// requirement sends the user to widen a filter that is not the
			// problem, and the connection is about to be refused for a reason
			// they were never shown.
			el.appendChild(E('div', { class: 'pv-pool-row is-in' },
				nodes((onlyV6 && !f) ? _('No gateways in these locations forward IPv6.')
					: _('No matches'))));
	},

	// ── card chrome ──────────────────────────────────────────────────────

	// One header line for both cards: led · label · detail · actions.
	//
	// An explicit grid, never flex-wrap. The detail is the only column that
	// flexes, so a long server name is ellipsised in its own column instead of
	// pushing the buttons onto a second row — which is what left the old
	// header ragged at narrow widths.
	//
	// `primary` is always visible. `secondary` is inline from 34em and behind
	// the kebab below it, so a desktop where four buttons fit shows four
	// buttons rather than a menu. The kebab is built only when there is
	// something for it to reveal.
	cardLine: function (card, led, label, detail, primary, secondary) {
		var kids = [
			E('span', { class: 'pv-led ' + led }),
			E('span', { class: 'pv-line-label' }, nodes(label)),
			E('span', { class: 'pv-grow', title: detail || '' }, nodes(detail || ''))
		];
		var acts = (primary || []).slice();
		if ((secondary || []).length)
			acts.push(E('button', { class: 'pv-kebab', type: 'button',
				title: _('More actions'), 'aria-label': _('More actions'),
				'data-pv-focus': 'kebab',
				click: L.bind(function (ev) {
					if (ev && ev.preventDefault)
						ev.preventDefault();
					card.classList.toggle('pv-acts-open');
				}, this) }, nodes('\u22EF')));
		if (acts.length)
			kids.push(E('span', { class: 'pv-acts' }, nodes(acts)));
		if ((secondary || []).length)
			kids.push(E('span', { class: 'pv-sec' }, nodes(secondary)));
		return E('div', { class: 'pv-line' }, nodes(kids));
	},

	// Repaint `container` without throwing away the keyboard.
	//
	// dom.content() replaces a container's children, and a browser blurs
	// whatever it removes — even when the very same node goes straight back
	// in, which is what happens to the client-version control on every
	// five-second poll. Focus then falls to <body> and a keyboard user loses
	// their place twelve times a minute.
	//
	// Controls carry a stable data-pv-focus key describing WHAT they do, not
	// where they sit: restoring by position would move focus onto whichever
	// button happened to take that slot, and on this page that could be
	// Disable. When the key is gone — the row the user just removed — focus
	// goes to `fallback` if one is offered, because the alternative is the
	// document body.
	repaintKeepingFocus: function (container, build, fallback) {
		var doc = container && container.ownerDocument;
		var active = doc && doc.activeElement;
		var key = null;
		if (active && active !== container && container.contains &&
			container.contains(active) && active.getAttribute)
			key = active.getAttribute('data-pv-focus');
		build();
		if (key == null)
			return;
		var back = container.querySelector &&
			container.querySelector('[data-pv-focus="' + key + '"]');
		if (!back && fallback && fallback.focus)
			back = fallback;
		if (back && back.focus)
			back.focus();
	},

	// Whether the keyboard is currently somewhere inside this element.
	//
	// Both panel-close paths ask this BEFORE hiding themselves, because
	// hiding a focused element blurs it: focus falls to <body>, the top of
	// the document and nowhere near what the user was doing. They then hand
	// the keyboard to the trigger that is being un-hidden at that same
	// moment. Asking first is what makes it answerable at all, and it is
	// also what keeps a panel closed by a click ELSEWHERE from yanking focus
	// away from whatever that click just gave it to.
	focusInside: function (el) {
		var doc = el && el.ownerDocument;
		var active = doc && doc.activeElement;
		return !!(active && el.contains && el.contains(active));
	},

	// Both cards are repainted by the five-second status poll, and a repaint
	// assigns className wholesale. The open-menu flag has to be carried
	// across or a menu the user has just opened shuts by itself within five
	// seconds, under the finger reaching for a button inside it.
	keepOpenFlag: function (card, cls) {
		return (card && card.classList && card.classList.contains('pv-acts-open'))
			? cls + ' pv-acts-open' : cls;
	},

	// A labelled fact for the state card. Label and value are separate
	// elements on purpose: that is what lets the value ellipsise on its own
	// rather than the whole line reflowing, and what replaced the middot
	// run-on that used to carry eight facts in one sentence.
	fact: function (label, value) {
		return E('div', { class: 'pv-fact' }, nodes([
			E('b', {}, nodes(label)), E('span', {}, nodes(value))
		]));
	},

	// ── credential banner ────────────────────────────────────────────────

	// Session expiry is NOT an outage: the tunnel and rotation keep working
	// from the cache, so the banner stays calm until the certificate — the
	// real deadline — is at risk.
	renderBand: function () {
		if (!this.bandEl)
			return;
		var st = this.session || {};
		var led, detail, explain = null;
		var primary = [], secondary = [];
		var cls = 'pv-card pv-acct';

		if (st.state === 'active') {
			led = 'pv-led-ok';
			// One line, because nothing is wrong. The paragraph this replaced
			// explained the silent token refresh on every page load and cost
			// 424px of card at 390px wide to say something true once.
			detail = _('signed in · session to %s').format(fmtDay(st.session_expires_at));
			secondary = [
				E('button', { class: 'cbi-button',
					'data-pv-focus': 'update-list',
					click: ui.createHandlerFn(this, 'handleRefreshLocations') },
					nodes(_('Update server list'))),
				E('button', { class: 'cbi-button cbi-button-remove',
					'data-pv-focus': 'sign-out',
					click: ui.createHandlerFn(this, 'handleLogout') }, nodes(_('Sign out')))
			];
		} else if (st.state === 'needs_2fa') {
			cls += ' pv-acct-warn';
			led = 'pv-led-warn';
			detail = _('two-factor code required');
			explain = _('The password was accepted; enter the code from your authenticator to finish.');
			primary = [
				E('button', { class: 'cbi-button cbi-button-apply',
					'data-pv-focus': 'login',
					click: ui.createHandlerFn(this, 'showLoginModal', 'totp') }, nodes(_('Enter code')))
			];
		} else if (st.state === 'expired') {
			cls += ' pv-acct-warn';
			led = 'pv-led-warn';
			detail = _('session expired');
			// Deliberately calm: an expired session does not drop the tunnel.
			explain = _('The tunnel keeps running, but the server list cannot be updated and the certificate cannot be renewed. Sign in again to restore that.');
			primary = [
				E('button', { class: 'cbi-button cbi-button-apply',
					'data-pv-focus': 'login',
					click: ui.createHandlerFn(this, 'showLoginModal', 'credentials') },
					nodes(_('Sign in again')))
			];
		} else {
			cls += ' pv-acct-bad';
			led = 'pv-led-bad';
			detail = _('not signed in');
			explain = _('ProtonVPN needs your account to fetch the server list and register this router as a device.');
			primary = [
				E('button', { class: 'cbi-button cbi-button-apply',
					'data-pv-focus': 'login',
					click: ui.createHandlerFn(this, 'showLoginModal', 'credentials') }, nodes(_('Sign in')))
			];
		}

		this.bandEl.className = this.keepOpenFlag(this.bandEl, cls);
		var kids = [ this.cardLine(this.bandEl, led, _('Proton account'), detail,
			primary, secondary) ];
		// The explanation is kept only where it is an instruction. In the
		// healthy state there is nothing to do about it, and a standing
		// paragraph is permanent furniture.
		if (explain)
			kids.push(E('div', { class: 'pv-acct-sub' }, nodes(explain)));
		// On the card in every session state: it is the setting somebody
		// reaches for while looking at a sign-in that has just failed, so it
		// must not be reachable only from one of those states. Behind a
		// disclosure, because it is also the setting almost nobody touches.
		// The version this package stamps, which the backend now carries on
		// session_state — a call the page already makes when it loads. Read
		// before the control is built so its very first label can name it,
		// and re-filled when it changes, because a repaint is how a page that
		// loaded against an older backend picks it up.
		var builtin = st.app_version_builtin || '';
		if (builtin && builtin !== this.appVerBuiltIn) {
			this.appVerBuiltIn = builtin;
			if (this.appVerSel)
				this.fillClientVersions(this.appVerSel.value);
		}
		kids.push(this.buildClientVersion());
		this.repaintKeepingFocus(this.bandEl, L.bind(function () {
			dom.content(this.bandEl, nodes(kids));
		}, this));
		this.syncClientVersionSummary();
	},

	// ── connection status ────────────────────────────────────────────────

	// What the tunnel is doing right now, plus the actions that change it.
	// Kept separate from the account card above: one is about credentials,
	// this one is about the link.
	// The action row, gated by state so it never offers something the backend
	// would refuse. Three cases, in order:
	//   * no keypair yet — there is nothing to act on, so only Refresh; the
	//     instance is started from the form below (or the login banner),
	//   * administratively off (`disconnect` sets enabled=0 and hands the
	//     networks back to normal routing) — the only sensible action is
	//     Enable, so the rest would be noise,
	//   * running — Reconnect, Rotate and Disable.
	// "Disable", not "Disconnect": the button does not merely drop the tunnel,
	// it turns the instance off, and the daemon will not bring it back.
	// Returns { primary, secondary }. The split is what lets the card follow
	// available width: the primary action is always on screen, the rest are
	// inline from 34em and behind the kebab below it. Refresh is primary only
	// when it is the only action there is — a kebab that opens onto nothing
	// would be an extra click for nothing.
	actionButtons: function (st, disp) {
		// Each button is keyed by what it does. A repaint restores focus by
		// that key and never by position: the action set changes with the
		// state, and landing on "whatever took slot 2" could put focus on
		// Disable.
		var refresh = E('button', { class: 'cbi-button', 'data-pv-focus': 'refresh',
			click: ui.createHandlerFn(this, 'refreshStatus') }, nodes(_('Refresh')));

		if (!st.configured)
			return { primary: [ refresh ], secondary: [] };

		if (st.enabled === false)
			return {
				primary: [ E('button', { class: 'cbi-button cbi-button-apply',
					'data-pv-focus': 'connect',
					click: ui.createHandlerFn(this, 'handleConnect') }, nodes(_('Enable'))) ],
				secondary: [ refresh ]
			};

		var secondary = [ refresh ];
		// Rotation cannot work on a pinned server — the backend refuses it — so
		// that case drops the button entirely. Otherwise it stays put and is
		// merely greyed while there is no live tunnel: a control that appears
		// and disappears under a 5-second poll is worse than a dead one.
		if (!st.fixed) {
			var live = (disp === 'connected' || disp === 'degraded');
			secondary.push(E('button', { class: 'cbi-button', disabled: !live || null,
				'data-pv-focus': 'rotate',
				click: ui.createHandlerFn(this, 'handleRotateNow') }, nodes(_('Rotate now'))));
		}
		secondary.push(E('button', { class: 'cbi-button cbi-button-remove',
			'data-pv-focus': 'disable',
			click: ui.createHandlerFn(this, 'handleDisconnect') }, nodes(_('Disable'))));

		return {
			primary: [ E('button', { class: 'cbi-button cbi-button-apply',
				'data-pv-focus': 'connect',
				click: ui.createHandlerFn(this, 'handleConnect') }, nodes(_('Reconnect'))) ],
			secondary: secondary
		};
	},

	updateStatusBand: function () {
		if (!this.stateEl)
			return;
		var st = this.status || {};
		var cls = 'pv-card pv-state';

		// One source of truth for "what state is this in": the instances table
		// and this card must never disagree, and an administratively disabled
		// instance has to read as deliberate rather than as a failure.
		var disp = this.dispState(st);
		var titles = {
			connected:      _('Connected'),
			connecting:     _('Connecting…'),
			degraded:       _('Degraded'),
			disconnected:   _('Disconnected'),
			disabled:       _('Disabled'),
			error:          _('Error'),
			not_configured: _('Not set up yet')
		};
		var leds = {
			connected: 'pv-led-ok',
			connecting: 'pv-led-warn',
			degraded: 'pv-led-warn',
			// Switched off on purpose — worth noticing, but not a fault.
			disabled: 'pv-led-warn'
		};
		var title = titles[disp] || this.stateInfo(disp).label;
		var led = leds[disp] || 'pv-led-bad';
		if (disp === 'degraded')
			cls += ' pv-acct-warn';

		// The header's flexing column: where the tunnel is, in one line. With
		// several tunnels running side by side it also has to say which one
		// the card is describing.
		var head = [];
		if ((this.instances || []).length > 1)
			head.push(this.instance);
		// Ordered by what identifies the tunnel: this column is the one that
		// ellipsises, so at 320px only its beginning is read.
		if (st.gateway)
			head.push(st.gateway);
		if (st.location && st.location.country) {
			var where = this.locationNames(st.location.country, st.location.city)
				.filter(Boolean).join(' / ');
			var flag = this.countryFlag(st.location.country);
			if (where)
				head.push((flag ? flag + ' ' : '') + where);
		}
		if (st.endpoint)
			head.push(st.endpoint);

		// The facts, as labelled pairs. This replaced a single sentence that
		// joined up to eight of them with middots: it wrapped to four lines on
		// a phone, and no value in it could be found by eye.
		var facts = [];
		var hs = this.fmtHandshake(st.latest_handshake_seconds);
		if (hs)
			facts.push(this.fact(_('Handshake'), hs));
		// IPv6 is the one routing decision that changes from server to server,
		// so the card has to say what it is doing right now — and, when it is
		// doing nothing, that the server is the reason rather than a setting.
		var v6 = st.ipv6 || {};
		var v6note = null;
		if (v6.mode === 'auto') {
			if (v6.active)
				facts.push(this.fact(_('IPv6'), _('through the tunnel')));
			// Distinct from the line below on purpose: with the requirement on
			// there is no connected server to blame, and saying there is sends
			// the user looking for a rotation that will never come.
			else if (v6.reason === 'ipv6_required_unavailable') {
				var unmet = this.ipv6Unmet(st);
				v6note = unmet.line + (unmet.exposure ? ' ' + unmet.exposure : '');
			}
			else if (v6.reason === 'gateway_no_ipv6')
				facts.push(this.fact(_('IPv6'), _('blocked — this server does not forward it')));
		}
		if (st.rotation && st.rotation.enabled)
			facts.push(this.fact(_('Rotation'), this.rotationFact()));
		if (st.certificate && st.certificate.present && st.certificate.days_left != null)
			facts.push(this.fact(_('Certificate'), _('%d days left').format(st.certificate.days_left)));
		if (disp === 'connected') {
			var ipKey = this.instance + '|' + (st.gateway || '');
			if (this.extIp && this.extIp.key === ipKey)
				facts.push(this.fact(_('External IP'), this.extIp.ip));
			else
				this.maybeFetchExternalIp(ipKey);
		}
		// Two separate facts, deliberately NOT phrased as one budget: the count
		// is the WireGuard configurations registered on the account (what the
		// dashboard lists under Downloads), while the allowance is the plan's
		// simultaneous-device number. Whether Proton charges the one against
		// the other is not something we have established, and the line this
		// replaced — "0 of 11 connections in use" — was wrong precisely because
		// it asserted a relationship that was not there. It read from the
		// legacy OpenVPN/IKEv2 session list, which stays empty however many
		// WireGuard tunnels are up.
		if (this.account && this.account.max_connect)
			facts.push(this.fact(_('Plan'), _('%s · %s configurations · up to %s devices').format(
				this.account.plan || '', this.account.devices_used != null
					? this.account.devices_used : '?', this.account.max_connect)));

		// Sentences, not facts: these are the two things the card has to say
		// in full because acting on them depends on the wording.
		var notes = [];
		// A Tor exit is a different product, not a flag on an ordinary server —
		// the extra latency and the sites that reject Tor need explaining.
		if (st.hop_mode === 'tor')
			notes.push(_('🧅 Tor over VPN'));
		if (v6note)
			notes.push(v6note);
		// Said only while it is true, and only while IPv6 really is on the
		// tunnel. The reported defect was this card announcing IPv6 as active
		// the moment the rules existed while four of five clients were still
		// holding their old address — a line saying so would have saved the
		// whole investigation. The backend forces the advertisement now, so
		// this is seconds rather than the ten minutes it was, and it stops
		// being said a few minutes later rather than standing there forever.
		if (v6.active && v6.clients_settling)
			notes.push(_('Clients are moving to the tunnel address; one that was asleep may take a few minutes.'));
		// From the LAN a working kill switch looks exactly like a broken
		// internet connection, so name it whenever it is the reason.
		if (disp !== 'connected' && st.routing && st.routing.killswitch)
			notes.push(_('Kill switch is blocking LAN traffic'));

		var acts = this.actionButtons(st, disp);

		this.stateEl.className = this.keepOpenFlag(this.stateEl, cls);
		var kids = [ this.cardLine(this.stateEl, led, title,
			head.join(' · ') || _('No tunnel yet.'), acts.primary, acts.secondary) ];
		if (facts.length)
			kids.push(E('div', { class: 'pv-facts' }, nodes(facts)));
		notes.forEach(function (n) {
			kids.push(E('div', { class: 'pv-state-note' }, nodes(n)));
		});
		this.repaintKeepingFocus(this.stateEl, L.bind(function () {
			dom.content(this.stateEl, nodes(kids));
		}, this));
	},

	// The rotation fact is the RELATIVE time only. nextRotationText() also
	// carries the full local timestamp, which belongs in the rotation section
	// further down the page and not in a column that has to sit beside five
	// others at 320px.
	rotationFact: function () {
		var r = ((this.status || {}).rotation) || {};
		if (!r.next_run)
			return _('on schedule');
		var diff = Math.floor((r.next_run * 1000 - Date.now()) / 1000);
		if (diff < 90)
			return _('due now');
		var h = Math.floor(diff / 3600), m = Math.floor((diff % 3600) / 60);
		return h > 0 ? _('in %dh %dm').format(h, m) : _('in %dm').format(m);
	},

	// Fetch the tunnel's public IP once per instance+gateway combination. The
	// status poll runs every 5 s and this is a live lookup through the tunnel,
	// so the result is cached until the tunnel actually moves. Fetching lazily
	// from the band (rather than only after a manual Connect) is what makes the
	// IP appear when the page is opened on an already-connected tunnel.
	maybeFetchExternalIp: function (key) {
		if (this._extIpPending === key)
			return;
		// Nothing caches this on the router: every call is up to two curl
		// attempts against public services with an 8 s timeout each, bound to
		// the tunnel device. A key that just failed must therefore back off
		// instead of being retried on the next 5-second tick — a tunnel that
		// is up but not passing traffic would otherwise keep rpcd busy
		// permanently. The cooldown still lets a transient failure recover.
		var fail = this._extIpFail;
		if (fail && fail.key === key && (Date.now() - fail.at) < 60000)
			return;
		this._extIpPending = key;
		callExternalIp(this.instance).then(L.bind(function (res) {
			// A newer gateway superseded this lookup while it was in flight.
			if (this._extIpPending !== key)
				return;
			this._extIpPending = null;
			if (res && res.ip) {
				this._extIpFail = null;
				this.extIp = { key: key, ip: res.ip };
				this.updateStatusBand();
			} else {
				this._extIpFail = { key: key, at: Date.now() };
			}
		}, this)).catch(L.bind(function () {
			this._extIpPending = null;
			this._extIpFail = { key: key, at: Date.now() };
		}, this));
	},

	// Drop the cached public IP (and any lookup still in flight) whenever the
	// tunnel it belonged to is gone: showing the previous exit address would be
	// worse than showing nothing. The back-off goes with it, so an explicit
	// reconnect always gets a fresh attempt.
	forgetExternalIp: function () {
		this.extIp = null;
		this._extIpPending = null;
		this._extIpFail = null;
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
			callSessionState().catch(function () { return null; }),
			callInstances().catch(function () { return null; })
		]).then(function (res) {
			if (res[0] && !res[0].error)
				self.status = res[0];
			if (res[1])
				self.session = res[1];
			if (res[2] && res[2].instances)
				self.instances = res[2].instances;
			self.updateInstancesTable();
			self.updateStatusBand();
			self.renderBand();
			// "Next rotation" is a countdown, not a constant: recompute it on
			// every tick or it freezes at whatever it said when the form was
			// built and quietly goes stale by hours.
			if (self.rotNextSpan)
				dom.content(self.rotNextSpan, nodes(self.nextRotationText()));
		});
	},

	// The background status poll is suspended while an apply runs: two pollers
	// compete for the one rpcd worker the apply itself needs, and a band
	// repainted from half-applied state contradicts the "Applying…" banner still
	// on screen. Both apply call sites refresh once on their own when they end.
	pauseStatusPoll: function () {
		this._applyRuns = (this._applyRuns || 0) + 1;
		if (this._applyRuns === 1 && this._statusPoll)
			poll.remove(this._statusPoll);
	},

	resumeStatusPoll: function () {
		this._applyRuns = Math.max(0, (this._applyRuns || 0) - 1);
		if (this._applyRuns === 0 && this._statusPoll)
			poll.add(this._statusPoll, STATUS_POLL_S);
	},

	// Starts an apply and resolves with the very object the old synchronous
	// `apply` returned, so every call site keeps its result handling unchanged.
	// Never rejects on a backend-reported failure — only on a watcher that cannot
	// reach the router at all.
	applyAsync: function (instance) {
		var self = this;
		var deadline = Date.now() + APPLY_TIMEOUT_MS;
		this.pauseStatusPoll();
		return callApplyStart(instance).then(function (res) {
			if (!res || !res.error)
				return self.waitForApply(deadline);
			// A refused start is usually "one is already running" — from the other
			// button, another tab, or a rotation. Matching on the message would be
			// brittle, so simply ask what the job queue is doing: if something is
			// running, that is the apply the user wanted anyway.
			return callApplyStatus().then(function (st) {
				return (st && st.state === 'running')
					? self.waitForApply(deadline) : { error: res.error };
			}, function () { return { error: res.error }; });
		}).then(function (result) {
			self.resumeStatusPoll();
			return result;
		}, function (err) {
			// The banner is the caller's to dismiss, but the poll must come back
			// no matter how this ended, or the page goes permanently static.
			self.resumeStatusPoll();
			throw err;
		});
	},

	// Probes apply_status until the job leaves 'running'. Anything that is not a
	// finished job is turned into an `error` result rather than an optimistic
	// success: a banner claiming a tunnel that never came up is worse than an
	// honest "no idea".
	waitForApply: function (deadline) {
		return new Promise(function (resolve, reject) {
			var probe = function () {
				callApplyStatus().then(function (st) {
					var state = st && st.state;
					if (state === 'done' || state === 'failed')
						return resolve((st && st.result) ||
							{ error: _('the apply finished without reporting a result') });
					if (state !== 'running')
						// 'idle' after a successful start means the job record is
						// gone — an rpcd restart, or the backend died mid-apply.
						return resolve({ error: _('the apply stopped reporting progress') });
					if (Date.now() >= deadline)
						return resolve({ error: _('the apply is still running after %d seconds — check the system log')
							.format(Math.round(APPLY_TIMEOUT_MS / 1000)) });
					window.setTimeout(probe, APPLY_POLL_MS);
				}, function (e) {
					// One lost probe is not a failed apply: rpcd may just be busy
					// with the apply itself. Keep trying until the deadline.
					if (Date.now() >= deadline)
						return reject(e);
					window.setTimeout(probe, APPLY_POLL_MS);
				});
			};
			// The start call already returned; nothing can be finished yet.
			window.setTimeout(probe, APPLY_POLL_MS);
		});
	},

	handleConnect: function () {
		var self = this;
		var n = this.notice(_('Connecting… this verifies a real WireGuard handshake and can take a few seconds.'), 'info');
		// The public IP of the tunnel we are leaving is about to be wrong; the
		// band re-fetches it lazily once the new gateway is known.
		this.forgetExternalIp();
		return this.applyAsync(this.instance).then(function (res) {
			self.dismiss(n);
			// An IPv6 refusal is not an ordinary "it did not come up": the user
			// asked for something the fleet could not give, the tunnel is down
			// because of that, and (with the kill switch off) their networks
			// moved to the provider. res.error carries all of it in words; the
			// flag is what makes it an error rather than a passing warning, so
			// it does not scroll away like a transient hiccup.
			if (res && res.ipv6_required)
				self.notice(res.error || _('the IPv6 requirement could not be met'), 'error');
			else if (!res || res.error)
				self.notice((res && res.error) || _('apply failed'), 'warning');
			else if (res.state === 'success')
				self.notice(_('Connected via %s.').format(res.gateway || '?'), 'info', 4000);
			else if (res.state === 'partial_failure')
				// The interface is up but no handshake came back: routing and
				// firewall are already in place, so this is not a clean failure.
				self.notice(_('The interface came up on %s, but the server never answered the handshake. Traffic may not pass — try reconnecting or pick another location.')
					.format(res.gateway || '?'), 'warning');
			else
				self.notice(res.error || _('the tunnel did not come up'), 'warning');
			return self.refreshStatus().then(function () { return self.loadAccount(); });
		}).catch(function (e) {
			self.dismiss(n);
			self.notice(_('Connect failed: %s').format(e), 'error');
		});
	},

	handleDisconnect: function () {
		var self = this;
		var n = this.notice(_('Disconnecting…'), 'info');
		this.forgetExternalIp();
		return callDisconnect(this.instance).then(function (res) {
			self.dismiss(n);
			if (res && res.error)
				self.notice(_('Disconnect failed: %s').format(res.error), 'error');
			else
				// Taking the tunnel down also removes the routing and firewall
				// objects it owned, so LAN traffic changes path — say so, or a
				// disconnect looks like it did nothing at all.
				self.notice(_('Instance disabled: its networks are back on normal routing (IPv6 included). Reconnect restores the VPN.'), 'info', 6000);
			return self.refreshStatus();
		}).catch(function (e) {
			self.dismiss(n);
			self.notice(_('Disconnect failed: %s').format(e), 'error');
		});
	},

	handleRotateNow: function () {
		var self = this;
		var n = this.notice(_('Rotating…'), 'info');
		return callRotateNow(this.instance).then(function (res) {
			self.dismiss(n);
			if (res && res.error)
				self.notice(res.error, 'warning');
			else if (res && res.skipped)
				self.notice(res.reason || _('nothing to rotate to'), 'info', 4000);
			else if (res && res.server)
				self.notice(_('Rotated to %s.').format(res.server), 'info', 4000);
			self.forgetExternalIp();
			return self.refreshStatus();
		}).catch(function (e) {
			self.dismiss(n);
			self.notice(_('Rotation failed: %s').format(e), 'error');
		});
	},

	// ── sections ─────────────────────────────────────────────────────────

	// LuCI's own two-column form markup, so the page lines up with every other
	// LuCI page instead of inventing a private layout.
	row: function (labelText, fieldNodes, descText) {
		var field = E('div', { class: 'cbi-value-field' }, nodes(fieldNodes));
		if (descText)
			field.appendChild(E('div', { class: 'cbi-value-description' }, nodes(descText)));
		return E('div', { class: 'cbi-value' }, nodes([
			E('label', { class: 'cbi-value-title' }, nodes(labelText)),
			field
		]));
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
		var seg = E('div', { class: 'pv-seg' }, nodes([
			[ 'standard', _('Standard') ],
			[ 'secure_core', _('Secure Core') ],
			[ 'tor', _('Tor') ]
		].map(L.bind(function (o) {
			var b = E('button', { type: 'button', click: L.bind(this.setHopMode, this, o[0]) }, nodes(o[1]));
			this.hopButtons[o[0]] = b;
			return b;
		}, this))));
		this.hopNote = E('div', { class: 'cbi-value-description' });

		this.poolChips = E('div', { class: 'pv-pool' });
		this.poolCount = E('span', { class: 'pv-pool-count' });
		this.poolNote = E('div', { class: 'cbi-value-description' });
		// pv-pool-trigger draws the ▾ caret: without it neither control reads as
		// a dropdown, they just look like ordinary buttons. type=button keeps
		// them from submitting the surrounding LuCI form, and the click is
		// stopped so it never reaches anything that would reopen/close a panel.
		this.poolTrigger = E('button', { type: 'button', class: 'cbi-button pv-pool-trigger',
			click: L.bind(function (ev) {
				ev.preventDefault();
				ev.stopPropagation();
				this.poolOpenPanel();
			}, this) }, nodes('+ ' + _('Add a location')));
		this.poolPanel = E('div', { class: 'pv-pool-panel pv-pool-acc hidden' });
		this.poolWrap = E('div', { class: 'pv-pool-wrap' }, nodes([ this.poolTrigger, this.poolPanel ]));

		this.srvTrigger = E('button', { type: 'button', class: 'cbi-button pv-pool-trigger pv-srv-trigger',
			click: L.bind(function (ev) {
				ev.preventDefault();
				ev.stopPropagation();
				this.srvOpenPanel();
			}, this) }, nodes(_('Automatic server')));
		this.srvPanel = E('div', { class: 'pv-pool-panel hidden' });

		this.srvWrap = E('span', { class: 'pv-pool-wrap' }, nodes([ this.srvTrigger, this.srvPanel ]));

		// Initial repaint: the same hooks a user edit would trigger.
		this.updateHopButtons();
		this.rebuildPoolWidget();
		this.refreshServerList();

		return E('fieldset', { class: 'cbi-section' }, nodes([
			E('legend', {}, nodes(_('Connection'))),
			E('div', { class: 'cbi-section-node' }, nodes([
				this.row(_('Hop mode'), [ seg, this.hopNote ]),
				this.row(_('Locations'), [
					E('div', {}, nodes([ this.poolChips ])),
					this.poolWrap,
					this.poolNote
				], _('Countries this instance connects between. Picking a country adds the whole country; the arrow at its right end expands its cities to narrow the set. The initial connect and the rotation both pick within this set.')),
				this.row(_('Server'), [
					this.srvWrap
				], _('Automatic picks a server from the set (rotation-friendly). Pin a specific one to lock it; pinning disables automatic rotation.'))
			]))
		]));
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
		// The client version control lives on the account card rather than in
		// this form, but it is collected, validated and discarded along with
		// the form's other fields. The reset of `refs` above would strand it:
		// save() would skip the setting entirely and a discard would leave an
		// abandoned choice on screen.
		if (this.appVerSel)
			this.syncClientVersion();
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
				nodes(_('Interface %s · routing table %s — edit under Advanced settings.').format(iface, tbl)))
		]));

		if (rt.mode === 'manual') {
			var what = [];
			if (rt.user_routes)
				what.push(_('%d custom route(s)/rule(s)').format(rt.user_routes));
			var table = g('routing_table', '');
			if (table)
				what.push(_('routing table "%s"').format(table));
			body.appendChild(this.row(_('Mode'), [
				E('div', {}, nodes([
					E('span', {}, nodes(_('Manual — %s detected. The app leaves routing and firewall untouched.')
						.format(what.join(' + ') || _('custom configuration')))),
					E('div', { class: 'cbi-value-description' },
						nodes(_('Remove your own routes/rules that reference this interface to manage routing from here.')))
				]))
			]));
			if (rt.ipv6_wan)
				body.appendChild(this.row('', [ E('span', { class: 'pv-inline-note' },
					nodes(_('⚠ IPv6 is active on the WAN and bypasses the VPN unless your rules cover it.'))) ]));
		} else {
			this.autoRouting = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
			// Absent means off, exactly as the backend reads it. It used to
			// default to on here, so a freshly created instance — where
			// create_instance writes only the interface and enabled — showed
			// "route all LAN traffic" ticked while the backend was doing
			// nothing of the sort, and the claim only became true if the user
			// happened to save. A fresh install still routes everything,
			// because the shipped config sets the key explicitly on `main`;
			// a second instance must not claim the whole LAN by default, or
			// it would fight the first one for the default route and the zone.
			this.autoRouting.checked = (g('auto_routing', '0') === '1');
			this.ksBox = E('input', { type: 'checkbox', change: L.bind(this.markDirty, this) });
			this.ksBox.checked = (g('killswitch', '0') === '1');
			// Three-valued on purpose: 'auto' is not "block off", it routes
			// IPv6 into the tunnel on the gateways that forward it and keeps
			// prohibiting it on the ones that do not, so there is no single
			// checkbox state that describes it.
			var v6mode = g('ipv6_mode', 'block');
			if ([ 'block', 'auto', 'off' ].indexOf(v6mode) < 0)
				v6mode = 'block';
			this.v6Sel = E('select', { class: 'cbi-input-select', change: L.bind(this.onRoutingToggle, this) }, nodes([
				E('option', { value: 'block' }, nodes(_('Block — no IPv6 past the router'))),
				E('option', { value: 'auto' }, nodes(_('Automatic — through the tunnel where the server supports it'))),
				E('option', { value: 'off' }, nodes(_('Off — leave IPv6 alone')))
			]));
			this.v6Sel.value = v6mode;
			this.v6Warn = E('div', { class: 'cbi-value-description pv-inline-note hidden' },
				nodes(_('⚠ IPv6 stays outside the tunnel and can leak your address.')));
			// "Automatic" follows whatever gateway you land on; this narrows
			// the fleet so you only ever land on one that forwards IPv6. Off
			// by default: it costs a third of the servers, which is only worth
			// paying when the user says IPv6 is what they came for.
			this.v6Only = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
			this.v6Only.checked = (g('require_ipv6', '0') === '1');
			this.v6OnlyNote = E('div', { class: 'cbi-value-description pv-inline-note hidden' }, nodes(''));
			// Filled in by onRoutingToggle: why 'auto' is unavailable, or what
			// it is doing on the gateway the tunnel is on right now.
			this.v6Note = E('div', { class: 'cbi-value-description pv-inline-note hidden' }, nodes(''));

			this.steerBoxes = {};
			var current = uci.get('protonvpn', this.instance, 'source_network');
			var currentList = Array.isArray(current) ? current : (current ? [ current ] : []);
			// Two instances steering one network give it two policy rules at
			// the same priority and one shared IPv6 addressing record, so
			// whichever is torn down first re-addresses the other's clients.
			// Nothing in the backend can reject that — the page writes uci
			// directly — so refuse it here, where the choice is made.
			var takenBy = this.networkOwners();
			var nets = rt.networks || [];
			this.steerWrap = E('div', { class: 'pv-inline', style: 'gap:1em' }, nodes(nets.map(L.bind(function (n) {
				var owner = takenBy[n];
				var cb = E('input', { type: 'checkbox', change: L.bind(this.onRoutingToggle, this) });
				cb.checked = currentList.indexOf(n) >= 0;
				// Never lock a box this instance already owns, or the network
				// could not be handed back.
				cb.disabled = !!owner && !cb.checked;
				this.steerBoxes[n] = cb;
				var label = E('label', { class: 'pv-check' }, nodes([ cb, n ]));
				if (cb.disabled)
					label.appendChild(E('span', { class: 'pv-inline-note' },
						nodes(_('(steered by %s)').format(owner))));
				return label;
			}, this))));

			body.appendChild(this.row(_('Traffic routing'), [
				E('label', { class: 'pv-check' }, nodes([ this.autoRouting, _('Route all LAN traffic through the VPN') ]))
			], _('Creates a firewall zone and a default route via the tunnel; disabling removes exactly what was created.')));
			this.steerRow = this.row(_('Steered networks'), [ this.steerWrap ],
				_('Or route only these networks through this instance — policy rules send their traffic into its routing table.'));
			if (nets.length)
				body.appendChild(this.steerRow);
			this.ksRow = this.row(_('Kill switch'), [
				E('label', { class: 'pv-check' }, nodes([ this.ksBox, _('Block LAN internet access while the VPN is down') ]))
			]);
			this.v6Row = this.row(_('IPv6'), [ this.v6Sel, this.v6Note, this.v6Warn ],
				_('ProtonVPN forwards IPv6 only on some gateways. Automatic routes it through the tunnel on those and keeps blocking it on the rest, so it can never fall back to your provider. Block is the default: a fresh install lets no IPv6 past the router at all, because an IPv6 path around the tunnel would expose your address just as plainly as no VPN.'));
			this.v6OnlyRow = this.row('', [
				E('label', { class: 'pv-check' }, nodes([ this.v6Only,
					_('Only use gateways that forward IPv6') ])),
				this.v6OnlyNote
			], _('Narrows the server list, rotation and the watchdog to gateways with IPv6. About two thirds of the fleet qualifies, and some countries have none — if your locations have none, the VPN will not connect rather than quietly give you a gateway without IPv6.'));
			body.appendChild(this.ksRow);
			body.appendChild(this.v6Row);
			body.appendChild(this.v6OnlyRow);
			this.onRoutingToggle(true);
		}

		return E('fieldset', { class: 'cbi-section' }, nodes([
			E('legend', {}, nodes(_('Traffic routing'))),
			body
		]));
	},

	// Logical networks another instance already steers, mapped to its name.
	networkOwners: function () {
		var out = {};
		(this.instances || []).forEach(L.bind(function (st) {
			var name = st.instance;
			if (!name || name === this.instance)
				return;
			var sn = uci.get('protonvpn', name, 'source_network');
			var list = Array.isArray(sn) ? sn : (sn ? [ sn ] : []);
			list.forEach(function (n) { out[n] = name; });
		}, this));
		return out;
	},

	steeredNetworks: function () {
		var out = [];
		for (var k in (this.steerBoxes || {}))
			if (this.steerBoxes[k].checked)
				out.push(k);
		return out;
	},

	// Why 'auto' would be inert under the routing currently on the form, or
	// '' when it would bite. Mirrors the backend's rule (protonvpn.common
	// require_ipv6_active): 'auto' hands clients IPv6 only through the
	// per-network policy rules that steered routing creates, so it needs
	// auto_routing off, at least one steered network and a routing table to
	// steer into. The conditions are named separately because the fix
	// differs per condition — a toggle to untick, a network to pick, a
	// table to name — so the note can say which one applies. The table is
	// read from the Advanced field once the form has built that far, and
	// from the stored value before it.
	v6AutoInert: function () {
		if (this.autoRouting && this.autoRouting.checked)
			return 'auto_routing';
		if (!this.steeredNetworks().length)
			return 'no_steered';
		var ref = (this.refs || {}).routing_table;
		var table = ref ? (ref.value || '').trim()
			: (uci.get('protonvpn', this.instance, 'routing_table') || '');
		if (!table)
			return 'no_table';
		return '';
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
		var mode = this.v6Sel ? this.v6Sel.value : 'block';
		// 'auto' hangs off the per-network policy rules that only steered
		// routing creates, so where it cannot bite the option is not offered
		// and the control is moved to what the save will store — with the
		// reason named, because the fix differs per condition. A missing
		// routing table is the exception: the save fills it from the
		// interface name, so the mode survives and only the note explains
		// why nothing has arrived yet.
		var inert = this.v6Sel ? this.v6AutoInert() : '';
		var deadOpt = (inert === 'auto_routing' || inert === 'no_steered');
		var autoOpt = this.v6Sel ? this.v6Sel.querySelector('option[value="auto"]') : null;
		if (autoOpt)
			autoOpt.disabled = deadOpt;
		if (deadOpt && mode === 'auto' && this.v6Sel) {
			this.v6Sel.value = 'block';
			mode = 'block';
			// With nothing steered the whole IPv6 row is hidden, so the note
			// cannot say this; auto_routing keeps the row and its note. Said
			// on initialization too: a saved 'auto' with nothing steered is a
			// supported legacy configuration, and normalizing it on page load
			// with no word anywhere is exactly the silent downgrade the note
			// and the save rewrite exist to eliminate.
			if (inert === 'no_steered')
				this.notice(_('Automatic IPv6 works only with at least one steered network — with none ticked, the mode is set to Block.'),
					'warning', 8000);
		}
		var note = '';
		if (inert === 'auto_routing')
			note = _('Automatic IPv6 needs steered networks; while all LAN traffic goes through the VPN, IPv6 is blocked.');
		else if (inert === 'no_table' && mode === 'auto')
			note = _('Automatic IPv6 needs a routing table to steer into — set one under Advanced settings; until it exists, IPv6 stays blocked.');
		else if (mode === 'auto' && this.ipv6Unmet())
			note = this.ipv6Unmet().note;
		else if (mode === 'auto' && rt.ipv6_gateway === false)
			note = _('This server does not forward IPv6, so it stays blocked until the next one that does.');
		// st.ipv6.active, not rt.ipv6_tunnel: the rule can be installed and
		// perfectly correct while the tunnel is down, and nothing is going
		// through it then.
		else if (mode === 'auto' && ((this.status || {}).ipv6 || {}).active)
			note = _('IPv6 is going through the tunnel on this server.');
		if (this.v6Note) {
			this.v6Note.textContent = note;
			this.v6Note.classList.toggle('hidden', !(on && note));
		}
		if (this.v6Warn)
			this.v6Warn.classList.toggle('hidden', !(on && mode === 'off' && rt.ipv6_wan));
		this.updateV6Only(mode, on, init === true);
	},

	// The "only IPv6 gateways" control: when it may be used, and why not.
	//
	// Availability mirrors protonvpn.common require_ipv6_active(). Outside
	// 'auto' the bit changes nothing about a client's traffic, so narrowing
	// the fleet would cost servers and buy nothing; outside Standard it is
	// unsatisfiable — measured on the full fleet cache, bit 16 is set on 0 of
	// 122 Secure Core and 0 of 7 Tor logicals, so every location set would
	// come back empty. Disabled with the reason shown rather than hidden: a
	// control that vanishes teaches nothing, and a user who ticked it in
	// Standard needs to know why it stopped applying in Secure Core.
	//
	// The stored value is deliberately left alone while it is unavailable, so
	// a round trip through another mode does not silently forget it — the
	// backend applies the same rule and ignores it meanwhile.
	updateV6Only: function (mode, on, init) {
		if (!this.v6Only || !this.v6OnlyRow)
			return;
		var hop = this.hopMode();
		var why = '';
		if (hop !== 'standard')
			why = (hop === 'secure_core')
				? _('No Secure Core gateway forwards IPv6, so this cannot be applied in this mode.')
				: _('No Tor gateway forwards IPv6, so this cannot be applied in this mode.');
		else if (mode !== 'auto')
			why = _('Needs the Automatic IPv6 mode — in Block and Off, IPv6 is not routed whichever gateway is picked.');
		this.v6Only.disabled = (why !== '');
		this.v6OnlyRow.classList.toggle('hidden', !on);
		this.v6OnlyNote.textContent = why;
		this.v6OnlyNote.classList.toggle('hidden', !(on && why));
		// Turning the requirement on can strand an already-pinned gateway that
		// does not carry the bit: the list stops offering it, but the pin is
		// still what would be saved, and the backend would refuse to connect.
		// Drop it on the same terms as a pin left behind by a region change —
		// only on a real edit, never while the saved configuration is merely
		// being loaded, where silently rewriting what the user stored would be
		// its own surprise. On load the panel marks it unusable instead.
		if (!init && this._serverChosen && !this.srvChosenOfferable()) {
			var lost = this._serverChosen;
			this.srvSetChosen('');
			this.notice(_('%s does not forward IPv6 and is no longer pinned.').format(lost),
				'warning', 8000);
		}
		// The picker draws from this, and the quick "Lowest load" pick with
		// it, so both have to be repainted when the answer changes.
		if (this._srvOpen)
			this.srvRenderPanel();
		this.srvRenderTrigger();
	},

	// Whether the pinned server is one the picker may still offer. A pin the
	// requirement excludes is present in the relay list but not selectable,
	// so "is it in the list" is no longer the same question as "can it be
	// used" — the panel and the strand check both need the second one.
	srvChosenOfferable: function () {
		var r = this.srvRelayByHost(this._serverChosen);
		if (!r)
			return false;
		return !this.requireV6Active() || this.relayHasV6(r);
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
			this.rotInterval.appendChild(E('option', { value: o[0], selected: (o[0] === interval) || null }, nodes(o[1])));
		}, this));

		this.rotTime = E('input', { type: 'time', class: 'cbi-input-text', value: time, style: 'width:auto', change: L.bind(this.markDirty, this) });
		this.refs.rotation_interval = this.rotInterval;
		this.refs.rotation_time = this.rotTime;

		this.rotFixedNote = E('div', { class: 'cbi-value-description pv-inline-note hidden' }, nodes(_('Automatic rotation is unavailable while a specific server is selected.')));
		this.rotModeRow = this.row(_('Schedule'), [
			E('div', { class: 'pv-radio-group' }, nodes([
				E('label', {}, nodes([ this.rotModeInterval, _('Every N hours') ])),
				E('label', {}, nodes([ this.rotModeTime, _('At specific time') ]))
			]))
		]);
		this.rotIntervalRow = this.row(_('Rotation interval'), [ this.rotInterval ]);
		this.rotTimeRow = this.row(_('Rotation time'), [ this.rotTime ], _('Router local time'));
		this.rotNextSpan = E('span', {}, nodes(this.nextRotationText()));
		this.rotNextRow = this.row(_('Next rotation'), [ this.rotNextSpan ]);

		var section = E('fieldset', { class: 'cbi-section', id: 'pv-rotation' }, nodes([
			E('legend', {}, nodes(_('Automatic rotation'))),
			E('div', { class: 'cbi-section-node' }, nodes([
				this.row(_('Automatic rotation'), [
					E('label', { class: 'pv-check' }, nodes([ this.rotEnable, _('Change server automatically on a schedule') ])),
					this.rotFixedNote
				]),
				this.rotModeRow, this.rotIntervalRow, this.rotTimeRow, this.rotNextRow
			]))
		]));

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
		// Say so out loud on the other instances: editing a row here changes
		// something global, which is not what the rest of this panel does.
		var shared = function (text) {
			if (self.instance === 'main')
				return text;
			var note = _('Shared by all instances (stored on "main").');
			return text ? text + ' ' + note : note;
		};
		var gm = function (o, d) { return uci.get('protonvpn', 'main', o) || d; };
		this.cacheRow = E('span', {}, nodes(this.cacheSummary()));

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
				nodes(_('✓ recommended value'))));
		} else if (recMtu) {
			mtuCtl.push(' ');
			mtuCtl.push(E('button', { class: 'cbi-button', click: L.bind(function (ev) {
				ev.preventDefault();
				mtuInput.value = recMtu;
				this.markDirty();
			}, this) }, nodes(_('Use recommended'))));
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
		this.dnsSel = E('select', { class: 'cbi-input-select', change: L.bind(this.markDirty, this) }, nodes([
			E('option', { value: 'off' }, nodes(_('Off — use system DNS'))),
			E('option', { value: 'standard' }, nodes(_('ProtonVPN — in-tunnel resolver (10.2.0.1)')))
		]));
		this.dnsSel.value = dnsMode;

		var body = E('div', { class: 'cbi-section-node' }, nodes([
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
				E('label', { class: 'pv-check' }, nodes([ this.wdBox, _('Reconnect automatically when the tunnel goes stale') ]))
			], _('Auto-reconnect when the tunnel goes stale (handshake-based; no external probe; off when a specific server is pinned)')),
			this.row(_('Cache directory'), [ this.input('cache_dir', 'text', gm('cache_dir', ''), { placeholder: '/tmp' }) ],
				shared(_('Where to store the downloaded server list (leave empty for /tmp)'))),
			this.row(_('Server cache'), [
				E('div', { class: 'pv-inline' }, nodes([
					this.cacheRow,
					E('button', { class: 'cbi-button', click: L.bind(this.refreshCache, this) }, nodes(_('Refresh server list')))
				]))
			], shared('')),
			this.row(_('DNS'), [ this.dnsSel ],
				_('Which resolver to use while connected. Proton runs a single in-tunnel resolver (10.2.0.1); it only works through the tunnel.'))
		]));

		// The connection section is built (and may restore a pinned server)
		// before this row exists — sync the initial visibility.
		if (this._serverChosen) {
			this.maxRetriesRow.classList.add('hidden');
			this.wdRow.classList.add('hidden');
		}

		return E('details', { class: 'pv-advanced cbi-section' }, nodes([
			E('summary', {}, nodes(_('Advanced settings'))),
			body
		]));
	},

	// The only shape the backend accepts — app_version() in protonvpn.api
	// matches exactly this and falls back to the built-in constant for
	// anything else. JS anchors ^ and $ to the whole string (ucode's anchor
	// matches line boundaries, which is why the backend rejects CR/LF
	// separately), so an embedded newline fails here too.
	APP_VERSION_RE: /^linux-vpn-[a-z0-9-]+@[0-9]+\.[0-9]+\.[0-9]+$/,

	// Why a malformed value must not be saved at all: the router would store
	// it, ignore it, and stamp the built-in version instead. The page would
	// then show an override that is not in force — the worst possible answer
	// for a setting somebody is editing precisely because sign-ins are
	// failing. It looks applied, it changes nothing, and the next sign-in
	// fails the same way.
	//
	// Returns the sentence to show, or null when there is nothing to say.
	appVersionError: function () {
		if (!this.refs || !this.refs.app_version)
			return null;
		var v = (this.refs.app_version.value || '').trim();
		if (v === '' || this.APP_VERSION_RE.test(v))
			return null;
		return _('The Proton client version must look like linux-vpn-gtk@4.18.2, or be empty to use the version built into the package. The router would ignore "%s" and keep stamping the built-in version, so it was not saved.')
			.format(v);
	},

	// Where the shared options live: the 'globals' section when the config has
	// one, 'main' otherwise. Same rule the backend reads by (globals_section()
	// in protonvpn.common) — writing anywhere else stores a value the router
	// never stamps.
	globalsSection: function () {
		var found = null;
		uci.sections('protonvpn', 'globals', function (s) {
			if (!found)
				found = s['.name'];
		});
		return found || 'main';
	},

	// What the control says about itself, in one sentence. It used to be five
	// lines and was the single biggest item on the account card — permanent
	// furniture for a setting almost nobody touches. It now sits inside the
	// disclosure, so it is read by the one person who opened it, and it keeps
	// the only fact that is actionable: 5003 is the code this control fixes,
	// and the other two a failing sign-in returns are not.
	CLIENT_VERSION_HELP: _('Change this only when Proton answers a sign-in with Code 5003 "this version of the app is no longer supported"; Code 2028 and Code 8002 are not fixed here.'),

	// The Proton client version (x-pm-appversion), on the account card next to
	// the sign-in controls.
	//
	// It belongs here rather than in Advanced settings for two reasons. It is
	// a GLOBAL setting, one value shared by every instance, and Advanced
	// settings is otherwise entirely per-instance options. And it matters
	// exactly when somebody is looking at a sign-in that has just failed,
	// which is this card — sending them off to open an accordion further down
	// the page is sending them away from the thing they are trying to fix.
	//
	// A select, not a text box: the only values worth stamping are ones that
	// exist, and a typo here is stored, ignored by the backend and shown back
	// as if it had applied. Read from the globals section when the config has
	// one, because that is where the backend looks.
	//
	// Built ONCE and then kept. renderBand() repaints the card on every
	// five-second status poll; rebuilding the control there would throw away a
	// fetched list and an unsaved choice on a timer, while the user is looking
	// at them.
	buildClientVersion: function () {
		if (this.appVerBox)
			return this.appVerBox;

		this.refs = this.refs || {};
		this.appVerList = [];
		this.appVerCurrent = '';
		// May already be known: renderBand() reads it off the session state
		// before it builds this, so the first fill can name it.
		this.appVerBuiltIn = this.appVerBuiltIn || '';
		this.appVerSel = E('select', { class: 'cbi-input-select pv-appver-list',
			'data-pv-focus': 'appver-select' });
		this.appVerSel.addEventListener('change', L.bind(function () {
			this.markDirty();
			this.syncClientVersionSummary();
		}, this));
		this.appVerBtn = E('button', { class: 'cbi-button pv-appver-fetch',
			'data-pv-focus': 'appver-fetch',
			click: L.bind(this.handleFetchClientVersions, this) },
			nodes(_('Fetch versions')));
		this.appVerNote = E('div', { class: 'cbi-value-description pv-appver-note' },
			nodes(this.CLIENT_VERSION_HELP));
		this.syncClientVersion();

		// A grid, not .pv-inline: flex-wrap put the button on a line of its
		// own as soon as the select's longest option outgrew the row, which
		// is what the owner photographed. Here the select is the only column
		// that may shrink and the button is sized to its text.
		this.appVerSummary = E('summary', { class: 'pv-more-summary',
			'data-pv-focus': 'appver-summary' });
		this.appVerBox = E('details', { class: 'pv-more' }, nodes([
			this.appVerSummary,
			E('div', { class: 'pv-verrow' }, nodes([ this.appVerSel, this.appVerBtn ])),
			this.appVerNote
		]));
		this.syncClientVersionSummary();
		return this.appVerBox;
	},

	// The summary says which version is in force, so the disclosure does not
	// have to be opened to find out — a closed <details> that hides the value
	// it controls is worse than the paragraph it replaced.
	syncClientVersionSummary: function () {
		if (!this.appVerSummary || !this.appVerSel)
			return;
		// The labels are kept beside the options rather than read back off the
		// DOM: a Map, because the values come from uci and from upstream and
		// one of them can perfectly well be "toString".
		var labels = this.appVerLabels || new Map();
		var v = this.appVerSel.value || '';
		var shown = labels.has(v) ? labels.get(v) : (v || this.builtInLabel());
		dom.content(this.appVerSummary,
			nodes(_('Client version — %s').format(shown)));
	},

	// The label for "no override": it names the version when the page knows
	// it, and says plainly what it is when it does not. The built-in string
	// lives in the backend (api.uc PM_APPVERSION) and arrives on
	// session_state, which the page calls on load — so it is normally known
	// before anybody presses anything. A backend too old to send it leaves
	// the label unnumbered rather than guessing: claiming a version that is
	// not the one being stamped is the one thing this control must never do.
	builtInLabel: function () {
		return this.appVerBuiltIn
			? _('Built into the package (%s)').format(this.appVerBuiltIn)
			: _('Built into the package');
	},

	// Re-read what uci holds and put the control back on it. Called from
	// buildFormSections(), which is every path that rebuilds the form from uci
	// — first render, discard, save, switching instance — so a discarded
	// choice really goes away and a saved one is what the control shows next.
	syncClientVersion: function () {
		this.appVerSaved = uci.get('protonvpn', this.globalsSection(), 'app_version') || '';
		this.refs.app_version = this.appVerSel;
		this.fillClientVersions(this.appVerSaved);
	},

	// Rebuild the options: the built-in version, whatever uci holds, and
	// whatever the last fetch returned — in that order, de-duplicated.
	//
	// The first two are unconditional, which is the whole of "degrade
	// honestly". With no fetch, or a failed one, the control is still a real
	// choice rather than an empty box. And the stored value is offered
	// WHATEVER it looks like, including a shape the backend will refuse:
	// dropping it would mean that merely opening this page, and later saving
	// something unrelated, silently changed a setting the user had put in uci
	// by hand. The refusal on Save is where a malformed value is dealt with,
	// and it names the value; see appVersionError().
	fillClientVersions: function (keep) {
		var self = this;
		// A Set, not an object: the values come from uci and from upstream, so
		// one of them can perfectly well be "toString" or "constructor". In a
		// plain {} those read back as already-present, the entry is dropped
		// from the list, and the control then shows a different value than the
		// one in force — which the next Save writes.
		var opts = [], seen = new Set();
		this.appVerLabels = new Map();
		var labels = this.appVerLabels;
		var add = function (v, label) {
			if (seen.has(v))
				return;
			seen.add(v);
			var shown = label ||
				((v === self.appVerCurrent) ? _('%s — current release').format(v) : v);
			labels.set(v, shown);
			opts.push(E('option', { value: v }, nodes(shown)));
		};
		add('', this.builtInLabel());
		if (this.appVerSaved)
			add(this.appVerSaved);
		(this.appVerList || []).forEach(function (v) { add(v); });
		dom.content(this.appVerSel, nodes(opts));
		this.appVerSel.value = seen.has(keep) ? keep : '';
		this.syncClientVersionSummary();
	},

	// Ask upstream which client versions the official Linux app has released.
	// Only ever reached from the button: this leaves the router's network,
	// which has no business happening while a page loads or a sign-in runs.
	//
	// It fills a list and nothing more. The selection is not touched here, on
	// success or on failure — a page that restamps the version by itself
	// breaks sign-ins for a reason its owner cannot see.
	handleFetchClientVersions: function (ev) {
		var self = this;
		if (ev && ev.preventDefault)
			ev.preventDefault();
		if (this.appVerBusy)
			return Promise.resolve();
		this.appVerBusy = true;
		var btn = this.appVerBtn;
		if (btn) {
			btn.disabled = true;
			dom.content(btn, nodes([ E('span', { class: 'spinning' }), ' ', _('Fetching…') ]));
		}
		dom.content(this.appVerNote, nodes(_('Asking the official client\'s repository…')));
		var done = function () {
			self.appVerBusy = false;
			if (btn) {
				btn.disabled = false;
				dom.content(btn, nodes(_('Fetch versions')));
			}
		};
		return callClientVersions().then(function (res) {
			done();
			self.renderClientVersions(res || {});
		}).catch(function (err) {
			done();
			self.renderClientVersions({ versions: [],
				error: (err && err.message) ? err.message : ('' + err) });
		});
	},

	// Draw what came back. A list that could not be retrieved is said plainly
	// — the alternative is a button that looks as if it did nothing, which is
	// the same defect this page already had on the Continue button.
	//
	// A failed fetch keeps whatever the list held before it, so pressing the
	// button while upstream is down cannot empty a list that was already
	// there, and the selection is carried across either way.
	renderClientVersions: function (res) {
		var list = res.versions || [];
		this.appVerCurrent = res.current || '';
		// `configured` is the value the backend actually stamps. With no uci
		// override in force that IS the version built into the package, which
		// is the only way this page can learn it.
		if (!this.appVerSaved && res.configured)
			this.appVerBuiltIn = res.configured;
		if (list.length)
			this.appVerList = list;
		this.fillClientVersions(this.appVerSel.value);

		if (!list.length) {
			dom.content(this.appVerNote, nodes(E('span', { class: 'pv-err' },
				nodes(res.error
					? _('Could not retrieve the version list: %s').format(res.error)
					: _('Could not retrieve the version list.')))));
			return;
		}

		var note = res.current
			? _('The official client currently ships %s. Pick a version and press Save — nothing is changed until you do.').format(res.current)
			: _('Pick a version and press Save — nothing is changed until you do.');
		if (res.error)
			note += ' ' + _('Part of the list could not be retrieved: %s').format(res.error);
		dom.content(this.appVerNote, nodes(note));
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
		dom.content(this.cacheRow, nodes(_('Refreshing…')));
		return this.handleRefreshLocations().then(L.bind(function () {
			btn.disabled = false;
			if (this.cacheRow)
				dom.content(this.cacheRow, nodes(this.cacheSummary()));
		}, this)).catch(L.bind(function (e) {
			btn.disabled = false;
			if (this.cacheRow)
				dom.content(this.cacheRow, nodes(this.cacheSummary()));
			this.notice(_('Refresh failed: %s').format(e), 'error');
		}, this));
	},

	buildActions: function () {
		this.saveBtn = E('button', {
			class: 'cbi-button cbi-button-save',
			disabled: true,
			click: L.bind(this.save, this)
		}, nodes(_('Save and reconnect')));
		this.discardBtn = E('button', {
			class: 'cbi-button',
			disabled: true,
			click: L.bind(this.discard, this)
		}, nodes(_('Discard changes')));
		return E('div', { class: 'cbi-page-actions' }, nodes([ this.saveBtn, ' ', this.discardBtn ]));
	},

	discard: function () {
		// uci.load() is cached, so unload first or the rebuild would render the
		// very changes that are being discarded.
		uci.unload('protonvpn');
		return uci.load('protonvpn').then(L.bind(function () {
			dom.content(this.formNode, nodes(this.buildFormSections()));
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
		// The client version is shared too, and the backend reads it from the
		// globals section when the config has one.
		if (this.refs.app_version)
			setv('app_version', (this.refs.app_version.value || '').trim(),
				this.globalsSection());

		uci.set('protonvpn', inst, 'hop_mode', this.hopMode());

		// The location set is the single source of truth; the legacy
		// country/city options are cleared so both paths agree.
		//
		// EVERY code is written back, including ones the page could not
		// resolve against the server list. That is deliberate, and it is the
		// second time it has been read as a bug, so: the display rule in
		// rebuildPoolWidget() is what makes it safe. A code that does not
		// resolve in the current hop mode but exists in another is kept and
		// hidden, so a mode round trip does not lose it; a code absent from
		// the server list entirely is SHOWN, marked "not in the server list",
		// and removable with its own ×.
		//
		// Filtering here instead would mean that opening this page against a
		// stale, partial or still-loading server list and saving anything at
		// all silently deleted locations the user never touched — a worse
		// failure than the one this replaced. The original defect was writing
		// these codes back while they were INVISIBLE, leaving uci as the only
		// way to remove one. They are visible now, so the write is honest:
		// nothing is in uci that the page does not show and cannot delete.
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
			// 'auto' hands clients IPv6 only through the per-network policy
			// rules that steered routing creates, so where the backend would
			// ignore it the 'block' it behaves as is stored instead — never
			// an 'auto' the control was no longer showing (v6AutoInert is the
			// same rule the toggle applies). A missing routing table is not a
			// rewrite case: it is filled from the interface name below, which
			// is all 'auto' needs.
			var v6 = (this.v6Sel && this.v6Sel.value) || 'block';
			var v6inert = this.v6AutoInert();
			uci.set('protonvpn', inst, 'ipv6_mode',
				(v6 === 'auto' && (v6inert === 'auto_routing' || v6inert === 'no_steered')) ? 'block' : v6);
			// Stored as ticked even where it cannot currently apply; the
			// backend runs the same availability rule, so an inapplicable
			// value is inert rather than wrong, and the setting survives a
			// trip through Secure Core.
			uci.set('protonvpn', inst, 'require_ipv6',
				(this.v6Only && this.v6Only.checked) ? '1' : '0');
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
		// Said twice on purpose: the notice is at the top of the page and the
		// field is inside a <details> the user may well be looking at instead.
		var appVerErr = this.appVersionError();
		if (appVerErr) {
			this.notice(appVerErr, 'warning');
			if (this.appVerNote)
				dom.content(this.appVerNote,
					[ E('span', { class: 'pv-err' }, nodes(appVerErr)) ]);
			return;
		}
		this.collectIntoUci();
		if (this.saveBtn)
			this.saveBtn.disabled = true;
		if (this.discardBtn)
			this.discardBtn.disabled = true;
		var p = this.notice(_('Saving configuration…'), 'info');

		return uci.save().then(function () {
			return callUciApply(0, false);
		}).then(function () {
			self._dirty = false;
			self.clearChangeIndicator();
			self.dismiss(p);
			p = self.notice(_('Applying and reconnecting…'), 'info');
			// The tunnel is about to move; the band re-fetches the public IP
			// lazily once the new gateway is known.
			self.forgetExternalIp();
			return self.applyAsync(self.instance);
		}).then(function (res) {
			self.dismiss(p);
			if (res && res.error)
				self.notice(_('Apply failed: %s').format(res.error), 'error');
			else if (res && res.state === 'success')
				self.notice(_('Connected via %s.').format(res.gateway || '?'), 'info', 4000);
			else if (res && res.state === 'partial_failure')
				// Settings are saved and the interface is up; only the handshake
				// is missing, so this must not read as "nothing was applied".
				self.notice(_('Settings saved, but the server never answered the handshake. The interface is up — try reconnecting or pick another location.'), 'warning');
			else
				self.notice(_('Could not connect: %s')
					.format((res && res.error) || _('unknown error')), 'error');
			// Rebuild the whole form, not just the status band: a saved change
			// can flip the detected routing mode, and the panel's shape follows it.
			return self.refreshStatus().then(function () {
				dom.content(self.formNode, nodes(self.buildFormSections()));
			});
		}).catch(function (e) {
			self.dismiss(p);
			self.notice(_('Save failed: %s').format(e), 'error');
		});
	},

	render: function (data) {
		var session = data[1] || {};
		var locations = data[2] || {};
		this.instances = (data[4] && data[4].instances) || [];
		this.account = null;
		// The first instance is the one the page opens on; 'main' always exists,
		// but it need not be first once others are added.
		this.instance = this.instances.length ? this.instances[0].instance : 'main';
		this.status = this.statusOf(this.instance) ||
			((data[3] && !data[3].error) ? data[3] : {});
		this.session = session;
		this.locations = locations;
		this.forgetExternalIp();
		this._serversReq = 0;
		this._dirty = false;

		this.bandEl = E('div', { class: 'pv-acct' });
		// The card is repainted by a background poll, so a screen reader has to
		// be told the state changed; updateStatusBand only rewrites className
		// and children, which leaves this attribute in place.
		this.stateEl = E('div', { class: 'pv-state', 'aria-live': 'polite' });
		this.instancesNode = E('div', {});
		this.formNode = E('div', {});
		dom.content(this.formNode, nodes(this.buildFormSections()));

		var body = E('div', {}, nodes([
			E('style', { type: 'text/css' }, nodes(STYLE)),
			E('h2', {}, nodes(_('ProtonVPN'))),
			this.bandEl,
			this.stateEl,
			this.instancesNode,
			this.formNode,
			this.buildActions()
		]));

		this.bindOutsideClose();
		this.renderBand();
		this.updateInstancesTable();
		this.updateStatusBand();
		// Limits arrive out of band; the quota line simply appears once known.
		this.loadAccount();
		// Live status: the same 5-second cadence the reference uses, so a
		// connect/rotate reflects without the user reloading. The bound function
		// is kept because poll.remove() matches on identity, and an apply takes
		// this poller off the queue for its duration.
		this._applyRuns = 0;
		this._statusPoll = L.bind(this.refreshStatus, this);
		poll.add(this._statusPoll, STATUS_POLL_S);
		return body;
	}
});

// SPDX-License-Identifier: MIT
// Which uplink a tunnel's endpoint rides on, decided before netifd decides it.
//
// ── What goes wrong without this ─────────────────────────────────────────
// Unless `nohostroute=1`, netifd's WireGuard handler turns every peer endpoint
// into a host dependency (wireguard.sh: proto_add_host_dependency with the
// interface's `tunlink`). With no tunlink, netifd resolves it by walking EVERY
// interface it knows, in name order, and taking the most specific route that
// covers the endpoint (interface-ip.c interface_ip_add_target_route, checked
// against the netifd revision OpenWrt 24.10 pins, 7901e66). Routes an
// interface got its table from `ip4table` are candidates like any other — and
// each of our instances carries exactly such a 0.0.0.0/0. So the moment the
// real uplink is gone, the best route to one instance's endpoint is another
// instance's tunnel, and netifd pins the host route there:
//     79.127.154.1 dev protonvpn proto static scope link
// Measured on the owner's router during a cable outage: the torrent instance,
// which must never leave through anything but the cable, rode inside the
// guest instance, which itself rode the SIM. And once resolved, netifd keeps
// the dependency on that interface, so the cable coming back changed nothing
// until a manual `ifup`.
//
// ── What this does instead ───────────────────────────────────────────────
// Before every ifup the package makes (bring_up in protonvpn.apply), the same
// lookup is done here over the interfaces that are NOT overlays, and its
// winner is written as the instance's `tunlink`. netifd then resolves the
// endpoint through that interface and no other: it takes the tunnel down when
// that interface goes down, and resolves it again — through that interface —
// when it comes back. That is netifd's own fail-closed and self-heal, and it
// holds on paths this package never sees: a boot, a reload, a hand-run ifup.
//
// When no such interface covers the endpoint, the instance is parked: no
// ifup, and if it has no pin yet, a tunlink that names no interface at all
// (NO_UPLINK) so that nothing else can start it unpinned either. The watchdog
// and the hotplug hook come back to it when an uplink appears
// (protonvpn.rotate uplink_reconcile).
//
// Leaving it standing is the owner's call, quoted: an instance that cannot get
// a correct route "should rather stand than leak through the neighbouring
// tunnel".
//
// ── Which interfaces count as an uplink here ─────────────────────────────
// Anything whose device stack is a provider attachment by the kernel's own
// account: routing.stack_refusal, the UPLINK_KINDS rule applied to every link
// of the stack. WireGuard is refused by its kind, and by its protocol before
// any device is read. A tun, a GRE, a VXLAN, another VPN package's tunnel, a
// VLAN or bridge built on one of those — all refused, and so is any device
// whose kind cannot be established.
//
// Deliberately NOT routing.wan_uplinks, which adds two more facts — a
// provider protocol and a WAN firewall zone — for the MTU advice. Both are
// right there and wrong here. The zone test refuses an uplink in a zone that
// neither masquerades nor is called `wan` — a routed setup behind an upstream
// router is the ordinary case — and a refusal here costs the tunnel, not a
// hint. The protocol list has no `dhcpv6`, so an IPv6 endpoint could never
// be pinned at all. Neither adds anything to the question asked here, which
// is "is this an overlay", and the device stack is what answers it.
//
// ── Scope ────────────────────────────────────────────────────────────────
// nohostroute=1 instances have no host dependency: they ride `main` on
// purpose (the owner's external failover moves them), so they are never pinned
// or parked by the gate. They still get the endpoint guard
// (routing.reconcile_endpoint_guard), and the leak check (leak(), run by the
// reconcile for every enabled instance) still takes one down whose endpoint
// the kernel routes through a tunnel.
// A tunlink the user set is theirs and is never rewritten, but it is checked
// like a picked one (user_pin_refusal); this module only writes a tunlink it
// stamps itself (TUNLINK_STAMP holds what it wrote).

'use strict';

import { readfile, unlink } from 'fs';
const _common = require('protonvpn.common');
const _routing = require('protonvpn.routing');

const TUNLINK_STAMP = 'protonvpn_tunlink';
// A tunlink no netifd interface can carry: section names in UCI cannot hold a
// '-', and dynamic interfaces are named with '_'. netifd looks it up, finds
// nothing, and keeps the interface unavailable — on every path, including a
// reboot — until this package writes a real one.
const NO_UPLINK = 'protonvpn-no-uplink';
const WG_REFUSAL = 'it is a WireGuard tunnel';
// What to tell someone who does route the endpoint by other means.
const ESCAPE = 'set nohostroute=1 on the interface if you route the endpoint yourself';

// ── Park records ─────────────────────────────────────────────────────────
// On tmpfs: they say why an instance is waiting and keep that from being
// logged on every tick. Nothing depends on them surviving a reboot — the
// NO_UPLINK pin in UCI is what keeps a parked instance down across one, and
// the next reconcile writes the record again.

function park_path(name) {
	return _common.RUN_DIR + '/protonvpn_uplink_' + (_common.validate_instance(name) || 'main') + '.json';
}

// { reason, since, leaks, last_leak } or null. `reason` is null once the
// instance is no longer waiting but its leak history is still being kept.
function park_state(name) {
	let raw = readfile(park_path(name));
	if (!raw)
		return null;
	try {
		let st = json(raw);
		return (type(st) == 'object') ? st : null;
	} catch (e) {
		return null;
	}
}

// Whether `name` is parked right now: the reason it waits, or null.
function waiting(name) {
	let st = park_state(name);
	return (st && st.reason != null) ? st.reason : null;
}

function write_park(name, st) {
	return _common.atomic_write(park_path(name), sprintf('%J', st));
}

// Record that `name` waits for an uplink. Logged when the reason changes, not
// per call: the watchdog asks every 30 seconds for as long as an outage lasts.
function park(name, reason) {
	let st = park_state(name) || { leaks: 0, last_leak: 0 };
	if (st.reason == reason)
		return st;
	if (st.reason == null)
		st.since = time();
	st.reason = reason;
	write_park(name, st);
	_common.log(name + ': waiting for an uplink — ' + reason);
	return st;
}

// A leak (P4): counted, and logged by the caller every time, because every
// one of them is traffic that went where it must not.
function park_leak(name, reason) {
	let st = park_state(name) || { leaks: 0, last_leak: 0 };
	if (st.reason == null)
		st.since = time();
	st.reason = 'leak: ' + reason;
	st.leaks = (st.leaks || 0) + 1;
	st.last_leak = time();
	write_park(name, st);
	return st;
}

// No longer waiting. A leak history outlives this — a pin that did not
// prevent one leak will not prevent the next, and the backoff has to grow
// across them — until forget_leaks() decides the instance has been clean
// for long enough.
function unpark(name, how) {
	let st = park_state(name);
	if (!st || st.reason == null)
		return false;
	if (st.leaks > 0) {
		st.reason = null;
		write_park(name, st);
	} else {
		unlink(park_path(name));
	}
	if (how)
		_common.log(name + ': ' + how);
	return true;
}

function forget_leaks(name) {
	let st = park_state(name);
	if (!st || st.reason != null)
		return false;
	if (st.leaks > 0 && time() - (st.last_leak || 0) < _common.WATCHDOG_COOLDOWN_MAX)
		return false;
	unlink(park_path(name));
	return true;
}

// Seconds a leak-parked instance waits before it is tried again. A leak that
// the pin did not prevent comes from something this module cannot see (a
// policy rule, a hand-made route); retrying it every tick would put it back
// on the wire every 30 seconds.
function leak_backoff(st) {
	let n = (st && st.leaks > 0) ? st.leaks : 0;
	if (n == 0)
		return 0;
	let shift = (n - 1 > 20) ? 20 : n - 1;
	let s = _common.WATCHDOG_COOLDOWN_BASE * (1 << shift);
	return (s > _common.WATCHDOG_COOLDOWN_MAX) ? _common.WATCHDOG_COOLDOWN_MAX : s;
}

// ── The lookup ───────────────────────────────────────────────────────────

// Why netifd interface `ifc` (a dump entry) must not carry an endpoint, or
// null when it may.
function refusal(ifc) {
	if (ifc.proto == 'wireguard')
		return WG_REFUSAL;
	if (!ifc.l3_device)
		return 'it has no device';
	return _routing.stack_refusal(ifc.l3_device);
}

// How `ifc` covers address `ep` (ip_words), the way netifd looks: an address
// of the interface whose subnet holds it, or its most specific route —
// enabled routes only, which is what the dump lists, and not the ones that
// carry an explicit `table` (netifd skips DEVROUTE_TABLE; a route that took
// its table from ip4table shows no `table` key and IS a candidate). Returns
// { addr: true } | { mask, metric, has_metric } | null.
function coverage(ifc, ep) {
	for (let a in (ifc[ep.v6 ? 'ipv6-address' : 'ipv4-address'] || [])) {
		if (type(a) != 'object')
			continue;
		if (!ep.v6 && a.ptpaddress != null &&
		    _common.ip_in_prefix(ep, _common.ip_words(a.ptpaddress), 32))
			return { addr: true };
		if (_common.ip_in_prefix(ep, _common.ip_words(a.address), a.mask))
			return { addr: true };
	}
	let best = null;
	for (let r in (ifc.route || [])) {
		if (type(r) != 'object' || r.table != null)
			continue;
		let net = _common.ip_words(r.target);
		if (!net || !_common.ip_in_prefix(ep, net, r.mask))
			continue;
		let hit = { mask: int(r.mask), has_metric: r.metric != null,
			metric: (r.metric != null) ? int(r.metric) : int(ifc.metric || 0) };
		if (!best || hit.mask > best.mask ||
		    (hit.mask == best.mask && hit.has_metric && hit.metric < best.metric))
			best = hit;
	}
	return best;
}

// The interface netifd would resolve `addr` through if overlays did not
// exist: { iface, refused: [ { iface, why } ] }, iface null when none.
//
// netifd walks its interfaces in avl order (strcmp of the name); the first
// one with an address covering the endpoint wins outright, otherwise the most
// specific route wins, a later interface displacing an earlier one only with
// a longer mask or, at an equal mask, a lower metric the route states itself.
// Same here, minus every interface refusal() rejects. The instance's own
// interface is one of them: it is WireGuard, like every other instance.
//
// `refuse` is refusal() by default; only covering interfaces are asked, so a
// router with many interfaces pays for the few that matter.
function pick(data, addr, refuse) {
	let ep = _common.ip_words(addr);
	let out = { iface: null, refused: [] };
	if (!ep || type(data) != 'object' || type(data.interface) != 'array')
		return out;
	refuse = refuse || refusal;
	let list = filter(data.interface, (i) => type(i) == 'object' && type(i.interface) == 'string');
	list = sort([ ...list ], (a, b) => (a.interface < b.interface) ? -1 : (a.interface > b.interface ? 1 : 0));
	let best = null;
	for (let ifc in list) {
		if (!ifc.up)
			continue;
		let hit = coverage(ifc, ep);
		if (!hit)
			continue;
		let why = refuse(ifc);
		if (why != null) {
			push(out.refused, { iface: ifc.interface, why: why });
			continue;
		}
		if (hit.addr) {
			out.iface = ifc.interface;
			return out;
		}
		if (!best || hit.mask > best.mask ||
		    (hit.mask == best.mask && hit.has_metric && hit.metric < best.metric))
			best = { ...hit, iface: ifc.interface };
	}
	out.iface = best ? best.iface : null;
	return out;
}

// One line for the log: why nothing was picked. When something other than a
// tunnel was turned away — a device kind the classifier does not know, say —
// the line names it and the way out, because that may be the user's real
// uplink rather than an outage.
function no_uplink_reason(addr, res) {
	let r = 'no uplink covers ' + addr;
	if (length(res.refused)) {
		let parts = map(res.refused, (x) => x.iface + ' (' + x.why + ')');
		r += '; refused: ' + join(', ', parts);
		if (length(filter(res.refused, (x) => x.why != WG_REFUSAL)))
			r += ' — ' + ESCAPE;
	}
	return r;
}

// ── The pin ──────────────────────────────────────────────────────────────

// What the instance's tunlink is: 'none' (unset), 'managed' (one this module
// wrote — real, or NO_UPLINK), or 'user' (anything else: theirs).
function pin_owner(uci, iface) {
	let pin = uci.get('network', iface, 'tunlink');
	if (pin == null || pin == '')
		return 'none';
	return (uci.get('network', iface, TUNLINK_STAMP) == pin) ? 'managed' : 'user';
}

function set_pin(uci, iface, to) {
	if (uci.get('network', iface, 'tunlink') == to &&
	    uci.get('network', iface, TUNLINK_STAMP) == to)
		return false;
	uci.set('network', iface, 'tunlink', to);
	uci.set('network', iface, TUNLINK_STAMP, to);
	return true;
}

function drop_pin(uci, iface) {
	if (pin_owner(uci, iface) != 'managed') {
		// A stamp the user's tunlink no longer matches is ours to clear; the
		// tunlink is theirs to keep.
		if (uci.get('network', iface, TUNLINK_STAMP) == null)
			return false;
		uci.delete('network', iface, TUNLINK_STAMP);
		return true;
	}
	uci.delete('network', iface, 'tunlink');
	uci.delete('network', iface, TUNLINK_STAMP);
	return true;
}

// A tunlink the user set by hand: never rewritten, but held to the same rule
// as one this module picks. netifd resolves the endpoint through whatever it
// names, so a tunlink naming a tunnel — `protonvpn`, `wg0`, another VPN
// package's — is exactly the leak this module exists to prevent, with a
// user's signature on it. The owner's rule has no exception for that ("never
// through a wireguard interface"), so it is refused, and the user who really
// routes the endpoint by other means has nohostroute=1 for it. Returns why
// it may not be used right now, or null.
function user_pin_refusal(data, pin, ep) {
	let u = null;
	for (let i in data.interface)
		if (type(i) == 'object' && i.interface == pin)
			u = i;
	if (!u)
		return 'names no interface netifd knows';
	let why = refusal(u);
	if (why != null)
		return 'is not an uplink: ' + why;
	if (!u.up)
		return 'is down';
	if (!coverage(u, _common.ip_words(ep)))
		return 'does not cover ' + ep;
	return null;
}

// Whether instance `s` may be brought up now, and through what — the pure
// half of the gate, shared by prepare() and the reconcile. Nothing is written.
// `data` is a netifd dump, or null to fetch one when it is needed.
//   { go, mode: 'nohostroute'|'user'|'managed', to, reason }
function decide(uci, s, data) {
	let iface = s.interface;
	if (uci.get('network', iface, 'nohostroute') == '1')
		return { go: true, mode: 'nohostroute' };
	let mode = (pin_owner(uci, iface) == 'user') ? 'user' : 'managed';
	let ep = _routing.endpoint_literal(uci, iface);
	if (!ep)
		// Proton endpoints are written by EntryIP; a name here was not
		// written by this package, and what it resolves to cannot be judged.
		return { go: false, mode: mode, reason: 'the endpoint is not an IP address' };
	if (data == null)
		data = _routing.netifd_dump();
	if (type(data) != 'object' || type(data.interface) != 'array')
		// The ifup about to be made goes through the same daemon; there is
		// nothing to gain from making it unpinned.
		return { go: false, mode: mode, reason: 'netifd did not answer' };
	if (mode == 'user') {
		let pin = uci.get('network', iface, 'tunlink');
		let why = user_pin_refusal(data, pin, ep.addr);
		return (why == null) ? { go: true, mode: mode, to: pin } :
			{ go: false, mode: mode, reason: 'refused: tunlink ' + pin + ' (set by hand) ' + why +
				'; the endpoint is never routed through a tunnel — ' + ESCAPE };
	}
	let res = pick(data, ep.addr);
	return res.iface ? { go: true, mode: mode, to: res.iface } :
		{ go: false, mode: mode, reason: no_uplink_reason(ep.addr, res) };
}

// The gate in front of every package ifup of instance `s`. Reconciles the
// endpoint guard and the tunlink in UCI (the caller commits, and has netifd
// load it — routing.activate_network) and answers { go, changed, reason }:
// go=false means do not ifup, the instance is parked.
//
// `dry` decides without writing anything to UCI (rotation asks first, so a
// rotation during an outage is skipped before it touches the peer); the park
// record is still kept, so status and the log say why.
function prepare(uci, s, dry) {
	let iface = s.interface;
	let changed = false;
	if (!dry && _routing.reconcile_endpoint_guard(uci, s))
		changed = true;

	let d = decide(uci, s);
	if (d.mode == 'nohostroute') {
		if (!dry && drop_pin(uci, iface))
			changed = true;
		unpark(s.name);
		return { go: true, changed: changed };
	}
	if (d.go) {
		// A user's tunlink is used as it is; only our own is (re)written.
		if (!dry && d.mode == 'managed' && set_pin(uci, iface, d.to))
			changed = true;
		unpark(s.name, 'uplink ' + d.to + ' covers the endpoint again');
		return { go: true, changed: changed, tunlink: d.to, user: (d.mode == 'user') ? d.to : null };
	}

	// Parked. A real pin already in place stays: netifd keeps the tunnel down
	// while that interface is, and brings it back through it on its own. With
	// none, NO_UPLINK keeps every other path from starting it unpinned. A
	// user's tunlink is left exactly as it is.
	if (!dry && pin_owner(uci, iface) == 'none' && set_pin(uci, iface, NO_UPLINK))
		changed = true;
	park(s.name, d.reason);
	return { go: false, changed: changed, reason: d.reason };
}

// ── Foreign damage (P4) ──────────────────────────────────────────────────

// Why the kernel's route to `addr` is a leak right now, or null. Asked of the
// kernel rather than of netifd's host route, because the kernel is what
// WireGuard's packets follow, whoever put the route there. No route at all is
// not a leak: the endpoint guard refuses it, and nothing leaves.
function leak(data, addr) {
	let w = _common.ip_words(addr);
	if (!w)
		return null;
	let dev = _routing.route_device(w.v6 ? '-6' : '-4', addr);
	if (dev == null)
		return null;
	for (let ifc in ((type(data) == 'object' && type(data.interface) == 'array') ? data.interface : []))
		if (type(ifc) == 'object' && ifc.l3_device == dev && ifc.proto == 'wireguard')
			return addr + ' is routed through WireGuard interface ' + ifc.interface;
	let why = _routing.stack_refusal(dev);
	return (why != null) ? addr + ' is routed through ' + dev + ': ' + why : null;
}

// ── Uninstall ────────────────────────────────────────────────────────────

// What the package leaves in /etc/config/network when it is removed, taken
// back out: every stamped endpoint guard (rule and rule6), every tunlink this
// module wrote — the value its stamp records, or NO_UPLINK, which no
// interface can ever satisfy and nothing would be left to replace — and the
// stamps themselves. A tunlink that does not match its stamp is the user's
// and stays. Commits when something changed; the caller reloads netifd.
// Run by the package's prerm through `protonvpn-uplink --uninstall`, on a
// real removal only. Returns true when something was removed.
function uninstall_cleanup(uci) {
	let guards = [], ifaces = [];
	for (let t in [ 'rule', 'rule6' ])
		uci.foreach('network', t, function(sec) {
			if (sec.protonvpn_managed == '1' && sec.protonvpn_role == 'endpoint_guard')
				push(guards, sec['.name']);
		});
	uci.foreach('network', 'interface', function(sec) {
		if (sec[TUNLINK_STAMP] != null || sec.tunlink == NO_UPLINK)
			push(ifaces, { name: sec['.name'], tunlink: sec.tunlink, stamp: sec[TUNLINK_STAMP] });
	});
	for (let g in guards)
		uci.delete('network', g);
	for (let i in ifaces) {
		if (i.tunlink != null && (i.tunlink == NO_UPLINK || i.tunlink == i.stamp))
			uci.delete('network', i.name, 'tunlink');
		if (i.stamp != null)
			uci.delete('network', i.name, TUNLINK_STAMP);
	}
	let changed = length(guards) > 0 || length(ifaces) > 0;
	if (changed)
		uci.commit('network');
	return changed;
}

return {
	TUNLINK_STAMP, NO_UPLINK,
	pick, refusal, coverage, decide, prepare, leak, pin_owner, set_pin, drop_pin,
	uninstall_cleanup,
	park_state, waiting, park, park_leak, unpark, forget_leaks, leak_backoff,
	no_uplink_reason
};

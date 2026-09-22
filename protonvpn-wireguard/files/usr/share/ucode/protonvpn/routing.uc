// SPDX-License-Identifier: MIT
// Traffic-routing detection and enforcement. Detects whether the user
// manages routing themselves (custom routing table or static routes/rules
// referencing the VPN interface) and, only when automatic routing is enabled
// AND no manual scheme is detected, maintains the firewall zone, the
// kill-switch and IPv6 rules and the DNS override. Every object this module
// creates is stamped with `protonvpn_managed`/`protonvpn_role`, and only
// stamped objects are ever modified or removed — user configuration is
// never touched.
//
// The one exception is the ULA addressing of a steered network under
// `ipv6_mode=auto` (see reconcile_v6_lan): those sections belong to the user,
// so the previous values are recorded next to the stamp and put back.

'use strict';

import { readfile } from 'fs';
const _common = require('protonvpn.common');

// Seconds given to any `ubus` call. ubus bounds itself with -t, which is the
// only bound available here: stock OpenWrt has no `timeout` binary, no busybox
// timeout applet, and this package declares no coreutils-timeout — a previous
// attempt wrapped the probe in `timeout` and was inert on the router while the
// suite, running on a machine that has GNU timeout, stayed green.
//
// Every call, not just the readiness probe: a wedged ubusd otherwise hangs an
// apply, the rpcd request behind it and the page in front of that, with no
// bound anywhere on the path.
const UBUS_TIMEOUT_S = '5';
const run = _common.run,
      run_ip = _common.run_ip,
      atomic_write = _common.atomic_write,
      iface_ipv6_capable = _common.iface_ipv6_capable;

const MARK = 'protonvpn_managed';
const ROLE = 'protonvpn_role';
// ProtonVPN in-tunnel DNS resolvers by mode. 'standard' only resolves
// through the tunnel; 'off' keeps the system/WAN resolver. Built from the
// constants rather than repeated, so the v6 resolver cannot drift away from
// the in-tunnel address it belongs to (see common.uc FIXED_ADDRESS6).
const VPN_DNS = {
	standard: _common.VPN_DNS4 + ' ' + _common.VPN_DNS6
};
// Addressing written onto a steered network while IPv6 goes through the
// tunnel, with the section's previous values recorded under V6_SAVED + option
// and the owning interface under V6_MARK.
const V6_LAN_OPTS = { ip6assign: '64', ip6class: 'local', delegate: '0' };

// A steered network must not draw the SAME /64 out of the router's ULA as
// another network already holds. netifd allocates sub-prefixes sequentially
// from 0, so a guest network and `lan` both end up on <ula>::/64 — and then the
// return route for a reply to a NAT6'd client resolves to whichever interface
// carries the lower metric, which is the LAN's kernel route. Measured on a live
// router: the tunnel round trip was symmetric and complete, conntrack reversed
// the translation, and the reply still left through br-lan.1 because both
// bridges claimed the same prefix; the client never saw it.
//
// So pin a sub-prefix per steered network. Derived from the network name so it
// is stable across applies — a hint that moved would re-address every client on
// every save — and different per network, in a range above what netifd's own
// sequential allocation reaches, so it cannot collide with a network that has
// no hint of its own.
function v6_hint(net) {
	let h = 0;
	for (let i = 0; i < length(net); i++)
		h = (h * 131 + ord(net, i)) % 0xf000;
	return sprintf('%04x', 0x1000 + h);
}

// V6_LAN_OPTS plus the per-network sub-prefix hint. Claim and release must be
// given the same map, or release would not recognise its own value.
function v6_lan_opts(net) {
	return { ...V6_LAN_OPTS, ip6hint: v6_hint(net) };
}
// What odhcpd needs before a client on that network sees the prefix at all.
// Allocating a prefix (V6_LAN_OPTS) does not announce one, and a network where
// IPv6 was never used ships `ra 'disabled'` — which is exactly what the old
// block-IPv6 policy encouraged, so this is the common case, not the corner.
//
//   ra 'server'     without it there is no router advertisement, so no prefix
//                   information option and no address.
//   ra_slaac '1'    sets the A flag on that option, which is what makes the
//                   client build an address for itself. Default in odhcpd,
//                   set explicitly so a network where it was turned off works.
//   ra_default '1'  without it the advertised router lifetime is 0 and the
//                   client gets an address it cannot route with. odhcpd counts
//                   a ULA as a usable prefix only when this is set
//                   (router.c: `!IN6_IS_ADDR_ULA(...) || iface->default_router`),
//                   and our prefix is always a ULA — there is no global one.
//
//   ra_flags 'none'  clears the M and O flags. Measured on a network that had
//                   been served by an ISP relay: it kept `ra_flags
//                   'managed-config' 'other-config'` while the two networks
//                   that worked had neither. M tells a client to go and ask
//                   DHCPv6 for its address — but the advertisement it arrives
//                   in already carries that address, so the round trip is
//                   pure delay on exactly the switch this addressing exists
//                   to make, and a client with no DHCPv6 implementation at
//                   all (Android) waits for something that will never come.
//                   Under this takeover the router is a SLAAC-only router for
//                   the network, and the advertisement should say so.
//   ndp 'disabled'  stops odhcpd proxying neighbour discovery toward the
//                   uplink. Same network, same leftover. This is the one that
//                   works AGAINST the takeover rather than merely alongside
//                   it: relaying keeps the path between the client and the
//                   ISP router alive at the neighbour level, for precisely
//                   the clients this is trying to move off it.
//
// dhcpv6 is deliberately left alone, and now in BOTH directions. We do not
// turn it on: SLAAC supplies the address and the RA supplies the route, so
// stateful assignment adds nothing. We do not turn it off either, for the
// mirror of the same reason — a service the user enabled is not ours to stop,
// and with the M flag cleared it is simply inert for address configuration
// while still answering anything they set it up to answer.
const V6_DHCP_OPTS = { ra: 'server', ra_slaac: '1', ra_default: '1',
	ra_flags: 'none', ndp: 'disabled' };
// odhcpd's init script. Absolute on a router, so PATH cannot shadow it the way
// it shadows ifup/ifdown; relocated for the offline suite the same way the
// table registry and the state dir are.
const ODHCPD_INIT = getenv('PROTONVPN_ODHCPD_INIT') || '/etc/init.d/odhcpd';
// How long to wait for netifd to put the new addressing on a bridge before
// nudging odhcpd anyway, and how often to look.
//
// Measured against the MONOTONIC clock, not counted in iterations. Every probe
// launches a process, so an iteration count times a sleep is not a bound at
// all: on a slow or busy router twenty probes of a second each is twenty-five
// seconds of "five second" wait. Monotonic rather than wall so that an NTP
// step mid-apply cannot turn the bound into either zero or forever.
//
// Five seconds because the assignment is computed locally out of the router's
// own ULA — it is either quick or it is not coming. Overridable so a slow
// router can be given more without a code change; the log line on timeout
// names the variable.
const RA_SETTLE_MS = 5000;
const RA_POLL_MS = 250;
// How long after that nudge the page may tell the user their clients are
// moving over. Long enough to cover a device that was asleep when the
// advertisement went out, short enough that it is news rather than furniture.
const RA_SETTLE_WINDOW = 300;
// And before any of that can take effect, the kernel has to accept an IPv6
// address on the bridge at all. `option ipv6 '0'` on a network's `config
// device` section becomes disable_ipv6=1 on the device, and then netifd
// computes the prefix assignment, fails to add the address, and reports the
// assignment with an empty `local-address` — every option above set correctly
// and the client still without an address. It is the device-level twin of
// `ra 'disabled'`, and a network where IPv6 was never used carries both.
//
// Measured on a live guest bridge: with ipv6='0' there is no global address on
// the bridge however the rest is configured; setting it to '1' and bringing
// that one interface up produces fd…::1/64 and a populated local-address, and
// putting it back removes them again. No wider reload is involved.
const V6_DEV_OPTS = { ipv6: '1' };
const V6_MARK = MARK + '_v6';
const V6_SAVED = 'protonvpn_saved_';
// PROTONVPN_RT_TABLES relocates the table registry for the offline suite,
// which must not touch the host's /etc (same convention as the state dir).
const RT_TABLES = getenv('PROTONVPN_RT_TABLES') || '/etc/iproute2/rt_tables';

// ── Small uci helpers ────────────────────────────────────────────────

// Normalize a zone/forwarding 'network' option (string or list) to an array.
function as_list(v) {
	if (v == null)
		return [];
	if (type(v) == 'array')
		return v;
	return split('' + v, ' ');
}

function find_peer(uci, iface) {
	let found = null;
	uci.foreach('network', null, function(sec) {
		if (sec['.type'] && index(sec['.type'], 'wireguard_') == 0 && sec.interface == iface) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// Zone whose network list contains the interface: { name, section, managed }.
function find_zone_of(uci, iface) {
	let found = null;
	uci.foreach('firewall', 'zone', function(sec) {
		for (let n in as_list(sec.network)) {
			if (n == iface) {
				found = { name: sec.name, section: sec['.name'], managed: sec[MARK] == '1' };
				return false;
			}
		}
	});
	return found;
}

// Masquerading firewall zone (preferred) or the zone named 'wan'.
function find_wan_zone(uci) {
	let masq = null, named = null;
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.masq == '1' && !masq)
			masq = sec.name;
		if (sec.name == 'wan' && !named)
			named = sec.name;
	});
	return masq || named;
}

// Zone named 'lan', else the zone containing network 'lan'.
function find_lan_zone(uci) {
	let named = null, holding = null;
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.name == 'lan' && !named)
			named = sec.name;
		for (let n in as_list(sec.network))
			if (n == 'lan' && !holding)
				holding = sec.name;
	});
	return named || holding;
}

// Count of unstamped route/route6/rule/rule6 sections referencing the
// interface or its routing table.
function count_user_routes(uci, iface, table) {
	let n = 0;
	let check = function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.interface == iface)
			n++;
		else if (table && table != '' && sec.table == table)
			n++;
	};
	for (let t in [ 'route', 'route6', 'rule', 'rule6' ])
		uci.foreach('network', t, check);
	return n;
}

// Stamped firewall section (rule/forwarding/zone) with the given role, or
// null. Zone/forwarding objects are per-interface (pass `iface`); the kill
// switch and IPv6 block are global (leave `iface` null).
function find_managed(uci, sectype, role, iface) {
	let found = null;
	uci.foreach('firewall', sectype, function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == role && (iface == null || sec.protonvpn_iface == iface)) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// ── Local subnets (steering bypass) ──────────────────────────────────
// A steered table's default swallows traffic to OTHER local subnets too, so
// LAN↔VLAN and LAN↔tunnel-services connectivity would silently die. Steering
// therefore maintains stamped bypass routes for every local IPv4 subnet.

function ip4_to_int(a) {
	let m = match(a, /^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$/);
	if (!m)
		return null;
	let o1 = int(m[1]), o2 = int(m[2]), o3 = int(m[3]), o4 = int(m[4]);
	if (o1 > 255 || o2 > 255 || o3 > 255 || o4 > 255)
		return null;
	return ((o1 * 256 + o2) * 256 + o3) * 256 + o4;
}

function int_to_ip4(n) {
	return sprintf('%d.%d.%d.%d',
		(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
}

function mask_len(netmask) {
	let n = ip4_to_int(netmask);
	if (n == null)
		return null;
	let len = 0;
	while (len < 32 && (n & 0x80000000)) {
		len++;
		n = (n << 1) & 0xffffffff;
	}
	return (n & 0xffffffff) == 0 ? len : null;
}

// Normalized 'a.b.c.d/len' network of a uci route section, accepting both the
// CIDR target form and the separate target+netmask form. Null when unparsable.
function route_cidr(sec) {
	let t = '' + (sec.target || '');
	let addr = null, len = null;
	let m = match(t, /^([0-9.]+)\/([0-9]+)$/);
	if (m) {
		addr = m[1];
		len = int(m[2]);
	} else if (sec.netmask) {
		addr = t;
		len = mask_len('' + sec.netmask);
	} else {
		return null;
	}
	if (len == null || len < 0 || len > 32)
		return null;
	let ip = ip4_to_int(addr);
	if (ip == null)
		return null;
	let mask = (len == 0) ? 0 : ((0xffffffff << (32 - len)) & 0xffffffff);
	return sprintf('%s/%d', int_to_ip4(ip & mask), len);
}

// Every local IPv4 subnet as { target: 'a.b.c.d/len', iface: <logical name> },
// from the static config plus (when available) netifd's runtime state, which
// also covers DHCP-assigned networks and tunnels like a user WireGuard link.
// `skip` maps interface names to ignore (the protonvpn instances themselves —
// they all share the fixed ProtonVPN range).
function local_subnets(uci, skip) {
	let out = [];
	let seen = {};
	let add = function(name, addr, len) {
		if (name == 'loopback' || skip[name] || addr == null || len == null || len < 1 || len > 30)
			return;
		let ip = ip4_to_int(addr);
		if (ip == null)
			return;
		let mask = (0xffffffff << (32 - len)) & 0xffffffff;
		let target = sprintf('%s/%d', int_to_ip4(ip & mask), len);
		if (target == '10.2.0.0/16' || seen[target])
			return;
		seen[target] = 1;
		push(out, { target: target, iface: name });
	};

	uci.foreach('network', 'interface', function(sec) {
		if (sec.proto != 'static')
			return;
		let addrs = sec.ipaddr;
		if (type(addrs) != 'array')
			addrs = (addrs != null) ? [ addrs ] : [];
		for (let a in addrs) {
			let m = match('' + a, /^([0-9.]+)\/([0-9]+)$/);
			if (m)
				add(sec['.name'], m[1], int(m[2]));
			else if (sec.netmask)
				add(sec['.name'], '' + a, mask_len(sec.netmask));
		}
	});

	// User static routes in the main table (e.g. a subnet behind their own
	// WireGuard link, where the interface address is a /32) are local
	// destinations too — mirror them.
	uci.foreach('network', 'route', function(sec) {
		if (sec[MARK] == '1' || (sec.table != null && sec.table != ''))
			return;
		let c = route_cidr(sec);
		if (c) {
			let m = match(c, /^([0-9.]+)\/([0-9]+)$/);
			add(sec.interface, m[1], int(m[2]));
		}
	});

	// Subnets routed through the user's OWN WireGuard links (peer allowed_ips
	// with route_allowed_ips) — e.g. services behind a personal wg tunnel.
	uci.foreach('network', null, function(sec) {
		if (!sec['.type'] || index(sec['.type'], 'wireguard_') != 0)
			return;
		if (sec.route_allowed_ips != '1' || sec.interface == null || skip[sec.interface])
			return;
		let ips = sec.allowed_ips;
		if (type(ips) != 'array')
			ips = (ips != null) ? [ ips ] : [];
		for (let a in ips) {
			let m = match('' + a, /^([0-9.]+)\/([0-9]+)$/);
			if (m)
				add(sec.interface, m[1], int(m[2]));
		}
	});

	let d = run([ 'ubus', '-t', UBUS_TIMEOUT_S, 'call', 'network.interface', 'dump' ]);
	if (d.code == 0) {
		let data;
		try {
			data = json(d.stdout);
		} catch (e) {
			data = null;
		}
		let dev2iface = {};
		for (let ifc in ((data ? data.interface : null) || [])) {
			if (ifc.l3_device)
				dev2iface[ifc.l3_device] = ifc.interface;
			for (let a in (ifc['ipv4-address'] || []))
				add(ifc.interface, a.address, a.mask);
		}

		// Pinned exception routes and foreign connected subnets in the main
		// table, any prefix length. netifd/scripted routes carry proto static,
		// hand-added `ip route add` ones proto boot, and connected subnets of
		// interfaces netifd does not manage itself (docker bridges etc.) carry
		// proto kernel — mirror all three so steered clients keep every local
		// or pinned destination. Only on-device (needs ubus for the mapping).
		let pin_lines = [];
		for (let proto in [ 'static', 'boot', 'kernel' ]) {
			let rt = run_ip([ '-4', 'route', 'show', 'table', 'main', 'proto', proto ]);
			if (rt.code == 0)
				for (let l in split(trim(rt.stdout || ''), '\n'))
					push(pin_lines, l);
		}
		{
			for (let line in pin_lines) {
				let m = match(line, /^([0-9.]+(\/[0-9]+)?) +via +([0-9.]+) +dev +([^ ]+)/);
				let target = null, gw = null, dev = null;
				if (m) {
					target = m[1];
					gw = m[3];
					dev = m[4];
				} else {
					m = match(line, /^([0-9.]+(\/[0-9]+)?) +dev +([^ ]+)/);
					if (m) {
						target = m[1];
						dev = m[3];
					}
				}
				if (!target || target == 'default' || !dev2iface[dev] || skip[dev2iface[dev]])
					continue;
				if (index(target, '/') < 0)
					target += '/32';
				if (seen[target])
					continue;
				seen[target] = 1;
				push(out, { target: target, iface: dev2iface[dev], gateway: gw });
			}
		}
	}
	return out;
}

// Reconcile the stamped bypass routes of one instance with the desired subnet
// list. Subnets already covered by an unstamped user route in the same table
// are left to the user's route. Returns true on change.
function reconcile_local_routes(uci, iface, table, desired) {
	let changed = false;
	let have = [];
	let covered = {};
	uci.foreach('network', 'route', function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == 'steer_local' && sec.protonvpn_iface == iface) {
			push(have, { section: sec['.name'], target: sec.target, table: sec.table });
		} else if (sec[MARK] != '1' && sec.table == table) {
			let c = route_cidr(sec);
			if (c)
				covered[c] = true;
		}
	});
	for (let h in have) {
		// A user route for the same subnet wins over ours.
		let keep = (h.table == table) && !covered[h.target];
		if (keep) {
			keep = false;
			for (let d in desired)
				if (d.target == h.target)
					keep = true;
		}
		if (!keep) {
			uci.delete('network', h.section);
			changed = true;
		}
	}
	for (let d in desired) {
		let present = false;
		for (let h in have)
			if (h.target == d.target && h.table == table && !covered[h.target])
				present = true;
		if (covered[d.target] || present)
			continue;
		let sec = uci.add('network', 'route');
		uci.set('network', sec, 'interface', d.iface);
		uci.set('network', sec, 'target', d.target);
		if (d.gateway)
			uci.set('network', sec, 'gateway', d.gateway);
		uci.set('network', sec, 'table', table);
		uci.set('network', sec, MARK, '1');
		uci.set('network', sec, ROLE, 'steer_local');
		uci.set('network', sec, 'protonvpn_iface', iface);
		changed = true;
	}
	return changed;
}

// netifd resolves named routing tables through /etc/iproute2/rt_tables; an
// unregistered name makes ip4table and lookup rules silently inert. Register
// the instance's table with a stamped line (best effort). Numeric tables and
// already-registered names need nothing.
function ensure_rt_table(name) {
	// The sink's own guard, asking the same validator the entry point asks.
	// Nothing in the product can reach here with a name validate_routing_table
	// refuses — load_settings runs the option through it — but this is the
	// last step before a line-oriented file that cannot express a multiline
	// name, and "the caller already checked" is how the value got here
	// unchecked in the first place. One definition, applied at both ends.
	if (_common.validate_routing_table(name) == null || name == '')
		return false;
	if (match(name, /^[0-9]+$/))
		return true;
	let data = readfile(RT_TABLES) || '';
	let used = {};
	for (let line in split(data, '\n')) {
		let m = match(line, /^[ \t]*([0-9]+)[ \t]+([^ \t#]+)/);
		if (!m)
			continue;
		if (m[2] == name)
			return true;
		used[m[1]] = true;
	}
	for (let n = 100; n <= 252; n++) {
		if (used['' + n])
			continue;
		return atomic_write(RT_TABLES,
			data + (length(data) && substr(data, -1) != '\n' ? '\n' : '') +
			sprintf('%d\t%s # %s\n', n, name, MARK));
	}
	return false;
}

// Remove ONLY a stamped rt_tables line for `name`; user entries are kept.
function drop_rt_table(name) {
	// A name this module could not have written is not one it goes looking
	// for: the same validator, so teardown and setup agree on what a name is.
	if (_common.validate_routing_table(name) == null || name == '' ||
	    match(name, /^[0-9]+$/))
		return;
	let data = readfile(RT_TABLES);
	if (!data || index(data, MARK) < 0)
		return;
	let kept = [];
	let changed = false;
	for (let line in split(data, '\n')) {
		let m = match(line, /^[ \t]*[0-9]+[ \t]+([^ \t#]+)[ \t]*#[ ]*protonvpn_managed/);
		if (m && m[1] == name) {
			changed = true;
			continue;
		}
		push(kept, line);
	}
	if (changed)
		atomic_write(RT_TABLES, join('\n', kept));
}

// True when the WAN has a default IPv6 route (potential leak path).
function wan_has_ipv6() {
	let r = run_ip([ '-6', 'route', 'show', 'default' ]);
	return r.code == 0 && length(trim(r.stdout || '')) > 0;
}

// L3-device MTU of the WAN uplink (the path WireGuard's UDP actually takes to
// the endpoint — NOT the tunnel). Found via the WAN firewall zone's networks so
// an active auto-routing default through the tunnel does not mislead us. Returns
// the smallest MTU across WAN devices, or null when it cannot be determined.
function wan_l3_mtu(uci) {
	let wannets = {};
	uci.foreach('firewall', 'zone', function(sec) {
		if (sec[MARK] == '1')
			return;
		if (sec.masq == '1' || sec.name == 'wan')
			for (let n in as_list(sec.network))
				wannets[n] = 1;
	});
	let d = run([ 'ubus', '-t', UBUS_TIMEOUT_S, 'call', 'network.interface', 'dump' ]);
	if (d.code != 0)
		return null;
	let data;
	try {
		data = json(d.stdout);
	} catch (e) {
		return null;
	}
	let best = null;
	for (let ifc in ((data ? data.interface : null) || [])) {
		if (!ifc.up || !ifc.l3_device || !wannets[ifc.interface])
			continue;
		// Never count a WireGuard tunnel as the WAN uplink: it is the path
		// WireGuard's UDP rides ON, not the uplink itself. Counting it creates
		// a feedback loop — setting the recommended tunnel MTU makes the tunnel
		// the smallest "WAN" device, dragging the next recommendation down 80.
		if (ifc.proto == 'wireguard')
			continue;
		let l = run_ip([ 'link', 'show', 'dev', ifc.l3_device ]);
		if (l.code != 0)
			continue;
		let m = match(l.stdout || '', /mtu ([0-9]+)/);
		if (m) {
			let v = int(m[1]);
			if (best == null || v < best)
				best = v;
		}
	}
	return best;
}

// Recommended WireGuard MTU: WAN MTU - 80 (60 bytes of real WG/UDP/IPv4
// overhead + 20 safety, matching the vendor's 1420 on a 1500 path and 1412
// on 1492 PPPoE), clamped to [1280 (IPv6 minimum), 1420 (vendor maximum)].
// Null when the WAN MTU is unknown.
function recommend_mtu(wanmtu) {
	if (type(wanmtu) != 'int' || wanmtu <= 0)
		return null;
	let v = wanmtu - 80;
	if (v < 1280)
		v = 1280;
	if (v > 1420)
		v = 1420;
	return v;
}

// Logical networks a user could steer through an instance: every interface
// section except loopback and WireGuard tunnels.
function available_networks(uci) {
	let out = [];
	uci.foreach('network', 'interface', function(sec) {
		if (sec['.name'] == 'loopback' || sec.proto == 'wireguard')
			return;
		push(out, sec['.name']);
	});
	return out;
}

// Stamped netifd rule sections (rule/rule6) of one instance and role.
function find_managed_rules(uci, sectype, role, iface) {
	let out = [];
	uci.foreach('network', sectype, function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == role && sec.protonvpn_iface == iface)
			push(out, { section: sec['.name'], net: sec['in'] });
	});
	return out;
}

// Reconcile stamped netifd rules with the desired source-network list:
// delete stamped rules for nets no longer wanted, create missing ones.
// `mkopts(net)` returns the option map for a new rule. Returns true on change.
function reconcile_rules(uci, sectype, role, iface, want_nets, mkopts) {
	let changed = false;
	let have = find_managed_rules(uci, sectype, role, iface);
	for (let r in have) {
		if (index(want_nets, r.net) < 0) {
			uci.delete('network', r.section);
			changed = true;
		}
	}
	for (let net in want_nets) {
		let present = false;
		for (let r in have)
			if (r.net == net)
				present = true;
		if (!present) {
			let sec = uci.add('network', sectype);
			let opts = mkopts(net);
			for (let k in opts)
				uci.set('network', sec, k, opts[k]);
			uci.set('network', sec, MARK, '1');
			uci.set('network', sec, ROLE, role);
			uci.set('network', sec, 'protonvpn_iface', iface);
			changed = true;
		}
	}
	return changed;
}

// Reconcile the two stamped rule6 objects of one instance against the IPv6
// mode and the gateway that is on the interface right now.
//
// Under 'auto' the pair is
//     rule6 in <net> lookup <table> priority 20000   (only with the bit)
//     rule6 in <net> prohibit       priority 21000   (unless the mode is 'off')
// and the order is the whole point. The lookup sends v6 into the instance's
// table, where netifd has already installed a ::/0 route from the peer's
// allowed_ips; the prohibit below it catches everything that table cannot
// serve — a down tunnel, a gateway without IPv6 — before the kernel ever
// reaches `main`, where the ISP default route lives. That ordering IS the v6
// kill switch, there is no separate option for it, and the prohibit therefore
// outlives the tunnel: it is the half that has to be standing exactly when
// there is nothing to route into.
//
// ProtonVPN forwards IPv6 only on the gateways that carry bit 16 of the
// logical Features bitmask. Measured on 12 gateways across 11 countries by
// probing 2606:4700:4700::1111 through the tunnel: all six with the bit
// answered in 0.02-1.07 s, all six without it timed out at 8-12 s on every
// attempt while the WireGuard TX counter kept climbing — the packets leave and
// nothing comes back. Routing v6 into such a gateway does not enable IPv6, it
// swallows it, and a black hole is worse than a block: clients wait out Happy
// Eyeballs on every connection and anything that is not a browser simply
// hangs. So 'auto' adds the lookup only when the bit is really there, and a
// missing stamp (an interface written by an older version) counts as no IPv6.
//
// `steering` is is_steering(): set up for steering AND switched on. BOTH
// halves hang off it, and that single condition is the fix for a real outage.
// The prohibit used to hang off configured-steering alone, so switching an
// instance off in LuCI left it behind — a persistent `rule6 in lan prohibit
// priority 21000` naming an interface that no longer existed, which a reboot
// did not clear. Meanwhile the ADDRESSING of the same networks follows
// is_steering (see reconcile_v6_lan, reached through v6_wants_net), so the
// clients had already been handed their ISP GUA and the router as default
// gateway. Happy Eyeballs then preferred IPv6 and every connection died at the
// rule, with `ip -6 route get` answering "Permission denied" and nothing in
// the UI saying why. The two are one decision: once this module gives the GUA
// back it has decided IPv6 goes to the provider, and a prohibit after that
// guards nothing while breaking everything.
//
// What this does NOT relax is the leak guard. "Switched off by the user" and
// "the tunnel is not up right now" are different states, and only the first
// reaches here as !steering. An ENABLED instance whose tunnel is down, or
// whose gateway lacks bit 16, still holds its clients' ULA addressing, so the
// prohibit stays — that is exactly the leak it exists to stop. `ipv6_mode`
// 'off' remains the way to ask for no guard at all while the instance runs.
function reconcile_ipv6_rules(uci, s, iface, steering, table, nets) {
	let changed = false;
	let mode = s.ipv6_mode || 'block';
	// Steered routing only: with auto_routing the whole LAN goes through the
	// tunnel and there is no per-network rule to hang a lookup on, so 'auto'
	// behaves exactly like 'block' there.
	let want = steering ? (nets || []) : [];
	// The lookup additionally needs this gateway to forward IPv6; anything
	// else would route v6 into a table that drops it.
	let tunnel = mode == 'auto' && iface_ipv6_capable(uci, iface);
	if (reconcile_rules(uci, 'rule6', 'steer_v6_lookup', iface,
		tunnel ? want : [], function(net) {
			return { 'in': net, lookup: table, priority: '20000' };
		}))
		changed = true;
	if (reconcile_rules(uci, 'rule6', 'steer_v6', iface,
		(mode != 'off') ? want : [], function(net) {
			return { 'in': net, action: 'prohibit', priority: '21000' };
		}))
		changed = true;
	return changed;
}

// ── Making the switch prompt ─────────────────────────────────────────
//
// Changing the addressing is not the same as the clients using it. Measured
// on a live router: steering a network DID work and the advertisement content
// was right — our ULA announced, the ISP prefix deprecated with a preferred
// lifetime of 0 — but unsolicited advertisements were ten minutes apart, and
// four of five clients were still holding ISP addresses because they had
// missed the one that carried the switch.
//
// There is no "advertise now" method on odhcpd: no ubus call, no signal. What
// it does guarantee is that when it starts advertising on an interface it
// sends the RFC 4861 §6.2.4 initial burst — several advertisements, seconds
// apart, rather than one — which is exactly the property a client that missed
// one needs. On OpenWrt the supported way to make that happen is the init
// script's reload, and the code already ran it.
//
// So the defect was never WHETHER but WHEN. `ubus call network reload` returns
// once netifd has accepted the new configuration, not once the interfaces have
// been reconfigured, and the odhcpd reload that immediately followed it could
// therefore re-initialise against the OLD prefix. The corrected advertisement
// then waited for the next scheduled one.
//
// Hence: wait for netifd to actually report the new addressing, then nudge
// odhcpd. Bounded, because a wait that can hang is worse than a slow switch,
// and it nudges on the way out regardless — a late burst still beats the next
// ten-minute tick.
//
// NOTE for whoever revisits this: the ordering above is inferred from netifd's
// and odhcpd's documented behaviour, not measured. What WAS measured is at the
// top of this comment. If the switch is still slow on a router, that ordering
// is the first thing to doubt.

// The leading hextets of the router's own ULA, which is where `ip6class local`
// draws every steered network's prefix from. Null when there is none to
// compare against, or when it is not on a hextet boundary — /48 is what
// OpenWrt writes, and guessing at anything else would be worse than not
// looking.
function ula_groups(uci) {
	let ula = uci.get('network', 'globals', 'ula_prefix') || '';
	let m = match(ula, /^([0-9a-fA-F:]+)\/([0-9]+)$/);
	if (!m)
		return null;
	let bits = int(m[2]);
	if (bits <= 0 || bits % 16 != 0)
		return null;
	let want = bits / 16;
	let parts = [];
	for (let g in split(lc(m[1]), ':'))
		if (length(g))
			push(parts, g);
	if (length(parts) != want)
		return null;
	return parts;
}

// The readiness budget in milliseconds. Read at CALL time, not folded into a
// constant at load time, so it is answerable — a knob nobody can observe is a
// claim, not a setting. A slow router can be given more without a code change
// and without a rebuild; the log line on timeout names the variable.
function ra_budget_ms() {
	let v = int(getenv('PROTONVPN_RA_SETTLE_MS') || '0');
	return (v > 0) ? v : RA_SETTLE_MS;
}

// The `notes` argument is kept in the signature for the callers that pass it,
// and deliberately not written to: see finish_ra for why this function logs
// instead.
function void_notes(notes) {
	return notes;
}

// Milliseconds on the monotonic clock.
function ms_now() {
	let c = clock(true);
	return c[0] * 1000 + int(c[1] / 1000000);
}

// One hextet as a number, or -1 for anything that is not one.
//
// Deliberately strict: a field this cannot read must not compare equal to
// another it also cannot read. A mutation run shows that strictness is not
// currently observable — the prefix being looked FOR is built here and is
// always well-formed and non-zero (a ULA starts fd.., v6_hint() never returns
// below 0x1000), so unreadable input on the other side can only fail to match
// whatever it decays to. That makes returning 0 instead an equivalent mutant
// rather than a caught bug, and this comment rather than a test is the honest
// record of it. It stays because the guarantee is about this function, not
// about its one caller: the day something asks it to compare a prefix with a
// zero hextet in it, -1 is the answer that does not quietly agree.
function hex16(g) {
	if (!length(g) || length(g) > 4)
		return -1;
	let v = 0;
	for (let i = 0; i < length(g); i++) {
		let c = ord(lc(g), i), d = -1;
		if (c >= 48 && c <= 57)
			d = c - 48;
		else if (c >= 97 && c <= 102)
			d = c - 87;
		else
			return -1;
		v = v * 16 + d;
	}
	return v;
}

// The first four hextets of an address, with `::` expanded — or null when
// they cannot be known.
//
// `::` stands for a run of zero groups, so the four leading hextets are only
// ambiguous when the run starts inside them. The length of the run is
// recoverable: an IPv6 address has eight groups, so the omitted ones are eight
// minus the ones written. That makes `fd7a::1abc:0:0:0:1` and
// `fd7a:0:0:1abc::1` the same first four groups, which a textual compare calls
// different.
//
// Null only for an address that is not one — too many groups, or more than one
// `::`. Everything netifd writes expands cleanly; this exists so that the
// comparison does not depend on that remaining true.
function expand4(addr) {
	let parts = split(lc(addr), ':');
	// A leading or trailing '::' produces an empty first or last field on top
	// of the empty one marking the run; drop those before counting.
	if (length(parts) > 1 && !length(parts[0]))
		parts = slice(parts, 1);
	if (length(parts) > 1 && !length(parts[length(parts) - 1]))
		parts = slice(parts, 0, length(parts) - 1);
	let out = [], gap = -1;
	for (let i = 0; i < length(parts); i++) {
		if (!length(parts[i])) {
			if (gap >= 0)
				return null;           // two '::' is not an address
			gap = length(out);
			continue;
		}
		push(out, parts[i]);
	}
	if (length(out) > 8 || (gap < 0 && length(out) != 8))
		return null;
	if (gap >= 0) {
		let zeros = [];
		for (let i = 0; i < 8 - length(out); i++)
			push(zeros, '0');
		out = [ ...slice(out, 0, gap), ...zeros, ...slice(out, gap) ];
	}
	return slice(out, 0, 4);
}

// Whether `addr` falls under the /64 named by the first four hextets of
// `want`, compared as NUMBERS rather than as text.
//
// The same prefix has several spellings — `fd7a:1b2c:3d4e:1abc`, `FD7A:...`,
// `fd7a:1b2c:3d4e:1abc:0:0:0:1` — and a textual match calls two of those
// different. netifd writes the canonical form, so this has never actually
// bitten; comparing the numbers costs a dozen lines and removes the question.
//
// `::` is expanded before comparing (see expand4), so an address that
// abbreviates a zero run inside its first four groups is matched too — that
// was the last spelling this could not see.
function addr_under_prefix(addr, want) {
	if (type(addr) != 'string')
		return false;
	let a = expand4(addr), w = split(want, ':');
	if (a == null)
		return false;
	for (let i = 0; i < 4; i++) {
		if (i >= length(w) || !length(w[i]))
			return false;
		if (hex16(a[i]) != hex16(w[i]))
			return false;
	}
	return true;
}

// The /64 this module asked netifd to give THIS network, as the leading text
// of any address out of it: the router's ULA with the network's own ip6hint
// as the fourth hextet.
//
// "Some address out of the ULA /48" is a different question, and wrong in both
// directions. On a claim it is answered yes by a sibling steered network's
// prefix, so the wait ends before ours exists, odhcpd is nudged against the
// old addressing and the ten-minute wait is straight back. On a release it is
// answered yes by that same sibling, so the wait times out every time while
// nothing is actually wrong. The hint is ours and computed per network
// (v6_hint), so the expected prefix is knowable rather than guessable.
//
// Null when it cannot be worked out: no ULA, or one that is not a /48 and so
// does not put the hint in the fourth hextet.
function v6_expect_prefix(groups, net) {
	// A /48 is what OpenWrt writes, and it is the only length that puts the
	// 16-bit hint in the fourth hextet. Anything else cannot be turned into an
	// expected prefix, and guessing would be worse than saying so: the wait
	// would time out on every apply while nothing was actually wrong.
	if (groups == null || length(groups) != 3)
		return null;
	return join(':', groups) + ':' + v6_hint(net) + ':';
}

// Whether netifd currently reports an address under `want` on this network.
//
// Returns { has: true|false|null, wedged: bool }. `has` is null when the
// question cannot be answered at all — no ubus, nothing that parses, or a
// probe that did not come back — which is a reason to stop waiting rather
// than to keep asking. `wedged` separates the last of those, because a ubus
// that does not answer is a different thing to tell the user about than one
// that is not there.
//
// THE PROBE IS BOUNDED, not just the loop around it. `run()` is synchronous
// and has no timeout of its own, so a busy or wedged ubus blocks here for as
// long as it likes — outside both of the loop's clock checks, and so straight
// through the budget that the log and the page both advertise.
//
// The bound is ubus's own `-t`, and that choice is the whole lesson of this
// round. The first attempt wrapped the call in `timeout`, which does not
// exist on stock OpenWrt — no binary, no busybox applet, no declared
// dependency — so on the router the probe failed to start, the wait was
// skipped, and the ten-minute switchover came back while the suite stayed
// green on a machine that has GNU timeout. `ubus -t` needs nothing installed
// and bounds the thing actually being waited on rather than the process
// around it. test_target_commands.uc now fails if anything here reaches for a
// command the target does not have.
//
// Whole seconds because that is what -t takes, rounded up and never below one
// — so the probe cap can overshoot a sub-second budget. That is exactly why
// the caller reports the time it MEASURED rather than the budget it intended:
// see finish_ra.
function net_has_prefix(net, want, secs) {
	let t0 = ms_now();
	let d = run([ 'ubus', '-t', '' + secs, 'call', 'network.interface.' + net, 'status' ]);
	if (d.code != 0) {
		// "Wedged" is decided from the CLOCK, not from an exit status.
		//
		// This is now a measured fact rather than a judgement call. On the
		// router this package was written for, `ubus -t 1 call
		// network.interface.<nonexistent> status` exits 4 — so on that build
		// 4 means "no such object", NOT a timeout. Keying on an exit code
		// would have picked the wrong branch whichever number was chosen:
		// 124 is GNU timeout's convention for a tool that is not even on the
		// target, and 4 is taken. (The documented enum puts
		// UBUS_STATUS_TIMEOUT at 7, which is corroboration, not evidence.)
		//
		// How long the call took is observable right here and means the same
		// thing on every build: if it used up the time it was given, it was
		// wedged; if it came back at once, ubus is missing or refusing, which
		// is a different thing to tell the user.
		let spent = ms_now() - t0;
		return { has: null, wedged: spent >= (secs * 1000 * 9) / 10 };
	}
	let data;
	try {
		data = json(d.stdout);
	} catch (e) {
		return { has: null, wedged: false };
	}
	if (type(data) != 'object')
		return { has: null, wedged: false };
	for (let a in (data['ipv6-prefix-assignment'] || [])) {
		let addr = (a['local-address'] || {}).address;
		if (addr_under_prefix(addr, want))
			return { has: true, wedged: false };
	}
	return { has: false, wedged: false };
}

// The tail every exit of ra_refresh takes: say what did not settle, ask odhcpd
// for a fresh advertisement, and stamp when that happened. Declared ahead of
// its caller because ucode resolves names at parse time.
function finish_ra(uci, iface, plan, pending, spent, unchecked) {
	// Logged directly rather than pushed into `notes`: only apply() ever logs
	// that array, so on both release paths — disconnect and delete_instance —
	// a timeout used to pass in complete silence, and a silent timeout is
	// indistinguishable from success. This is the one moment where the fix
	// can be known to have fallen back to the old behaviour, so it has to
	// reach the log wherever it happens.
	//
	// The line says what was DONE as well as what went wrong: "it timed out"
	// alone leaves the reader not knowing whether the clients were told at
	// all. They were, which is why the ten-minute wait is usually still
	// avoided even on this path.
	// The number reported is the one the CALLER waited, not the budget that
	// was intended. A probe capped at whole seconds can overshoot a sub-second
	// budget, and a log that rounds in its own favour is how a bound stops
	// meaning anything — the time here and the time the user sat through are
	// the same number by construction.
	for (let p in (pending || []))
		_common.log('routing: network ' + p.net + ': its IPv6 addressing did not ' +
			'settle within ' + (spent || 0) + 'ms (budget ' + ra_budget_ms() +
			'ms), advertised anyway — clients may take a few minutes to move. ' +
			'Raise PROTONVPN_RA_SETTLE_MS if this router is simply slow.');
	// A ubus that does not answer is a different thing to tell the user than
	// one that answers "not yet": nothing is wrong with the addressing, the
	// question could not be put.
	for (let p in (unchecked || []))
		_common.log('routing: network ' + p.net + ': readiness could not be checked ' +
			'— the ubus probe did not answer within ' + (spent || 0) + 'ms, ' +
			'advertised anyway. Something is holding up ubus on this router.');
	run([ ODHCPD_INIT, 'reload' ]);
	// Stamped only when something was CLAIMED. The stamp exists for one
	// reader — the page saying "clients are moving to the tunnel address" —
	// and that line is only ever shown while IPv6 is active on the tunnel, so
	// after a pure release there is nothing it could say. Writing it anyway
	// would mean a disconnect edited the configuration for no reader at all.
	let claimed = false;
	for (let p in (plan || []))
		if (p.want)
			claimed = true;
	if (claimed && iface != null && uci.get('network', iface) != null)
		uci.set('network', iface, 'protonvpn_v6_ra_at', '' + time());
	return true;
}

// Make the clients of the networks in `plan` move now rather than at the next
// scheduled advertisement. Each entry is { net, want }: want=true after a
// claim (wait for the ULA to appear), false after a release (wait for it to
// go). `iface` is stamped with the moment the nudge went out, so the page can
// say the clients are moving over while that is still true.
function ra_refresh(uci, iface, plan, notes) {
	if (!length(plan))
		return false;
	// `notes` is accepted for the callers that still pass it; what this
	// function has to say goes to the log, because that is the only channel
	// every caller actually reads. See finish_ra.
	void_notes(notes);
	let groups = ula_groups(uci);
	let budget = ra_budget_ms();
	let deadline = ms_now() + budget;
	let pending = [], blind = [];
	for (let p in plan) {
		let want = v6_expect_prefix(groups, p.net);
		if (want == null)
			push(blind, p);
		else
			push(pending, { net: p.net, want: p.want, prefix: want });
	}

	// Nothing to watch for. Two different reasons, and only one is worth
	// waiting through:
	//
	//   * no usable ula_prefix at all — then there IS no ULA addressing, the
	//     clients were never going to get an address (reconcile_v6_lan says so
	//     separately), and a wait would be five seconds of sleep before
	//     announcing nothing;
	//   * a ULA that is not a /48 — the addressing exists but the hint is not
	//     in the fourth hextet, so the prefix cannot be named. Here the safe
	//     side is to wait the whole budget anyway: what is being guarded
	//     against is nudging odhcpd before netifd is done, and an unverifiable
	//     wait still gives netifd the time.
	//
	// Either way the log says readiness was not verified, because a wait that
	// proved nothing must not read as one that did.
	if (length(blind)) {
		let t0 = ms_now();
		if (groups != null)
			sleep(budget);
		void_notes(ms_now() - t0);
		let ula = uci.get('network', 'globals', 'ula_prefix') || '';
		for (let p in blind)
			_common.log('routing: network ' + p.net + ': could not work out which ' +
				'IPv6 prefix to expect (network.globals.ula_prefix is ' +
				(length(ula) ? ula : 'unset') + '), so readiness was not ' +
				'verified; advertised anyway');
	}

	let started = ms_now();
	while (length(pending)) {
		let still = [];
		for (let p in pending) {
			// Each probe gets what is left of the budget, rounded up to the
			// whole seconds `timeout` takes and never below one. Without this
			// the probe sits outside every clock check and one wedged ubus
			// call overruns the whole bound.
			let left = deadline - ms_now();
			let r = net_has_prefix(p.net, p.prefix,
				(left > 1000) ? int((left + 999) / 1000) : 1);
			// Unanswerable — no ubus, nothing that parses, or a probe that
			// never came back. Waiting cannot turn that into an answer, so
			// stop rather than spend the budget on identical failures, and
			// claim nothing about readiness.
			if (r.has == null)
				return finish_ra(uci, iface, plan, [], ms_now() - started,
					r.wedged ? [ p ] : []);
			// `want` is the direction: a claim waits for our prefix to
			// appear, a release for it to go. Testing only for presence makes
			// every release time out.
			if (r.has != p.want)
				push(still, p);
		}
		pending = still;
		// Against the clock before AND after the sleep.
		//
		// The SECOND check is what bounds the loop: without it there is no
		// deadline test on the path at all and a network that never settles
		// spins forever — a mutation that removes it does not fail the suite,
		// it hangs, and that hang is the proof.
		//
		// The FIRST check is deliberately not redundant, and a mutation run
		// found it survives, so it is worth saying why it stays. It only
		// stops the loop sleeping 250ms it has already run out of time for,
		// which is a quarter second nobody waits at the end of an apply. That
		// is below what any reasonable test can measure against a five-second
		// budget, so it is an equivalent mutant rather than a gap — not dead
		// code to delete on the grounds that nothing caught its removal.
		if (!length(pending) || ms_now() >= deadline)
			break;
		sleep(RA_POLL_MS);
		if (ms_now() >= deadline)
			break;
	}
	return finish_ra(uci, iface, plan, pending, ms_now() - started, []);
}

// Reconcile the ULA addressing this module writes onto the steered networks
// while IPv6 goes through the tunnel. Returns true on change.
//
// Proton hands every client the same fixed /128 (FIXED_ADDRESS6) on every
// gateway and publishes no delegable prefix, so LAN clients can only reach
// IPv6 behind NAT6 — which means they must not hold an ISP GUA at the same
// time, or Happy Eyeballs prefers it and IPv6 leaves through the WAN while the
// tunnel sits unused. `ip6class local` takes the prefix from the router's own
// ULA instead of the delegation and `delegate 0` stops the ISP prefix from
// reaching the network, so the client sees a ULA and nothing else.
//
// The addressing follows the MODE, not the gateway: re-addressing every client
// each time a rotation lands on a gateway without the bit would be churn for
// nothing, and a ULA with the v6 prohibit in force is simply an address that
// goes nowhere.
//
// These are sections the module does not own, so the previous values are
// recorded next to the stamp and put back on teardown — and an option whose
// value is no longer the one we wrote was changed by the user afterwards and
// is left exactly as it is.
// ── Which device a network sits on ───────────────────────────────────
// Everything below that touches a device — the sections claimed for the ULA
// addressing, the eligibility judgement and the neighbour-discovery opening —
// asks this, so it lives here, ahead of the first caller: ucode declares
// functions in order and does not hoist them.

// How many `@` hops to follow before giving up. The walk already terminates on
// its own — it records every interface it has stood on and refuses to enter
// one twice, so a self-reference or a cycle stops at the step that closes it,
// and an acyclic chain is bounded by the number of interface sections. This
// limit is the second, independent bound: it holds whatever the visited set
// does, so no edit to the cycle check can ever turn this walk into a spin. A
// device reached through more than a handful of references is not a
// configuration anyone wrote, so refusing it costs nothing.
const DEV_REF_DEPTH = 8;

// Phrase a failure found at `hop` so it reads after "network <net> ". When the
// failure is on the steered network itself the hop is invisible; further along
// the chain it has to be named, or the user is told about a problem with a
// network they did not configure and cannot see the link to.
function hop_note(hop, net, tail) {
	return (hop == net) ? tail
		: ('reaches its device through network ' + hop + ', which ' + tail);
}

// Follow `net`'s device to the end and report where it lands:
//   { device, nets, why }
// `device` is the L3 device name, or null when the chain cannot be resolved —
// `why` then says what stopped it. `nets` is every interface stood on, the
// steered one first.
//
// netifd accepts a device REFERENCE where a device name goes: `option device
// '@edge'` means "whatever L3 device interface `edge` ends up using", not a
// device literally called `@edge` (netifd device.c hands a leading `@` to
// device_alias_get(), and interface.c points that alias at the referenced
// interface's l3_dev when it comes up). Read literally, the reference named a
// device no other network appeared to share — so an alias pointing through an
// uplink was admitted — and the opening written for it said `iifname "@edge"`,
// which matches no packet: IPv6 was advertised on a network whose neighbour
// discovery could never work. `@` is the only such prefix in netifd; a name
// containing a dot is a VLAN device it creates on demand, and that IS a real
// device name.
//
// The reference may point at another reference, so this is a walk rather than
// a lookup, and the alias table is keyed by INTERFACE name — a `config device`
// section of that name is not one.
//
// `option type 'bridge'` is the pre-DSA spelling: the interface lists its
// MEMBERS in `ifname`, and netifd builds a bridge named after the interface
// over them. Binding to a member would match nothing useful — the members
// carry no address, and on a non-bridge interface two of them are not one
// device to bind to either.
function device_path(uci, net) {
	let nets = [], seen = {}, hop = net;
	for (let depth = 0; depth < DEV_REF_DEPTH; depth++) {
		push(nets, hop);
		seen[hop] = true;
		if (uci.get('network', hop, 'type') == 'bridge')
			return { device: 'br-' + hop, nets: nets };
		let d = uci.get('network', hop, 'device') || uci.get('network', hop, 'ifname');
		if (d == null || d == '')
			return { device: null, nets: nets,
				why: hop_note(hop, net, 'names no device to scope the opening to') };
		let parts = split(trim('' + d), /[ \t]+/);
		if (length(parts) != 1 || parts[0] == '')
			return { device: null, nets: nets,
				why: hop_note(hop, net, 'names no single device to scope the opening to') };
		let tok = parts[0];
		if (substr(tok, 0, 1) != '@')
			return { device: tok, nets: nets };
		let ref = substr(tok, 1);
		if (ref == '' || uci.get('network', ref) != 'interface')
			return { device: null, nets: nets,
				why: hop_note(hop, net, 'is bound to ' + tok +
					', which names no interface') };
		if (seen[ref])
			return { device: null, nets: nets,
				why: hop_note(hop, net, 'is bound to ' + tok +
					', a device reference that leads back round') };
		hop = ref;
	}
	return { device: null, nets: nets,
		why: hop_note(hop, net, 'is behind more than ' + DEV_REF_DEPTH +
			' device references') };
}

// The single L3 device the network sits on — the one an address lives on and
// the one a packet from a client arrives on. Null when the configuration does
// not name one unambiguously, in which case there is nothing to scope the
// opening to and the network is left alone entirely.
function net_device(uci, net) {
	return device_path(uci, net).device;
}

// The `dhcp` section serving a network, found by its `interface` option — it
// is usually named after the network, but it need not be. Null when the
// network has none.
function find_dhcp(uci, net) {
	let found = null;
	uci.foreach('dhcp', 'dhcp', function(sec) {
		if (sec.interface == net) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// The `config device` section of the bridge a network sits on, looked up by
// the device the network RESOLVES to: a `config device` section is named after
// the real device, so a network reaching it through `@edge` — or a pre-DSA
// bridge, whose section is named after the L3 device and not after the members
// in `ifname` — would otherwise find nothing and leave the bridge with the
// `ipv6 0` that stops the kernel accepting an address on it at all.
// Null when the network resolves to no device, or when that device has no
// section of its own — netifd leaves IPv6 enabled by default then, so there is
// nothing to switch on and nothing to say.
function find_device(uci, net) {
	let dev = net_device(uci, net);
	if (dev == null || dev == '')
		return null;
	let found = null;
	uci.foreach('network', 'device', function(sec) {
		if (sec.name == dev) {
			found = sec['.name'];
			return false;
		}
	});
	return found;
}

// Write `opts` onto a section this module does not own, recording whatever was
// there so it can be given back, and stamp it with the owning interface.
// Returns true on change.
function claim_section(uci, config, section, opts, iface) {
	let changed = false;
	let fresh = (uci.get(config, section, V6_MARK) != iface);
	for (let opt in opts) {
		let cur = uci.get(config, section, opt);
		if (fresh && cur != null && cur != '')
			uci.set(config, section, V6_SAVED + opt, cur);
		if (cur != opts[opt]) {
			uci.set(config, section, opt, opts[opt]);
			changed = true;
		}
	}
	if (fresh) {
		uci.set(config, section, V6_MARK, iface);
		changed = true;
	}
	return changed;
}

// Put a claimed section back the way it was found. An option whose value is no
// longer the one we wrote was changed by the user afterwards and is left
// exactly as it is — we only ever undo our own edit.
function release_section(uci, config, section, opts) {
	for (let opt in opts) {
		let saved = uci.get(config, section, V6_SAVED + opt);
		if (uci.get(config, section, opt) == opts[opt]) {
			if (saved != null && saved != '')
				uci.set(config, section, opt, saved);
			else
				uci.delete(config, section, opt);
		}
		if (saved != null)
			uci.delete(config, section, V6_SAVED + opt);
	}
	uci.delete(config, section, V6_MARK);
}

// Reconcile stamped firewall forwardings (into the instance zone) with the
// desired source-zone list. Returns true on change.
function reconcile_forwardings(uci, iface, dest_zone, want_srcs) {
	let changed = false;
	let have = [];
	uci.foreach('firewall', 'forwarding', function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == 'forwarding' && sec.protonvpn_iface == iface)
			push(have, { section: sec['.name'], src: sec.src });
	});
	for (let f in have) {
		if (index(want_srcs, f.src) < 0) {
			uci.delete('firewall', f.section);
			changed = true;
		}
	}
	for (let src in want_srcs) {
		let present = false;
		for (let f in have)
			if (f.src == src)
				present = true;
		if (!present) {
			let sec = uci.add('firewall', 'forwarding');
			uci.set('firewall', sec, 'src', src);
			uci.set('firewall', sec, 'dest', dest_zone);
			uci.set('firewall', sec, MARK, '1');
			uci.set('firewall', sec, ROLE, 'forwarding');
			uci.set('firewall', sec, 'protonvpn_iface', iface);
			changed = true;
		}
	}
	return changed;
}

// The ICMPv6 types a client must be able to send TO the router for IPv6 to
// work on its network at all: router solicitation to ask for the prefix, and
// neighbour solicitation/advertisement so the router can resolve the client
// and actually deliver a packet to it.
//
// This is not theoretical. Measured on a live guest network: the zone's input
// chain allowed DHCP and DNS and then jumped to reject, so the client's
// neighbour advertisement never reached the router, the neighbour entry sat at
// FAILED, and every reply coming back through the tunnel was dropped on the
// last hop — with the tunnel round trip itself complete and conntrack already
// reversing the translation. A guest-style zone rejects what it does not name,
// and nobody names neighbour discovery.
//
// Kept to those three types and to the source zones of the steered networks:
// echo, MLD and everything else stay shut. fw4 evaluates traffic rules before
// the zone's input policy, so this is enough on a zone whose policy is REJECT
// and changes nothing on one that already accepts.
const ICMPV6_ND = [ 'router-solicitation', 'neighbour-solicitation',
	'neighbour-advertisement' ];

// True when `net` is a LAN-side network this instance may open neighbour
// discovery on. Disqualified two independent ways, so neither has to be right
// on its own: it does not run a router-side protocol, or it sits in the WAN
// firewall zone. Neighbour discovery belongs on the networks behind the
// router; an ACCEPT on the uplink zone faces the internet.
// The neighbour-discovery ACCEPT is bound to ONE DEVICE, not to a zone.
//
// It was written on a zone for four rounds, and a zone holds arbitrary
// networks, so admitting a network meant proving that nothing else in its zone
// was an uplink — a proof that was correct each time and complete none of
// them: a second masquerading zone, a default route in its own section, a
// WireGuard peer carrying `route_allowed_ips`. fw4 accepts `option device` on
// a `config rule` and renders it as an `iifname` match (verified on the
// router: `iifname "br-guest" icmpv6 type nd-router-solicit ... accept`,
// surviving reloads, with neighbour discovery still working), so the opening
// now covers exactly the steered network's own interface. What else shares the
// zone cannot reach it, and that entire class of hole is closed by
// construction rather than by a list that keeps needing another entry.
//
// The network itself still has to be judged — binding to a device does not
// help if the device IS the uplink — and that judgement stays positive:
// admitted on recognised evidence, refused otherwise.

// The one protocol that positively says "this router addresses this network
// itself". `none` is deliberately absent: it means the router does NOT
// configure the interface, which is absence of information, and an unmanaged
// uplink whose default route is installed at runtime looks exactly like it.
const LAN_PROTOS = [ 'static' ];

// True when `target` (with an optional separate `netmask`) is a default route.
// Both spellings netifd accepts are covered, and an ambiguous bare 0.0.0.0 or
// :: is read as a default — on this path, uncertainty resolves to "uplink".
function is_default_target(target, netmask) {
	let t = trim('' + (target || ''));
	if (t == '')
		return false;
	if (t == '0.0.0.0/0' || t == '::/0' || t == 'default')
		return true;
	if (t != '0.0.0.0' && t != '::')
		return false;
	let m = trim('' + (netmask || ''));
	return (m == '' || m == '0.0.0.0' || m == '0' || m == '::');
}

// True when the configuration declares a default route through `net`: inline
// on the interface, or in a `config route` / `route6` section naming it. The
// table is not consulted on purpose — a default route is a way out whichever
// table it lives in.
function has_default_route(uci, net) {
	let gw = uci.get('network', net, 'gateway');
	if (gw != null && gw != '')
		return true;
	let found = false;
	for (let t in [ 'route', 'route6' ])
		uci.foreach('network', t, function(sec) {
			if (sec.interface == net && is_default_target(sec.target, sec.netmask)) {
				found = true;
				return false;
			}
		});
	return found;
}

// EVERY firewall zone listing `net`, by section name. A network can be in more
// than one, and stopping at the first let a network that was also in the WAN
// zone pass as LAN-side on the strength of its other membership.
function zones_of(uci, net) {
	let out = [];
	uci.foreach('firewall', 'zone', function(sec) {
		for (let n in as_list(sec.network))
			if (n == net) {
				push(out, sec['.name']);
				return;
			}
	});
	return out;
}

// True when a zone is one this router sends traffic out through: it NATs, or
// it carries a conventional uplink name.
function zone_is_uplink(uci, zsec) {
	if (uci.get('firewall', zsec, 'masq') == '1' ||
	    uci.get('firewall', zsec, 'masq6') == '1')
		return true;
	let name = uci.get('firewall', zsec, 'name');
	return (name == 'wan' || name == 'wan6');
}

// Every logical network bound to `dev`, by section name.
function networks_on_device(uci, dev) {
	let out = [];
	uci.foreach('network', 'interface', function(sec) {
		if (net_device(uci, sec['.name']) == dev)
			push(out, sec['.name']);
	});
	return out;
}

// Why traffic could leave the router through this network, or null when it
// could not: it speaks a protocol that dials out, it declares a default route,
// or it sits in a zone this router NATs through. A phrase rather than a flag,
// so the user is told which of the three applied instead of a bare verdict.
function way_out_reason(uci, net) {
	let proto = uci.get('network', net, 'proto');
	if (proto == null || proto == '')
		return 'names no protocol, so there is nothing to tell from';
	if (index(LAN_PROTOS, '' + proto) < 0)
		return 'uses proto ' + proto + ', which is one a router goes out through';
	if (has_default_route(uci, net))
		return 'declares a default route of its own';
	for (let z in zones_of(uci, net))
		if (zone_is_uplink(uci, z))
			return 'is in ' + uci.get('firewall', z, 'name') + ', an uplink zone';
	return null;
}

function net_is_way_out(uci, net) {
	return way_out_reason(uci, net) != null;
}

// Why anything on this device is a way out, or null when nothing is.
//
// Scoping the opening to a device rather than a zone closed the question of
// what else is in the zone, but not of what else is on the device: a second
// logical network — an alias, a second subnet — can be bound to the same
// bridge and carry a gateway of its own, and a rule matching the device covers
// that network too. So the question is asked of the device, not of the one
// network being steered.
function device_way_out_reason(uci, dev) {
	let nets = networks_on_device(uci, dev);
	if (!length(nets))
		return 'is on device ' + dev + ', which no network declares';
	for (let n in nets) {
		let why = way_out_reason(uci, n);
		if (why != null)
			return 'shares device ' + dev + ' with network ' + n + ', which ' + why;
	}
	return null;
}

function device_is_lan_side(uci, dev) {
	return device_way_out_reason(uci, dev) == null;
}

// Why this instance may NOT give `net` IPv6, or null when it may: the network
// must not itself be a way out, must be in a firewall zone (one is needed to
// select the chain), must resolve to a single L3 device, and nothing else on
// that device may be a way out either.
function v6_decline_reason(uci, net) {
	let why = way_out_reason(uci, net);
	if (why != null)
		return why;
	if (!length(zones_of(uci, net)))
		return 'is in no firewall zone';
	let path = device_path(uci, net);
	// Every interface the chain stood on, judged as well: a reference must not
	// launder the uplink it points through. They all resolve to the same
	// device — a walk started half way along is a suffix of this one — so the
	// device check below would refuse them anyway; asking here names the hop
	// that is the way out and the reason it is one, which the co-tenant
	// wording cannot, and it still answers for a chain that then failed to
	// resolve, where there is no device left to ask about at all.
	//
	// It also settles whether the resolved NAME is the one netifd will use. A
	// reference resolves at runtime to the referenced interface's l3_dev,
	// which for a dialled protocol is a device invented then (`pppoe-wan`, not
	// the `dsl0` written in the config) — but every such hop is refused right
	// here, so the only chains that survive are ones whose every interface is
	// `proto static`, where the l3_dev is exactly the device the configuration
	// names. Only then is that name written into a rule.
	for (let hop in path.nets) {
		// `net` is the first of them and was cleared above.
		if (hop == net)
			continue;
		let hwhy = way_out_reason(uci, hop);
		if (hwhy != null)
			return 'reaches its device through network ' + hop + ', which ' + hwhy;
	}
	if (path.device == null)
		return path.why;
	// `net` itself is on this device and has already been cleared, so it
	// cannot be the one reported.
	return device_way_out_reason(uci, path.device);
}

function is_lan_side(uci, net) {
	return v6_decline_reason(uci, net) == null;
}

// Reconcile the stamped neighbour-discovery rules with the desired source-zone
// list. Returns true on change.
// `want` is a list of { src, device }: one rule per steered network, bound to
// that network's own interface.
function reconcile_icmpv6(uci, iface, want) {
	let changed = false;
	let have = [];
	uci.foreach('firewall', 'rule', function(sec) {
		if (sec[MARK] == '1' && sec[ROLE] == 'icmpv6_nd' && sec.protonvpn_iface == iface)
			push(have, { section: sec['.name'], src: sec.src, device: sec.device });
	});
	for (let r in have) {
		let keep = false;
		for (let w in want)
			if (w.src == r.src && w.device == r.device)
				keep = true;
		if (!keep) {
			uci.delete('firewall', r.section);
			changed = true;
		}
	}
	for (let w in want) {
		let present = false;
		for (let r in have)
			if (r.src == w.src && r.device == w.device)
				present = true;
		if (present)
			continue;
		let sec = uci.add('firewall', 'rule');
		uci.set('firewall', sec, 'name', 'ProtonVPN IPv6 neighbour discovery');
		uci.set('firewall', sec, 'src', w.src);
		uci.set('firewall', sec, 'device', w.device);
		uci.set('firewall', sec, 'proto', 'icmp');
		uci.set('firewall', sec, 'family', 'ipv6');
		uci.set('firewall', sec, 'icmp_type', ICMPV6_ND);
		uci.set('firewall', sec, 'target', 'ACCEPT');
		uci.set('firewall', sec, MARK, '1');
		uci.set('firewall', sec, ROLE, 'icmpv6_nd');
		uci.set('firewall', sec, 'protonvpn_iface', iface);
		changed = true;
	}
	return changed;
}

// ── Detection (read-only) ────────────────────────────────────────────

// Classify the routing situation (read-only). `runtime` enables external-
// command checks. Modes: 'manual'  — unstamped user routes/rules reference
//                    the interface or its table, or a table is set without
//                    steering: never touch;
//        'auto'    — route everything (auto_routing);
//        'steered' — route the configured source networks via the instance
//                    table;
//        'none'    — tunnel only, no managed routing.
function detect(uci, s, runtime) {
	let iface = s.interface;
	let zone = find_zone_of(uci, iface);
	let peer = find_peer(uci, iface);
	let steering = length(s.source_networks || []) > 0;
	// With steering active, extra user routes INSIDE the instance's table are
	// legitimate companions (e.g. a media→LAN route); only routes referencing
	// the interface itself signal a hand-built scheme. Without steering, a
	// table reference is the manual-mode signal it always was.
	let user_routes = count_user_routes(uci, iface, steering ? '' : s.routing_table);
	// A bare routing_table is NOT manual on its own — only actual user routes or
	// rules (referencing the interface, or living in the instance's table when
	// not steering) are. A hand-built policy scheme always has such routes, so
	// this still detects it; but merely naming a table no longer collapses the
	// panel into the hands-off view, so the table can be used for steered mode.
	let manual = user_routes > 0;

	let wanmtu = runtime ? wan_l3_mtu(uci) : null;
	return {
		mode: manual ? 'manual' : (s.auto_routing ? 'auto' : (steering ? 'steered' : 'none')),
		zone: zone ? zone.name : null,
		zone_managed: zone ? zone.managed : false,
		user_routes: user_routes,
		source_networks: s.source_networks || [],
		route_allowed_ips: peer ? (uci.get('network', peer, 'route_allowed_ips') == '1') : false,
		killswitch: find_managed(uci, 'rule', 'killswitch') != null ||
			length(find_managed_rules(uci, 'rule', 'steer_ks', iface)) > 0,
		ipv6_block: find_managed(uci, 'rule', 'ipv6block') != null ||
			length(find_managed_rules(uci, 'rule6', 'steer_v6', iface)) > 0,
		ipv6_mode: s.ipv6_mode || 'block',
		// Whether the gateway on the interface right now forwards IPv6, and
		// whether the lookup rule that uses it is actually installed.
		ipv6_gateway: iface_ipv6_capable(uci, iface),
		ipv6_tunnel: length(find_managed_rules(uci, 'rule6', 'steer_v6_lookup', iface)) > 0,
		wan_zone: find_wan_zone(uci),
		lan_zone: find_lan_zone(uci),
		networks: available_networks(uci),
		ipv6_wan: runtime ? wan_has_ipv6() : null,
		wan_mtu: wanmtu,
		recommended_mtu: recommend_mtu(wanmtu)
	};
}

// ── Enforcement ──────────────────────────────────────────────────────

// Missing `enabled` (test fixtures) counts as on, like enforce().
function is_active(s) {
	return (s.enabled == null) ? true : !!s.enabled;
}

// True when the instance is SET UP for steering: the detected mode is
// 'steered' and it has the routing table steering needs. Says nothing about
// the instance being switched on, which is why nothing that WRITES an object
// may key off it on its own: an artifact created on this condition outlives
// an explicit Disable, and the v6 prohibit doing exactly that is what broke a
// LAN's IPv6 (see reconcile_ipv6_rules). It survives only to tell a user who
// selected steered mode without a routing table why nothing happened.
function steering_configured(s, mode) {
	return (mode == 'steered') &&
		(s.routing_table != null && s.routing_table != '');
}

// True when this instance is steering right now: set up for it and on.
function is_steering(uci, s, mode) {
	return steering_configured(s, mode) && is_active(s);
}

// Whether instance `s` gives IPv6 to its steered networks at all: it is on and
// steering as configured, the user asked for auto, and there really is a
// WireGuard interface for the clients to reach — all of this serves clients
// reaching that tunnel, and with no tunnel there is nothing to reach. `mode`
// is the DETECTED mode, not just the options: an instance with auto_routing
// on, or one whose routing the user has taken over by hand, steers nothing
// however its source_network list reads.
//
// The tunnel is judged by its `proto`, which is what makes the section a
// WireGuard interface and is written by both places that create one. Asking
// instead whether a section of that name EXISTS answered a different
// question, and answered it with a trace of our own previous run: step 1
// stamps the interface with the routing mark, and where that stamp brings a
// bare section into being the next reconcile reads it back as proof of a
// tunnel and configures a ULA, a router advertisement and an opening for an
// interface that is not there. A self-confirming condition cannot be placed
// safely — round 11 moved the sampling before the stamp and round 15's
// reordering reintroduced it from the other side — so it is not a question of
// when to ask any more. The same weakness also admitted a leftover static
// interface, or a `config device`, that happened to carry the name.
//
// The other places that ask about a section by presence alone — the `d.net`
// guard and the claim loop below, both meaning "this steered network is still
// a network" — cannot be fooled the same way: everything they go on to read
// is an OPTION, and way_out_reason refuses a section with no `proto` before
// any of it is used. Tightening them to the section type changes no reachable
// outcome, which is the only reason they are left as they are.
function v6_configures(uci, s, mode) {
	return s.ipv6_mode == 'auto' && is_steering(uci, s, mode) &&
		uci.get('network', s.interface, 'proto') == 'wireguard';
}

// ...and whether it would configure IPv6 on THIS network: the same test, plus
// the network being one of its own and being eligible for the opening.
//
// This is the only place those conditions live. enforce() builds the list of
// networks to configure from it and the successor search below asks it of a
// candidate heir, so an heir passes exactly the test an owner passed. It used
// to pass a weaker one — on, auto, steering — and nothing about eligibility,
// so a network that had just become ineligible was not given back but handed
// to a peer that would have refused to configure it itself, with the stamp
// claiming that peer was looking after it. The addressing and the
// announcement stayed up on a network whose opening had gone: the
// half-configured state the decide-before-writing order exists to prevent,
// re-entering through inheritance. Two copies of these conditions is how that
// happened, so there is one.
function v6_wants_net(uci, s, net, mode) {
	return v6_configures(uci, s, mode) &&
		index(s.source_networks || [], net) >= 0 &&
		v6_decline_reason(uci, net) == null;
}

// The interface of another instance that would configure `net` itself — or
// null. Nothing stops two instances from listing the same source network and
// the stamp records a single owner, so releasing ours has to check whether
// anyone else is still standing on it, and whether it still may.
function v6_lan_successor(uci, net, iface) {
	let found = null;
	for (let n in _common.list_instances(uci)) {
		let o = _common.load_settings(uci, n);
		if (o.interface == iface)
			continue;
		if (v6_wants_net(uci, o, net, detect(uci, o, false).mode)) {
			found = o.interface;
			break;
		}
	}
	return found;
}

function reconcile_v6_lan(uci, iface, want_nets, notes) {
	let cn = false, cd = false;
	// Networks whose ANNOUNCEMENT changed on this run, so their clients can be
	// told now instead of at the next scheduled advertisement (see
	// ra_refresh). Keyed on the dhcp section rather than on the network's
	// addressing, deliberately: odhcpd is what gets nudged, so a network with
	// no dhcp section to announce through is a nudge for nobody, and every
	// network that does announce has that section claimed or released in the
	// same run as its prefix.
	//
	// A hand-over to another instance is NOT one of these: the addressing and
	// the announcement both stay exactly as they are, only the record of who
	// owns them moves, and re-advertising would be noise.
	let touched = [], seen = {};
	let touch = function(net) {
		if (net == null || seen[net])
			return;
		seen[net] = true;
		push(touched, net);
	};

	// Sections this instance currently holds, in both config files.
	let have = [];
	uci.foreach('network', 'interface', function(sec) {
		if (sec[V6_MARK] == iface)
			push(have, sec['.name']);
	});
	let have_dhcp = [];
	uci.foreach('dhcp', 'dhcp', function(sec) {
		if (sec[V6_MARK] == iface)
			push(have_dhcp, { section: sec['.name'], net: sec.interface });
	});
	let have_dev = [];
	uci.foreach('network', 'device', function(sec) {
		if (sec[V6_MARK] == iface)
			push(have_dev, { section: sec['.name'], name: sec.name });
	});

	// Someone else still steering a network keeps its addressing: hand the
	// record over rather than restore it, or disabling one instance would
	// re-address the clients of another that is very much still running. The
	// saved values travel with the stamp, so the survivor gives back the
	// user's original configuration when it lets go.
	for (let net in have) {
		if (index(want_nets, net) >= 0)
			continue;
		let heir = v6_lan_successor(uci, net, iface);
		if (heir)
			uci.set('network', net, V6_MARK, heir);
		else
			release_section(uci, 'network', net, v6_lan_opts(net));
		cn = true;
	}
	for (let d in have_dhcp) {
		// Held only while this instance still steers that network AND the
		// network section it serves still exists: the prefix is allocated
		// there, so an announcement outliving it promises an address nothing
		// can hand out, and the stamp left behind would mean nobody ever gives
		// the user's own settings back. A section that can no longer be
		// addressed is released outright rather than handed on — no instance
		// could do anything with it either.
		let addressable = (d.net != null) && (uci.get('network', d.net) != null);
		if (addressable && index(want_nets, d.net) >= 0)
			continue;
		let heir = addressable ? v6_lan_successor(uci, d.net, iface) : null;
		if (heir) {
			uci.set('dhcp', d.section, V6_MARK, heir);
		} else {
			release_section(uci, 'dhcp', d.section, V6_DHCP_OPTS);
			touch(d.net);
		}
		cd = true;
	}

	// Same rule for the device section, asked of EVERY network on the device.
	// This is the one section here not keyed by a network — a `config device`
	// records none of its own — so it had to be matched back by asking which
	// network sat on the device, and that was answered with the first one
	// found. A bridge carries as many logical networks as the user puts on it
	// and no instance steers most of them, so the first was routinely the
	// wrong one to ask about: the hand-over looked for an instance still
	// steering a network nobody steers, found none, and gave the bridge back
	// under the clients of an instance that was still running. Turning one
	// instance off stopped IPv6 on another the user never touched.
	//
	// Both questions are therefore asked of the whole list: the section stays
	// while ANY network on it is one this instance still steers, and goes to
	// the first co-tenant that has a successor rather than to the first
	// co-tenant there is. An empty list is a device no network declares any
	// more — nothing to hand on, so it is released.
	for (let dv in have_dev) {
		let nets = (dv.name != null) ? networks_on_device(uci, dv.name) : [];
		let mine = false;
		for (let n in nets)
			if (index(want_nets, n) >= 0)
				mine = true;
		if (mine)
			continue;
		let heir = null;
		for (let n in nets) {
			heir = v6_lan_successor(uci, n, iface);
			if (heir != null)
				break;
		}
		if (heir)
			uci.set('network', dv.section, V6_MARK, heir);
		else
			release_section(uci, 'network', dv.section, V6_DEV_OPTS);
		cn = true;
	}

	for (let net in want_nets) {
		if (uci.get('network', net) == null)
			continue;                 // a steered network that no longer exists
		// Another instance got here first: the addressing it wrote is the same
		// as ours, so leave its record alone rather than overwrite the values
		// it has to give back.
		let owner = uci.get('network', net, V6_MARK);
		if (owner == null || owner == iface)
			if (claim_section(uci, 'network', net, v6_lan_opts(net), iface))
				cn = true;

		// Let the kernel accept an address on the bridge in the first place.
		// Judged on its own stamp for the same reason as the dhcp section
		// below; absent, there is nothing to do.
		let dv = find_device(uci, net);
		if (dv != null) {
			let vowner = uci.get('network', dv, V6_MARK);
			if (vowner == null || vowner == iface)
				if (claim_section(uci, 'network', dv, V6_DEV_OPTS, iface))
					cn = true;
		}

		// The announcement that turns that prefix into an address on a client.
		// Judged on its OWN stamp, deliberately not on the network section's:
		// the two are separate objects the user can add and remove separately,
		// so a dhcp section created after the other instance sharing this
		// network last ran would otherwise never be claimed by anyone.
		let d = find_dhcp(uci, net);
		if (d == null) {
			// Nothing to announce through, and fabricating a dhcp section is
			// not an option: one governs IPv4 as well, so inventing it could
			// start handing out v4 leases on a network the user deliberately
			// left without a server. Say so instead of doing nothing quietly.
			push(notes, 'network ' + net + ' has no dhcp section; IPv6 cannot be ' +
				'announced to its clients');
			continue;
		}
		let downer = uci.get('dhcp', d, V6_MARK);
		if (downer != null && downer != iface)
			continue;
		if (claim_section(uci, 'dhcp', d, V6_DHCP_OPTS, iface)) {
			cd = true;
			touch(net);
		}
	}

	// ip6class 'local' draws the prefix from the router's own ULA. Without one
	// there is nothing to allocate, so the clients get no address however the
	// announcement is configured — the silent no-op this whole path exists to
	// avoid.
	if (length(want_nets) &&
	    (uci.get('network', 'globals', 'ula_prefix') || '') == '')
		push(notes, 'the router has no ULA prefix (network.globals.ula_prefix); ' +
			'steered clients cannot be given an IPv6 address');

	let plan = [];
	for (let net in touched)
		push(plan, { net: net, want: index(want_nets, net) >= 0 });
	return { network: cn, dhcp: cd, ra: plan };
}

// Redo ONLY the IPv6 rule decision for one instance, against whatever gateway
// sits on the interface right now. Rotation writes the peer itself and never
// runs the full enforcement, so without this a rotation from a bit-16 gateway
// onto one without the bit would leave the lookup rule pointing into a table
// whose ::/0 route goes nowhere — a black hole for every steered client, and
// the other way round IPv6 would stay blocked on a gateway that does forward
// it. Never commits: the caller owns the transaction.
function reconcile_ipv6(uci, s) {
	let mode = detect(uci, s, false).mode;
	return reconcile_ipv6_rules(uci, s, s.interface,
		is_steering(uci, s, mode), s.routing_table, s.source_networks);
}

// Whether IPv6 currently goes through the tunnel for this instance and, when
// it does not, why — for the status card, which has to be able to say "the
// gateway has no IPv6" rather than leave the user guessing. `mode` is the
// detected routing mode; pass null to have it detected here. `connected` is
// the runtime view: the rules can be installed and perfectly correct while the
// tunnel is down, and nothing is going through it then, so a caller that knows
// passes false and the card stops claiming otherwise. Callers with no runtime
// view (enforce, rotation) leave it out and get the configuration's answer.
function ipv6_state(uci, s, mode, connected) {
	let m = (mode != null) ? mode : detect(uci, s, false).mode;
	let capable = iface_ipv6_capable(uci, s.interface);
	let out = { mode: s.ipv6_mode || 'block', gateway_ipv6: capable,
		active: false, reason: null,
		// What the instance asked for, and whether that ask currently binds
		// server selection. They differ under secure_core/tor or a non-'auto'
		// mode, where the option is kept but cannot apply — reporting only one
		// of the two would either hide the setting or overstate it.
		require_ipv6: (s.require_ipv6 ? true : false),
		require_ipv6_active: _common.require_ipv6_active(s),
		// Which of the ways the requirement can go unmet this was, so the page
		// can word it for what actually happened instead of guessing. Only
		// meaningful with the reason below; null when nothing was recorded.
		required_cause: null,
		// True for a few minutes after this module asked odhcpd for a fresh
		// advertisement, and only while IPv6 really is on the tunnel. The page
		// says the clients are moving over exactly while that is the case: the
		// whole reported defect was a page claiming IPv6 was active while four
		// of five clients were still on their old address, and a permanent
		// line saying so would be furniture on a card that was cut from 748px
		// to 248 for good reason.
		clients_settling: false };
	if (out.mode == 'off')
		out.reason = 'mode_off';
	else if (out.mode == 'block')
		out.reason = 'mode_block';
	else if (s.enabled != null && !s.enabled)
		out.reason = 'disabled';
	else if (m == 'auto')
		out.reason = 'auto_routing';
	else if (!is_steering(uci, s, m))
		out.reason = 'not_steered';
	else if (!capable)
		// Under an active requirement the backend never connects to a gateway
		// without the bit, so "this gateway does not forward IPv6" cannot be
		// the explanation — it would describe a server that is not there. The
		// true one is that no eligible gateway was reachable and the tunnel
		// was taken down for it. The click path says this in the apply error;
		// this is what a page RELOAD has to say, which is the only thing the
		// user sees if they come back later.
		if (_common.require_ipv6_active(s)) {
			out.reason = 'ipv6_required_unavailable';
			out.required_cause = _common.iface_ipv6_unmet(uci, s.interface);
		} else {
			out.reason = 'gateway_no_ipv6';
		}
	else if (connected === false)
		out.reason = 'tunnel_down';
	else
		out.active = true;
	if (out.active) {
		let at = int(uci.get('network', s.interface, 'protonvpn_v6_ra_at') || '0');
		out.clients_settling = (at > 0) && ((time() - at) < RA_SETTLE_WINDOW);
	}
	return out;
}

// Reconcile all stamped objects with the settings (peer route_allowed_ips,
// steering/prohibit rules, local bypass routes, per-instance firewall zone,
// forwardings, kill-switch rule, IPv6 leak-block rule, IPv6 client addressing
// and its router advertisement, DNS override). Creates objects only in
// automatic mode; removes ONLY stamped objects when their toggle (or automatic
// mode itself) is off. Never commits — the caller owns the transaction.
// Returns { changed_network, changed_firewall, changed_dhcp, notes }.
function enforce(uci, s) {
	let notes = [];
	let cn = false, cf = false, cd = false;
	let iface = s.interface;
	let det = detect(uci, s, false);
	// A disabled instance releases EVERY managed object it put on the steered
	// networks: an explicit Disable means "give me normal networking back",
	// and the next apply recreates them. That includes the IPv6 prohibit,
	// because it includes the IPv6 addressing — the two are one decision, and
	// letting them follow different triggers is what left a LAN refusing its
	// own IPv6 after a Disable (see reconcile_ipv6_rules).
	let active = is_active(s);
	let auto = (det.mode == 'auto') && active;
	// Steering right now: set up for it and switched on. Everything written
	// below keys off this one flag; `steer_ready` only picks the note.
	let steer_ready = steering_configured(s, det.mode);
	let steer = steer_ready && active;
	if ((det.mode == 'steered') && active && !steer_ready)
		push(notes, 'steering needs a routing table; set one for this instance');
	let managed = auto || steer;
	let peer = find_peer(uci, iface);

	// 0. Which of the steered networks may be given IPv6 at all. Decided here,
	//    before anything is written, because the addressing, the announcement
	//    and the neighbour-discovery opening are one thing: a client that is
	//    handed a ULA and told this router is its default gateway, on a network
	//    whose neighbour discovery was then declined, has an address it cannot
	//    use and no way to tell. Configuring first and declining afterwards
	//    produced exactly that. The list feeds both reconcilers, so the three
	//    move together or not at all.
	//
	//    It is also why this comes before step 1 rather than after: v6_wants_net
	//    asks whether the tunnel's own interface section exists, and step 1
	//    stamps that section, creating it as a side effect — asked afterwards
	//    the answer would always be yes.
	let v6_nets = [], nd_want = [];
	for (let net in (s.source_networks || [])) {
		if (!v6_wants_net(uci, s, net, det.mode)) {
			// Only the network's own reason is worth reporting. The rest of
			// the test is the user's own settings for this instance, which
			// they can already see; a `block`-mode instance saying why each of
			// its networks would have been declined is noise.
			let why = v6_configures(uci, s, det.mode) ? v6_decline_reason(uci, net) : null;
			if (why != null)
				push(notes, 'network ' + net + ' ' + why + '; IPv6 was not ' +
					'configured on it');
			continue;
		}
		push(v6_nets, net);
		// Any of its zones will do to select the chain — the device match is
		// what scopes the rule.
		let src = uci.get('firewall', zones_of(uci, net)[0], 'name');
		let dev = net_device(uci, net);
		let present = false;
		for (let w in nd_want)
			if (w.src == src && w.device == dev)
				present = true;
		if (!present)
			push(nd_want, { src: src, device: dev });
	}

	// 1. Routes via the tunnel (netifd routes for allowed_ips; they land in the
	//    instance's ip4table when a routing table is set). Stamped on the
	//    interface so a user-set route_allowed_ips is never removed.
	if (managed) {
		// Stamp the interface even before the first peer exists — write_relay
		// propagates the stamp to route_allowed_ips when it creates the peer.
		if (uci.get('network', iface, MARK + '_routing') != '1') {
			uci.set('network', iface, MARK + '_routing', '1');
			cn = true;
		}
		if (peer && uci.get('network', peer, 'route_allowed_ips') != '1') {
			uci.set('network', peer, 'route_allowed_ips', '1');
			cn = true;
		}
	} else if (uci.get('network', iface, MARK + '_routing') == '1') {
		if (peer)
			uci.delete('network', peer, 'route_allowed_ips');
		uci.delete('network', iface, MARK + '_routing');
		cn = true;
		if (det.mode == 'manual')
			push(notes, 'manual routing detected; automatic default route removed');
	}

	// 1b. Steering rules: per source network, a lookup rule into the instance
	//     table, plus prohibit rules that act as kill switch (IPv4, only with
	//     the option) and IPv6 stop (unless ipv6_mode is 'off'). Prohibit
	//     sits between the lookup and the main table, so it only fires when
	//     the tunnel's table cannot serve the traffic.
	//
	//     IPv6 is not symmetric with IPv4 by default: whether it may be routed
	//     at all depends on the gateway, so the lookup half is decided per
	//     gateway in reconcile_ipv6_rules — which is also the only piece
	//     rotation and apply have to redo when they move the peer. Both halves
	//     are given the live steering flag, the same one the v6 addressing
	//     follows, so a Disable releases the guard and the addressing together
	//     or not at all.
	let steer_nets = steer ? s.source_networks : [];
	let table = s.routing_table;
	if (steer) {
		if (!ensure_rt_table(table))
			push(notes, 'could not register routing table ' + table + ' in ' + RT_TABLES);
	} else {
		drop_rt_table(s.routing_table);
	}
	if (reconcile_rules(uci, 'rule', 'steer_lookup', iface, steer_nets, function(net) {
		return { 'in': net, lookup: table, priority: '20000' };
	}))
		cn = true;
	if (reconcile_rules(uci, 'rule', 'steer_ks', iface, (steer && s.killswitch) ? steer_nets : [], function(net) {
		return { 'in': net, action: 'prohibit', priority: '21000' };
	}))
		cn = true;
	if (reconcile_ipv6_rules(uci, s, iface, steer, table, s.source_networks))
		cn = true;
	// The ULA addressing on the eligible networks, and the router advertisement
	// that carries it to the clients.
	let v6lan = reconcile_v6_lan(uci, iface, v6_nets, notes);
	if (v6lan.network)
		cn = true;
	if (v6lan.dhcp)
		cd = true;
	let v6ra = v6lan.ra;

	// 1c. Bypass routes for local subnets, so the steered default does not
	//     swallow LAN↔VLAN or LAN↔local-tunnel traffic. The protonvpn
	//     instances' own interfaces are excluded (they share the fixed
	//     ProtonVPN range).
	let locals = [];
	if (steer) {
		let skip = {};
		for (let n in _common.list_instances(uci))
			skip[_common.load_settings(uci, n).interface] = true;
		locals = local_subnets(uci, skip);
	}
	if (reconcile_local_routes(uci, iface, table || '', locals))
		cn = true;

	// 2. Firewall zone (named after the interface, one per instance) and
	//    forwardings into it from the source zones: the LAN zone in auto mode,
	//    the zones holding the steered networks in steered mode. Sources
	//    already covered by an unstamped user forwarding are skipped.
	if (managed) {
		if (!det.zone) {
			let clash = false;
			uci.foreach('firewall', 'zone', function(sec) {
				if (sec.name == iface) {
					clash = true;
					return false;
				}
			});
			if (clash) {
				push(notes, 'a firewall zone named ' + iface + ' already exists; add the interface to a zone manually');
			} else {
				let z = uci.add('firewall', 'zone');
				uci.set('firewall', z, 'name', iface);
				uci.set('firewall', z, 'input', 'REJECT');
				uci.set('firewall', z, 'output', 'ACCEPT');
				uci.set('firewall', z, 'forward', 'REJECT');
				uci.set('firewall', z, 'masq', '1');
				uci.set('firewall', z, 'mtu_fix', '1');
				uci.set('firewall', z, 'network', [ iface ]);
				uci.set('firewall', z, MARK, '1');
				uci.set('firewall', z, ROLE, 'zone');
				uci.set('firewall', z, 'protonvpn_iface', iface);
				cf = true;
				det.zone = iface;
			}
		}
		// NAT6 on our own zone, for the ULA the steered networks get under
		// ipv6_mode=auto: the tunnel's address is a fixed /128 shared by every
		// Proton client, so masquerading is the only way a LAN client can use
		// it. Set unconditionally — it is inert while nothing routes IPv6 into
		// the zone, and doing it here rather than at creation also repairs a
		// zone stamped by a version that predates it.
		let ourzone = find_managed(uci, 'zone', 'zone', iface);
		if (ourzone && uci.get('firewall', ourzone, 'masq6') != '1') {
			uci.set('firewall', ourzone, 'masq6', '1');
			cf = true;
		}
		if (det.zone) {
			let want_srcs = [];
			if (auto) {
				if (det.lan_zone)
					push(want_srcs, det.lan_zone);
				else
					push(notes, 'could not determine the LAN zone; add a forwarding to the VPN zone manually');
			} else {
				for (let net in steer_nets) {
					let z = find_zone_of(uci, net);
					if (!z)
						push(notes, 'network ' + net + ' is in no firewall zone; add a forwarding to the VPN zone manually');
					else if (index(want_srcs, z.name) < 0)
						push(want_srcs, z.name);
				}
			}
			let filtered = [];
			for (let src in want_srcs) {
				let covered = false;
				uci.foreach('firewall', 'forwarding', function(sec) {
					if (sec[MARK] != '1' && sec.dest == det.zone && sec.src == src) {
						covered = true;
						return false;
					}
				});
				if (!covered)
					push(filtered, src);
			}
			if (reconcile_forwardings(uci, iface, det.zone, filtered))
				cf = true;
		}
	} else {
		if (reconcile_forwardings(uci, iface, det.zone || '', []))
			cf = true;
		let z = find_managed(uci, 'zone', 'zone', iface);
		if (z) {
			uci.delete('firewall', z);
			cf = true;
		}
	}

	// 2b. Neighbour discovery for the steered networks, without which a client
	//     on them cannot be reached at all (see ICMPV6_ND).
	//
	//     Deliberately outside the managed-zone branch above, and not filtered
	//     against user rules. Releasing an ACCEPT must never depend on the
	//     rest of the managed routing still being in one piece: an instance
	//     whose interface had been taken out of its zone used to skip the
	//     whole branch, so switching the mode to 'block' left the opening
	//     installed while the user believed IPv6 was shut. Same reasoning as
	//     the v6 prohibit, which also does not key off `managed`.
	//
	//     `nd_want` was decided in step 0 alongside the addressing, so that a
	//     network cannot end up with one and not the other.
	if (reconcile_icmpv6(uci, iface, nd_want))
		cf = true;

	// 3. Kill switch: our own REJECT rule LAN->WAN. fw4 evaluates traffic rules
	//    before zone forwardings, so the user's forwardings stay untouched.
	let want_ks = auto && s.killswitch;
	let ks = find_managed(uci, 'rule', 'killswitch');
	if (want_ks && !ks) {
		if (det.lan_zone && det.wan_zone) {
			let r = uci.add('firewall', 'rule');
			uci.set('firewall', r, 'name', 'ProtonVPN kill switch');
			uci.set('firewall', r, 'src', det.lan_zone);
			uci.set('firewall', r, 'dest', det.wan_zone);
			uci.set('firewall', r, 'proto', 'all');
			uci.set('firewall', r, 'target', 'REJECT');
			uci.set('firewall', r, MARK, '1');
			uci.set('firewall', r, ROLE, 'killswitch');
			cf = true;
		} else {
			push(notes, 'could not determine the LAN/WAN zones; kill switch not installed');
		}
	} else if (!want_ks && ks) {
		uci.delete('firewall', ks);
		cf = true;
	}

	// 4. IPv6 leak block: same shape, family ipv6 only. Routing everything
	//    through the tunnel leaves no per-network rule to hang an adaptive
	//    lookup on, so 'auto' is treated as 'block' here — only 'off' takes
	//    the rule away.
	let want_v6 = auto && (s.ipv6_mode || 'block') != 'off';
	let v6 = find_managed(uci, 'rule', 'ipv6block');
	if (want_v6 && !v6) {
		if (det.lan_zone && det.wan_zone) {
			let r = uci.add('firewall', 'rule');
			uci.set('firewall', r, 'name', 'ProtonVPN IPv6 leak block');
			uci.set('firewall', r, 'family', 'ipv6');
			uci.set('firewall', r, 'src', det.lan_zone);
			uci.set('firewall', r, 'dest', det.wan_zone);
			uci.set('firewall', r, 'proto', 'all');
			uci.set('firewall', r, 'target', 'REJECT');
			uci.set('firewall', r, MARK, '1');
			uci.set('firewall', r, ROLE, 'ipv6block');
			cf = true;
		} else {
			push(notes, 'could not determine the LAN/WAN zones; IPv6 block not installed');
		}
	} else if (!want_v6 && v6) {
		uci.delete('firewall', v6);
		cf = true;
	}

	// 5. DNS override on the interface (stamped, netifd-managed lifecycle). The
	// stamp records the mode, so changing resolvers re-applies instead of
	// being skipped as "already set".
	let mode = (managed && s.vpn_dns && s.vpn_dns != 'off') ? s.vpn_dns : null;
	let stamped = uci.get('network', iface, MARK + '_dns');
	if (mode && VPN_DNS[mode]) {
		if (stamped != mode) {
			uci.set('network', iface, 'dns', split(VPN_DNS[mode], ' '));
			uci.set('network', iface, MARK + '_dns', mode);
			cn = true;
		}
	} else if (stamped != null && stamped != '') {
		uci.delete('network', iface, 'dns');
		uci.delete('network', iface, MARK + '_dns');
		cn = true;
	}

	return { changed_network: cn, changed_firewall: cf, changed_dhcp: cd,
		// Which networks' clients have to be moved, and in which direction.
		// The caller runs it after the reloads, because the advertisement has
		// to describe addressing netifd has already put in place.
		v6_ra: v6ra, notes: notes };
}

return { detect, enforce, reconcile_ipv6, ipv6_state, v6_hint, ra_refresh,
	ra_budget_ms,
	is_lan_side, v6_decline_reason, net_is_way_out, way_out_reason,
	device_is_lan_side, device_way_out_reason, networks_on_device,
	has_default_route, zones_of, zone_is_uplink, net_device, device_path,
	find_wan_zone, find_lan_zone, count_user_routes, recommend_mtu,
	ensure_rt_table, drop_rt_table };

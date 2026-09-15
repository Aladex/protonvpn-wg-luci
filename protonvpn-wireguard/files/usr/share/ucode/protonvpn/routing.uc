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
const run = _common.run,
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
// dhcpv6 is deliberately left alone: SLAAC supplies the address and the RA
// supplies the route, so stateful assignment adds nothing, and turning on a
// service the user disabled is not ours to do.
const V6_DHCP_OPTS = { ra: 'server', ra_slaac: '1', ra_default: '1' };
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

	let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
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
			let rt = run([ 'ip', '-4', 'route', 'show', 'table', 'main', 'proto', proto ]);
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
	if (name == null || name == '' || match(name, /^[0-9]+$/))
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
	let r = run([ 'ip', '-6', 'route', 'show', 'default' ]);
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
	let d = run([ 'ubus', 'call', 'network.interface', 'dump' ]);
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
		let l = run([ 'ip', 'link', 'show', 'dev', ifc.l3_device ]);
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
//     rule6 in <net> prohibit       priority 21000   (always)
// and the order is the whole point. The lookup sends v6 into the instance's
// table, where netifd has already installed a ::/0 route from the peer's
// allowed_ips; the prohibit below it catches everything that table cannot
// serve — a down tunnel, a disabled instance, a gateway without IPv6 — before
// the kernel ever reaches `main`, where the ISP default route lives. That
// ordering IS the v6 kill switch, there is no separate option for it, and the
// prohibit therefore stays in place for as long as the mode is not 'off'.
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
// `configured` is whether the instance is set up for steering at all (steered
// mode plus a routing table); `active` whether it is switched on. They are
// deliberately separate: the lookup follows `active`, the prohibit does not.
function reconcile_ipv6_rules(uci, s, iface, configured, active, table, nets) {
	let changed = false;
	let mode = s.ipv6_mode || 'block';
	// Steered routing only: with auto_routing the whole LAN goes through the
	// tunnel and there is no per-network rule to hang a lookup on, so 'auto'
	// behaves exactly like 'block' there.
	let want = configured ? (nets || []) : [];
	// The lookup is only ever right while the instance is up AND this gateway
	// forwards IPv6; anything else would route v6 into a table that drops it.
	let tunnel = active && mode == 'auto' && iface_ipv6_capable(uci, iface);
	if (reconcile_rules(uci, 'rule6', 'steer_v6_lookup', iface,
		tunnel ? want : [], function(net) {
			return { 'in': net, lookup: table, priority: '20000' };
		}))
		changed = true;
	// The prohibit is NOT conditional on the instance being up. It is the v6
	// kill switch, and taking it away the moment the tunnel goes is the leak
	// it exists to stop: the steered clients still have IPv6, the lookup above
	// is gone, so the next rule they meet is `main` — where the ISP default
	// route lives. A disabled instance, a down tunnel and a gateway without
	// the bit are all "IPv6 has nowhere legitimate to go", not "stop guarding
	// IPv6"; the mode 'off' is how a user asks for that.
	if (reconcile_rules(uci, 'rule6', 'steer_v6', iface,
		(mode != 'off') ? want : [], function(net) {
			return { 'in': net, action: 'prohibit', priority: '21000' };
		}))
		changed = true;
	return changed;
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
// the instance being switched on — the IPv6 prohibit hangs off this rather
// than off is_steering(), because it has to outlive the tunnel.
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
		if (heir)
			uci.set('dhcp', d.section, V6_MARK, heir);
		else
			release_section(uci, 'dhcp', d.section, V6_DHCP_OPTS);
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
		if (claim_section(uci, 'dhcp', d, V6_DHCP_OPTS, iface))
			cd = true;
	}

	// ip6class 'local' draws the prefix from the router's own ULA. Without one
	// there is nothing to allocate, so the clients get no address however the
	// announcement is configured — the silent no-op this whole path exists to
	// avoid.
	if (length(want_nets) &&
	    (uci.get('network', 'globals', 'ula_prefix') || '') == '')
		push(notes, 'the router has no ULA prefix (network.globals.ula_prefix); ' +
			'steered clients cannot be given an IPv6 address');

	return { network: cn, dhcp: cd };
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
		steering_configured(s, mode), is_active(s), s.routing_table,
		s.source_networks);
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
		active: false, reason: null };
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
		out.reason = 'gateway_no_ipv6';
	else if (connected === false)
		out.reason = 'tunnel_down';
	else
		out.active = true;
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
	// A disabled instance releases the managed objects that send traffic
	// through the tunnel: an explicit Disable means "give me normal networking
	// back", and the next apply recreates them. The one thing it does NOT
	// release is the IPv6 prohibit — see reconcile_ipv6_rules; that is the
	// difference between a disabled instance and ipv6_mode 'off'.
	let active = is_active(s);
	let auto = (det.mode == 'auto') && active;
	// Steering as configured vs. steering right now. Everything that routes
	// traffic keys off `steer`; only the v6 prohibit keys off `steer_ready`.
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
	//     table, plus prohibit rules that act as kill switch (IPv4, only when
	//     enabled) and IPv6 stop (always, unless ipv6_mode is 'off'). Prohibit
	//     sits between the lookup and the main table, so it only fires when
	//     the tunnel's table cannot serve the traffic.
	//
	//     IPv6 is not symmetric with IPv4 by default: whether it may be routed
	//     at all depends on the gateway, so the lookup half is decided per
	//     gateway in reconcile_ipv6_rules — which is also the only piece
	//     rotation and apply have to redo when they move the peer. Its
	//     prohibit half also outlives a disabled instance, which is why it is
	//     given the configured-steering flag rather than the live one.
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
	if (reconcile_ipv6_rules(uci, s, iface, steer_ready, active, table,
		s.source_networks))
		cn = true;
	// The ULA addressing on the eligible networks, and the router advertisement
	// that carries it to the clients.
	let v6lan = reconcile_v6_lan(uci, iface, v6_nets, notes);
	if (v6lan.network)
		cn = true;
	if (v6lan.dhcp)
		cd = true;

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
		notes: notes };
}

return { detect, enforce, reconcile_ipv6, ipv6_state, v6_hint,
	is_lan_side, v6_decline_reason, net_is_way_out, way_out_reason,
	device_is_lan_side, device_way_out_reason, networks_on_device,
	has_default_route, zones_of, zone_is_uplink, net_device, device_path,
	find_wan_zone, find_lan_zone, count_user_routes, recommend_mtu,
	ensure_rt_table, drop_rt_table };

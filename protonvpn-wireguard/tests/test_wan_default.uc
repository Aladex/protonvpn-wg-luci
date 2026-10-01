#!/usr/bin/ucode -S
// SPDX-License-Identifier: MIT
// The WAN default-route self-heal, and the WAN classification.
//
// The self-heal exists because a global netifd reload on OpenWrt 24.10 can
// remove the kernel's main IPv4 default while netifd still reports it
// installed. On the owner's router (DS-Lite, `default dev ds-dslite`) that cut
// the WAN twice in a day.
//
// Five review rounds went into IDENTIFYING the uplink from the router's state —
// route shape, protocol, device kind, the device stack — and every round found
// a configuration the identification got wrong: our own tunnels, a static tun,
// a VLAN or bridge on a tap, PPPoE over a tap, a tunnel whose packets leave
// through a source-policy tun. The heal no longer identifies anything. It puts
// back what was in the main table before the operation's own reload, and only
// what netifd still claims (see restore_wan_default). The cases in the second
// half are about that.
//
// The classification (wan_verdicts) is kept for what it was first written
// for, the MTU advice, where a wrong answer costs a hint and not the WAN. The
// first half tests it directly; its shapes are the ones the rounds found.
//
// Two harnesses, both in a child process (helpers/wan-default.uc), because
// ucode cannot change its own PATH:
//
//   * fake `ip` and `ubus` first on PATH. The fake `ip` keeps the main-table
//     defaults in a file, answers the text and JSON queries from it, and
//     records every route-changing call; a successful `route add default`
//     makes the default appear, the way the kernel would. These assert the
//     exact command, and run everywhere.
//   * real `ip` in a throwaway network namespace (`unshare -rn`), fake `ubus`
//     only. Whether a restored route is one netifd can later delete is a
//     property of the kernel's matching, so it is measured against the kernel.
//     Skipped, and said so, where unprivileged namespaces are not allowed.
//
// Run: part of tests/run.sh.

'use strict';

import { writefile, readfile, mkdir, chmod, unlink, lsdir, popen } from 'fs';

let fails = 0;
function ok(l, c, extra) {
	if (c) printf('ok   %s\n', l);
	else { fails++; printf('FAIL %s%s\n', l, extra ? ' (' + extra + ')' : ''); }
}
function eq(l, got, want) {
	let g = sprintf('%J', got), w = sprintf('%J', want);
	ok(l, g == w, 'got ' + g + ', want ' + w);
}

const STATE = getenv('PROTONVPN_STATE_DIR') || '/tmp/protonvpn-test-state';
const FAKE = STATE + '/wan-default-bin';
const NSBIN = STATE + '/wan-default-ns';
mkdir(FAKE);
mkdir(NSBIN);

const FAKE_IP = '#!/bin/sh\n' +
	'# Fake `ip` for test_wan_default.uc; see that file.\n' +
	'd="$PVT_FAKE"\n' +
	'if [ "$1 $2 $3 $4" = "-4 route show default" ]; then\n' +
	'\tcat "$d/default" 2>/dev/null\n' +
	'\texit 0\n' +
	'fi\n' +
	'# The main-table defaults as JSON, built from the same file by reading it\n' +
	'# the way iproute2 parses its own arguments: an optional route type, then\n' +
	'# keyword and value in order, a bare flag on its own, and route metrics\n' +
	'# (mtu, advmss, ...) collected into `metrics` the way ip -j reports them.\n' +
	'# Like the kernel, a route without a gateway gets link scope unless told.\n' +
	'if [ "$1 $2 $3 $4 $5" = "-j -4 route show default" ]; then\n' +
	'\t[ -f "$d/show-fails" ] && exit 2\n' +
	'\tawk \'BEGIN { printf "[" } NF { printf "%s{", (n++ ? "," : ""); fl = ""; mx = ""; gw = 0; sc = 0; i = 1;\n' +
	'\t\tif ($1 != "default") { printf "\\"type\\":\\"%s\\",", $1; i = 2 }\n' +
	'\t\tprintf "\\"dst\\":\\"default\\""; i++;\n' +
	'\t\twhile (i <= NF) { k = $i;\n' +
	'\t\t\tif (k ~ /^(onlink|linkdown|dead|offload|trap|unresolved|rt_offload|rt_trap|rt_offload_failed|pervasive)$/) {\n' +
	'\t\t\t\tfl = fl (fl == "" ? "" : ",") "\\"" k "\\""; i++; continue }\n' +
	'\t\t\tv = $(i + 1); i += 2;\n' +
	'\t\t\tif (k == "mtu" || k == "advmss" || k == "hoplimit" || k == "window" || k == "initcwnd") {\n' +
	'\t\t\t\tmx = mx (mx == "" ? "" : ",") "\\"" k "\\":" v; continue }\n' +
	'\t\t\tif (k == "via") { k = "gateway"; gw = 1 } else if (k == "proto") k = "protocol"; else if (k == "src") k = "prefsrc";\n' +
	'\t\t\tif (k == "scope") sc = 1;\n' +
	'\t\t\tif (k == "metric") printf ",\\"%s\\":%s", k, v; else printf ",\\"%s\\":\\"%s\\"", k, v }\n' +
	'\t\tif (!gw && !sc && $1 == "default") printf ",\\"scope\\":\\"link\\"";\n' +
	'\t\tprintf ",\\"flags\\":[%s]", fl; if (mx != "") printf ",\\"metrics\\":[{%s}]", mx; printf "}" }\n' +
	'\t\tEND { print "]" }\' "$d/default" 2>/dev/null || echo "[]"\n' +
	'\texit 0\n' +
	'fi\n' +
	'# The link, from one JSON file per device; no file is a device the\n' +
	'# kernel does not know, answered the way ip answers it. `no-json` stands\n' +
	'# for an ip that ignores -j and prints text.\n' +
	'if [ "$1 $2 $3 $4 $5" = "-d -j link show dev" ]; then\n' +
	'\t[ -f "$d/link-$6.json" ] || { echo "Device \\"$6\\" does not exist." >&2; exit 1; }\n' +
	'\tif [ -f "$d/no-json" ]; then echo "5: $6: <POINTOPOINT,NOARP,UP> mtu 1452"; exit 0; fi\n' +
	'\tcat "$d/link-$6.json"\n' +
	'\texit 0\n' +
	'fi\n' +
	'if [ "$1 $2 $3 $4" = "-j link show master" ]; then\n' +
	'\tcat "$d/members-$5.json" 2>/dev/null || echo "[]"\n' +
	'\texit 0\n' +
	'fi\n' +
	'if [ "$1 $3 $4" = "-j route get" ]; then\n' +
	'\t[ -f "$d/route-get-$5.json" ] || { echo "RTNETLINK answers: Network is unreachable" >&2; exit 2; }\n' +
	'\tcat "$d/route-get-$5.json"\n' +
	'\texit 0\n' +
	'fi\n' +
	'echo "$*" >> "$d/ip.log"\n' +
	'if [ "$1 $2 $3" = "route add default" ]; then\n' +
	'\t[ -f "$d/add-fails" ] && exit 2\n' +
	'\t# Accepted but never visible: what verification has to catch.\n' +
	'\t[ -f "$d/add-vanishes" ] && exit 0\n' +
	'\tshift 2\n' +
	'\t# Accepted, but stored other than asked.\n' +
	'\tline="$*"\n' +
	'\t[ -f "$d/add-mangle" ] && line=$(echo "$line" | sed -e "$(cat "$d/add-mangle")")\n' +
	'\techo "$line" >> "$d/default"\n' +
	'fi\n' +
	'exit 0\n';
const FAKE_UBUS = '#!/bin/sh\n' +
	'# Fake `ubus` for test_wan_default.uc: answers only the netifd dump.\n' +
	'[ "$1" = "-t" ] && shift 2\n' +
	'[ "$1 $2 $3" = "call network.interface dump" ] || exit 1\n' +
	'cat "$PVT_FAKE/dump.json"\n';
writefile(FAKE + '/ip', FAKE_IP);
writefile(FAKE + '/ubus', FAKE_UBUS);
writefile(NSBIN + '/ubus', FAKE_UBUS);
chmod(FAKE + '/ip', 0o755);
chmod(FAKE + '/ubus', 0o755);
chmod(NSBIN + '/ubus', 0o755);

// One netifd dump entry, shaped like `ubus call network.interface dump`:
// `metric` is reported for every up interface, `ip4table` only when one is in
// force, and `route` holds the 0.0.0.0/0 netifd says it installed. `extra`
// adds or overrides top-level keys (metric, ip4table, data).
function ifc(name, proto, l3, route, up, extra) {
	let o = { interface: name, up: (up == null) ? true : up, proto: proto,
		l3_device: l3, metric: 0, route: route ? [ route ] : [] };
	for (let k in extra)
		o[k] = extra[k];
	return o;
}
// netifd always dumps `source` ("addr/len", "0.0.0.0/0" when the route has
// none) and dumps `mtu` only when the route has one; a null in `extra`
// removes a key, to model a producer that does not say.
function dflt(extra) {
	let r = { target: '0.0.0.0', mask: 0, nexthop: '0.0.0.0', source: '0.0.0.0/0' };
	for (let k in extra) {
		if (extra[k] == null)
			delete r[k];
		else
			r[k] = extra[k];
	}
	return r;
}

// The owner's firewall: the WAN zone holds the uplink networks, and each
// instance has the stamped zone this package creates for it.
function firewall(wan_networks, extra) {
	let fw = {
		lan: { '.type': 'zone', name: 'lan', network: [ 'lan' ] },
		wan: { '.type': 'zone', name: 'wan', masq: '1', network: wan_networks },
		pvz1: { '.type': 'zone', name: 'protonvpn', masq: '1', network: [ 'protonvpn' ],
			protonvpn_managed: '1', protonvpn_role: 'zone', protonvpn_iface: 'protonvpn' },
		pvz2: { '.type': 'zone', name: 'pv_media', masq: '1', network: [ 'pv_media' ],
			protonvpn_managed: '1', protonvpn_role: 'zone', protonvpn_iface: 'pv_media' }
	};
	for (let k in extra)
		fw[k] = extra[k];
	return fw;
}
function network(extra) {
	let n = {
		lan: { '.type': 'interface', proto: 'static' },
		wan6: { '.type': 'interface', proto: 'dhcpv6' },
		dslite: { '.type': 'interface', proto: 'dslite' },
		protonvpn: { '.type': 'interface', proto: 'wireguard' },
		pv_media: { '.type': 'interface', proto: 'wireguard', ip4table: '107' }
	};
	for (let k in extra) {
		if (!n[k])
			n[k] = { '.type': 'interface' };
		for (let o in extra[k])
			n[k][o] = extra[k][o];
	}
	return n;
}

function write_config(sc, dir) {
	if (!sc.no_dump)
		writefile(dir + '/dump.json', sprintf('%J', { interface: sc.dump }));
	let cfg = dir + '/uci.json';
	writefile(cfg, sprintf('%J', { network: sc.network, firewall: sc.firewall,
		protonvpn: {}, dhcp: {} }));
	return cfg;
}
function helper_cmd(dir, cfg, bindir, env) {
	return (env || '') + ' PVT_FAKE=' + dir + ' PROTONVPN_MOCK_UCI=' + cfg +
		' PATH=' + bindir + ':' + getenv('PATH') + ' ' + (getenv('UCODE') || 'ucode') +
		' ' + (getenv('PVT_UCODE_L') || '') +
		' -S ' + getenv('PVT_HELPERS') + '/wan-default.uc 2>' + dir + '/stderr';
}
function sh_out(cmd) {
	let p = popen(cmd, 'r');
	let out = p ? (p.read('all') || '') : '';
	if (p)
		p.close();
	return out;
}

// A device as `ip -d -j link show` reports it (shapes measured with real ip
// in a namespace): `linkinfo.info_kind` for anything a driver registers a
// kind for and no linkinfo for a plain hardware device; the parent in
// top-level `link` for a vlan, macvlan or bound tunnel (absent for an unbound
// one); `link_netnsid` when the parent lives in another namespace. Bridge and
// bond ports are what `ip -j link show master <dev>` lists.
//
// A scenario describes devices in `kinds`: a string is a kind with nothing
// under it, null is hardware, false is a device the kernel does not know, and
// an object spells it out: { kind, link, netnsid, remote, members }.
// `routes` answers `ip -j route get <addr>` with the device it resolves to.
// Defaults follow the protocol the way the device would really be made;
// DS-Lite's ip6tnl is bound to the hardware port eth1, as on the router.
const DEFAULT_KIND = { wireguard: 'wireguard', dslite: { kind: 'ip6tnl', link: 'eth1' },
	map: { kind: 'ip6tnl', link: 'eth1' }, openvpn: 'tun', none: 'tun', gre: 'gre', pppoe: 'ppp' };
function link_json(dev, spec) {
	if (type(spec) != 'object')
		spec = { kind: spec };
	let o = { ifname: dev, mtu: 1500, link_type: spec.kind ? 'none' : 'ether' };
	if (spec.link)
		o.link = spec.link;
	if (spec.netnsid != null)
		o.link_netnsid = spec.netnsid;
	if (spec.kind) {
		o.linkinfo = { info_kind: spec.kind };
		if (spec.remote)
			o.linkinfo.info_data = { remote: spec.remote };
	}
	return sprintf('%J', [ o ]);
}
function write_device(dev, spec) {
	if (spec === false)
		return;
	writefile(FAKE + '/link-' + dev + '.json', link_json(dev, spec));
	if (type(spec) == 'object' && spec.members)
		writefile(FAKE + '/members-' + dev + '.json',
			sprintf('%J', map(spec.members, (m) => ({ ifname: m }))));
}

// Lay a scenario out for the fakes: routing table, devices, netifd's dump,
// the uci config. Returns the config path.
function stage(sc) {
	for (let f in lsdir(FAKE) || [])
		if (f != 'ip' && f != 'ubus')
			unlink(FAKE + '/' + f);
	if (sc.before != null)
		writefile(FAKE + '/default', sc.before);
	writefile(FAKE + '/default.after', sc.after || '');
	for (let flag in [ 'add_fails', 'add_vanishes', 'no_json', 'show_fails' ])
		if (sc[flag])
			writefile(FAKE + '/' + replace(flag, '_', '-'), '1');
	if (sc.add_mangle)
		writefile(FAKE + '/add-mangle', sc.add_mangle);
	let kinds = sc.kinds || {};
	// The port DS-Lite is bound to, unless the scenario says otherwise.
	if (!exists(kinds, 'eth1'))
		write_device('eth1', null);
	for (let i in sc.dump)
		if (i.l3_device && !exists(kinds, i.l3_device))
			write_device(i.l3_device, DEFAULT_KIND[i.proto]);
	for (let dev in kinds)
		write_device(dev, kinds[dev]);
	for (let addr in (sc.routes || {}))
		writefile(FAKE + '/route-get-' + addr + '.json',
			sprintf('%J', [ { dst: addr, dev: sc.routes[addr], flags: [] } ]));
	return write_config(sc, FAKE);
}

// How many log lines match `re`.
function said(log, re) {
	let n = 0;
	for (let l in split(log, '\n'))
		if (match(l, re))
			n++;
	return n;
}

// ════════════════════════════════════════════════════════════════════════
// Part 1 — WAN classification (wan_verdicts), which feeds the MTU advice
// ════════════════════════════════════════════════════════════════════════

// The classification of a scenario: { admitted: [names], why: { name: why },
// log }.
function uplinks(sc) {
	let cfg = stage(sc);
	let out = trim(sh_out(helper_cmd(FAKE, cfg, FAKE, 'PVT_MODE=uplinks')));
	let res = { admitted: [], why: {}, log: readfile(FAKE + '/stderr') || '' };
	let v;
	try { v = json(out); } catch (e) { v = null; }
	if (type(v) != 'array') {
		res.admitted = 'unparsable: ' + out;
		return res;
	}
	for (let x in v) {
		if (x.why == null)
			push(res.admitted, x.name);
		res.why[x.name] = x.why;
	}
	return res;
}
function with_dslite(name, proto, l3, kinds, net_extra, extra_ifc) {
	return {
		network: network(net_extra || { [name]: { proto: proto, device: l3 } }),
		firewall: firewall([ 'wan6', 'dslite', name ]),
		dump: [ ifc(name, proto, l3, dflt(), null, extra_ifc), ifc('dslite', 'dslite', 'ds-dslite', dflt()) ],
		kinds: kinds
	};
}
function wan_only(proto, l3, kinds) {
	return {
		network: network({ wan: { proto: proto, device: l3 } }),
		firewall: firewall([ 'wan', 'wan6' ]),
		dump: [ ifc('wan', proto, l3, dflt({ nexthop: '203.0.113.1' })) ],
		kinds: kinds
	};
}

// The owner's router: the DS-Lite uplink and two of our tunnels, all three
// reporting an identical gateway-less default.
{
	let r = uplinks({ network: network(), firewall: firewall([ 'wan6', 'dslite' ]),
		dump: [ ifc('protonvpn', 'wireguard', 'protonvpn', dflt()),
			ifc('pv_media', 'wireguard', 'pv_media', dflt(), null, { ip4table: 107 }),
			ifc('wan6', 'dhcpv6', 'eth1', null), ifc('dslite', 'dslite', 'ds-dslite', dflt()) ] });
	eq('class owner: only DS-Lite is the uplink', r.admitted, [ 'dslite' ]);
	ok('class owner: a WireGuard tunnel is refused for its protocol',
		match(r.why.protonvpn || '', /protocol wireguard/), r.why.protonvpn);
}
// Our tunnels listed in the wan zone by hand, a VPN client's tun in a
// masquerading zone of its own, OpenVPN and GRE in the wan zone.
{
	let r = uplinks({
		network: network({ vpn: { proto: 'none', device: 'tun0' }, ovpn: { proto: 'openvpn' },
			gre_hq: { proto: 'gre' } }),
		firewall: firewall([ 'wan6', 'dslite', 'protonvpn', 'pv_media', 'ovpn', 'gre_hq' ],
			{ vpnz: { '.type': 'zone', name: 'vpn', masq: '1', network: [ 'vpn' ] } }),
		dump: [ ifc('protonvpn', 'wireguard', 'protonvpn', dflt()), ifc('gre_hq', 'gre', 'gre4-hq', dflt()),
			ifc('ovpn', 'openvpn', 'tun1', dflt()), ifc('vpn', 'none', 'tun0', dflt()),
			ifc('dslite', 'dslite', 'ds-dslite', dflt()) ] });
	eq('class overlays: none of them is an uplink', r.admitted, [ 'dslite' ]);
}
// Zones: a provider protocol outside every WAN zone is not the way out;
// netifd's runtime `data.zone` counts like the zone's network list, and only
// for a WAN zone that is not ours.
{
	let r = uplinks({ network: network({ mgmt: { proto: 'dhcp' } }),
		firewall: firewall([ 'wan6', 'dslite' ],
			{ mz: { '.type': 'zone', name: 'mgmt', network: [ 'mgmt' ] } }),
		dump: [ ifc('mgmt', 'dhcp', 'eth2', dflt({ nexthop: '192.168.77.1' })),
			ifc('dslite', 'dslite', 'ds-dslite', dflt()) ] });
	eq('class zone: a DHCP client outside the WAN zone is not an uplink', r.admitted, [ 'dslite' ]);
	ok('class zone: and says why', match(r.why.mgmt || '', /not in a WAN firewall zone/), r.why.mgmt);
	r = uplinks({ network: network({ office: { proto: 'dhcp' }, pv_tun: { proto: 'dhcp' } }),
		firewall: firewall([ 'wan6' ], { ofz: { '.type': 'zone', name: 'office', network: [] } }),
		dump: [ ifc('dslite', 'dslite', 'ds-dslite', dflt(), null, { data: { zone: 'wan' } }),
			ifc('office', 'dhcp', 'eth3', dflt(), null, { data: { zone: 'office' } }),
			ifc('pv_tun', 'dhcp', 'eth4', dflt(), null, { data: { zone: 'protonvpn' } }) ] });
	eq('class runtime zone: placed in wan at runtime counts; office or ours does not',
		r.admitted, [ 'dslite' ]);
}
// The protocol alone cannot say it: an overlay configured `proto static` is
// refused for its device, and `proto none` on hardware for its protocol.
for (let k in [ 'tun', 'wireguard', 'gre', 'gretap', 'vxlan', 'vti', 'veth' ]) {
	let r = uplinks(with_dslite('a_ov', 'static', 'ov-' + k, { ['ov-' + k]: k }));
	eq('class static ' + k + ': not an uplink', r.admitted, [ 'dslite' ]);
	ok('class static ' + k + ': refused for its kind',
		match(r.why.a_ov || '', regexp('device kind ' + k + ' ')), r.why.a_ov);
}
{
	let r = uplinks(with_dslite('a_ext', 'none', 'eth3', { eth3: null }));
	eq('class proto none: an unconfigured interface on hardware is not an uplink',
		r.admitted, [ 'dslite' ]);
}
// The whole stack, not its top: the parent of a vlan, macvlan or bound
// tunnel, every port of a bridge or bond, the route of an unbound tunnel.
for (let c in [
	[ 'vlan on tap', 'tap0.5', { 'tap0.5': { kind: 'vlan', link: 'tap0' }, tap0: 'tun' }, /tap0\.5 > tap0: device kind tun/ ],
	[ 'bridge with a tap port', 'br-x', { 'br-x': { kind: 'bridge', members: [ 'eth5', 'tap0' ] }, eth5: null, tap0: 'tun' }, /br-x > tap0: device kind tun/ ],
	[ 'overlay two levels down', 'v2', { v2: { kind: 'vlan', link: 'v1' }, v1: { kind: 'macvlan', link: 'wg9' }, wg9: 'wireguard' }, /v2 > v1 > wg9: device kind wireguard/ ],
	[ 'bond with an overlay slave', 'bond0', { bond0: { kind: 'bond', members: [ 'eth6', 'gtap0' ] }, eth6: null, gtap0: 'gretap' }, /bond0 > gtap0: device kind gretap/ ],
	[ 'bridge port stacked on a tap', 'br-y', { 'br-y': { kind: 'bridge', members: [ 'eth5', 'v9' ] }, eth5: null, v9: { kind: 'vlan', link: 'tap0' }, tap0: 'tun' }, /br-y > v9 > tap0: device kind tun/ ],
	[ 'unknown parent', 'eth1.7', { 'eth1.7': { kind: 'vlan', link: 'ghost0' } }, /eth1\.7 > ghost0: device kind could not be determined/ ],
	[ 'vlan with no parent', 'eth1.7', { 'eth1.7': 'vlan' }, /vlan reports no parent device/ ],
	[ 'bridge with no ports', 'br-wan', { 'br-wan': { kind: 'bridge', members: [] } }, /bridge has no ports/ ],
	[ 'parent in another namespace', 'eth1.7', { 'eth1.7': { kind: 'vlan', link: 'eth1', netnsid: 0 } }, /another network namespace/ ],
	[ 'loop', 'va', { va: { kind: 'vlan', link: 'vb' }, vb: { kind: 'vlan', link: 'va' } }, /va > vb > va: device stack loops/ ],
	[ 'device unknown', 'ghost9', { ghost9: false }, /^device kind could not be determined/ ]
]) {
	let r = uplinks(with_dslite('a_st', 'static', c[1], c[2]));
	eq('class stack ' + c[0] + ': not an uplink', r.admitted, [ 'dslite' ]);
	ok('class stack ' + c[0] + ': the reason names the chain', match(r.why.a_st || '', c[3]), r.why.a_st);
}
{
	let deep = {};
	for (let i = 0; i < 12; i++)
		deep['d' + i] = { kind: 'vlan', link: 'd' + (i + 1) };
	deep.d12 = null;
	eq('class stack deeper than any real one: not an uplink',
		uplinks(with_dslite('a_st', 'static', 'd0', deep)).admitted, [ 'dslite' ]);
}
// Ordinary stacks pass.
for (let c in [
	[ 'VLAN on the WAN port', 'static', 'eth1.7', { 'eth1.7': { kind: 'vlan', link: 'eth1' } } ],
	[ 'bridged WAN of hardware ports', 'static', 'br-wan', { 'br-wan': { kind: 'bridge', members: [ 'eth1', 'eth2' ] }, eth2: null } ],
	[ 'DHCP on hardware', 'dhcp', 'eth1', { eth1: null } ],
	[ 'LTE/5G modem (wwan)', 'static', 'wwan0', { wwan0: 'wwan' } ],
	[ 'modem data channel on its modem', 'static', 'rmnet_data0', { rmnet_data0: { kind: 'rmnet', link: 'wwan0' }, wwan0: null } ]
])
	eq('class ' + c[0] + ': an uplink', uplinks(wan_only(c[1], c[2], c[3])).admitted, [ 'wan' ]);
// DS-Lite's own stack: bound to a port, or unbound and judged by the route
// to its AFTR.
{
	let sc = function(kinds, routes) {
		return { network: network(), firewall: firewall([ 'wan6', 'dslite' ]),
			dump: [ ifc('dslite', 'dslite', 'ds-dslite', dflt()) ], kinds: kinds, routes: routes };
	};
	eq('class tunnel: DS-Lite bound to a hardware port is an uplink',
		uplinks(sc()).admitted, [ 'dslite' ]);
	eq('class tunnel: bound to a tap it is not',
		uplinks(sc({ 'ds-dslite': { kind: 'ip6tnl', link: 'tap0' }, tap0: 'tun' })).admitted, []);
	let unbound = { 'ds-dslite': { kind: 'ip6tnl', remote: '2001:db8::1' }, protonvpn: 'wireguard' };
	eq('class tunnel: unbound, AFTR reached over the port: an uplink',
		uplinks(sc(unbound, { '2001:db8::1': 'eth1' })).admitted, [ 'dslite' ]);
	eq('class tunnel: unbound, AFTR reached through WireGuard: not',
		uplinks(sc(unbound, { '2001:db8::1': 'protonvpn' })).admitted, []);
	eq('class tunnel: unbound, no route to the AFTR: not', uplinks(sc(unbound, {})).admitted, []);
	eq('class tunnel: unbound with no remote: not',
		uplinks(sc({ 'ds-dslite': 'ip6tnl' })).admitted, []);
}
// An ip that cannot answer in JSON: nothing is identified, and the log says
// why, once.
{
	let sc = { network: network({ wan: { proto: 'dhcp' } }), firewall: firewall([ 'wan', 'wan6', 'dslite' ]),
		dump: [ ifc('dslite', 'dslite', 'ds-dslite', dflt()), ifc('wan', 'dhcp', 'eth1', dflt()) ],
		no_json: true };
	let r = uplinks(sc);
	eq('class no json: nothing identified', r.admitted, []);
	eq('class no json: the log says what is missing and what to install, once',
		said(r.log, /did not answer in JSON.*ip-full/), 1);
}

// ════════════════════════════════════════════════════════════════════════
// Part 2 — the self-heal: put back what the operation's reload took
// ════════════════════════════════════════════════════════════════════════

// Run the heal once: the main table holds `before`, the helper snapshots it,
// the "reload" leaves `after` (by default: nothing), then the heal runs.
// Returns { ret, adds, log }: what it returned, every route-changing `ip`
// call in order, and what it logged.
function heal(sc) {
	let cfg = stage(sc);
	let env = 'PVT_RELOAD="cp ' + FAKE + '/default.after ' + FAKE + '/default"';
	if (sc.snapshot == 'unreadable')
		env += ' PVT_SNAPSHOT=unreadable';
	let out = trim(sh_out(helper_cmd(FAKE, cfg, FAKE, env)));
	let adds = [];
	for (let line in split(trim(readfile(FAKE + '/ip.log') || ''), '\n'))
		if (line != '')
			push(adds, line);
	let ret;
	try { ret = json(out); } catch (e) { ret = 'unparsable: ' + out; }
	return { ret: ret, adds: adds, log: readfile(FAKE + '/stderr') || '' };
}

// netifd's view on the owner's router, as measured: DS-Lite and both tunnels
// up, each claiming a gateway-less default, pv_media in its own table.
function owner_dump(extra) {
	let d = [
		ifc('protonvpn', 'wireguard', 'protonvpn', dflt()),
		ifc('pv_media', 'wireguard', 'pv_media', dflt(), null, { ip4table: 107 }),
		ifc('wan6', 'dhcpv6', 'eth1', null),
		ifc('dslite', 'dslite', 'ds-dslite', dflt())
	];
	for (let i in extra)
		unshift(d, i);
	return d;
}
const DSLITE_DEFAULT = 'default dev ds-dslite proto static scope link\n';
const RESTORE_DSLITE = [ 'route add default dev ds-dslite proto static' ];
function owner(extra) {
	let sc = { before: DSLITE_DEFAULT, network: network(), firewall: firewall([ 'wan6', 'dslite' ]),
		dump: owner_dump() };
	for (let k in extra)
		sc[k] = extra[k];
	return sc;
}

// The owner's outage: the reload took `default dev ds-dslite`.
{
	let r = heal(owner());
	eq('heal owner: exactly the lost DS-Lite default is put back', r.adds, RESTORE_DSLITE);
	eq('heal owner: reported as success', r.ret, true);
	eq('heal owner: logged as restored, once', said(r.log, /restored missing WAN default route on ds-dslite/), 1);
}
// Round 5's PPPoE-over-TAP, as the classification saw it: an interface that
// claims a default, on a device every per-device rule admits, named to sort
// first. It was not the main-table default before the reload, so it is not
// put back — whatever it is.
{
	let r = heal(owner({ dump: owner_dump([ ifc('a_ppp', 'pppoe', 'ppp0', dflt({ nexthop: '10.64.64.64' })) ]),
		network: network({ a_ppp: { proto: 'pppoe', device: 'tap0' } }),
		firewall: firewall([ 'wan6', 'dslite', 'a_ppp' ]), kinds: { ppp0: 'ppp' } }));
	eq('heal pppoe over tap: not put back, the lost DS-Lite default is', r.adds, RESTORE_DSLITE);
}
// The other way round: if the main default before the reload went through
// an overlay, that is what was working, and that is what is put back. The
// heal undoes its own reload; it does not judge the user's routing.
{
	let r = heal(owner({ before: 'default dev tun-vpn proto static scope link\n',
		dump: owner_dump([ ifc('vpn', 'static', 'tun-vpn', dflt()) ]),
		network: network({ vpn: { proto: 'static', device: 'tun-vpn' } }) }));
	eq('heal no judgment: the default that was there is restored, even through a tun',
		r.adds, [ 'route add default dev tun-vpn proto static' ]);
}
// Removed on purpose: the operation itself took our tunnel's default away
// (auto routing turned off), so netifd no longer claims it. Only what netifd
// still claims is put back.
{
	let dump = [ ifc('protonvpn', 'wireguard', 'protonvpn', null),
		ifc('wan', 'dhcp', 'eth1', dflt({ nexthop: '192.0.2.1' }), null, { metric: 10 }) ];
	let r = heal({ before: 'default dev protonvpn proto static scope link\n' +
			'default via 192.0.2.1 dev eth1 proto static metric 10\n',
		network: network({ wan: { proto: 'dhcp' } }), firewall: firewall([ 'wan', 'wan6' ]), dump: dump });
	eq('heal removed on purpose: the tunnel default netifd dropped is not put back',
		r.adds, [ 'route add default via 192.0.2.1 dev eth1 proto static metric 10' ]);
	eq('heal removed on purpose: the default that is back counts as success', r.ret, true);
	ok('heal removed on purpose: and the one passed over is named',
		match(r.log, /protonvpn: netifd no longer claims/), r.log);
}
// netifd's claim and the snapshot must agree on everything netifd's own
// deletion matches on, or nothing is put back.
for (let c in [
	[ 'interface went down', [ ifc('dslite', 'dslite', 'ds-dslite', dflt(), false) ] ],
	[ 'claim moved to another table', [ ifc('dslite', 'dslite', 'ds-dslite', dflt(), null, { ip4table: 107 }) ] ],
	[ 'claim has another metric', [ ifc('dslite', 'dslite', 'ds-dslite', dflt(), null, { metric: 20 }) ] ],
	[ 'claim has a gateway the snapshot did not', [ ifc('dslite', 'dslite', 'ds-dslite', dflt({ nexthop: '192.0.0.1' })) ] ],
	[ 'claim on another device', [ ifc('dslite', 'dslite', 'ds-other', dflt()) ] ]
]) {
	let r = heal(owner({ dump: c[1] }));
	eq('heal ' + c[0] + ': nothing put back', r.adds, []);
	eq('heal ' + c[0] + ': reported as failure', r.ret, false);
	ok('heal ' + c[0] + ': the log says nothing was restored and why',
		said(r.log, /restored nothing/) == 1 && match(r.log, /no longer claims/), r.log);
}
{
	let r = heal({ before: 'default via 192.0.2.1 dev eth1 proto static metric 10\n',
		network: network({ wan: { proto: 'dhcp' } }), firewall: firewall([ 'wan', 'wan6' ]),
		dump: [ ifc('wan', 'dhcp', 'eth1', dflt({ nexthop: '192.0.2.99' }), null, { metric: 10 }) ] });
	eq('heal gateway changed: a renewed gateway is not guessed at', r.adds, []);
	eq('heal gateway changed: reported as failure', r.ret, false);
}
// Only netifd's own routes: one added by hand (`proto boot`) is not netifd's
// to have lost, and not this heal's to put back.
{
	let r = heal(owner({ before: 'default via 192.0.2.1 dev eth1 proto boot\n',
		dump: [ ifc('wan', 'dhcp', 'eth1', dflt({ nexthop: '192.0.2.1' })) ] }));
	eq('heal proto boot: not put back', r.adds, []);
	ok('heal proto boot: and the log says it was not netifd\'s',
		match(r.log, /eth1: not netifd's route \(proto boot\)/), r.log);
}
// The fallback: no snapshot to go by. It refuses outright — it never falls
// back to guessing which interface is the uplink.
{
	let r = heal(owner({ before: '' }));
	eq('heal nothing before: nothing put back, even though DS-Lite claims a default', r.adds, []);
	eq('heal nothing before: reported as failure', r.ret, false);
	eq('heal nothing before: the log says the default was already missing, once',
		said(r.log, /already missing before this operation/), 1);
	r = heal(owner({ snapshot: 'unreadable' }));
	eq('heal unreadable snapshot: nothing put back', r.adds, []);
	eq('heal unreadable snapshot: reported as failure', r.ret, false);
	eq('heal unreadable snapshot: the log says so, once',
		said(r.log, /could not read the main-table default before this operation/), 1);
	r = heal(owner({ no_dump: true }));
	eq('heal no netifd: nothing put back', r.adds, []);
	eq('heal no netifd: reported as failure', r.ret, false);
	ok('heal no netifd: and says why', match(r.log, /could not ask netifd/), r.log);
}
// Nothing was lost.
{
	let r = heal(owner({ after: DSLITE_DEFAULT }));
	eq('heal not lost: nothing done', r.adds, []);
	eq('heal not lost: success', r.ret, true);
	eq('heal not lost: nothing logged', r.log, '');
}
// Two defaults before — a primary and a backup — both lost, both still
// netifd's: both back, in the order the kernel listed them.
{
	let r = heal({ before: 'default via 192.0.2.1 dev eth1 proto static metric 10\n' +
			'default via 10.64.0.1 dev wwan0 proto static metric 20\n',
		network: network({ wan: { proto: 'dhcp' } }), firewall: firewall([ 'wan', 'wan6' ]),
		dump: [ ifc('wwan_4', 'dhcp', 'wwan0', dflt({ nexthop: '10.64.0.1' }), null, { metric: 20 }),
			ifc('wan', 'dhcp', 'eth1', dflt({ nexthop: '192.0.2.1' }), null, { metric: 10 }) ] });
	eq('heal two defaults: both put back, as they were listed',
		r.adds, [ 'route add default via 192.0.2.1 dev eth1 proto static metric 10',
			'route add default via 10.64.0.1 dev wwan0 proto static metric 20' ]);
	eq('heal two defaults: success', r.ret, true);
}
// Exactly what was there: the preferred source and onlink travel too.
{
	let r = heal({ before: 'default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10 onlink\n',
		network: network({ wan: { proto: 'static' } }), firewall: firewall([ 'wan', 'wan6' ]),
		dump: [ ifc('wan', 'static', 'eth1', dflt({ nexthop: '10.0.0.1', source: '192.0.2.5/32' }),
			null, { metric: 10 }) ] });
	eq('heal exact: source and onlink are carried',
		r.adds, [ 'route add default via 10.0.0.1 dev eth1 proto static metric 10 src 192.0.2.5 onlink' ]);
	eq('heal exact: and confirmed', r.ret, true);
}
// ── Route attributes: snapshot and netifd ───────────────────────────────
// A provider can pin a route MTU or a preferred source on its default. For
// each, netifd's claim is in one of three states, and each is handled
// differently (see claim_attrs in apply.uc, which cites netifd's dump code):
//   * netifd states a value  -> netifd's value, over a stale snapshot;
//   * netifd states NONE     -> the attribute is cleared, not inherited;
//   * netifd does not say    -> the snapshot stands.
// The log names every place netifd overrode or cleared the snapshot. (On the
// owner's router the default carries neither — `default dev ds-dslite proto
// static scope link` — so these reach users whose provider sets them.)
function wan_attr(before, claim, extra) {
	let sc = { before: before, network: network({ wan: { proto: 'static' } }),
		firewall: firewall([ 'wan', 'wan6' ]),
		dump: [ ifc('wan', 'static', 'eth1', dflt(claim), null, { metric: 10 }) ] };
	for (let k in extra)
		sc[k] = extra[k];
	return heal(sc);
}
const VIA10 = 'route add default via 10.0.0.1 dev eth1 proto static metric 10';
{
	let r = wan_attr('default via 10.0.0.1 dev eth1 proto static metric 10 mtu 1280\n',
		{ nexthop: '10.0.0.1', mtu: 1280 });
	eq('mtu value: carried when netifd states the same', r.adds, [ VIA10 + ' mtu 1280' ]);
	eq('mtu value: and confirmed', r.ret, true);
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static metric 10 mtu 1400\n',
		{ nexthop: '10.0.0.1', mtu: 1280 });
	eq('mtu value: netifd\'s MTU wins over a stale snapshot', r.adds, [ VIA10 + ' mtu 1280' ]);
	eq('mtu value: still a success', r.ret, true);
	ok('mtu value: the log says netifd\'s value was used over the snapshot\'s',
		match(r.log, /restored missing WAN default route .*mtu 1280 as netifd now claims \(was 1400\)/), r.log);
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static metric 10\n',
		{ nexthop: '10.0.0.1', mtu: 1280 });
	eq('mtu value: netifd\'s MTU is used where the snapshot had none', r.adds, [ VIA10 + ' mtu 1280' ]);

	// netifd states none: its dump has no `mtu` exactly when the route has
	// none, and an explicit 0 installs none either.
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static metric 10 mtu 1280\n',
		{ nexthop: '10.0.0.1' });
	eq('mtu none: an MTU netifd no longer has is cleared, not inherited', r.adds, [ VIA10 ]);
	eq('mtu none: and that is a success', r.ret, true);
	ok('mtu none: the log says it was cleared because netifd says so',
		match(r.log, /no mtu as netifd now claims \(was 1280\)/), r.log);
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static metric 10 mtu 1280\n',
		{ nexthop: '10.0.0.1', mtu: 0 });
	eq('mtu none: an explicit 0 clears it too', r.adds, [ VIA10 ]);

	// netifd does not say: a statement that cannot be read is no statement.
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static metric 10 mtu 1280\n',
		{ nexthop: '10.0.0.1', mtu: 'n/a' });
	eq('mtu unknown: the snapshot\'s MTU stands', r.adds, [ VIA10 + ' mtu 1280' ]);
	eq('mtu unknown: and nothing is said about it', said(r.log, /as netifd now claims/), 0);
}
{
	let r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10\n',
		{ nexthop: '10.0.0.1', source: '192.0.2.9/32' });
	eq('src value: netifd\'s source wins over a stale snapshot', r.adds, [ VIA10 + ' src 192.0.2.9' ]);
	eq('src value: still a success', r.ret, true);
	ok('src value: the log says netifd\'s value was used over the snapshot\'s',
		match(r.log, /source 192\.0\.2\.9 as netifd now claims \(was 192\.0\.2\.5\)/), r.log);
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static metric 10\n',
		{ nexthop: '10.0.0.1', source: '192.0.2.9/32' });
	eq('src value: netifd\'s source is used where the snapshot had none', r.adds, [ VIA10 + ' src 192.0.2.9' ]);
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10\n',
		{ nexthop: '10.0.0.1', source: '192.0.2.5/32' });
	eq('src value: carried when netifd states the same', r.adds, [ VIA10 + ' src 192.0.2.5' ]);
	eq('src value: and nothing is said about it', said(r.log, /as netifd now claims/), 0);

	// netifd states none — the gate's case: the claim changed to 0.0.0.0.
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10\n',
		{ nexthop: '10.0.0.1', source: '0.0.0.0/0' });
	eq('src none: a source netifd no longer has is cleared, not inherited', r.adds, [ VIA10 ]);
	eq('src none: and that is a success', r.ret, true);
	ok('src none: the log says it was cleared because netifd says so',
		match(r.log, /no source as netifd now claims \(was 192\.0\.2\.5\)/), r.log);
	// netifd installs a preferred source only for a non-zero length, whatever
	// the address says.
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10\n',
		{ nexthop: '10.0.0.1', source: '192.0.2.5/0' });
	eq('src none: an address with length 0 is no source', r.adds, [ VIA10 ]);

	// netifd does not say.
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10\n',
		{ nexthop: '10.0.0.1', source: null });
	eq('src unknown: the snapshot\'s source stands where netifd does not say', r.adds, [ VIA10 + ' src 192.0.2.5' ]);
	eq('src unknown: and nothing is said about it', said(r.log, /as netifd now claims/), 0);
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10\n',
		{ nexthop: '10.0.0.1', source: 'garbage' });
	eq('src unknown: nor where what it says cannot be read', r.adds, [ VIA10 + ' src 192.0.2.5' ]);
}
// Cleared means ABSENT: a route that comes back still carrying the cleared
// attribute is not the route that was wanted.
{
	let r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10\n',
		{ nexthop: '10.0.0.1', source: '0.0.0.0/0' }, { add_mangle: 's/$/ src 192.0.2.5/' });
	eq('verify cleared source: a route that still has it is a failure', r.ret, false);
	eq('verify cleared source: and is not logged as restored', said(r.log, /restored missing WAN default/), 0);
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static metric 10 mtu 1280\n',
		{ nexthop: '10.0.0.1' }, { add_mangle: 's/$/ mtu 1280/' });
	eq('verify cleared mtu: a route that still has it is a failure', r.ret, false);
}

// What cannot be put back exactly is not put back at all: restoring such a
// route without the attribute would be another route reported as this one.
for (let c in [
	[ 'advmss', 'default via 10.0.0.1 dev eth1 proto static metric 10 advmss 1200\n', /advmss/ ],
	[ 'hoplimit', 'default via 10.0.0.1 dev eth1 proto static metric 10 hoplimit 5\n', /hoplimit/ ],
	[ 'scope host', 'default via 10.0.0.1 dev eth1 proto static scope host metric 10\n', /scope host/ ],
	[ 'unknown key', 'default via 10.0.0.1 dev eth1 proto static metric 10 realms 7\n', /realms/ ]
]) {
	let r = wan_attr(c[1], { nexthop: '10.0.0.1' });
	eq('uncarried ' + c[0] + ': not put back', r.adds, []);
	eq('uncarried ' + c[0] + ': reported as failure', r.ret, false);
	ok('uncarried ' + c[0] + ': and the log names what could not be carried',
		match(r.log, c[2]) && match(r.log, /restored nothing/), r.log);
}
{
	// `linkdown` is the link's state, not the route's configuration: it comes
	// back with the carrier, and does not stop the route being put back.
	let r = heal(owner({ before: 'default dev ds-dslite proto static scope link linkdown\n' }));
	eq('state flag: a linkdown default is still put back', r.adds, RESTORE_DSLITE);
	eq('state flag: and confirmed', r.ret, true);
	// Hardware offload marks are the kernel's and the driver's report on the
	// route, not something it was configured with: they come back on their own.
	for (let f in [ 'offload', 'trap', 'unresolved', 'rt_offload', 'rt_trap', 'rt_offload_failed' ]) {
		r = heal(owner({ before: 'default dev ds-dslite proto static scope link ' + f + '\n' }));
		eq('state flag: a default marked ' + f + ' is still put back', r.adds, RESTORE_DSLITE);
	}
	// A flag that is configuration and not carried is still refused.
	r = heal(owner({ before: 'default dev ds-dslite proto static scope link pervasive\n' }));
	eq('flag pervasive: not carried, so not put back', r.adds, []);
	ok('flag pervasive: and named', match(r.log, /flag pervasive/), r.log);
}
{
	// A default the kernel holds without a device (blackhole, unreachable)
	// was still a default before the reload: it is reported as not carried,
	// not mistaken for "there was none".
	let r = wan_attr('blackhole default proto static metric 10\n', { nexthop: '10.0.0.1' });
	eq('uncarried blackhole: not put back', r.adds, []);
	ok('uncarried blackhole: named, not reported as already missing',
		match(r.log, /type blackhole/) && !match(r.log, /already missing/), r.log);
}

// Read back before claiming anything: each attribute netifd's deletion
// matches on, and the ones carried from the snapshot.
{
	let sc = owner();
	sc.add_vanishes = true;
	let r = heal(sc);
	eq('verify vanished: reported as failure', r.ret, false);
	eq('verify vanished: not logged as restored', said(r.log, /restored missing WAN default/), 0);
	ok('verify vanished: the log says it could not be confirmed', match(r.log, /could not confirm/), r.log);
	sc = owner();
	sc.add_fails = true;
	eq('verify add fails: reported as failure', heal(sc).ret, false);
	sc = owner();
	sc.show_fails = true;
	eq('verify read-back fails: reported as failure', heal(sc).ret, false);
}
{
	let base = function() {
		return { before: 'default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10 onlink mtu 1280\n',
			network: network({ wan: { proto: 'static' } }), firewall: firewall([ 'wan', 'wan6' ]),
			dump: [ ifc('wan', 'static', 'eth1', dflt({ nexthop: '10.0.0.1', source: '192.0.2.5/32', mtu: 1280 }),
				null, { metric: 10 }) ] };
	};
	for (let m in [ [ 'proto', 's/ proto static//' ], [ 'metric', 's/ metric 10//' ],
			[ 'device', 's/dev eth1/dev eth9/' ], [ 'gateway', 's/via 10.0.0.1/via 10.0.0.99/' ],
			[ 'source', 's/ src 192.0.2.5//' ], [ 'onlink', 's/ onlink//' ],
			[ 'mtu', 's/ mtu 1280//' ], [ 'other mtu', 's/ mtu 1280/ mtu 1500/' ],
			[ 'extra attribute', 's/$/ advmss 1200/' ] ]) {
		let sc = base();
		sc.add_mangle = m[1];
		eq('verify ' + m[0] + ': a route stored without the intended ' + m[0] + ' is a failure',
			heal(sc).ret, false);
	}
}
{
	// The read-back confirms the value intended, not the snapshot's: a route
	// stored with the stale source is not the one that was wanted.
	let r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10 mtu 1400\n',
		{ nexthop: '10.0.0.1', source: '192.0.2.9/32', mtu: 1280 },
		{ add_mangle: 's/src 192.0.2.9/src 192.0.2.5/' });
	eq('verify stale source: a route stored with the snapshot\'s source is a failure', r.ret, false);
	r = wan_attr('default via 10.0.0.1 dev eth1 proto static src 192.0.2.5 metric 10 mtu 1400\n',
		{ nexthop: '10.0.0.1', source: '192.0.2.9/32', mtu: 1280 },
		{ add_mangle: 's/mtu 1280/mtu 1400/' });
	eq('verify stale mtu: a route stored with the snapshot\'s MTU is a failure', r.ret, false);
}
// Values are values: a device named like a keyword of the route grammar.
for (let name in [ 'via', 'metric', 'proto', 'dev', 'src', 'onlink' ]) {
	let r = heal({ before: 'default via 192.0.2.1 dev ' + name + ' proto static metric 5\n',
		network: network({ wan: { proto: 'dhcp', device: name } }), firewall: firewall([ 'wan', 'wan6' ]),
		dump: [ ifc('wan', 'dhcp', name, dflt({ nexthop: '192.0.2.1' }), null, { metric: 5 }) ] });
	eq('values: a default on a device named "' + name + '" is restored and confirmed', r.ret, true);
}

// ── Every caller snapshots before it reloads ─────────────────────────────
// The heal is only as good as the snapshot it is handed, and the snapshot is
// only right if it is taken before the operation's first reload or ifup/
// ifdown. Read from the sources: in every function that heals, the snapshot
// comes first, and the heal is handed it.
{
	let SRC = getenv('PVT_TESTS') + '/../files/usr/share/ucode/protonvpn/';
	let RELOADS = [ 'commit_routing(', 'settle_ipv6(', 'apply_inner(', 'rotate_inner(',
		"'network', 'reload'", "'ifdown'", "'ifup'", 'tear_down_peer(' ];
	let sites = 0;
	for (let f in [ 'apply.uc', 'rotate.uc' ]) {
		let src = readfile(SRC + f) || '';
		let parts = split(src, /\nfunction /);
		for (let body in parts) {
			if (index(body, 'restore_wan_default(') < 0 || index(body, 'restore_wan_default(snap) {') == 0)
				continue;
			let name = substr(body, 0, index(body, '('));
			if (name == 'restore_wan_default')
				continue;
			sites += length(match(body, /restore_wan_default\(/g));
			let snap_at = index(body, 'let snap = wan_default_snapshot();');
			let first = -1;
			for (let r in RELOADS) {
				let i = index(body, r);
				if (i >= 0 && (first < 0 || i < first))
					first = i;
			}
			ok('callers: ' + f + ' ' + name + '() snapshots before its first reload',
				snap_at >= 0 && (first < 0 || snap_at < first),
				'snapshot at ' + snap_at + ', first reload at ' + first);
			ok('callers: ' + f + ' ' + name + '() hands the heal its snapshot',
				length(match(body, /restore_wan_default\(snap\)/g)) ==
				length(match(body, /restore_wan_default\(/g)), name);
		}
	}
	eq('callers: every heal site was checked (apply, disconnect, delete twice, rotate)', sites, 5);
}

// ── Against the real kernel ──────────────────────────────────────────────
// Real `ip`, a fake netifd. The "reload" flushes the main-table defaults, as
// the observed one does; netifd's later deletion is `ip route del ... proto
// static metric N`, which the kernel only honours for an exact match.
function in_netns(setup, sc, del) {
	for (let f in lsdir(NSBIN) || [])
		if (f != 'ubus')
			unlink(NSBIN + '/' + f);
	let cfg = write_config(sc, NSBIN);
	let env = 'PVT_RELOAD="ip -4 route flush exact 0.0.0.0/0 table main"';
	// Written to a file rather than passed to `sh -c`: the helper's command
	// line carries its own single quotes.
	writefile(NSBIN + '/run.sh', setup + '\n' +
		'echo "before: $(ip -4 route show default)"\n' +
		'echo "helper: $(' + helper_cmd(NSBIN, cfg, NSBIN, env) + ')"\n' +
		'echo "restored: $(ip -4 route show default)"\n' +
		del + ' 2>/dev/null\necho "after del: $(ip -4 route show default)"\n' +
		'echo "log: $(cat ' + NSBIN + '/stderr)"\n');
	return sh_out('unshare -rn sh ' + NSBIN + '/run.sh 2>&1');
}
if (trim(sh_out("unshare -rn sh -c 'ip link add pvt0 type dummy && echo yes' 2>/dev/null")) != 'yes') {
	printf('skip netns: unprivileged network namespaces are not available here, so the ' +
		'kernel-level cases did not run\n');
} else {
	// Devices made the way netifd makes them where a namespace allows: DS-Lite
	// is an ip6tnl in ip4ip6 mode bound to a port. A namespace cannot make a
	// hardware device, so stacks are rooted on `lo`; nothing here classifies
	// devices any more, so what they sit on does not change the outcome.
	const DSLITE = 'ip link set lo up && ip link add ds-dslite type ip6tnl mode ip4ip6 ' +
		'remote 2001:db8::1 local 2001:db8::2 dev lo && ip link set ds-dslite up';
	let gw_dev = function(name) {
		return 'ip link set lo up && ip link add ' + name + ' type ip6tnl mode ip4ip6 ' +
			'remote 2001:db8::9 local 2001:db8::8 dev lo && ip link set ' + name + ' up && ' +
			'ip addr add 192.0.2.2/24 dev ' + name;
	};

	let out = in_netns(DSLITE + ' && ip route add default dev ds-dslite proto static metric 30',
		owner({ dump: [ ifc('dslite', 'dslite', 'ds-dslite', dflt(), null, { metric: 30 }) ] }),
		'ip route del default dev ds-dslite proto static metric 30');
	ok('netns dslite: the lost default is put back exactly',
		match(out, /restored: default dev ds-dslite proto static scope link metric 30/) &&
		match(out, /helper: true/), out);
	ok('netns dslite: netifd\'s own deletion removes it', match(out, /after del: *\n/) != null, out);

	out = in_netns(gw_dev('eth9') + ' && ip route add default via 192.0.2.1 dev eth9 proto static metric 10',
		{ network: network({ wan: { proto: 'dhcp' } }), firewall: firewall([ 'wan', 'wan6' ]),
			dump: [ ifc('wan', 'dhcp', 'eth9', dflt({ nexthop: '192.0.2.1' }), null, { metric: 10 }) ] },
		'ip route del default via 192.0.2.1 dev eth9 proto static metric 10');
	ok('netns gateway: put back via the gateway, proto static, its metric',
		match(out, /restored: default via 192\.0\.2\.1 dev eth9 proto static metric 10/) &&
		match(out, /helper: true/), out);
	ok('netns gateway: netifd\'s own deletion removes it', match(out, /after del: *\n/) != null, out);

	// A real tun that netifd says has a default, named to sort first, which
	// was not the main default before: not put back.
	out = in_netns(DSLITE + ' && ip tuntap add a-tun mode tun && ip link set a-tun up && ' +
			'ip route add default dev ds-dslite proto static',
		owner({ dump: owner_dump([ ifc('a_vpn', 'static', 'a-tun', dflt()) ]) }), 'true');
	ok('netns tun claiming a default: the lost DS-Lite default is put back, not the tun',
		match(out, /restored: default dev ds-dslite proto static scope link *\n/) != null, out);

	// Exactly what was there, against real JSON output: source and onlink.
	out = in_netns(gw_dev('eth9') + ' && ip route add default via 10.0.0.1 dev eth9 proto static ' +
			'src 192.0.2.2 metric 10 onlink',
		{ network: network({ wan: { proto: 'static' } }), firewall: firewall([ 'wan', 'wan6' ]),
			dump: [ ifc('wan', 'static', 'eth9', dflt({ nexthop: '10.0.0.1', source: '192.0.2.2/32' }),
				null, { metric: 10 }) ] },
		'true');
	ok('netns exact: source and onlink put back and confirmed',
		match(out, /restored: default via 10\.0\.0\.1 dev eth9 proto static src 192\.0\.2\.2 metric 10 onlink/) &&
		match(out, /helper: true/), out);

	// The gate's MTU case on the real kernel: a pinned 1280 must come back as
	// 1280, not as the device's own 1460 — and the route lookup must show it.
	out = in_netns(DSLITE + ' && ip link set ds-dslite mtu 1460 && ' +
			'ip route add default dev ds-dslite proto static metric 30 mtu 1280',
		owner({ dump: [ ifc('dslite', 'dslite', 'ds-dslite', dflt({ mtu: 1280 }), null, { metric: 30 }) ] }),
		'echo "lookup: $(ip -4 route get 198.51.100.7)"');
	ok('netns mtu: the pinned route MTU is put back and confirmed',
		match(out, /restored: default dev ds-dslite proto static scope link metric 30 mtu 1280/) &&
		match(out, /helper: true/), out);
	ok('netns mtu: and is what a lookup through it gets',
		match(out, /lookup: 198\.51\.100\.7 dev ds-dslite/) && match(out, /cache mtu 1280/), out);

	// netifd now states another source than the route had: netifd's is used.
	out = in_netns(gw_dev('eth9') + ' && ip addr add 192.0.2.3/24 dev eth9 && ' +
			'ip route add default via 192.0.2.1 dev eth9 proto static src 192.0.2.2 metric 10',
		{ network: network({ wan: { proto: 'static' } }), firewall: firewall([ 'wan', 'wan6' ]),
			dump: [ ifc('wan', 'static', 'eth9', dflt({ nexthop: '192.0.2.1', source: '192.0.2.3/32' }),
				null, { metric: 10 }) ] },
		'true');
	ok('netns src: netifd\'s current source is put back and confirmed',
		match(out, /restored: default via 192\.0\.2\.1 dev eth9 proto static src 192\.0\.2\.3 metric 10/) &&
		match(out, /helper: true/), out);

	// netifd now states no source and no MTU for the route that had both: it
	// comes back with neither, and the real kernel's JSON confirms the absence.
	out = in_netns(gw_dev('eth9') + ' && ip route add default via 192.0.2.1 dev eth9 proto static ' +
			'src 192.0.2.2 metric 10 mtu 1280',
		{ network: network({ wan: { proto: 'static' } }), firewall: firewall([ 'wan', 'wan6' ]),
			dump: [ ifc('wan', 'static', 'eth9', dflt({ nexthop: '192.0.2.1', source: '0.0.0.0/0' }),
				null, { metric: 10 }) ] },
		'true');
	ok('netns cleared: source and MTU netifd no longer has are not put back',
		match(out, /restored: default via 192\.0\.2\.1 dev eth9 proto static metric 10 *\n/) &&
		match(out, /helper: true/), out);

	// An attribute the heal does not carry: nothing is restored, and it says so.
	out = in_netns(gw_dev('eth9') + ' && ip route add default via 192.0.2.1 dev eth9 proto static ' +
			'metric 10 advmss 1200',
		{ network: network({ wan: { proto: 'static' } }), firewall: firewall([ 'wan', 'wan6' ]),
			dump: [ ifc('wan', 'static', 'eth9', dflt({ nexthop: '192.0.2.1' }), null, { metric: 10 }) ] },
		'true');
	ok('netns uncarried: a route with advmss is not put back without it',
		match(out, /restored: *\n/) && match(out, /helper: false/) && match(out, /advmss/), out);

	// A device named like a route keyword, confirmed against real output.
	out = in_netns(gw_dev('via') + ' && ip route add default via 192.0.2.1 dev via proto static metric 5',
		{ network: network({ wan: { proto: 'dhcp', device: 'via' } }), firewall: firewall([ 'wan', 'wan6' ]),
			dump: [ ifc('wan', 'dhcp', 'via', dflt({ nexthop: '192.0.2.1' }), null, { metric: 5 }) ] },
		'true');
	ok('netns device named via: put back and confirmed',
		match(out, /restored: default via 192\.0\.2\.1 dev via proto static metric 5/) &&
		match(out, /helper: true/), out);
}

printf('\n%s\n', fails ? ('FAILURES: ' + fails) : 'ALL WAN DEFAULT TESTS PASSED');
exit(fails ? 1 : 0);

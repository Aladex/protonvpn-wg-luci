# Traffic routing

**English** · [Русский](routing.ru.md) · [Deutsch](routing.de.md) · [← README](../README.md)

With **automatic routing** the backend creates a firewall zone and sends all
LAN traffic through the tunnel. It never touches anything if it detects a
custom routing table or routes you added yourself.

Instead of routing everything, name **source networks**: only those leave
through the tunnel, via policy rules into the instance's own routing table.
The **kill switch** then blocks those networks from reaching the WAN while the
tunnel is down, and **`ipv6_mode`** decides what happens to IPv6.

IPv6 is a per-server matter on ProtonVPN: only some gateways forward it, and
Proton marks them with bit 16 of the logical server's `Features` bitmask.
Measured on 12 gateways across 11 countries by probing `2606:4700:4700::1111`
through the tunnel — all six with the bit answered in 0.02–1.07 s, all six
without it timed out at 8–12 s every single time while the WireGuard transmit
counter kept climbing. On such a server the packets leave and nothing comes
back, which is not "IPv6 off", it is a black hole — and a black hole is worse
than a block: clients wait out Happy Eyeballs on every connection and anything
that is not a browser simply hangs.

So the three modes are:

* `block` (default) — a `prohibit` rule stops IPv6 on the steered networks, as
  before.
* `auto` — on a gateway with the bit, IPv6 goes through the tunnel; on one
  without it, the same `prohibit` as in `block`. The prohibit rule sits below
  the lookup but above the main table, so a down tunnel or a server without
  IPv6 stops there and never reaches your provider's default route. That
  ordering is the IPv6 kill switch, and it stays up for as long as the instance
  is enabled.

  Disabling the instance is the one thing that takes it down, and it has to:
  Disable also hands the steered networks their normal addressing back, so the
  clients are holding an ISP address again. A prohibit left standing after that
  guards nothing and breaks everything — it refuses every IPv6 packet from
  those networks, and being netifd config it survives a reboot. `off` is how
  you ask for no guard while the instance keeps running.
* `off` — the app does not touch IPv6 at all.

`auto` applies to steered routing only; with `auto_routing` there are no
per-network rules to attach it to, so it behaves as `block`. The tunnel's own
address is a fixed `/128` that every Proton client shares, so there is no
prefix to delegate: under `auto` the steered networks are addressed from the
router's own ULA (`ip6assign 64`, `ip6class local`, `delegate 0`) and NAT6'd
behind the instance's firewall zone. The client then sees a ULA and no ISP
address at all, which is exactly what keeps Happy Eyeballs from preferring the
WAN. Allocating a prefix is not the same as announcing one, though: on a
network where IPv6 was never used — `ra 'disabled'`, which is what the old
blocking policy encouraged — the client would end up with no address at all. So
`auto` also switches the router advertisement on for those networks
(`ra 'server'`, `ra_slaac 1`) and sets `ra_default 1`, without which odhcpd
advertises a router lifetime of zero on a ULA-only interface and the client
gets an address it cannot route with. DHCPv6 is left alone. It also opens
neighbour discovery for the steered networks — router solicitation and
neighbour solicitation/advertisement, IPv6 only, nothing else, and bound to
that network's own interface so nothing else sharing its firewall zone is
covered. A guest-style zone rejects what it does not name, and nothing names
neighbour discovery, so without that the router cannot resolve a client's
address and every reply coming back through the tunnel is dropped on the last
hop. Both the network
and the `dhcp` settings belong to you, so the previous values are recorded and
put back when `auto` is switched off. If the router has no ULA prefix of its
own there is nothing to hand out, and the log says so rather than failing
quietly.

Which networks this applies to is decided before anything is written, and the
three parts — addressing, announcement, opening — are granted or refused
together: a client handed a ULA and told this router is its default gateway, on
a network whose neighbour discovery was then refused, has an address it cannot
use and no way to tell. A network qualifies when it is one the router serves
clients on: a protocol it does not dial out with, no default route of its own,
a firewall zone to attach the rule to, and a single device to bind it to. That
last question is asked of the device and not of the network, because an alias
or a second subnet can sit on the same bridge and carry a gateway of its own,
and a rule matching the device would cover it too. A network that does not
qualify is left exactly as you had it, and the log names the network and the
reason.

`auto` follows the fleet rather than narrowing it: you land on whatever gateway
the selection gives you, and IPv6 is routed or prohibited to match. If you
would rather have IPv6 than the widest choice of servers, **`require_ipv6`**
turns that around and only considers gateways that carry the bit — for the
initial connect, for every rotation and for the watchdog's recovery alike, not
merely in the list the page shows. 11 832 of 17 890 logicals qualify (66 %),
and some countries have none at all.

When the selected locations hold no such gateway, the instance does not
connect and says so. It never falls back to a gateway without IPv6: you asked
for IPv6 explicitly, and a connection that silently delivers the opposite is
the failure this whole feature exists to avoid. A pinned `fixed_server`
without the bit is refused on the same grounds — pinning already disables
rotation, so being left on it would be permanent. Widen the locations, pick a
different server, or turn the requirement off.

The same applies to a tunnel that is already up. If you turn the requirement on
while connected to a gateway without the bit and nothing eligible can be
reached, the tunnel is taken down rather than left running: declining to choose
such a gateway while still carrying you on one would report the requirement as
failed and break it at the same time. A tunnel that already satisfies the
requirement is left alone. IPv6 cannot escape either way — the prohibit rule
stays installed whether the tunnel is up or down, as long as the instance is
enabled — but IPv4 from the steered
networks falls back to your provider while the tunnel is down, exactly as it
does after any other connection failure. Turn the kill switch on if you would
rather those networks lose access than leave through the WAN.

Both halves are said where you will see them, and from the status the page
always has rather than only in the reply to the click: the band reports the
requirement, and — when the kill switch is off — that the steered networks are
now leaving through your provider, with the advice to turn the kill switch on.
A reload, the status poll and a background rotation all say the same thing.

It also says which way the requirement went unmet, because the remedies
differ: none of the gateways in these locations support IPv6 (add a location
that has them), the IPv6-capable gateways here could not be reached (they do
forward IPv6 — reconnect rather than changing anything), or the pinned server
does not support it (pick another server).

The option applies only where `auto` can actually deliver IPv6: with
`ipv6_mode` `auto`, `hop_mode` `standard`, and steered routing — the same
conditions `auto` itself needs. The page disables it elsewhere with the reason
shown, and a hand-written configuration that meets none of them keeps its whole
fleet rather than being refused over an option that changes nothing. Outside `auto` nothing
is routed through the tunnel whichever gateway is picked, so narrowing the
fleet would cost servers and buy nothing; outside Standard it cannot be
satisfied, because bit 16 is set on 0 of 122 Secure Core and 0 of 7 Tor
logicals. The stored value survives a trip through the other modes rather than
being forgotten.

![Traffic routing](screenshots/routing.png)

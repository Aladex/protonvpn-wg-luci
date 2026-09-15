# ProtonVPN WireGuard for OpenWrt

**English** · [Русский](README.ru.md) · [Deutsch](README.de.md)

Configure ProtonVPN's WireGuard service on OpenWrt: browser-side SRP-6a login
with TOTP support, locally generated WireGuard keys registered as Proton
certificates, an authenticated server list with load and score, a location set
to connect and rotate across (Standard, Secure Core, Tor), automatic rotation,
a watchdog, multiple parallel VPN instances, per-network traffic steering with
kill switch and adaptive IPv6, and a native LuCI page.

> **Unofficial.** This project is not affiliated with, endorsed by, or
> supported by Proton AG. "Proton" and "ProtonVPN" are trademarks of their
> respective owners. Use your own ProtonVPN account.

![LuCI overview page](docs/screenshots/overview.png)

## Architecture

The project ships as **two packages** so the VPN service is useful without a
web interface and the LuCI app stays a thin frontend:

- **`protonvpn-wireguard`** — the backend (targets `openwrt/packages`,
  `net/protonvpn-wireguard`). ucode + procd + an rpcd/ubus object. Relays the
  SRP login steps, keeps the session and certificates alive, caches the
  server list, generates WireGuard interfaces and peers, verifies handshakes,
  runs scheduled rotation and reports runtime status. Works from the CLI and
  over ubus with no LuCI installed.
- **`luci-app-protonvpn`** — the LuCI frontend (targets `openwrt/luci`,
  `applications/luci-app-protonvpn`). A JavaScript view that calls the
  backend's ubus methods, and computes the SRP-6a proof in the browser
  (native BigInt) because the router's ucode cannot do 2048-bit modexp.

Two Proton-specific facts shape the design:

1. **Auth is SRP-6a**, not a token. The browser runs SRP; the router only
   relays the HTTP steps. The Proton password never reaches the router and is
   never stored. Afterwards the router maintains the session on its own
   (`/auth/refresh`, 30-day horizon) and renews the WireGuard certificate,
   both without asking again.
2. **The server list is authenticated** — `GET /vpn/logicals` returns 401
   without a live session, so the location picker only fills in after login.

## Installation

### From the signed package feed (recommended)

CI builds signed, architecture-independent packages for every release.

**OpenWrt 24.10 (opkg):**

```sh
wget -O /etc/opkg/keys/4fcb996825e11695 \
  https://aladex.github.io/protonvpn-wg-luci/keys/4fcb996825e11695
echo 'src/gz protonvpn_luci https://aladex.github.io/protonvpn-wg-luci/packages/opkg' \
  >> /etc/opkg/customfeeds.conf
opkg update
opkg install luci-app-protonvpn      # or just protonvpn-wireguard for headless
```

**OpenWrt snapshots / 25.x (apk):**

```sh
wget -O /etc/apk/keys/protonvpn-wg-luci-apk.pem \
  https://aladex.github.io/protonvpn-wg-luci/keys/protonvpn-wg-luci-apk.pem
echo 'https://aladex.github.io/protonvpn-wg-luci/packages/apk/packages.adb' \
  >> /etc/apk/repositories.d/customfeeds.list
apk update
apk add luci-app-protonvpn
```

Log out of LuCI and back in after installing, then open **VPN → ProtonVPN**.

### From source

Both packages are plain feed packages; build them with the OpenWrt SDK for
your target:

```sh
# backend (packages feed style)
cp -r protonvpn-wireguard <sdk>/package/net/protonvpn-wireguard
# frontend (from an openwrt/luci checkout)
cp -r luci-app-protonvpn <luci>/applications/luci-app-protonvpn

make package/protonvpn-wireguard/compile V=s
make package/luci-app-protonvpn/compile V=s
```

They are `PKGARCH:=all`, so one build serves every target.

## Usage

Open **VPN → ProtonVPN** and press **Log in**. The modal asks for your Proton
address and password, and for a TOTP code only if the account uses one — the
password is processed in your browser and never sent to the router. The server
list downloads right after login; it is large (Proton publishes tens of
thousands of servers), so the first refresh takes a few seconds.

Then pick a **location set** — whole countries, or individual cities inside
them — and press **Save and reconnect**. The initial connect and every later
rotation pick from that set. Leave **Server** on *Automatic* to let the backend
choose by load, or pin one; pinning disables rotation for that instance.

**Hop mode** switches between Standard, Secure Core (entry through a hardened
Proton-owned server in a privacy-friendly country) and Tor (exit through the
Tor network). The three are different products rather than filters over one
list, so switching mode clears the location set: pick again for the new mode.

![Choosing locations](docs/screenshots/location-picker.png)

Servers are listed least-loaded first, with a one-click lowest-load pick on
top. Within an equal load they are ordered by name, numerically — so `NL#5`
comes before `NL#27`, not after it:

![Choosing a server](docs/screenshots/server-picker.png)

The status band shows the connected server, the handshake age and the external
IP as seen through the tunnel — the one check that proves traffic really
leaves through the VPN, which a handshake alone does not.

### Multiple instances

Every instance runs its own WireGuard interface (`pv_<name>`), its own keypair
and certificate, its own location set and schedule, and — when it steers
traffic — its own routing table and firewall zone. They share one Proton
account and one server-list cache, which `main` owns. Deleting `main` resets it
to defaults instead of removing it, because it anchors both.

![The VPN instances table](docs/screenshots/instances.png)

Typical use: `main` for the LAN and a second instance for a guest network or a
media device that should exit in another country.

### Traffic routing

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
  without it, the same `prohibit` as in `block`. The prohibit rule is always
  installed and sits below the lookup but above the main table, so a down
  tunnel, a disabled instance or a server without IPv6 stops there and never
  reaches your provider's default route. That ordering is the IPv6 kill switch.
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

![Traffic routing](docs/screenshots/routing.png)

### Rotation and the watchdog

Rotation moves to another server in the set, either every N minutes or at a
fixed time of day. A candidate is only accepted once a real WireGuard
handshake completes; if it does not, the next candidate is tried and the
previous peer is restored if none work.

The optional **watchdog** reconnects when the tunnel goes stale — detection is
handshake-based, with no external probe — and stays out of the way when a
specific server is pinned.

![Automatic rotation](docs/screenshots/rotation.png)

## Configuration (`/etc/config/protonvpn`)

Everything below is also reachable from the page's *Advanced settings*:

![Advanced settings](docs/screenshots/advanced.png)

One `config instance` section per tunnel; `main` is the default. Secrets are
never stored here: the session lives in a root-only state file and the
WireGuard private key on the managed network interface.

| Option | Default | Meaning |
|---|---|---|
| `enabled` | `0` | Master switch; a fresh install ships disabled |
| `interface` | `protonvpn` | Managed WireGuard interface |
| `locations` (list) | — | Countries (`ch`) and/or cities (`nl-amsterdam`) to connect and rotate across |
| `hop_mode` | `standard` | `standard`, `secure_core` or `tor` |
| `fixed_server` | — | Pin one server by name; disables rotation |
| `rotation_enabled` | `0` | Automatic rotation |
| `rotation_mode` | `interval` | `interval` or `time` |
| `rotation_interval` | `360` | Minutes between rotations |
| `rotation_time` | `04:30` | Time of day for `time` mode |
| `watchdog` | `0` | Reconnect automatically when the tunnel goes stale |
| `verify_timeout` | `8` | Seconds to wait for a handshake before rejecting a server |
| `max_retries` | `10` | Candidate servers a rotation may try |
| `auto_routing` | `1` | Create the firewall zone and route all LAN traffic |
| `source_network` | — | Steer only these networks instead of everything |
| `routing_table` | — | Custom routing table (empty = main) |
| `killswitch` | `0` | Block the steered networks from the WAN while down |
| `ipv6_mode` | `block` | IPv6 handling: `block` (prohibit it), `auto` (through the tunnel on gateways that forward IPv6, prohibit on the rest; steered routing only) or `off` (leave IPv6 alone) |
| `vpn_dns` | `off` | `off` (system resolver) or `standard` (in-tunnel 10.2.0.1) |
| `mtu` | — | Interface MTU (the UI recommends WAN MTU − 80) |
| `cache_dir` | — | Server-list cache directory, shared by all instances |
| `cache_refresh_interval` | `21600` | Seconds between background cache refreshes |

## ubus API

All methods are on the `protonvpn` object. Read methods never mutate; no
secret is ever returned.

```bash
ubus call protonvpn status              # runtime state, session/cert expiry
ubus call protonvpn instances           # status of every configured instance
ubus call protonvpn session_state       # session horizon and required action
ubus call protonvpn account             # plan, tier, registered configurations
ubus call protonvpn auth_info '{"username":"..."}'   # SRP step 1 relay
ubus call protonvpn auth_finish '{...}'              # SRP step 3 relay
ubus call protonvpn set_totp '{"code":"123456"}'     # 2FA step
ubus call protonvpn refresh_session     # POST /auth/refresh (token rotation)
ubus call protonvpn logout              # drop the session, tunnels down
ubus call protonvpn locations           # cached country/city tree
ubus call protonvpn servers '{"locations":["ch","nl-amsterdam"],"hop_mode":"standard"}'
ubus call protonvpn certificate_renew   # re-register the WireGuard certificate
ubus call protonvpn apply               # rebuild the peer, bring the tunnel up
ubus call protonvpn apply_start         # the same apply, detached; returns at once
ubus call protonvpn apply_status        # progress/outcome of that apply
ubus call protonvpn rotate_now          # one-shot rotation
ubus call protonvpn disconnect          # tunnel down, rotation paused
ubus call protonvpn refresh_locations   # async server-list refresh
ubus call protonvpn refresh_status      # progress of that refresh
ubus call protonvpn external_ip         # public IP through the tunnel
ubus call protonvpn create_instance '{"instance":"media"}'
ubus call protonvpn delete_instance '{"instance":"media"}'
```

## Certificates and the device list

A WireGuard client on Proton is a **certificate**, not a session: the account's
saved WireGuard configurations (dashboard → *Downloads* → *WireGuard
configuration*) are what each instance occupies. `/vpn/v1/sessions` tracks the
legacy OpenVPN/IKEv2 logins and stays empty however many tunnels are up, so the
account card counts registered certificates instead.

A certificate cannot be revoked with the token a VPN client holds — the
dashboard gets there by asking for the password again. So when an instance is
deleted its certificate is renewed down to the shortest life the API grants
(ten minutes) instead: a renewal supersedes the previous registration, and
what is left expires on its own. Without that, every deleted instance would
sit in the account's configurations for a year.

## Security

- The **Proton password never reaches the router**. SRP proves knowledge of it
  without sending it, and the proof is computed in the browser.
- If LuCI is served over plain HTTP, the page that computes that proof arrives
  over an unauthenticated channel — anyone on the LAN could substitute it.
  Serving LuCI over HTTPS (`luci-ssl`) is strongly recommended.
- The session (UID, access and refresh tokens) lives in a root-only state file
  under `/etc/protonvpn`, mode 0600, **not** in UCI — so it stays out of config
  diffs and `sysupgrade` backups.
- The token's scope covers VPN and account settings only; probes against the
  mail and Drive endpoints return 403.
- The WireGuard private key is stored where every other WireGuard key on
  OpenWrt lives: the managed interface in `/etc/config/network`.

## Services and logs

```sh
/etc/init.d/protonvpn status
/etc/init.d/protonvpn version
logread -e protonvpn
```

The daemon refreshes the session and the server cache, renews certificates
before Proton's own `RefreshTime`, runs the rotation clock and the watchdog.

## Development

Offline ucode tests (no account or network needed):

```sh
# with ucode + ucode-mod-fs + ucode-mod-math available
sh protonvpn-wireguard/tests/run.sh
```

JS tests for the browser-side SRP implementation, including
cross-implementation vectors:

```sh
node --test luci-app-protonvpn/tests/*.test.mjs
```

CI runs shell/JSON static checks, LuCI ESLint on the view, the ucode tests and
a snapshot-SDK build of both packages; tags additionally build and publish the
signed feed.

## Related projects

- [nordvpn-luci](https://github.com/Aladex/nordvpn-luci) — the same design for
  NordVPN, which this project's layout follows.

## License

[MIT](LICENSE) — do whatever you want with it, just keep the copyright notice.

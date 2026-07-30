# ProtonVPN WireGuard for OpenWrt

> **Status: working, not yet packaged.** Login, tunnel, routing, rotation and
> multiple instances all run and have been verified end to end against a live
> Proton account on an ImmortalWrt 24.10 router. What is *not* done: the
> packages have never been built and installed as real `.ipk`/`.apk` artifacts
> — everything so far was validated by copying files onto a router — and the
> package feed still needs its signing keys and a build runner. Treat this as
> a release of the software, not of an installable package.
>
> Every API behaviour this depends on was checked against the live Proton API
> rather than assumed; the reasoning is recorded in the code comments next to
> the calls that rely on it.

Configure ProtonVPN's WireGuard service on OpenWrt: browser-side SRP-6a login
(TOTP 2FA supported), locally generated WireGuard keypairs registered as
account-wide certificates, an authenticated server-list cache with Load and
Score, a location set to connect and rotate across (Standard / Secure Core /
Tor), automatic rotation with handshake verification, a watchdog, per-network
traffic steering with kill switch and IPv6 leak protection, and a native LuCI
page.

> **Unofficial.** This project is not affiliated with, endorsed by, or
> supported by Proton AG. "ProtonVPN" is a trademark of its respective owner.
> Use your own ProtonVPN account.

## Installation

> The feed is published from GitHub Pages, which a **private** repository
> cannot serve on the free plan — until this repository is public the build and
> signing steps run but the final publish does not, so the URLs below are not
> live yet. Until then, build with the SDK (see *Development*).

CI builds signed, architecture-independent packages for every tag.

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

The backend needs `openssl-util` (Ed25519 key generation) and `curl`; both are
pulled in as dependencies. Log out of LuCI and back in after installing, then
open **VPN → ProtonVPN** and sign in with your Proton account.

## Screenshots

The account card and the status band: session horizon, the connected server
with its country and handshake age, and the plan's WireGuard configurations.

![Account card and connection status](docs/screenshots/overview.png)

Several tunnels side by side — each with its own key, certificate, interface
and schedule. Clicking a row switches the form to that instance; `main` is
reset rather than removed.

![The VPN instances table](docs/screenshots/instances.png)

Locations are a *set* to connect and rotate within, not a single country.
Picking a country takes it whole; opening its chip narrows it to cities.

![Choosing locations](docs/screenshots/location-picker.png)

Servers are listed with their load, cheapest first, with Quick Connect on top.
Pinning one disables rotation for that instance.

![Choosing a server](docs/screenshots/server-picker.png)

Per-network steering with a kill switch and IPv6 leak protection, so only the
networks you name leave through the tunnel.

![Traffic routing](docs/screenshots/routing.png)

![Automatic rotation](docs/screenshots/rotation.png)

![Advanced settings](docs/screenshots/advanced.png)

## Architecture

The project is the third member of a family (after
[nordvpn-luci](https://github.com/Aladex/nordvpn-luci)) and clones its
two-package layout, so the VPN service is useful without a web interface and
the LuCI app stays a thin frontend:

- **`protonvpn-wireguard`** — the backend (targets `openwrt/packages`,
  `net/protonvpn-wireguard`). ucode + procd + an rpcd/ubus object. Relays the
  SRP login HTTP steps, refreshes the session/certificate, caches the
  (authenticated) server list, generates WireGuard interfaces/peers, verifies
  handshakes, runs scheduled rotation and reports runtime status. Works from
  the CLI and over ubus with no LuCI installed.
- **`luci-app-protonvpn`** — the LuCI frontend (targets `openwrt/luci`,
  `applications/luci-app-protonvpn`). A JavaScript view that calls the
  backend's ubus methods — and computes the SRP-6a login in the browser
  (native BigInt), because the router's ucode cannot do 2048-bit modexp.

Two Proton-specific facts shape the design:

1. **Auth is SRP-6a**, not a token. The browser runs SRP; rpcd only relays
   `POST /auth/info` and `POST /auth`. The Proton password never leaves the
   browser and is never stored. Afterwards the router maintains the session
   itself: `POST /auth/refresh` (30-day session, auto-refreshed by the
   daemon) and certificate renewal (≤365 days) — both without SRP.
2. **The server list is authenticated** — `GET /vpn/logicals` returns 401
   without a live session, so nothing works before login. Sessions and the
   WireGuard private key are never stored in `/etc/config/protonvpn`
   (session: root-only state file, 0600; key: the managed network
   interface).

## Repository layout

```
protonvpn-wireguard/                         # backend package (packages feed)
├── Makefile
├── test.sh                                  # CI version smoke test
├── files/etc/config/protonvpn               # non-secret settings (owns config)
├── files/etc/init.d/protonvpn               # consolidated procd service
├── files/etc/uci-defaults/90-protonvpn-migrate
├── files/usr/bin/protonvpn-service          # uloop scheduler daemon
├── files/usr/bin/protonvpn-cache-update     # one-shot cache worker
├── files/usr/bin/protonvpn-rotate           # one-shot rotation worker
├── files/usr/share/rpcd/ucode/protonvpn.uc  # ubus object 'protonvpn'
├── files/usr/share/ucode/protonvpn/*.uc     # shared ucode modules
└── tests/                                   # offline ucode fixture/unit tests

luci-app-protonvpn/                          # LuCI frontend (luci feed)
├── Makefile
├── htdocs/luci-static/resources/view/protonvpn/overview.js
├── po/templates/protonvpn.pot
└── root/usr/share/{luci/menu.d,rpcd/acl.d}/luci-app-protonvpn.json

.github/workflows/                           # CI + signed package feed
```

## ubus API

All methods are on the `protonvpn` object. Read methods never mutate; secrets
are never returned.

```bash
ubus call protonvpn status              # runtime state, session/cert expiry
ubus call protonvpn instances           # status of every configured instance
ubus call protonvpn session_state       # session horizon and required action
ubus call protonvpn account             # plan, tier, registered configurations
ubus call protonvpn auth_info '{"username":"..."}'   # SRP step 1 relay
ubus call protonvpn auth_finish '{...}'              # SRP step 3 relay
ubus call protonvpn set_totp '{"code":"123456"}'     # 2FA upgrade
ubus call protonvpn refresh_session     # POST /auth/refresh (token rotation)
ubus call protonvpn logout              # drop the session, tunnels down
ubus call protonvpn locations           # cached country/city tree
ubus call protonvpn servers '{"locations":["ch","nl-amsterdam"],"hop_mode":"standard"}'
ubus call protonvpn certificate_renew   # re-register the WG certificate
ubus call protonvpn apply               # rebuild the peer, bring the tunnel up
ubus call protonvpn rotate_now          # one-shot rotation
ubus call protonvpn disconnect          # tunnel down, rotation paused
ubus call protonvpn refresh_locations   # async server-list refresh
ubus call protonvpn refresh_status      # progress of that refresh
ubus call protonvpn external_ip         # public IP through the tunnel
ubus call protonvpn create_instance '{"instance":"media"}'   # a second tunnel
ubus call protonvpn delete_instance '{"instance":"media"}'   # remove it again
```

## Multiple tunnels

Every instance runs its own WireGuard interface (`pv_<name>`), its own keypair
and certificate, its own location set and schedule, and — when it steers
traffic — its own routing table and firewall zone. They share one Proton
account and one server-list cache, which `main` owns. Deleting `main` resets it
to defaults instead of removing it, because it anchors both.

Proton cannot revoke a WireGuard certificate for the token a VPN client holds
(the dashboard gets there by asking for the password again). So when an
instance is deleted its certificate is instead *renewed down to ten minutes* —
a renewal supersedes the previous registration for that key, and what is left
expires on its own. Without that, every deleted instance would sit in the
account's saved configurations for a year.

## Development

Offline ucode tests (no account or network needed):

```bash
# with ucode + ucode-mod-fs + ucode-mod-math available
sh protonvpn-wireguard/tests/run.sh
```

There are also JS tests for the browser-side SRP implementation, including
cross-implementation vectors:

```bash
node --test luci-app-protonvpn/tests/*.test.mjs
```

CI runs shell/JSON static checks, LuCI ESLint on the JS view, the ucode tests,
and a snapshot-SDK build of both packages. See `.github/workflows/build.yml`.
Two things are still missing before a tag can produce installable packages:
the build job wants a self-hosted runner labelled `protonvpn-build`, and the
signed feed (`.github/workflows/feed.yml`) needs its own signing keypair in
repository secrets — see the TODO comments there.

## License

[MIT](LICENSE) — do whatever you want with it, just keep the copyright notice.

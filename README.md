# ProtonVPN WireGuard for OpenWrt

> **Status: pre-alpha scaffold.** This repository currently contains only the
> project skeleton: package metadata, config/init scaffolding, ucode module
> stubs with TODO bodies, the rpcd/ubus method table, a LuCI view skeleton and
> CI workflows. Nothing connects to ProtonVPN yet. The reconnaissance notes
> that drive the design live in `RECON.md`.

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

Two Proton-specific facts shape the design (see `RECON.md`):

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

## ubus API (planned)

All methods are on the `protonvpn` object. Read methods never mutate; secrets
are never returned.

```bash
ubus call protonvpn status              # runtime state, session/cert expiry
ubus call protonvpn instances           # status of every configured instance
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
ubus call protonvpn external_ip         # public IP through the tunnel
```

## Development

Offline ucode tests (no account or network needed):

```bash
# with ucode + ucode-mod-fs + ucode-mod-math available
sh protonvpn-wireguard/tests/run.sh
```

CI runs shell/JSON static checks, LuCI ESLint on the JS view, the ucode
tests, and a snapshot-SDK build of both packages. See
`.github/workflows/build.yml`. The signed package feed
(`.github/workflows/feed.yml`) needs its own signing keypair and repository
secrets before the first tag build — see the TODO comments there.

## License

[MIT](LICENSE) — do whatever you want with it, just keep the copyright notice.

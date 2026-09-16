# How it works

**English** · [Русский](architecture.ru.md) · [Deutsch](architecture.de.md) · [← README](../README.md)

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

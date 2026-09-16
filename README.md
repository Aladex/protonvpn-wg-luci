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

## Quick start

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

Building from source and the full installation notes: [Installation](docs/installation.md).

## Documentation

- [Installation](docs/installation.md) — the signed package feed, or a build from source
- [Usage](docs/usage.md) — logging in, location sets, multiple instances, rotation
- [Traffic routing](docs/routing.md) — source networks, the kill switch, the IPv6 modes
- [Configuration](docs/configuration.md) — every `/etc/config/protonvpn` option
- [Command line](docs/cli.md) — the ubus API, services and logs
- [How it works](docs/architecture.md) — the two packages, certificates, security
- [Development](docs/development.md) — tests and CI

## Related projects

- [nordvpn-luci](https://github.com/Aladex/nordvpn-luci) — the same design for
  NordVPN, which this project's layout follows.

## License

[MIT](LICENSE) — do whatever you want with it, just keep the copyright notice.

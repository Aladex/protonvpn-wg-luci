# ProtonVPN WireGuard für OpenWrt

[English](README.md) · [Русский](README.ru.md) · **Deutsch**

Richtet den WireGuard-Dienst von ProtonVPN unter OpenWrt ein: SRP-6a-Anmeldung
im Browser samt TOTP-Unterstützung, lokal erzeugte WireGuard-Schlüssel, die als
Proton-Zertifikate registriert werden, eine authentifizierte Serverliste mit
Last und Score, ein Standort-Set zum Verbinden und Rotieren (Standard, Secure
Core, Tor), automatische Rotation, ein Watchdog, mehrere parallele
VPN-Instanzen, netzweise Traffic-Steuerung mit Kill Switch und adaptivem
IPv6 sowie eine native LuCI-Seite.

> **Inoffiziell.** Dieses Projekt ist weder mit Proton AG verbunden noch von
> ihnen unterstützt oder befürwortet. „Proton“ und „ProtonVPN“ sind Marken
> ihrer jeweiligen Inhaber. Verwende dein eigenes ProtonVPN-Konto.

![LuCI-Übersichtsseite](docs/screenshots/overview.png)

## Schnellstart

Die CI baut für jeden Release signierte, architekturunabhängige Pakete.

**OpenWrt 24.10 (opkg):**

```sh
wget -O /etc/opkg/keys/4fcb996825e11695 \
  https://aladex.github.io/protonvpn-wg-luci/keys/4fcb996825e11695
echo 'src/gz protonvpn_luci https://aladex.github.io/protonvpn-wg-luci/packages/opkg' \
  >> /etc/opkg/customfeeds.conf
opkg update
opkg install luci-app-protonvpn      # or just protonvpn-wireguard for headless
```

**OpenWrt Snapshots / 25.x (apk):**

```sh
wget -O /etc/apk/keys/protonvpn-wg-luci-apk.pem \
  https://aladex.github.io/protonvpn-wg-luci/keys/protonvpn-wg-luci-apk.pem
echo 'https://aladex.github.io/protonvpn-wg-luci/packages/apk/packages.adb' \
  >> /etc/apk/repositories.d/customfeeds.list
apk update
apk add luci-app-protonvpn
```

Melde dich nach der Installation bei LuCI ab und wieder an, dann öffne
**VPN → ProtonVPN**.

Der Build aus den Quellen und die vollständigen Installationshinweise: [Installation](docs/installation.de.md).

## Dokumentation

- [Installation](docs/installation.de.md) — der signierte Paket-Feed oder ein Build aus den Quellen
- [Verwendung](docs/usage.de.md) — Anmeldung, Standort-Sets, mehrere Instanzen, Rotation
- [Traffic-Routing](docs/routing.de.md) — Quellnetzwerke, Kill Switch, die IPv6-Modi
- [Konfiguration](docs/configuration.de.md) — jede Option in `/etc/config/protonvpn`
- [Kommandozeile](docs/cli.de.md) — die ubus-API, Dienste und Logs
- [Wie es funktioniert](docs/architecture.de.md) — die zwei Pakete, Zertifikate, Sicherheit
- [Entwicklung](docs/development.de.md) — Tests und CI

## Verwandte Projekte

- [nordvpn-luci](https://github.com/Aladex/nordvpn-luci) — dasselbe Design für
  NordVPN, dessen Aufbau dieses Projekt folgt.

## Lizenz

[MIT](LICENSE) — mach damit, was du willst, behalte nur den Copyright-Hinweis.

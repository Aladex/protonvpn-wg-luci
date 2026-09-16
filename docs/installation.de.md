# Installation

[English](installation.md) · [Русский](installation.ru.md) · **Deutsch** · [← README](../README.de.md)

## Aus dem signierten Paket-Feed (empfohlen)

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

## Aus den Quellen

Beide Pakete sind ganz normale Feed-Pakete; baue sie mit dem OpenWrt-SDK für
deine Zielplattform:

```sh
# backend (packages feed style)
cp -r protonvpn-wireguard <sdk>/package/net/protonvpn-wireguard
# frontend (from an openwrt/luci checkout)
cp -r luci-app-protonvpn <luci>/applications/luci-app-protonvpn

make package/protonvpn-wireguard/compile V=s
make package/luci-app-protonvpn/compile V=s
```

Sie sind `PKGARCH:=all`, ein Build bedient also jede Zielplattform.

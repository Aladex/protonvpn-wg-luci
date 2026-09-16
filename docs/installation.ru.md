# Установка

[English](installation.md) · **Русский** · [Deutsch](installation.de.md) · [← README](../README.ru.md)

## Из подписанного feed-репозитория пакетов (рекомендуется)

CI собирает подписанные, архитектурно-независимые пакеты для каждого релиза.

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

После установки выйдите из LuCI и войдите снова, затем откройте
**VPN → ProtonVPN**.

## Из исходников

Оба пакета — обычные feed-пакеты; соберите их с помощью OpenWrt SDK под свою
платформу:

```sh
# backend (packages feed style)
cp -r protonvpn-wireguard <sdk>/package/net/protonvpn-wireguard
# frontend (from an openwrt/luci checkout)
cp -r luci-app-protonvpn <luci>/applications/luci-app-protonvpn

make package/protonvpn-wireguard/compile V=s
make package/luci-app-protonvpn/compile V=s
```

Они собираются с `PKGARCH:=all`, поэтому одной сборки хватает на любую
платформу.

# ProtonVPN WireGuard для OpenWrt

[English](README.md) · **Русский** · [Deutsch](README.de.md)

Настройка сервиса WireGuard от ProtonVPN на OpenWrt: вход по SRP-6a прямо в
браузере с поддержкой TOTP, локально сгенерированные ключи WireGuard, которые
регистрируются как сертификаты Proton, аутентифицированный список серверов с
нагрузкой и score, набор локаций для подключения и ротации (Standard, Secure
Core, Tor), автоматическая ротация, watchdog, несколько параллельных
VPN-инстансов, маршрутизация трафика по сетям с kill switch (аварийным
отключением) и адаптивный IPv6, а также нативная страница LuCI.

> **Неофициальный проект.** Он не связан с Proton AG, не одобрен и не
> поддерживается компанией. «Proton» и «ProtonVPN» — торговые марки их
> соответствующих владельцев. Используйте свою учётную запись ProtonVPN.

![Обзорная страница LuCI](docs/screenshots/overview.png)

## Быстрый старт

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

Сборка из исходников и полные заметки по установке: [Установка](docs/installation.ru.md).

## Документация

- [Установка](docs/installation.ru.md) — подписанный feed пакетов или сборка из исходников
- [Использование](docs/usage.ru.md) — вход, наборы локаций, несколько инстансов, ротация
- [Маршрутизация трафика](docs/routing.ru.md) — исходные сети, kill switch, режимы IPv6
- [Конфигурация](docs/configuration.ru.md) — все параметры `/etc/config/protonvpn`
- [Командная строка](docs/cli.ru.md) — ubus API, сервисы и логи
- [Как это устроено](docs/architecture.ru.md) — два пакета, сертификаты, безопасность
- [Разработка](docs/development.ru.md) — тесты и CI

## Связанные проекты

- [nordvpn-luci](https://github.com/Aladex/nordvpn-luci) — тот же дизайн для
  NordVPN, чью раскладку повторяет этот проект.

## Лицензия

[MIT](LICENSE) — делайте что угодно, только сохраняйте копирайт.

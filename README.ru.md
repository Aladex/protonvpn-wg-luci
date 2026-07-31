# ProtonVPN WireGuard для OpenWrt

[English](README.md) · **Русский** · [Deutsch](README.de.md)

Настройка сервиса WireGuard от ProtonVPN на OpenWrt: вход по SRP-6a прямо в
браузере с поддержкой TOTP, локально сгенерированные ключи WireGuard, которые
регистрируются как сертификаты Proton, аутентифицированный список серверов с
нагрузкой и score, набор локаций для подключения и ротации (Standard, Secure
Core, Tor), автоматическая ротация, watchdog, несколько параллельных
VPN-инстансов, маршрутизация трафика по сетям с kill switch (аварийным
отключением) и защитой от утечки IPv6, а также нативная страница LuCI.

> **Неофициальный проект.** Он не связан с Proton AG, не одобрен и не
> поддерживается компанией. «Proton» и «ProtonVPN» — торговые марки их
> соответствующих владельцев. Используйте свою учётную запись ProtonVPN.

![Обзорная страница LuCI](docs/screenshots/overview.png)

## Архитектура

Проект поставляется в виде **двух пакетов**, чтобы VPN-сервис был полезен и без
веб-интерфейса, а приложение LuCI оставалось тонким фронтендом:

- **`protonvpn-wireguard`** — бэкенд (целевой feed `openwrt/packages`,
  `net/protonvpn-wireguard`). ucode + procd + объект rpcd/ubus. Ретранслирует
  шаги SRP-логина, поддерживает живыми сессию и сертификаты, кэширует список
  серверов, генерирует интерфейсы и пиры WireGuard, проверяет handshake
  (рукопожатия), выполняет запланированную ротацию и отдаёт статус в рантайме.
  Работает из CLI и через ubus без установленного LuCI.
- **`luci-app-protonvpn`** — фронтенд LuCI (целевой feed `openwrt/luci`,
  `applications/luci-app-protonvpn`). JavaScript-представление, вызывающее
  методы ubus бэкенда и вычисляющее доказательство SRP-6a прямо в браузере
  (нативный BigInt), потому что ucode на роутере не потянет 2048-битное
  возведение в степень по модулю.

Дизайн определяют два специфичных для Proton факта:

1. **Аутентификация — это SRP-6a**, а не токен. SRP выполняет браузер; роутер
   лишь ретранслирует HTTP-шаги. Пароль Proton не попадает на роутер и никогда
   не сохраняется. Дальше роутер сам поддерживает сессию (`/auth/refresh`,
   горизонт 30 дней) и продлевает сертификат WireGuard — и то, и другое без
   повторных вопросов.
2. **Список серверов аутентифицирован** — `GET /vpn/logicals` без живой сессии
   отвечает 401, поэтому выбор локаций наполняется только после входа.

## Установка

### Из подписанного feed-репозитория пакетов (рекомендуется)

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

### Из исходников

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

## Использование

Откройте **VPN → ProtonVPN** и нажмите **Log in** (Войти). Модальное окно
спросит ваш адрес Proton и пароль, а код TOTP — только если он включён в
учётной записи; пароль обрабатывается в браузере и никогда не отправляется на
роутер. Список серверов скачивается сразу после входа; он большой (Proton
публикует десятки тысяч серверов), поэтому первое обновление занимает несколько
секунд.

Затем выберите **набор локаций** (location set) — страны целиком или отдельные
города внутри них — и нажмите **Save and reconnect** (Сохранить и
переподключиться). И первичное подключение, и каждая последующая ротация
выбирают из этого набора. Оставьте **Server** (Сервер) в положении *Automatic*,
чтобы бэкенд выбирал по нагрузке, либо закрепите конкретный; закрепление
отключает ротацию для этого инстанса.

**Hop mode** (Режим переходов) переключает между Standard, Secure Core (вход
через укреплённый сервер, принадлежащий самому Proton, в стране с дружественным
к приватности законодательством) и Tor (выход через сеть Tor). Это три разных
продукта, а не фильтры над одним списком, поэтому смена режима очищает набор
локаций: выберите заново под новый режим.

![Выбор локаций](docs/screenshots/location-picker.png)

Серверы перечислены от наименьшей нагрузки, сверху — выбор самого
разгруженного одним кликом. При равной нагрузке порядок по имени, с разбором
чисел: `NL#5` идёт раньше `NL#27`, а не позже:

![Выбор сервера](docs/screenshots/server-picker.png)

Полоса статуса показывает подключённый сервер, возраст handshake и внешний IP,
видимый через туннель, — единственную проверку, которая доказывает, что трафик
действительно уходит через VPN, чего один handshake не даёт.

### Несколько инстансов

Каждый инстанс поднимает собственный интерфейс WireGuard (`pv_<name>`),
собственную пару ключей и сертификат, собственный набор локаций и расписание,
а если он направляет трафик — ещё и собственную таблицу маршрутизации и зону
файрвола. Общими остаются одна учётная запись Proton и один кэш списка серверов,
которым владеет `main`. Удаление `main` сбрасывает его к значениям по умолчанию
вместо удаления, потому что он держит и то, и другое.

![Таблица VPN-инстансов](docs/screenshots/instances.png)

Типичный сценарий: `main` для LAN и второй инстанс для гостевой сети или
медиаустройства, которое должно выходить в другой стране.

### Маршрутизация трафика

При **автоматической маршрутизации** бэкенд создаёт зону файрвола и отправляет
весь трафик LAN через туннель. Он не трогает ничего, если обнаружит собственную
таблицу маршрутизации или маршруты, добавленные вами.

Вместо того чтобы гнать через туннель всё, укажите **исходные сети**: уйдут
только они — по policy-правилам в собственную таблицу маршрутизации инстанса.
**Kill switch** тогда закрывает этим сетям выход в WAN, пока туннель лежит, а
**защита от утечки IPv6** не даёт прямому IPv6 обойти его.

IPv6 именно блокируется, а не маршрутизируется, и это сделано намеренно. Proton
выдаёт туннелю адрес IPv6 и принимает `::/0`, так что интерфейс выглядит
dual-stack, — но серверы IPv6 не форвардят. Замерено на серверах в двух
странах: v6-пакеты увеличивают счётчик отправленного у WireGuard, и назад не
приходит ничего, тогда как IPv4 на том же туннеле ходит ровно один к одному;
молчит даже собственный внутритуннельный резолвер Proton. Официальная
рекомендация Proton для ручных конфигураций WireGuard — отключать IPv6.
Маршрутизировать его всё-таки в туннель значило бы не включить IPv6, а
проглотить его, а чёрная дыра хуже блокировки: клиенты будут на каждом
соединении ждать, пока отработает Happy Eyeballs, а всё, что не браузер, просто
зависнет. Блокировка же оставляет их на IPv4, который работает.

![Маршрутизация трафика](docs/screenshots/routing.png)

### Ротация и watchdog

Ротация переходит на другой сервер из набора — либо каждые N минут, либо в
заданное время суток. Кандидат принимается только после того, как состоялся
настоящий handshake WireGuard; если он не состоялся, пробуется следующий
кандидат, а если не подошёл ни один — восстанавливается предыдущий пир.

Опциональный **watchdog** переподключается, когда туннель протухает — детект
идёт по handshake, без внешних проб, — и не лезет под руку, когда закреплён
конкретный сервер.

![Автоматическая ротация](docs/screenshots/rotation.png)

## Конфигурация (`/etc/config/protonvpn`)

Всё перечисленное ниже доступно и со страницы, из раздела *Advanced settings*
(Расширенные настройки):

![Расширенные настройки](docs/screenshots/advanced.png)

Одна секция `config instance` на туннель; `main` — инстанс по умолчанию.
Секреты здесь не хранятся: сессия лежит в файле состояния, доступном только
root, а приватный ключ WireGuard — на управляемом сетевом интерфейсе.

| Параметр | По умолчанию | Значение |
|---|---|---|
| `enabled` | `0` | Главный выключатель; свежая установка поставляется выключенной |
| `interface` | `protonvpn` | Управляемый интерфейс WireGuard |
| `locations` (list) | — | Страны (`ch`) и/или города (`nl-amsterdam`) для подключения и ротации |
| `hop_mode` | `standard` | `standard`, `secure_core` или `tor` |
| `fixed_server` | — | Закрепить один сервер по имени; отключает ротацию |
| `rotation_enabled` | `0` | Автоматическая ротация |
| `rotation_mode` | `interval` | `interval` или `time` |
| `rotation_interval` | `360` | Минут между ротациями |
| `rotation_time` | `04:30` | Время суток для режима `time` |
| `watchdog` | `0` | Автоматически переподключаться, когда туннель протух |
| `verify_timeout` | `8` | Сколько секунд ждать handshake, прежде чем отбраковать сервер |
| `max_retries` | `10` | Сколько серверов-кандидатов может перебрать одна ротация |
| `auto_routing` | `1` | Создать зону файрвола и направить в туннель весь трафик LAN |
| `source_network` | — | Направлять только эти сети вместо всего трафика |
| `routing_table` | — | Своя таблица маршрутизации (пусто = main) |
| `killswitch` | `0` | Закрыть направляемым сетям выход в WAN, пока туннель лежит |
| `block_ipv6` | `1` | Блокировать прямой IPv6, чтобы он не мог обойти туннель |
| `vpn_dns` | `off` | `off` (системный резолвер) или `standard` (в туннеле, 10.2.0.1) |
| `mtu` | — | MTU интерфейса (UI рекомендует MTU WAN − 80) |
| `cache_dir` | — | Каталог кэша списка серверов, общий для всех инстансов |
| `cache_refresh_interval` | `21600` | Секунд между фоновыми обновлениями кэша |

## ubus API

Все методы принадлежат объекту `protonvpn`. Методы чтения ничего не изменяют;
секреты никогда не возвращаются.

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
ubus call protonvpn rotate_now          # one-shot rotation
ubus call protonvpn disconnect          # tunnel down, rotation paused
ubus call protonvpn refresh_locations   # async server-list refresh
ubus call protonvpn refresh_status      # progress of that refresh
ubus call protonvpn external_ip         # public IP through the tunnel
ubus call protonvpn create_instance '{"instance":"media"}'
ubus call protonvpn delete_instance '{"instance":"media"}'
```

## Сертификаты и список устройств

Клиент WireGuard в Proton — это **сертификат**, а не сессия: каждый инстанс
занимает одну из сохранённых в учётной записи конфигураций WireGuard (дашборд →
*Downloads* → *WireGuard configuration*). `/vpn/v1/sessions` отслеживает
легаси-логины OpenVPN/IKEv2 и остаётся пустым, сколько бы туннелей ни было
поднято, поэтому карточка учётной записи считает вместо них зарегистрированные
сертификаты.

Сертификат нельзя отозвать тем токеном, который есть у VPN-клиента, — дашборд
добивается этого, переспрашивая пароль. Поэтому при удалении инстанса его
сертификат вместо отзыва продлевается на минимальный срок жизни, который выдаёт
API (десять минут): продление вытесняет предыдущую регистрацию, а остаток
истекает сам. Без этого каждый удалённый инстанс висел бы в конфигурациях
учётной записи год.

## Безопасность

- **Пароль Proton не попадает на роутер.** SRP доказывает знание пароля, не
  пересылая его, а само доказательство вычисляется в браузере.
- Если LuCI отдаётся по обычному HTTP, страница, которая вычисляет это
  доказательство, приходит по неаутентифицированному каналу — любой в локальной
  сети мог бы её подменить. Настоятельно рекомендуется отдавать LuCI по HTTPS
  (`luci-ssl`).
- Сессия (UID, access- и refresh-токены) лежит в файле состояния, доступном
  только root, в `/etc/protonvpn`, с правами 0600, и **не** в UCI — так она не
  попадает ни в диффы конфигурации, ни в бэкапы `sysupgrade`.
- Область действия токена покрывает только VPN и настройки учётной записи;
  запросы к эндпоинтам почты и Drive отвечают 403.
- Приватный ключ WireGuard хранится там же, где и любой другой ключ WireGuard в
  OpenWrt: на управляемом интерфейсе в `/etc/config/network`.

## Сервисы и логи

```sh
/etc/init.d/protonvpn status
/etc/init.d/protonvpn version
logread -e protonvpn
```

Демон обновляет сессию и кэш серверов, продлевает сертификаты до наступления
собственного `RefreshTime` от Proton, ведёт часы ротации и watchdog.

## Разработка

Offline-тесты ucode (не нужны ни аккаунт, ни сеть):

```sh
# with ucode + ucode-mod-fs + ucode-mod-math available
sh protonvpn-wireguard/tests/run.sh
```

JS-тесты браузерной реализации SRP, включая кросс-реализационные векторы:

```sh
node --test luci-app-protonvpn/tests/*.test.mjs
```

CI выполняет статические проверки shell/JSON, LuCI ESLint для представления,
тесты ucode и сборку обоих пакетов под snapshot-SDK; на тегах дополнительно
собирается и публикуется подписанный feed.

## Связанные проекты

- [nordvpn-luci](https://github.com/Aladex/nordvpn-luci) — тот же дизайн для
  NordVPN, чью раскладку повторяет этот проект.

## Лицензия

[MIT](LICENSE) — делайте что угодно, только сохраняйте копирайт.

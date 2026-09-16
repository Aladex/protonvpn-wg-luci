# Разработка

[English](development.md) · **Русский** · [Deutsch](development.de.md) · [← README](../README.ru.md)

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

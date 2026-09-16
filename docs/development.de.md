# Entwicklung

[English](development.md) · [Русский](development.ru.md) · **Deutsch** · [← README](../README.de.md)

Offline-ucode-Tests (weder Konto noch Netzwerk nötig):

```sh
# with ucode + ucode-mod-fs + ucode-mod-math available
sh protonvpn-wireguard/tests/run.sh
```

JS-Tests für die browserseitige SRP-Implementierung, inklusive
implementierungsübergreifender Testvektoren:

```sh
node --test luci-app-protonvpn/tests/*.test.mjs
```

Die CI führt statische Shell-/JSON-Prüfungen aus, LuCI-ESLint auf der Ansicht,
die ucode-Tests und einen Snapshot-SDK-Build beider Pakete; bei Tags werden
zusätzlich der signierte Feed gebaut und veröffentlicht.

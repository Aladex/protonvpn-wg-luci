# Development

**English** · [Русский](development.ru.md) · [Deutsch](development.de.md) · [← README](../README.md)

Offline ucode tests (no account or network needed):

```sh
# with ucode + ucode-mod-fs + ucode-mod-math available
sh protonvpn-wireguard/tests/run.sh
```

JS tests for the browser-side SRP implementation, including
cross-implementation vectors:

```sh
node --test luci-app-protonvpn/tests/*.test.mjs
```

CI runs shell/JSON static checks, LuCI ESLint on the view, the ucode tests and
a snapshot-SDK build of both packages; tags additionally build and publish the
signed feed.

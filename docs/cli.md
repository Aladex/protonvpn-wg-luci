# Command line

**English** · [Русский](cli.ru.md) · [Deutsch](cli.de.md) · [← README](../README.md)

## ubus API

All methods are on the `protonvpn` object. Read methods never mutate; no
secret is ever returned.

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
ubus call protonvpn apply_start         # the same apply, detached; returns at once
ubus call protonvpn apply_status        # progress/outcome of that apply
ubus call protonvpn rotate_now          # one-shot rotation
ubus call protonvpn disconnect          # tunnel down, rotation paused
ubus call protonvpn refresh_locations   # async server-list refresh
ubus call protonvpn refresh_status      # progress of that refresh
ubus call protonvpn external_ip         # public IP through the tunnel
ubus call protonvpn create_instance '{"instance":"media"}'
ubus call protonvpn delete_instance '{"instance":"media"}'
```

Without `offset`, `servers` answers as it always did: the whole list in
`relays`. A selection too large for one ubus message (the United States is one)
is refused with an `error` and `"paged": true` instead of being cut short. Ask
for pages then: pass `"offset": 0`, and as long as a reply carries `next`, pass
that back as `offset`. `total` is the size of the whole selection, and
`generation` identifies the server-list cache a page was cut from: when it
changes between two pages the cache was replaced, so start again at 0. An entry
too large to send at all is reported as an `error` too:

```bash
ubus call protonvpn servers '{"locations":["us"],"hop_mode":"standard","offset":0}'
```

## Services and logs

```sh
/etc/init.d/protonvpn status
/etc/init.d/protonvpn version
logread -e protonvpn
```

The daemon refreshes the session and the server cache, renews certificates
before Proton's own `RefreshTime`, runs the rotation clock and the watchdog.

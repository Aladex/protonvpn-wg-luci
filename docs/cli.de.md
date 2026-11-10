# Kommandozeile

[English](cli.md) · [Русский](cli.ru.md) · **Deutsch** · [← README](../README.de.md)

## ubus-API

Alle Methoden liegen am `protonvpn`-Objekt. Lesende Methoden verändern nie
etwas; es wird nie ein Geheimnis zurückgegeben.

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

Ohne `offset` antwortet `servers` wie bisher: die ganze Liste in `relays`. Eine
Auswahl, die nicht in eine ubus-Nachricht passt (die USA zum Beispiel), wird mit
einem `error` und `"paged": true` abgelehnt, statt abgeschnitten zu werden. Dann
seitenweise abfragen: `"offset": 0` übergeben und, solange eine Antwort `next`
enthält, diesen Wert als `offset` zurückgeben. `total` ist die Größe der
gesamten Auswahl, `generation` bezeichnet den Server-Cache, aus dem die Seite
stammt: Ändert er sich zwischen zwei Seiten, wurde der Cache ersetzt — dann bei
0 neu beginnen. Ein Eintrag, der zu groß zum Senden ist, wird ebenfalls als
`error` gemeldet:

```bash
ubus call protonvpn servers '{"locations":["us"],"hop_mode":"standard","offset":0}'
```

## Dienste und Logs

```sh
/etc/init.d/protonvpn status
/etc/init.d/protonvpn version
logread -e protonvpn
```

Der Daemon aktualisiert die Sitzung und den Server-Cache, erneuert Zertifikate
vor Protons eigener `RefreshTime` und betreibt den Rotationstakt sowie den
Watchdog. Außerdem prüft er, über welchen Uplink der Endpoint jedes Tunnels
läuft (siehe [Traffic-Routing](routing.de.md#der-weg-des-tunnels-selbst));
derselbe Durchlauf läuft bei jedem Interface-Ereignis und von Hand als
`protonvpn-uplink`, das pro Instanz ausgibt, was es getan hat.

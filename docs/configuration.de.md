# Konfiguration (`/etc/config/protonvpn`)

[English](configuration.md) · [Русский](configuration.ru.md) · **Deutsch** · [← README](../README.de.md)

Alles Folgende ist auch über die *Advanced settings* (Erweiterte Einstellungen)
der Seite erreichbar:

![Erweiterte Einstellungen](screenshots/advanced.png)

Ein `config instance`-Abschnitt pro Tunnel; `main` ist der Standard. Geheimnisse
werden hier nie gespeichert: die Sitzung liegt in einer nur für root lesbaren
State-Datei und der private WireGuard-Schlüssel am verwalteten
Netzwerk-Interface.

| Option | Standard | Bedeutung |
|---|---|---|
| `enabled` | `0` | Hauptschalter; eine frische Installation wird deaktiviert ausgeliefert |
| `interface` | `protonvpn` | Verwaltetes WireGuard-Interface |
| `locations` (list) | — | Länder (`ch`) und/oder Städte (`nl-amsterdam`) zum Verbinden und Rotieren |
| `hop_mode` | `standard` | `standard`, `secure_core` oder `tor` |
| `fixed_server` | — | Einen Server namentlich anpinnen; deaktiviert die Rotation |
| `rotation_enabled` | `0` | Automatische Rotation |
| `rotation_mode` | `interval` | `interval` oder `time` |
| `rotation_interval` | `360` | Minuten zwischen zwei Rotationen |
| `rotation_time` | `04:30` | Tageszeit für den Modus `time` |
| `watchdog` | `0` | Automatisch neu verbinden, wenn der Tunnel veraltet |
| `verify_timeout` | `8` | Sekunden, die auf einen Handshake gewartet wird, bevor ein Server verworfen wird |
| `max_retries` | `10` | Kandidaten-Server, die eine Rotation probieren darf |
| `auto_routing` | `1` | Firewall-Zone anlegen und den gesamten LAN-Traffic leiten |
| `source_network` | — | Nur diese Netzwerke steuern statt alles |
| `routing_table` | — | Eigene Routing-Tabelle (leer = main) |
| `killswitch` | `0` | Den gesteuerten Netzwerken das WAN sperren, solange der Tunnel unten ist |
| `ipv6_mode` | `block` | Umgang mit IPv6: `block` (verbieten), `auto` (durch den Tunnel auf Gateways, die IPv6 weiterleiten, sonst verbieten; nur bei geleiteten Netzwerken) oder `off` (nicht anfassen) |
| `require_ipv6` | `0` | Nur Gateways berücksichtigen, die IPv6 weiterleiten — beim ersten Verbinden, bei der Rotation und beim Watchdog gleichermaßen. Gilt nur mit `ipv6_mode` `auto`, `hop_mode` `standard` und geleitetem Routing; enthalten die gewählten Standorte kein solches Gateway, verbindet sich die Instanz nicht |
| `vpn_dns` | `off` | `off` (System-Resolver) oder `standard` (im Tunnel, 10.2.0.1) |
| `mtu` | — | Interface-MTU (die UI empfiehlt WAN-MTU − 80) |
| `cache_dir` | — | Verzeichnis für den Serverlisten-Cache, von allen Instanzen gemeinsam genutzt |
| `cache_refresh_interval` | `21600` | Sekunden zwischen den Cache-Aktualisierungen im Hintergrund |

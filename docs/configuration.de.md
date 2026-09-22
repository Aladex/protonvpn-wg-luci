# Konfiguration (`/etc/config/protonvpn`)

[English](configuration.md) · [Русский](configuration.ru.md) · **Deutsch** · [← README](../README.de.md)

Alles Folgende ist auch über die *Advanced settings* (Erweiterte Einstellungen)
der Seite erreichbar, sofern nicht als UCI-only markiert:

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
| `ipv6_mode` | `block` | Umgang mit IPv6: `block` (verbieten), `auto` (durch den Tunnel auf Gateways, die IPv6 weiterleiten, sonst verbieten) oder `off` (nicht anfassen). `auto` hängt an den netzspezifischen Policy-Regeln, die nur das geleitete Routing erzeugt, und ist daher wirkungslos bei eingeschaltetem `auto_routing`, ohne `source_network` oder ohne `routing_table`; die Seite nennt die zutreffende Bedingung, statt still `block` zu speichern. `block` ist der Standard, weil ein IPv6-Pfad am Tunnel vorbei deine Adresse genauso offenlegt wie gar kein VPN |
| `require_ipv6` | `0` | Nur Gateways berücksichtigen, die IPv6 weiterleiten — beim ersten Verbinden, bei der Rotation und beim Watchdog gleichermaßen. Gilt nur mit `ipv6_mode` `auto`, `hop_mode` `standard` und geleitetem Routing; enthalten die gewählten Standorte kein solches Gateway, verbindet sich die Instanz nicht |
| `vpn_dns` | `off` | `off` (System-Resolver) oder `standard` (im Tunnel, 10.2.0.1) |
| `mtu` | — | Interface-MTU (die UI empfiehlt WAN-MTU − 80) |
| `cache_dir` | — | Verzeichnis für den Serverlisten-Cache, von allen Instanzen gemeinsam genutzt |
| `cache_refresh_interval` | `21600` | Sekunden zwischen den Cache-Aktualisierungen im Hintergrund |
| `app_version` | — | Client-Version, die bei Proton-API-Aufrufen gestempelt wird (`x-pm-appversion`), von allen Instanzen gemeinsam genutzt. In der LuCI-Oberfläche auf der Karte **Proton-Konto** neben den Anmelde-Schaltflächen als **Client-Version** änderbar — eine Aufklappzeile, deren Kopf immer die wirksame Version nennt; sie sitzt auf dieser Karte, weil es eine globale Einstellung ist und sie genau dann gebraucht wird, wenn eine Anmeldung gerade fehlgeschlagen ist. **Versionen abrufen** fragt ab, was der offizielle Linux-Client veröffentlicht hat, und füllt die Liste. Die Liste ist nur ein Angebot — Sie wählen einen Eintrag und speichern ihn wie jede andere Einstellung, geändert wird nie etwas von selbst. Ohne Abruf (und nach einem fehlgeschlagenen) bietet die Liste weiterhin die eingebaute Version und den aktuell gespeicherten Wert an, sodass das blosse Öffnen der Seite einen bereits wirksamen Wert weder verlieren noch stillschweigend ändern kann. Der erste Eintrag, **Im Paket eingebaut**, ist der leere Wert und für fast alle die richtige Wahl. Nur setzen, wenn Proton die eingebaute Version abzulehnen beginnt — das ist **Code 5003** „diese Version der App wird nicht mehr unterstützt", nicht Code 2028 (eine vorübergehende Kontosperre) und nicht Code 8002 (falsche Zugangsdaten oder unbekannter Benutzer) — und noch kein Paket-Update installiert ist. Die aktuelle Zeichenkette des offiziellen Linux-Clients verwenden, z. B. `linux-vpn-gtk@4.18.2` (siehe `versions.yml` in ProtonVPN/proton-vpn-gtk-app). Ungültige Werte werden ignoriert. Wirkt sofort. Wird aus dem `globals`-Abschnitt gelesen, wenn einer existiert, der dann Vorrang vor `main` hat — die Option in dem Fall dort setzen |

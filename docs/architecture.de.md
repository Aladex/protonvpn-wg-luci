# Wie es funktioniert

[English](architecture.md) · [Русский](architecture.ru.md) · **Deutsch** · [← README](../README.de.md)

## Architektur

Das Projekt wird als **zwei Pakete** ausgeliefert, damit der VPN-Dienst auch
ohne Weboberfläche nützlich ist und die LuCI-App ein schlankes Frontend bleibt:

- **`protonvpn-wireguard`** — das Backend (Ziel `openwrt/packages`,
  `net/protonvpn-wireguard`). ucode + procd + ein rpcd/ubus-Objekt. Leitet die
  SRP-Login-Schritte weiter, hält Sitzung und Zertifikate am Leben, speichert
  die Serverliste zwischen, erzeugt WireGuard-Interfaces und -Peers,
  verifiziert Handshakes, führt die geplante Rotation aus und meldet den
  Laufzeitstatus. Funktioniert über die CLI und über ubus, auch ohne
  installiertes LuCI.
- **`luci-app-protonvpn`** — das LuCI-Frontend (Ziel `openwrt/luci`,
  `applications/luci-app-protonvpn`). Eine JavaScript-Ansicht, die die
  ubus-Methoden des Backends aufruft und den SRP-6a-Beweis im Browser berechnet
  (natives BigInt), weil das ucode des Routers keine 2048-Bit-Modexp
  bewältigen kann.

Zwei Proton-spezifische Gegebenheiten prägen das Design:

1. **Die Authentifizierung ist SRP-6a**, kein Token. Der Browser führt SRP aus;
   der Router leitet lediglich die HTTP-Schritte weiter. Das Proton-Passwort
   erreicht den Router nie und wird nie gespeichert. Danach hält der Router die
   Sitzung selbst aufrecht (`/auth/refresh`, 30-Tage-Horizont) und erneuert das
   WireGuard-Zertifikat — beides, ohne erneut nachzufragen.
2. **Die Serverliste ist authentifiziert** — `GET /vpn/logicals` antwortet ohne
   lebende Sitzung mit 401, deshalb füllt sich die Standortauswahl erst nach
   der Anmeldung.

## Zertifikate und die Geräteliste

Ein WireGuard-Client ist bei Proton ein **Zertifikat**, keine Sitzung: die im
Konto gespeicherten WireGuard-Konfigurationen (Dashboard → *Downloads* →
*WireGuard configuration*) sind das, was jede Instanz belegt. `/vpn/v1/sessions`
verfolgt die alten OpenVPN-/IKEv2-Anmeldungen und bleibt leer, egal wie viele
Tunnel aktiv sind — deshalb zählt die Kontokarte stattdessen die registrierten
Zertifikate.

Ein Zertifikat lässt sich mit dem Token, den ein VPN-Client besitzt, nicht
widerrufen — das Dashboard schafft das nur, indem es erneut nach dem Passwort
fragt. Wird eine Instanz gelöscht, wird ihr Zertifikat deshalb stattdessen auf
die kürzeste Lebensdauer erneuert, die die API vergibt (zehn Minuten): eine
Erneuerung verdrängt die vorherige Registrierung, und der Rest läuft von selbst
ab. Ohne das würde jede gelöschte Instanz ein Jahr lang in den Konfigurationen
des Kontos herumliegen.

## Sicherheit

- Das **Proton-Passwort erreicht den Router nie**. SRP beweist dessen Kenntnis,
  ohne es zu übertragen, und der Beweis wird im Browser berechnet.
- Wird LuCI über einfaches HTTP ausgeliefert, kommt ausgerechnet die Seite, die
  diesen Beweis berechnet, über einen nicht authentifizierten Kanal — jeder im
  LAN könnte sie austauschen. LuCI über HTTPS auszuliefern (`luci-ssl`) ist
  dringend empfohlen.
- Die Sitzung (UID, Access- und Refresh-Token) liegt in einer nur für root
  lesbaren State-Datei unter `/etc/protonvpn`, Modus 0600, und **nicht** in UCI
  — so bleibt sie aus Config-Diffs und `sysupgrade`-Backups heraus.
- Der Geltungsbereich des Tokens deckt nur VPN- und Kontoeinstellungen ab;
  Anfragen an die Mail- und Drive-Endpunkte antworten mit 403.
- Der private WireGuard-Schlüssel liegt dort, wo unter OpenWrt jeder andere
  WireGuard-Schlüssel liegt: am verwalteten Interface in
  `/etc/config/network`.

# Verwendung

[English](usage.md) · [Русский](usage.ru.md) · **Deutsch** · [← README](../README.de.md)

Öffne **VPN → ProtonVPN** und klicke auf **Log in** (Anmelden). Der Dialog
fragt nach deiner Proton-Adresse und deinem Passwort — und nach einem
TOTP-Code nur dann, wenn das Konto einen verwendet. Das Passwort wird im
Browser verarbeitet und nie an den Router gesendet. Die Serverliste wird direkt
nach der Anmeldung heruntergeladen; sie ist groß (Proton veröffentlicht
Zehntausende Server), deshalb dauert die erste Aktualisierung einige Sekunden.

Stelle dann ein **Standort-Set** (location set) zusammen. Die Auswahl ist ein
Akkordeon: Ein Klick auf ein Land wählt es komplett aus, und der Pfeil am
rechten Ende der Zeile klappt die Städte dieses Landes direkt in der Liste
auf — so lässt sich das Set auf einzelne Städte eingrenzen, ohne die Liste
je zu verlassen. Jede Zeile zeigt die durchschnittliche Last ihrer
Gateways im aktuellen Hop-Modus. Verlangt die Instanz IPv6-Gateways (die
Option *Only use gateways that forward IPv6*, wirksam bei Automatic-IPv6 im
Standard-Modus mit geleitetem Routing), zeigt die Zeile zusätzlich, wie viele
ihrer Gateways IPv6 weiterleiten. Im Kopf des Panels, neben dem Filterfeld,
liegt außerdem der Schalter **IPv6 only** (Nur IPv6): Ist er aktiv, bleiben
Länder und Städte ohne IPv6-weiterleitende Gateways außen vor, und eine Zeile
unter der Liste sagt, wie viele ausgeblendet wurden — getrennt für Länder und
für Städte, damit die Eingrenzung nie still geschieht. Der IPv6-Zähler in den
Zeilen erscheint, solange der Schalter aktiv ist, auch wenn die Instanz kein
IPv6 verlangt. Es ist ein reiner Ansichtsfilter: Er ändert, was die Liste
zeigt, niemals was die Instanz speichert oder wohin sie sich verbindet — das
bleibt der Option *Only use gateways that forward IPv6* vorbehalten, und der
Schalter ist standardmäßig aktiv, wenn diese Option bereits eingeschaltet
ist. In Secure Core und Tor ist der Schalter nicht verfügbar, weil diese
Gateways niemals IPv6 weiterleiten (das Bit ist bei 0 von 122
Secure-Core-Servern und 0 von 7 Tor-Servern der gesamten Flotte gesetzt).
Klicke auf **Save and reconnect** (Speichern und
neu verbinden). Sowohl die erste Verbindung als auch jede spätere Rotation
wählt aus diesem Set. Lass **Server** auf *Automatic*, damit das Backend
zufällig einen Server aus dem Set wählt, oder pinne einen fest; das Anpinnen
deaktiviert die Rotation für
diese Instanz.

![Der Filter „IPv6 only“](screenshots/location-filter.png)

Der **Hop-Modus** (Hop mode) schaltet zwischen Standard, Secure Core (Eintritt
über einen gehärteten, Proton-eigenen Server in einem datenschutzfreundlichen
Land) und Tor (Austritt über das Tor-Netzwerk) um. Die drei sind eigenständige
Produkte und keine Filter über einer gemeinsamen Liste, deshalb leert ein
Moduswechsel das Standort-Set: wähle für den neuen Modus neu aus.

![Standorte wählen](screenshots/location-picker.png)

Die Server sind nach geringster Last sortiert, mit der Auswahl des am wenigsten
ausgelasteten Servers ganz oben. Bei gleicher Last wird nach Namen sortiert,
numerisch — `NL#5` steht also vor `NL#27`, nicht dahinter:

![Server wählen](screenshots/server-picker.png)

Die Karte **Proton-Konto** am Seitenanfang ist eine einzige Zeile, solange die
Sitzung in Ordnung ist — der Zustand und das Datum, bis zu dem sie läuft. Eine
Erklärung kommt nur in den Zuständen dazu, die etwas von Ihnen verlangen: eine
abgelaufene Sitzung, ein ausstehender Zwei-Faktor-Code oder gar keine Sitzung.
Die Client-Version sitzt auf derselben Karte hinter einer Aufklappzeile, deren
Kopf immer die wirksame Version nennt.

Die Zustandskarte darunter ist ebenfalls eine Zeile — was der Tunnel tut, auf
welchem Server er ist und wo dieser Server steht — und darunter die Fakten als
beschriftete Paare: Handshake-Alter, IPv6, Rotation, Zertifikat, externe IP
und Tarif. Die durch den Tunnel sichtbare externe IP ist die einzige Prüfung,
die belegt, dass der Traffic wirklich über das VPN hinausgeht, was ein
Handshake allein nicht tut. **Neu verbinden** steht immer in der Zeile;
**Aktualisieren**, **Jetzt rotieren** und **Deaktivieren** treten daneben,
sobald das Fenster breit genug ist, und rücken unterhalb von etwa 34em hinter
die Schaltfläche **⋯**.

Die gewählten Standorte stehen unter der Auswahl, eine Zeile je Land: Flagge,
Name, wie viel von diesem Land im Satz ist, und ein × zum Entfernen. Zeile und
× sind beide mit Tab erreichbar und mit Enter auslösbar, ebenso die Zeilen in
beiden Auswahllisten. **Escape** schliesst jede der beiden, ebenso ihr ✕ und
das Auswählen eines Servers — und jeder dieser Wege gibt die Tastatur an die
Schaltfläche zurück, die diese Liste öffnet, nicht an die Seite dahinter. Ein Klick auf die
Zeile öffnet wieder die Städte dieses Landes. Ein gespeicherter Standort, den die Serverliste nicht mehr kennt, wird
gestrichelt und mit *not in the server list* angezeigt: er steht weiterhin im
gespeicherten Satz und wird bei jedem Speichern zurückgeschrieben, wird also
gezeigt statt versteckt — sein × ist der Weg, ihn loszuwerden. Ein paar Länder liefert
Proton unter Codes, für die Unicode keine Flagge kennt — der reale Fall ist
Kosovo, das als `XK` kommt — und die zeigen den Zwei-Buchstaben-Code in einem
kleinen Feld statt des Glyphs „weisse Flagge mit Fragezeichen", zu dem eine
erfundene Flagge wird.

## Mehrere Instanzen

Jede Instanz betreibt ihr eigenes WireGuard-Interface (`pv_<name>`), ihr
eigenes Schlüsselpaar samt Zertifikat, ihr eigenes Standort-Set und ihren
eigenen Zeitplan — und, sofern sie Traffic steuert, ihre eigene Routing-Tabelle
und Firewall-Zone. Gemeinsam genutzt werden ein Proton-Konto und ein
Serverlisten-Cache, die `main` besitzt. `main` zu löschen setzt die Instanz auf
die Standardwerte zurück, statt sie zu entfernen, denn sie verankert beides.

![Die Tabelle der VPN-Instanzen](screenshots/instances.png)

Typischer Einsatz: `main` für das LAN und eine zweite Instanz für ein
Gastnetzwerk oder ein Mediengerät, das in einem anderen Land austreten soll.

## Rotation und der Watchdog

Die Rotation wechselt auf einen anderen Server aus dem Set — entweder alle N
Minuten oder zu einer festen Tageszeit. Ein Kandidat wird erst akzeptiert, wenn
ein echter WireGuard-Handshake zustande kommt; andernfalls wird der nächste
Kandidat probiert und, falls keiner funktioniert, der vorherige Peer wieder
hergestellt.

Der optionale **Watchdog** verbindet neu, wenn der Tunnel veraltet — die
Erkennung erfolgt über den Handshake, ohne externe Probe — und hält sich
heraus, solange ein bestimmter Server angepinnt ist.

![Automatische Rotation](screenshots/rotation.png)

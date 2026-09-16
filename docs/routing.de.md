# Traffic-Routing

[English](routing.md) · [Русский](routing.ru.md) · **Deutsch** · [← README](../README.de.md)

Beim **automatischen Routing** legt das Backend eine Firewall-Zone an und
schickt den gesamten LAN-Traffic durch den Tunnel. Es rührt nichts an, sobald
es eine eigene Routing-Tabelle oder von dir hinzugefügte Routen erkennt.

Statt alles zu leiten, benenne **Quellnetzwerke**: nur diese verlassen den
Router durch den Tunnel, per Policy-Regeln in die eigene Routing-Tabelle der
Instanz. Der **Kill Switch** verhindert dann, dass diese Netzwerke das WAN
erreichen, während der Tunnel unten ist, und **`ipv6_mode`** entscheidet, was
mit IPv6 geschieht.

IPv6 ist bei ProtonVPN Sache des einzelnen Servers: nur ein Teil der Gateways
leitet es weiter, und Proton markiert diese mit Bit 16 der `Features`-Bitmaske
des logischen Servers. Auf 12 Gateways in 11 Ländern nachgemessen, jeweils mit
einer Anfrage an `2606:4700:4700::1111` durch den Tunnel: alle sechs mit dem Bit
antworteten in 0,02–1,07 s, alle sechs ohne das Bit liefen jedes Mal in einen
Timeout von 8–12 s, während der Sendezähler von WireGuard weiter stieg. Auf
einem solchen Server gehen die Pakete hinaus und nichts kommt zurück — das ist
kein „IPv6 aus“, sondern ein schwarzes Loch, und ein schwarzes Loch ist
schlimmer als eine Blockade: Clients warten bei jeder Verbindung Happy Eyeballs
ab, und alles, was kein Browser ist, hängt schlicht.

Daraus ergeben sich drei Modi:

* `block` (Vorgabe) — eine `prohibit`-Regel stoppt IPv6 auf den geleiteten
  Netzwerken, wie bisher.
* `auto` — auf einem Gateway mit dem Bit geht IPv6 durch den Tunnel, auf einem
  ohne das Bit greift dasselbe `prohibit` wie im Modus `block`. Die
  `prohibit`-Regel steht immer: sie liegt unter der Lookup-Regel, aber über der
  Tabelle `main`, sodass ein liegender Tunnel, eine deaktivierte Instanz oder
  ein Server ohne IPv6 dort endet und die Default-Route des Providers nie
  erreicht. Genau diese Reihenfolge ist der IPv6-Kill-Switch.
* `off` — die App fasst IPv6 überhaupt nicht an.

`auto` gilt nur für geleitete Netzwerke; bei `auto_routing` gibt es keine
Regeln pro Netzwerk, an die es sich hängen ließe, also verhält es sich wie
`block`. Die Tunnel-Adresse selbst ist ein festes `/128`, das sich alle
Proton-Clients teilen — es gibt kein Präfix zu delegieren. Unter `auto` werden
die geleiteten Netzwerke deshalb aus der ULA des Routers adressiert
(`ip6assign 64`, `ip6class local`, `delegate 0`) und hinter der Firewall-Zone
der Instanz per NAT6 übersetzt. Der Client sieht dann nur eine ULA und keine
Provider-Adresse, und genau das hindert Happy Eyeballs daran, das WAN
vorzuziehen. Ein Präfix zuzuteilen heißt aber nicht, es anzukündigen: in einem
Netzwerk, in dem IPv6 nie benutzt wurde — `ra 'disabled'`, wozu die frühere
Blockade-Politik geradezu einlud — bekäme der Client überhaupt keine Adresse.
Deshalb schaltet `auto` für diese Netzwerke auch das Router Advertisement ein
(`ra 'server'`, `ra_slaac 1`) und setzt `ra_default 1`; ohne das kündigt odhcpd
auf einem Interface mit ausschließlich ULA eine Router-Lifetime von 0 an, und
der Client erhält eine Adresse, mit der er nicht routen kann. DHCPv6 bleibt
unangetastet. Zusätzlich wird Neighbour Discovery für die geleiteten
Netzwerke geöffnet — Router Solicitation sowie Neighbour
Solicitation/Advertisement, ausschließlich IPv6 und sonst nichts, gebunden an
das Interface des Netzwerks selbst, sodass nichts anderes aus seiner
Firewall-Zone erfasst wird. Eine
Gast-Zone weist ab, was sie nicht ausdrücklich nennt, und Neighbour Discovery
nennt dort niemand; ohne das kann der Router die Adresse eines Clients nicht
auflösen, und jede Antwort aus dem Tunnel geht auf dem letzten Stück
verloren. Sowohl die Netzwerk- als auch die `dhcp`-Einstellungen gehören
dir, also werden die vorigen Werte gemerkt und zurückgeschrieben, sobald `auto`
abgeschaltet wird. Hat der Router kein eigenes ULA-Präfix, gibt es nichts zu
verteilen — das steht dann im Log, statt still zu scheitern.

Für welche Netzwerke das gilt, wird entschieden, bevor irgendetwas geschrieben
wird, und die drei Teile — Adressierung, Ankündigung, Öffnung — werden
gemeinsam gewährt oder gemeinsam verweigert: Ein Client, der eine ULA bekommt
und diesen Router als Standard-Gateway genannt bekommt, dessen Netzwerk
Neighbour Discovery dann aber verweigert wurde, hat eine Adresse, die er nicht
benutzen kann, und erfährt es nicht. Ein Netzwerk qualifiziert sich, wenn es
eines ist, in dem der Router Clients bedient: ein Protokoll, mit dem er nicht
nach außen wählt, keine eigene Standardroute, eine Firewall-Zone, an die sich
die Regel hängen lässt, und genau ein Gerät, an das sie gebunden werden kann.
Die letzte Frage wird dem Gerät gestellt und nicht dem Netzwerk, denn ein Alias
oder ein zweites Subnetz kann auf derselben Bridge liegen und ein eigenes
Gateway führen, und eine Regel, die auf das Gerät passt, würde es mit erfassen.
Ein Netzwerk, das sich nicht qualifiziert, bleibt genau so, wie du es hattest,
und das Log nennt das Netzwerk und den Grund.

`auto` richtet sich nach der Flotte, statt sie einzuschränken: du landest auf
dem Gateway, das die Auswahl hergibt, und IPv6 wird entsprechend geleitet oder
verboten. Wer lieber IPv6 hat als die größte Serverauswahl, dreht das mit
**`require_ipv6`** um: dann kommen nur noch Gateways mit dem Bit in Frage — für
die erste Verbindung, für jede Rotation und für die Wiederherstellung durch den
Watchdog gleichermaßen, nicht bloß in der angezeigten Liste. 11 832 von 17 890
logischen Servern qualifizieren sich (66 %), und in manchen Ländern gibt es
kein einziges.

Enthalten die gewählten Standorte kein solches Gateway, verbindet sich die
Instanz nicht und sagt das auch. Ein Rückfall auf ein Gateway ohne IPv6 findet
nie statt: du hast IPv6 ausdrücklich verlangt, und eine Verbindung, die
stillschweigend das Gegenteil liefert, ist genau der Fehler, den dieses Feature
verhindern soll. Ein angepinnter `fixed_server` ohne das Bit wird aus demselben
Grund abgelehnt — Anpinnen deaktiviert die Rotation ohnehin, du bliebest also
dauerhaft darauf sitzen. Erweitere die Standorte, wähle einen anderen Server
oder schalte die Anforderung ab.

Dasselbe gilt für einen bereits bestehenden Tunnel. Schaltest du die
Anforderung ein, während du auf einem Gateway ohne das Bit verbunden bist, und
lässt sich kein geeignetes erreichen, wird der Tunnel abgebaut statt
weiterzulaufen: ein solches Gateway nicht zu wählen und dich gleichzeitig
darauf weiterzutragen, hieße die Anforderung für gescheitert zu erklären und
sie im selben Moment zu brechen. Ein Tunnel, der die Anforderung erfüllt,
bleibt unangetastet. IPv6 entweicht dabei nicht — die `prohibit`-Regel steht,
ob der Tunnel oben oder unten ist —, aber IPv4 aus den geleiteten Netzwerken
geht bei liegendem Tunnel zu deinem Provider, genau wie nach jedem anderen
Verbindungsfehler. Schalte den Kill Switch ein, wenn dir lieber ist, dass diese
Netzwerke dann gar keinen Zugang haben.

Beide Hälften stehen dort, wo du sie siehst, und stammen aus dem Status, den
die Seite immer hat — nicht bloß aus der Antwort auf einen Klick: Das
Statusband nennt die Anforderung und — bei ausgeschaltetem Kill Switch — dass
die geleiteten Netzwerke jetzt über deinen Provider laufen, samt dem Hinweis,
den Kill Switch einzuschalten. Ein Reload, der Status-Poll und eine Rotation im
Hintergrund sagen dasselbe.

Es nennt außerdem, auf welche Weise die Anforderung unerfüllt blieb, denn die
Abhilfe unterscheidet sich: keines der Gateways in diesen Standorten
unterstützt IPv6 (nimm einen Standort dazu, der solche hat), die
IPv6-fähigen Gateways hier waren nicht erreichbar (sie leiten IPv6 weiter —
verbinde einfach neu, ohne etwas zu ändern), oder der angepinnte Server
unterstützt es nicht (wähle einen anderen).

Die Option gilt nur dort, wo `auto` IPv6 überhaupt liefern kann: mit
`ipv6_mode` `auto`, `hop_mode` `standard` und geleitetem Routing — also genau
unter den Bedingungen, die `auto` selbst braucht. Sonst deaktiviert die Seite
sie und nennt den Grund, und eine von Hand geschriebene Konfiguration, die
keine davon erfüllt, behält ihre ganze Flotte, statt an einer Option zu
scheitern, die nichts ändert. Außerhalb von `auto` geht IPv6
durch keinen Tunnel, welches Gateway auch gewählt wird — die Flotte zu
verkleinern kostete Server und brächte nichts; außerhalb von Standard ist die
Anforderung unerfüllbar, denn Bit 16 ist bei 0 von 122 Secure-Core- und 0 von 7
Tor-Logicals gesetzt. Der gespeicherte Wert übersteht einen Ausflug in die
anderen Modi, statt vergessen zu werden.

![Traffic-Routing](screenshots/routing.png)

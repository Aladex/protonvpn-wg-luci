# Usage

**English** · [Русский](usage.ru.md) · [Deutsch](usage.de.md) · [← README](../README.md)

Open **VPN → ProtonVPN** and press **Log in**. The modal asks for your Proton
address and password, and for a TOTP code only if the account uses one — the
password is processed in your browser and never sent to the router. The server
list downloads right after login; it is large (Proton publishes tens of
thousands of servers), so the first refresh takes a few seconds.

Then pick a **location set** — whole countries, or individual cities inside
them — and press **Save and reconnect**. The initial connect and every later
rotation pick from that set. Leave **Server** on *Automatic* to let the backend
choose by load, or pin one; pinning disables rotation for that instance.

**Hop mode** switches between Standard, Secure Core (entry through a hardened
Proton-owned server in a privacy-friendly country) and Tor (exit through the
Tor network). The three are different products rather than filters over one
list, so switching mode clears the location set: pick again for the new mode.

![Choosing locations](screenshots/location-picker.png)

Servers are listed least-loaded first, with a one-click lowest-load pick on
top. Within an equal load they are ordered by name, numerically — so `NL#5`
comes before `NL#27`, not after it:

![Choosing a server](screenshots/server-picker.png)

The status band shows the connected server, the handshake age and the external
IP as seen through the tunnel — the one check that proves traffic really
leaves through the VPN, which a handshake alone does not.

## Multiple instances

Every instance runs its own WireGuard interface (`pv_<name>`), its own keypair
and certificate, its own location set and schedule, and — when it steers
traffic — its own routing table and firewall zone. They share one Proton
account and one server-list cache, which `main` owns. Deleting `main` resets it
to defaults instead of removing it, because it anchors both.

![The VPN instances table](screenshots/instances.png)

Typical use: `main` for the LAN and a second instance for a guest network or a
media device that should exit in another country.

## Rotation and the watchdog

Rotation moves to another server in the set, either every N minutes or at a
fixed time of day. A candidate is only accepted once a real WireGuard
handshake completes; if it does not, the next candidate is tried and the
previous peer is restored if none work.

The optional **watchdog** reconnects when the tunnel goes stale — detection is
handshake-based, with no external probe — and stays out of the way when a
specific server is pinned.

![Automatic rotation](screenshots/rotation.png)

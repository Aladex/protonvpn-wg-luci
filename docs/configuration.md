# Configuration (`/etc/config/protonvpn`)

**English** · [Русский](configuration.ru.md) · [Deutsch](configuration.de.md) · [← README](../README.md)

Everything below is also reachable from the page's *Advanced settings*:

![Advanced settings](screenshots/advanced.png)

One `config instance` section per tunnel; `main` is the default. Secrets are
never stored here: the session lives in a root-only state file and the
WireGuard private key on the managed network interface.

| Option | Default | Meaning |
|---|---|---|
| `enabled` | `0` | Master switch; a fresh install ships disabled |
| `interface` | `protonvpn` | Managed WireGuard interface |
| `locations` (list) | — | Countries (`ch`) and/or cities (`nl-amsterdam`) to connect and rotate across |
| `hop_mode` | `standard` | `standard`, `secure_core` or `tor` |
| `fixed_server` | — | Pin one server by name; disables rotation |
| `rotation_enabled` | `0` | Automatic rotation |
| `rotation_mode` | `interval` | `interval` or `time` |
| `rotation_interval` | `360` | Minutes between rotations |
| `rotation_time` | `04:30` | Time of day for `time` mode |
| `watchdog` | `0` | Reconnect automatically when the tunnel goes stale |
| `verify_timeout` | `8` | Seconds to wait for a handshake before rejecting a server |
| `max_retries` | `10` | Candidate servers a rotation may try |
| `auto_routing` | `1` | Create the firewall zone and route all LAN traffic |
| `source_network` | — | Steer only these networks instead of everything |
| `routing_table` | — | Custom routing table (empty = main) |
| `killswitch` | `0` | Block the steered networks from the WAN while down |
| `ipv6_mode` | `block` | IPv6 handling: `block` (prohibit it), `auto` (through the tunnel on gateways that forward IPv6, prohibit on the rest) or `off` (leave IPv6 alone). `auto` rides on the per-network policy rules that only steered routing creates, so it is inert with `auto_routing` on, with no `source_network` or with no `routing_table`; the page names whichever condition applies rather than silently storing `block`. `block` is the default because an IPv6 path around the tunnel would expose your address just as plainly as no VPN |
| `require_ipv6` | `0` | Only consider gateways that forward IPv6, for the initial connect, rotation and the watchdog alike. Applies only with `ipv6_mode` `auto`, `hop_mode` `standard` and steered routing; when the selected locations hold no such gateway the instance does not connect |
| `vpn_dns` | `off` | `off` (system resolver) or `standard` (in-tunnel 10.2.0.1) |
| `mtu` | — | Interface MTU (the UI recommends WAN MTU − 80) |
| `cache_dir` | — | Server-list cache directory, shared by all instances |
| `cache_refresh_interval` | `21600` | Seconds between background cache refreshes |

# Tunnel

An OpenVPN client for Linux with the conveniences of commercial VPN apps:
import your own `.ovpn` profiles, switch locations in one click, and (next
phase) split tunneling and a kill switch that apply without reconnecting.

## Layout

```
crates/tunnel-core    shared types, D-Bus contract, .ovpn parser and sanitizer
crates/tunneld        privileged daemon: runs OpenVPN, exposes org.tunnelvpn.Daemon1
crates/tunnel-cli     `tunnel` command-line client
apps/desktop          Tauri 2 + React + shadcn/ui desktop app (src-tauri is the Rust side)
packaging             systemd unit, D-Bus policy, polkit actions
scripts               dev install script
```

```
desktop app / tunnel CLI  ──D-Bus (polkit)──►  tunneld (root, systemd)
                                                 └─ openvpn  ◄─ management socket
```

The GUI never runs as root. `tunneld` drives `openvpn` over its management
socket (state, traffic counters, credential prompts, logs) and broadcasts
`StatusChanged` / `LogLine` signals.

### Profile security

`tunneld` runs OpenVPN as root, so an imported profile could otherwise run
code as root. Imports are sanitized: script hooks (`up`, `down`,
`script-security`, `plugin`, ...), management and logging directives, and
anything that reads or writes an arbitrary path are rejected. Keys and
certificates must be inline; the app and CLI read referenced files as the
user and embed them before sending the profile to the daemon. The same
checks apply to a profile's extra options.

## Sign-in

Everything a server or profile can ask for is supported, and each secret
can be saved in your keyring:

- username and password, with a static one-time code (`static-challenge`);
- a passphrase for an encrypted private key (asked up front when the key is
  visibly encrypted, otherwise the first time OpenVPN needs it);
- dynamic challenges (`CRV1`, e.g. a token PIN after the password) and
  pending-auth challenges (`CR_TEXT`), answered in a dialog;
- web sign-in (`WEB_AUTH` / `OPEN_URL`), opened in your browser;
- the username and password of the proxy you connect through.

## Profiles

Import `.ovpn`/`.conf` files or a whole folder (it and its subfolders one
level deep), by drag and drop or from Settings › Profiles. Per profile you
can rename it, group it, set its country, turn off data channel offload
(DCO), and add extra OpenVPN directives (`mssfix 1400`, ...).

To reach servers from networks that only let web traffic out, set a
connection proxy (HTTP or SOCKS5, optionally with a password) in
Settings › Network, or `tunnel settings proxy=http://proxy.lan:3128
proxy-auth=on`. It replaces any proxy the profile names.

## Development

System packages (Ubuntu 26.04):

```bash
sudo apt install rustup build-essential pkg-config libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev libssl-dev libxdo-dev
```

```bash
rustup default stable
```

Run the tests:

```bash
cargo test --workspace
```

### UI only, no root

Run a simulated daemon on your session bus and point the app at it:

```bash
cargo run -p tunneld -- --session --mock
```

```bash
cd apps/desktop && pnpm install && TUNNEL_SESSION_BUS=1 pnpm tauri dev
```

Opening `pnpm dev` in a plain browser also works: the UI falls back to
built-in sample data.

### Real connections

Install the daemon with its systemd unit, D-Bus policy and polkit actions
(asks for sudo), then start the app normally:

```bash
scripts/install-dev.sh
```

```bash
cd apps/desktop && pnpm tauri dev
```

CLI:

```bash
tunnel import ~/Downloads/de-fra.ovpn
```

```bash
tunnel connect de-fra
```

## Install

Download `tunnel_X.Y.Z_amd64.deb` from the latest release, then:

```bash
sudo apt install ./tunnel_X.Y.Z_amd64.deb
```

The package contains the app, the `tunnel` CLI and the `tunneld` service,
which starts right away. `sudo apt purge tunnel` removes everything,
including saved profiles.

## Releases and updates

`.github/workflows/release.yml` runs on every `v*` tag: it tests, builds the
`.deb`, signs it with minisign, and publishes it with `SHA256SUMS` as a
GitHub release. The app checks the latest release every few hours (it can
be turned off under Settings › About), shows an **Update** button, downloads
the package as the user, and passes it to `tunneld`. The service installs it
only when it is signed with the release key in
`packaging/update-key.pub`, is named `tunnel`, and is newer than what's
installed. The install runs in its own systemd unit, so it survives the
service restarting itself.

To publish a version:

```bash
scripts/release.sh 0.2.0
```

One-time setup: add the contents of the minisign secret key
(`~/.config/tunnel-release/minisign.key`) as a repository secret named
`MINISIGN_SECRET_KEY`. Keep that file safe: losing it means installed apps
can't verify new releases, and anyone who has it can ship updates.

## Firewall and DNS

The kill switch is one nftables table, `inet tunnelvpn`, owned by `tunneld`
and replaced atomically on every change. While it's active, outgoing
traffic may only use the tunnel interface (`tunnel0`), loopback, DHCP and
neighbor discovery, the LAN (if allowed), and the daemon's own cgroup (so
OpenVPN can reach the server). While connecting, systemd-resolved may also
resolve the server's name.

- **Automatic** (default): on while connecting and connected; if the tunnel
  drops, traffic stays blocked until you reconnect or press Unblock.
- **Always on**: blocks everything outside the VPN even when disconnected.
  The table stays in place across service restarts and is removed when the
  package is removed.
- **Off**.

DNS goes through systemd-resolved: once connected, the tunnel link gets the
pushed (or your custom) servers and the `~.` routing domain. With DNS leak
protection on, port 53 and 853 are rejected everywhere except the tunnel.
IPv6 outside the tunnel can be blocked separately for IPv4-only VPNs.

From the CLI:

```bash
tunnel settings firewall=always lan=off dns=1.1.1.1,9.9.9.9
```

## Split tunneling

Pick apps, domains, IPs/networks and whole countries, then either
**exclude** them from the VPN (everything else uses it) or use the VPN
**only** for them. Rule changes apply to the running connection; switching
between the two modes reconnects.

How it works (`crates/tunneld/src/split`):

- An nftables table, `inet tunnelsplit`, marks split packets in a
  `route` chain (so the kernel re-routes them) and masquerades them, since
  sockets pick their source address before the mark is set. Connection
  tracking keeps a flow on the side it started on.
- Policy routing sends marked packets elsewhere. Exclude: `main` without
  OpenVPN's `0/1`+`128/1` (LAN routes still apply), then a table with the
  physical gateway. Include: OpenVPN runs with `--route-noexec`, and marked
  packets use a table whose default route is the tunnel.
- Domains: systemd-resolved sends the tunnel's lookups to a small forwarder
  on `127.0.0.153`. Split names are asked on the side they'll use (so CDNs
  answer with nearby servers) and their addresses go into an nft set with a
  timeout before the answer is returned.
- Apps: processes are found by executable once a second and moved into the
  `/sys/fs/cgroup/tunnel-split` cgroup, which the rules match.
  `tunnel bypass -- <command>` starts anything in it directly.
- Countries: RIR delegation lists (ipverse, ipdeny as a fallback), cached in
  `/var/cache/tunneld/geoip` and refreshed weekly.

```bash
tunnel split add '*.ir' country:IR /usr/bin/telegram-desktop
```

```bash
tunnel split on
```

The routing tests run against the real kernel in a throwaway network
namespace:

```bash
cargo test -p tunneld --no-run && unshare -rn target/debug/deps/tunneld-* --ignored --test-threads=1 netns
```

## Everyday conveniences

- **Saved passwords** live in your keyring (GNOME Keyring, KWallet, ...)
  through the Secret Service API. The app hands them straight to the
  service; they never reach the web view. A password the server rejects is
  forgotten, so the next attempt asks again.
- **Start at login, connect on start, connect on untrusted networks.**
  Tunnel watches NetworkManager's primary connection; joining a network
  that isn't on your trusted list connects the last (or chosen) location.
  Profiles with one-time codes still ask.
- **Exit location on the map**, from ipwho.is through the tunnel (can be
  turned off).
- **Proxy gateway**: one port on your LAN address speaking SOCKS5 and HTTP,
  so phones and TVs can use the VPN. It only runs while connected and only
  serves private addresses.
- **GNOME quick settings tile** (`tunnel@tunnelvpn.org`, installed with the
  package): status, recent locations, firewall and split toggles. Turn it
  on in the Extensions app, or:

```bash
gnome-extensions enable tunnel@tunnelvpn.org
```

## Roadmap

1. Done: import, connect/disconnect, location list with latency, live
   status, tray, logs, signed updates.
2. Done: kill switch, DNS leak protection, IPv6 leak blocking, allow-LAN.
3. Done: split tunneling by app, domain, IP/network and country.
4. Done: saved passwords, start at login, trusted networks, exit location,
   proxy gateway, GNOME quick settings tile.
5. Done: key passphrases, dynamic and web sign-in, connection proxy,
   folder import, DCO and extra options per profile.

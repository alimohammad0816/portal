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
user and embed them before sending the profile to the daemon.

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

## Roadmap

1. Done: import, connect/disconnect, location list with latency, live
   status, tray, logs, signed updates.
2. Done: kill switch, DNS leak protection, IPv6 leak blocking, allow-LAN.
3. Split tunneling: profiles run with `route-nopull`; routes live in a
   dedicated table selected by `fwmark`, nftables sets hold excluded IPs,
   hostnames (via a DNS forwarder) and apps (cgroup v2), so rule changes
   apply live.
4. Credentials in GNOME Keyring, trusted networks, proxy gateway, GNOME
   Shell quick-settings tile, server geolocation.

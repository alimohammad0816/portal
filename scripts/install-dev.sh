#!/usr/bin/env bash
# Build tunneld and install it with its systemd unit, D-Bus policy and
# polkit actions, so the desktop app can talk to the real daemon on the
# system bus. Run from the repository root; asks for sudo.
#
#   scripts/install-dev.sh            install or update
#   scripts/install-dev.sh --remove   uninstall
set -euo pipefail

cd "$(dirname "$0")/.."

FILES=(
  "/usr/libexec/tunneld"
  "/etc/systemd/system/tunneld.service"
  "/usr/share/dbus-1/system.d/org.tunnelvpn.Daemon1.conf"
  "/usr/share/dbus-1/system-services/org.tunnelvpn.Daemon1.service"
  "/usr/share/polkit-1/actions/org.tunnelvpn.policy"
)

if [[ "${1:-}" == "--remove" ]]; then
  sudo systemctl disable --now tunneld.service 2>/dev/null || true
  sudo rm -f "${FILES[@]}"
  sudo systemctl daemon-reload
  echo "Removed. Profiles are still in /var/lib/tunneld; delete it yourself if you want them gone."
  exit 0
fi

cargo build --release -p tunneld -p tunnel-cli

sudo install -Dm755 target/release/tunneld /usr/libexec/tunneld
sudo install -Dm755 target/release/tunnel /usr/local/bin/tunnel
sudo install -Dm644 packaging/systemd/tunneld.service /etc/systemd/system/tunneld.service
sudo install -Dm644 packaging/dbus/org.tunnelvpn.Daemon1.conf /usr/share/dbus-1/system.d/org.tunnelvpn.Daemon1.conf
sudo install -Dm644 packaging/dbus/org.tunnelvpn.Daemon1.service /usr/share/dbus-1/system-services/org.tunnelvpn.Daemon1.service
sudo install -Dm644 packaging/polkit/org.tunnelvpn.policy /usr/share/polkit-1/actions/org.tunnelvpn.policy

sudo systemctl daemon-reload
sudo systemctl reload dbus.service 2>/dev/null || sudo busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig
sudo systemctl enable tunneld.service
sudo systemctl restart tunneld.service
systemctl --no-pager --lines=5 status tunneld.service

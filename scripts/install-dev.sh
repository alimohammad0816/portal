#!/usr/bin/env bash
# Build portald and install it with its systemd unit, D-Bus policy and
# polkit actions, so the desktop app can talk to the real daemon on the
# system bus. Run from the repository root; asks for sudo.
#
#   scripts/install-dev.sh            install or update
#   scripts/install-dev.sh --remove   uninstall
set -euo pipefail

cd "$(dirname "$0")/.."

FILES=(
  "/usr/libexec/portald"
  "/etc/systemd/system/portald.service"
  "/usr/share/dbus-1/system.d/io.github.alimohammad0816.Portal.Daemon1.conf"
  "/usr/share/dbus-1/system-services/io.github.alimohammad0816.Portal.Daemon1.service"
  "/usr/share/polkit-1/actions/io.github.alimohammad0816.Portal.policy"
)

if [[ "${1:-}" == "--remove" ]]; then
  sudo systemctl disable --now portald.service 2>/dev/null || true
  sudo rm -f "${FILES[@]}"
  sudo systemctl daemon-reload
  echo "Removed. Profiles are still in /var/lib/portald; delete it yourself if you want them gone."
  exit 0
fi

cargo build --release -p portald -p portal-cli

sudo install -Dm755 target/release/portald /usr/libexec/portald
sudo install -Dm755 target/release/portal /usr/local/bin/portal
sudo install -Dm644 packaging/systemd/portald.service /etc/systemd/system/portald.service
sudo install -Dm644 packaging/dbus/io.github.alimohammad0816.Portal.Daemon1.conf /usr/share/dbus-1/system.d/io.github.alimohammad0816.Portal.Daemon1.conf
sudo install -Dm644 packaging/dbus/io.github.alimohammad0816.Portal.Daemon1.service /usr/share/dbus-1/system-services/io.github.alimohammad0816.Portal.Daemon1.service
sudo install -Dm644 packaging/polkit/io.github.alimohammad0816.Portal.policy /usr/share/polkit-1/actions/io.github.alimohammad0816.Portal.policy

sudo systemctl daemon-reload
sudo systemctl reload dbus.service 2>/dev/null || sudo busctl call org.freedesktop.DBus / org.freedesktop.DBus ReloadConfig
sudo systemctl enable portald.service
sudo systemctl restart portald.service
systemctl --no-pager --lines=5 status portald.service

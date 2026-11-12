#!/bin/sh
# Install a Portal package in a fresh distro container and check that it
# landed whole: files in place, every library found, the binaries start.
#   install-test.sh deb|rpm|arch <package file>
set -eu
kind=$1
pkg=$2

case $kind in
  deb)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq "./$pkg"
    ;;
  rpm)
    if command -v dnf >/dev/null; then
      dnf install -y -q "./$pkg"
    else
      zypper --non-interactive --quiet install --allow-unsigned-rpm "./$pkg"
    fi
    ;;
  arch)
    pacman -Syu --noconfirm --quiet
    pacman -U --noconfirm "./$pkg"
    ;;
  *)
    echo "unknown package kind $kind" >&2
    exit 2
    ;;
esac

echo "--- checking the install"
grep -qx "$kind" /usr/lib/portal/package-format
for f in \
  /usr/lib/systemd/system/portald.service \
  /usr/share/dbus-1/system.d/io.github.alimohammad0816.Portal.Daemon1.conf \
  /usr/share/dbus-1/system-services/io.github.alimohammad0816.Portal.Daemon1.service \
  /usr/share/polkit-1/actions/io.github.alimohammad0816.Portal.policy \
  /usr/share/gnome-shell/extensions/portal@alimohammad0816.github.io/extension.js
do
  test -f "$f" || { echo "missing $f" >&2; exit 1; }
done
for b in /usr/libexec/portald /usr/bin/portal /usr/bin/portal-desktop; do
  if ldd "$b" | grep 'not found'; then
    echo "$b is missing libraries" >&2
    exit 1
  fi
done
# The tray loads this at run time, so ldd doesn't see it.
ldconfig -p | grep -q 'libayatana-appindicator3.so.1' || { echo "no tray library" >&2; exit 1; }
command -v openvpn >/dev/null || { echo "openvpn wasn't pulled in" >&2; exit 1; }
command -v nft >/dev/null || { echo "nftables wasn't pulled in" >&2; exit 1; }
/usr/libexec/portald --version
/usr/bin/portal --version
echo "--- ok"

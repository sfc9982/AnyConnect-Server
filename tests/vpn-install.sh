#!/usr/bin/env bash
# Run only in the disposable container used by vpn-e2e.yml.
set -euo pipefail
: "${VPN_E2E_DISPOSABLE:?Use a disposable test container}"
[[ "$VPN_E2E_DISPOSABLE" == 1 && "$EUID" -eq 0 ]] || exit 1

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${1:?installer script required}"
case "$script" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
# shellcheck disable=SC1090
source "$repo_dir/$script"
check_sys

# Bullseye security indexes outlived their package files on the regular mirrors.
# Keep this legacy fixture on Debian's signed archive without changing transport
# verification or the still-available base and updates repositories.
if [[ "$release" == debian && "${VERSION_ID:-}" == 11 ]]; then
    for source_list in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
        [[ -f "$source_list" ]] || continue
        sed -i -E 's#(https?://)(deb|security)\.debian\.org/debian-security/?([[:space:]]|$)#\1archive.debian.org/debian-security\3#g' "$source_list"
    done
fi

# This Leap image contains a newer ncurses runtime than its archived development
# packages. Align only this observed pair in the disposable test container; never
# apply a distribution downgrade or change the production installer's policy.
if [[ "$pm" == zypper && "${VERSION_ID:-}" == 15.6 ]] &&
    [[ "$(rpm -q --qf '%{VERSION}-%{RELEASE}' libncurses6)" == 6.1-150000.5.33.1 ]]; then
    zypper -n refresh
    zypper -n install --oldpackage --no-recommends \
        repo-sle-update:libncurses6 repo-sle-update:ncurses-devel
fi

# Exercise the installer's real dependency list and pinned source build.
Installation_dependency
Download_ocserv

case "$pm" in
    apt-get)
        apt-get install -y openconnect vpnc-scripts curl iputils-ping dnsutils python3
        ;;
    dnf|yum)
        "$pm" install -y openconnect vpnc-script iputils bind-utils python3
        if ! command -v curl >/dev/null 2>&1; then "$pm" install -y curl; fi
        ;;
    pacman)
        pacman -S --noconfirm openconnect vpnc curl iputils bind python
        ;;
    zypper)
        zypper -n install openconnect curl iputils bind-utils python3
        ;;
    *) echo "Unsupported test package manager: $pm" >&2; exit 1 ;;
esac

"$file" --version
openconnect --version
certtool --version
echo 'Source build and real client dependencies installed'

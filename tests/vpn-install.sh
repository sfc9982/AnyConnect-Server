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

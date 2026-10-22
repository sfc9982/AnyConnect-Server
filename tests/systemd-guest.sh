#!/usr/bin/env bash
# Destructive VM-only test. Called over pinned SSH by systemd-vm.sh.
set -Eeuo pipefail
[[ ${VPN_E2E_DISPOSABLE:-} == 1 && $EUID == 0 && $(cat /proc/1/comm) == systemd ]] || exit 2
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
installer=${1:?}; action=${2:?}; identity=${3:?}
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
# shellcheck disable=SC1090
source "$repo/$installer"
export TERM=xterm LC_ALL=C
state=/root/vpn-systemd-fixture
normalize() { sed -E '/^#/d; s/\[[0-9]+:[0-9]+\]/[0:0]/g'; }
identity_hashes() { sha256sum "$CA_CERT" "$SSL_DIR/server-cert.pem" "$passwd_file"; }
case "$action" in
    install)
        [[ ! -e $state && ! -e /usr/local/sbin/ocserv ]] || exit 2
        mkdir -m 700 "$state"
        # Dependency acquisition, build, accounts, unit install, firewall and startup
        # all go through the real installer; only public-address discovery is deterministic.
        Get_ip() { ip=$identity; }
        check_sys
        modprobe tun
        printf 'net.ipv4.ip_forward=0\n' >> /etc/sysctl.conf
        apt-get update > "$state/bootstrap.log" 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y iptables openssl >> "$state/bootstrap.log" 2>&1
        iptables -A INPUT -p tcp --dport 54321 -m comment --comment unrelated-vm-rule -j ACCEPT
        iptables -t nat -A POSTROUTING -s 198.18.254.0/24 -m comment --comment unrelated-vm-rule -j RETURN
        iptables-save | normalize > "$state/baseline.rules"
        openssl rand -hex 24 > "$state/password"
        { printf 'boot-test\n'; cat "$state/password"; printf '4443\n4443\n'; } > "$state/install.input"
        Install_ocserv < "$state/install.input" > "$state/install.log" 2>&1
        for unit in ocserv ocserv-firewall; do systemctl is-enabled --quiet "$unit" || exit 1; done
        systemctl is-active --quiet ocserv
        identity_hashes > "$state/identity.sha256"
        iptables-save | normalize > "$state/installed.rules"
        ;;
    check)
        for unit in ocserv ocserv-firewall; do systemctl is-enabled --quiet "$unit" || exit 1; done
        systemctl is-active --quiet ocserv
        [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]
        [[ $(Get_Ocserv_PID) == "$(systemctl show -p MainPID --value ocserv)" ]]
        systemd-analyze verify /etc/systemd/system/ocserv.service /etc/systemd/system/ocserv-firewall.service
        identity_hashes | cmp -s - "$state/identity.sha256"
        iptables-save | normalize | cmp -s - "$state/installed.rules"
        ss -H -ltn | grep -q ':4443 '
        ss -H -lun | grep -q ':4443 '
        ;;
    restarted)
        systemctl restart ocserv
        systemctl is-active --quiet ocserv
        ;;
    crashed)
        old=$(systemctl show -p MainPID --value ocserv)
        systemctl kill --kill-whom=main --signal=SIGKILL ocserv
        for ((n=0; n<100; n++)); do
            current=$(systemctl show -p MainPID --value ocserv)
            if [[ $current != 0 && $current != "$old" ]] && systemctl is-active --quiet ocserv; then break; fi
            sleep .2
        done
        [[ $current != 0 && $current != "$old" ]]
        systemctl is-active --quiet ocserv
        ;;
    stopped)
        systemctl stop ocserv
        if systemctl is-active --quiet ocserv; then exit 1; fi
        if ss -H -ltn | grep -q ':4443 '; then exit 1; fi
        ;;
    started)
        systemctl start ocserv
        systemctl is-active --quiet ocserv
        ;;
    booted)
        systemctl is-active --quiet ocserv-firewall
        bash "$0" "$installer" check "$identity"
        ;;
    uninstall)
        Uninstall_ocserv <<< y > "$state/uninstall.log" 2>&1
        [[ ! -e /usr/local/sbin/ocserv && ! -e /etc/ocserv ]]
        iptables-save | normalize | cmp -s - "$state/baseline.rules"
        normalize < /etc/iptables.up.rules | cmp -s - "$state/baseline.rules"
        ;;
    absent)
        [[ ! -e /usr/local/sbin/ocserv && ! -e /etc/ocserv ]]
        if systemctl is-active --quiet ocserv; then exit 1; fi
        if systemctl is-enabled --quiet ocserv; then exit 1; fi
        if ss -H -ltn | grep -q ':4443 '; then exit 1; fi
        if ss -H -lun | grep -q ':4443 '; then exit 1; fi
        ;;
    *) exit 2 ;;
esac
printf 'PASS: systemd %s\n' "$action"

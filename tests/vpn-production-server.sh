#!/usr/bin/env bash
# Real production helpers, restricted to a fresh disposable test system.
set -euo pipefail
[[ ${VPN_E2E_DISPOSABLE:-0} == 1 && $EUID == 0 ]] || exit 2
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
script=${1:?installer} action=${2:?action} state=${3:?private state directory}
case "$script" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
# shellcheck disable=SC1090
source "$repo_dir/$script"
check_sys
case "$action" in
    configure)
        [[ ! -e "$CA_KEY" && ! -e "$passwd_file" ]] || { echo 'Refusing an existing VPN installation' >&2; exit 2; }
        mkdir -p "$conf_file"
        cp "$repo_dir/ocserv.conf" "$conf"
        Generate_SSL vpn-server.test
        Ensure_CRL
        Configure_Auth
        Set_Conf_Value tcp-port 4443
        Set_Conf_Value udp-port 4443
        Set_Conf_Value ipv6-network fd42:7::/48
        Set_Conf_Value ipv6-subnet-prefix 128
        Set_Conf_Value dns 198.51.100.2
        printf 'dns = fd42:2::2\n' >> "$conf"
        Set_Conf_Value max-ban-score 0
        Set_Conf_Value pid-file "$state/ocserv.pid"
        Set_Conf_Value occtl-socket-file "$state/occtl.socket"
        Set_Conf_Value dpd 5
        Set_Conf_Value switch-to-tcp-timeout 5
        Add_User < "$state/account.input"
        cp "$CA_CERT" "$state/ca.pem"
        cp "$USERS_DIR/qa-user/qa-user.cer" "$state/client.cer"
        cp "$USERS_DIR/qa-user/qa-user-key.pem" "$state/client-key.pem"
        iptables -P FORWARD DROP
        ip6tables -P FORWARD DROP
        ip6tables -A INPUT -p tcp --dport 4444 -m comment --comment qa-unrelated -j ACCEPT
        ip6tables-save > "$state/ip6-before.rules"
        Set_iptables
        Add_iptables 4443 4443
        Save_iptables
        Set_iptables
        Add_iptables 4443 4443
        Save_iptables
        sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
        sysctl -p /etc/sysctl.conf
        [[ $(sysctl -n net.ipv4.ip_forward) == 1 && $(sysctl -n net.ipv6.conf.all.forwarding) == 1 ]]
        [[ $(ip6tables-save | grep -c -- '--comment ocserv-v6') == 4 ]]
        "$file" --test-config -c "$conf"
        ;;
    cleanup)
        # The caller stops the foreground server before running this action.
        Remove_IPv6_Rules
        Remove_IPv6_Rules
        Save_iptables
        ip6tables-restore < /etc/ip6tables.up.rules
        ip6tables-save > "$state/ip6-after.rules"
        sed -E '/^#/d;s/\[[0-9]+:[0-9]+\]/[0:0]/g' "$state/ip6-before.rules" > "$state/ip6-before.normal"
        sed -E '/^#/d;s/\[[0-9]+:[0-9]+\]/[0:0]/g' "$state/ip6-after.rules" > "$state/ip6-after.normal"
        cmp "$state/ip6-before.normal" "$state/ip6-after.normal"
        ;;
    *) exit 2 ;;
esac

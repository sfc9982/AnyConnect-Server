#!/usr/bin/env bash
# Real installer helpers; all persistent paths are inside a disposable machine.
set -Eeuo pipefail
[[ "${VPN_E2E_DISPOSABLE:-}" == 1 && "$EUID" -eq 0 ]] || exit 1
repo=$(cd "$(dirname "$0")/../.." && pwd)
installer=${1:?}; state=${2:?}; clients=${3:?}
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
# shellcheck disable=SC1090
source "$repo/$installer"
check_sys
rm -rf /etc/ocserv
mkdir -p /etc/ocserv
cp "$repo/ocserv.conf" "$conf"
Generate_SSL vpn-qualification.test
Ensure_CRL
Configure_Auth
Set_Conf_Value tcp-port 4443
Set_Conf_Value udp-port 4443
Set_Conf_Value dns 198.51.100.2
printf '\ndns = 2001:db8:2::2\n' >> "$conf"
Set_Conf_Value max-ban-score 0
Set_Conf_Value pid-file "$state/server.pid"
Set_Conf_Value occtl-socket-file "$state/server.socket"
# Exercise both installer account creation paths with distinct real users.
for ((n=0; n<clients; n++)); do
    Add_User < "$state/account-$n.input"
done
iptables -P FORWARD DROP
ip6tables -P FORWARD DROP
Set_iptables
Add_iptables 4443 4443
Save_iptables
bash "$repo/ocserv-network.sh" configure --pool fd42:7::/64 --client-prefix 128 \
    --ingress vs --egress ve --mode routed
"$file" --test-config -c "$conf"

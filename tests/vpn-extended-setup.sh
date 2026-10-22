#!/usr/bin/env bash
# Fixture supplies a routed IPv6 prefix; production helpers install all firewall rules.
set -uo pipefail
[[ ${VPN_E2E_DISPOSABLE:-} == 1 && $EUID == 0 ]] || exit 2
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
installer=${1:?}; state=${2:?}; clients=${3:?}
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
# shellcheck disable=SC1090
source "$repo/$installer"
: "${conf_file:?}" "${conf:?}" "${passwd_file:?}" "${file:?}"
check_sys
mkdir -p "$conf_file" || exit 1
cp "$repo/ocserv.conf" "$conf" || exit 1
Generate_SSL vpn-fixture.invalid > "$state/pki.log" 2>&1 || exit 1
Ensure_CRL >> "$state/pki.log" 2>&1 || exit 1
Configure_Auth || exit 1
for pair in 'tcp-port 4443' 'udp-port 4443' 'max-ban-score 0' \
    'ipv6-network fd42:70::/48' 'ipv6-subnet-prefix 128' \
    'dns 198.51.100.2' 'route default' 'mtu 1280'; do
    read -r key value <<< "$pair"
    Set_Conf_Value "$key" "$value" || exit 1
done
Set_Conf_Value pid-file "$state/ocserv.pid" || exit 1
Set_Conf_Value occtl-socket-file "$state/occtl.socket" || exit 1
# A deliberate IPv6 split exclusion must not overwrite production IPv4 exclusions.
printf '\nno-route = fd42:99::/64\n' >> "$conf" || exit 1
for ((i=0; i<clients; i++)); do
    # Independent synthetic load identities, not copies of one session/lease.
    { cat "$state/password"; cat "$state/password"; } |
        ocpasswd -c "$passwd_file" -- "load-$i" || exit 1
done
chmod 600 "$passwd_file" || exit 1
# Require the real IPv6 helper to open the routed path under a deny policy.
# The lab supplies the upstream return route, never NAT66 or test-only ACCEPT rules.
ip6tables -P FORWARD DROP || exit 1
Set_iptables || exit 1
Add_iptables 4443 4443 || exit 1
Save_iptables || exit 1
"$file" --test-config -c "$conf" || exit 1

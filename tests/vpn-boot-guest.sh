#!/usr/bin/env bash
# Runs only in the disposable QEMU guest. All service operations are real systemd.
set -euo pipefail
[[ ${VPN_E2E_DISPOSABLE:-0} == 1 && $EUID == 0 && $(cat /proc/1/comm) == systemd ]] || exit 2
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
script=${1:?installer} action=${2:?action} state=${3:?private state}
case "$script" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
# shellcheck disable=SC1090
source "$repo_dir/$script"
check_sys
export TERM=xterm
normalize() { sed -E '/^#/d;s/\[[0-9]+:[0-9]+\]/[0:0]/g'; }
case "$action" in
    install)
        [[ ! -e "$file" && ! -e "$CA_KEY" && ! -e "$passwd_file" ]] || exit 2
        export DEBIAN_FRONTEND=noninteractive OCSERV_SERVER_IDENTITY=192.0.2.1
        apt-get update
        apt-get install -y openconnect vpnc-scripts curl python3 iptables
        mkdir -p "$conf_file"
        cp "$repo_dir/ocserv.conf" "$conf"
        # This is the real checked-out configuration, not a template fetched from main.
        iptables -P FORWARD DROP
        iptables -A INPUT -p tcp --dport 18081 -m comment --comment qa-unrelated -j ACCEPT
        Install_ocserv < "$state/install.input"
        systemctl is-enabled --quiet ocserv
        systemctl is-enabled --quiet ocserv-firewall
        systemctl is-active --quiet ocserv
        systemctl is-active --quiet ocserv-firewall
        iptables-save | normalize > "$state/expected.rules"
        sha256sum "$CA_CERT" "$CA_KEY" "$SSL_DIR/server-key.pem" "$passwd_file" > "$state/credentials.sha256"
        ;;
    inspect)
        # Do not call start/restart here: this checks unattended boot.
        systemctl is-active --quiet ocserv
        systemctl is-active --quiet ocserv-firewall
        systemctl is-enabled --quiet ocserv
        [[ $(sysctl -n net.ipv4.ip_forward) == 1 ]]
        iptables-save | normalize > "$state/actual.rules"
        cmp "$state/expected.rules" "$state/actual.rules"
        sha256sum -c "$state/credentials.sha256"
        systemctl show ocserv -p MainPID -p ActiveState -p UnitFileState -p Requires -p After -p NRestarts
        cat /proc/sys/kernel/random/boot_id
        ;;
    probe)
        ns=vpn-boot-client
        client_pid=''
        cleanup() {
            local status=$?
            trap - EXIT
            if ((status != 0)) && [[ -f "$state/client.log" ]]; then
                # Synthetic guest identity only; never print private cookies or passwords.
                python3 - "$state" <<'PYDIAG'
import re, sys
from pathlib import Path
p = Path(sys.argv[1])
s = (p / 'client.log').read_text(errors='replace').replace((p / 'password').read_text().strip(), '<redacted>')
for line in s.splitlines()[-80:]:
    if not re.search(r'cookie|session-token|authorization|password|PRIVATE KEY', line, re.I):
        print(line, file=sys.stderr)
PYDIAG
            fi
            if [[ -n "$client_pid" ]]; then
                kill -INT "$client_pid" 2>/dev/null || true
                for ((i=0;i<30;i++)); do
                    kill -0 "$client_pid" 2>/dev/null || break
                    sleep 0.1
                done
                kill -TERM "$client_pid" 2>/dev/null || true
                sleep 0.2
                kill -KILL "$client_pid" 2>/dev/null || true
                wait "$client_pid" 2>/dev/null || true
            fi
            ip netns del "$ns" 2>/dev/null || true
            rm -rf "/etc/netns/$ns"
            exit "$status"
        }
        trap cleanup EXIT
        ip netns add "$ns"
        ip link add boot-server type veth peer name boot-client
        ip link set boot-client netns "$ns"
        ip addr add 192.0.2.1/24 dev boot-server
        ip link set boot-server up
        ip -n "$ns" link set lo up
        ip -n "$ns" addr add 192.0.2.2/24 dev boot-client
        ip -n "$ns" link set boot-client up
        ip -n "$ns" route add default via 192.0.2.254
        mkdir -p "/etc/netns/$ns" "$state/client"
        printf 'nameserver 192.0.2.254\n' > "/etc/netns/$ns/resolv.conf"
        port=$(cat "$state/target-port")
        target="http://10.0.2.2:$port/payload"
        if ip netns exec "$ns" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 "$target" -o /dev/null; then
            echo 'Target reachable before VPN' >&2; exit 1
        fi
        export VPNC_REAL_SCRIPT=/usr/share/vpnc-scripts/vpnc-script VPNC_STATE_DIR="$state/client"
        rm -f "$VPNC_STATE_DIR/connected"
        args=(openconnect --protocol=anyconnect --non-inter --no-proxy --no-system-trust
              --cafile "$CA_CERT" --user qa-user --passwd-on-stdin --reconnect-timeout 3
              --interface bootvpn --script "exec bash $repo_dir/tests/vpn-vpnc.sh")
        transport=${4:-dtls}
        [[ $transport == dtls ]] || args+=(--no-dtls)
        ip netns exec "$ns" iptables -N BOOT_UDP
        ip netns exec "$ns" iptables -A BOOT_UDP -j RETURN
        ip netns exec "$ns" iptables -A INPUT -p udp --sport 4443 -j BOOT_UDP
        ip netns exec "$ns" "${args[@]}" https://192.0.2.1:4443/ < "$state/password" \
            > "$state/client.log" 2>&1 &
        client_pid=$!
        for ((i=0;i<150;i++)); do
            [[ -f "$VPNC_STATE_DIR/connected" ]] && break
            kill -0 "$client_pid" || { cat "$state/client.log" >&2; exit 1; }
            sleep 0.2
        done
        [[ -f "$VPNC_STATE_DIR/connected" ]]
        ip -n "$ns" route get 10.0.2.2 | grep -q 'dev bootvpn'
        if [[ $transport == dtls ]]; then
            for ((i=0;i<100;i++)); do
                grep -q 'Established DTLS connection' "$state/client.log" && break
                kill -0 "$client_pid" || exit 1
                sleep 0.2
            done
            grep -q 'Established DTLS connection' "$state/client.log"
        fi
        before=$(ip netns exec "$ns" iptables -nvxL BOOT_UDP | awk '$3=="RETURN" {print $2}')
        ip netns exec "$ns" curl --noproxy '*' -fsS --max-time 20 "$target" -o "$state/received"
        [[ $(sha256sum "$state/received" | awk '{print $1}') == "$(cat "$state/expected-sha256")" ]]
        after=$(ip netns exec "$ns" iptables -nvxL BOOT_UDP | awk '$3=="RETURN" {print $2}')
        if [[ $transport == dtls ]]; then ((after - before > 800000)); else ((after == before)); fi
        echo "PASS: real systemd-managed $transport tunnel carries 1 MiB outside the VM"
        ;;
    stopped)
        ! systemctl is-active --quiet ocserv
        ! ss -Hltn | grep -Eq ':4443[[:space:]]'
        ! ss -Hlun | grep -Eq ':4443[[:space:]]'
        ;;
    uninstall)
        Uninstall_ocserv <<< y
        [[ ! -e "$file" && ! -e "$conf_file" && ! -e /etc/systemd/system/ocserv.service ]]
        ! systemctl is-enabled --quiet ocserv
        iptables -C INPUT -p tcp --dport 18081 -m comment --comment qa-unrelated -j ACCEPT
        ! iptables-save | grep -qE 'vpns|192\.168\.7\.'
        ;;
    *) exit 2 ;;
esac

#!/usr/bin/env bash
# Real dual-stack tunnels, separate edge ACLs and simultaneous bidirectional load.
set -Eeuo pipefail
[[ ${VPN_E2E_DISPOSABLE:-} == 1 && $EUID == 0 && -c /dev/net/tun ]] || exit 2
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
installer=${1:?installer required}
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
seconds=${VPN_SOAK_SECONDS:-60}; clients=${VPN_SOAK_CLIENTS:-6}
[[ $seconds =~ ^[1-9][0-9]*$ && $clients =~ ^[1-9][0-9]*$ ]] || exit 2
((seconds <= 7200 && clients >= 2 && clients <= 100)) || exit 2
for cmd in ip iptables ip6tables curl dig openconnect python3 openssl ping; do
    command -v "$cmd" >/dev/null || { echo "Missing $cmd" >&2; exit 2; }
done
export LC_ALL=C TERM=xterm
state=$(mktemp -d /tmp/vpn-extended.XXXXXX)
logs=${VPN_E2E_LOG_DIR:-/tmp/vpn-extended-results}/extended-$installer
mkdir -p "$logs"
edge=ve-edge-$$; server=ve-server-$$; target=ve-target-$$
namespaces=(); workers=(); client_pids=(); client_names=(); client_modes=()
fail() { printf 'FAIL: %s\n' "$*" | tee "$logs/failure.txt" >&2; exit 1; }
cleanup() {
    status=$?
    trap - EXIT
    set +e
    for ns in "${namespaces[@]}"; do
        mapfile -t remaining < <(ip netns pids "$ns" 2>/dev/null)
        ((${#remaining[@]} == 0)) || kill -TERM "${remaining[@]}" 2>/dev/null
    done
    sleep 1
    for ns in "${namespaces[@]}"; do
        mapfile -t remaining < <(ip netns pids "$ns" 2>/dev/null)
        ((${#remaining[@]} == 0)) || kill -KILL "${remaining[@]}" 2>/dev/null
        ip netns del "$ns" 2>/dev/null
        rm -rf "/etc/netns/$ns"
    done
    # Diagnostics are from generated isolated fixtures only; fail closed on key material.
    # External VPS authentication logs are never uploaded by vpn-probe.py.
    if ((status != 0)); then
        python3 - "$state" "$logs" <<'PYDIAG'
import re, sys
from pathlib import Path
root, output = map(Path, sys.argv[1:])
secret_file = root / 'password'
secret = secret_file.read_text().strip() if secret_file.exists() else ''
for pattern in ('setup.log', 'server.log', 'target.log', 'worker-*.log', 'c*/client.log'):
    for path in root.glob(pattern):
        text = path.read_text(errors='replace')
        if 'PRIVATE KEY' in text:
            continue
        if secret:
            text = text.replace(secret, '<redacted>')
        lines = [line for line in text.splitlines()
                 if not re.search(r'cookie|session-token|authorization|password', line, re.I)]
        (output / ('diagnostic-' + str(path.relative_to(root)).replace('/', '-'))).write_text('\n'.join(lines[-100:]) + '\n')
PYDIAG
    fi
    # Never upload raw authentication logs, cookies, keys or account inputs.
    printf '{"exit_status":%s,"requested_seconds":%s,"requested_clients":%s}\n' \
        "$status" "$seconds" "$clients" > "$logs/status.json"
    rm -rf "$state"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
new_ns() {
    ip netns add "$1"; namespaces+=("$1")
    ip -n "$1" link set lo up
    ip netns exec "$1" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
}
pair() {
    ip link add "vpa$$" type veth peer name "vpb$$"
    ip link set "vpa$$" netns "$1"; ip -n "$1" link set "vpa$$" name "$2"
    ip link set "vpb$$" netns "$3"; ip -n "$3" link set "vpb$$" name "$4"
    ip -n "$1" link set "$2" up; ip -n "$3" link set "$4" up
}
addr() { ip -n "$1" addr add "$3" dev "$2"; ip -n "$1" -6 addr add "$4" dev "$2" nodad; }
for ns in "$edge" "$server" "$target"; do new_ns "$ns"; done
ip -n "$edge" link add brc type bridge
ip -n "$edge" link set brc up
addr "$edge" brc 192.0.2.1/24 fd42:10::1/64
pair "$edge" es "$server" wan
addr "$edge" es 203.0.113.1/24 fd42:20::1/64
addr "$server" wan 203.0.113.2/24 fd42:20::2/64
pair "$server" ve "$target" vt
addr "$server" ve 198.51.100.1/24 fd42:30::1/64
addr "$target" vt 198.51.100.2/24 fd42:30::2/64
ip -n "$server" route add default via 198.51.100.2
ip -n "$server" -6 route add default via fd42:30::2
ip -n "$server" route add 192.0.2.0/24 via 203.0.113.1
ip -n "$server" -6 route add fd42:10::/64 via fd42:20::1
ip -n "$target" -6 route add fd42:70::/48 via fd42:30::1
ip netns exec "$edge" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
# Use a real default router. A nonexistent IPv6 next hop becomes NUD_FAILED;
# Linux can then reject the more-specific exclusion and select the tunnel's
# usable default instead. Isolation must be enforced by ACLs, not dead gateways.
for fw in iptables ip6tables; do
    ip netns exec "$edge" "$fw" -P FORWARD DROP
    if [[ $fw == iptables ]]; then endpoint=203.0.113.2; else endpoint=fd42:20::2; fi
    for protocol in tcp udp; do
        ip netns exec "$edge" "$fw" -A FORWARD -d "$endpoint" -p "$protocol" --dport 4443 -j ACCEPT
        ip netns exec "$edge" "$fw" -A FORWARD -s "$endpoint" -p "$protocol" --sport 4443 \
            -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    done
done
for ((i=0; i<clients; i++)); do
    c=ve-client-$i-$$; client_names+=("$c"); client_pids+=(0); client_modes+=(tls)
    new_ns "$c"; pair "$c" vc "$edge" "c$i"
    # Counters belong to this client, not all sessions on the server. Another
    # client's handshake/keepalive must not look like TLS unexpectedly using UDP.
    for fw in iptables ip6tables; do
        ip netns exec "$c" "$fw" -N VE_UDP
        ip netns exec "$c" "$fw" -A VE_UDP -j RETURN
        ip netns exec "$c" "$fw" -A INPUT -p udp --sport 4443 -j VE_UDP
    done
    ip -n "$edge" link set "c$i" master brc
    addr "$c" vc "192.0.2.$((i+10))/24" "fd42:10::$((i+10))/64"
    ip -n "$c" route add default via 192.0.2.1
    ip -n "$c" route add 203.0.113.2/32 via 192.0.2.1
    ip -n "$c" -6 route add default via fd42:10::1
    ip -n "$c" -6 route add fd42:20::2/128 via fd42:10::1
    mkdir -p "/etc/netns/$c" "$state/c$i"
    printf 'nameserver 192.0.2.254\n' > "/etc/netns/$c/resolv.conf"
    # Alternate outer IP family, independently of inner workload family.
    if ((i%2)); then endpoint=fd42:20::2; else endpoint=203.0.113.2; fi
    printf '127.0.0.1 localhost\n::1 localhost\n%s vpn-fixture.invalid\n' "$endpoint" > "/etc/netns/$c/hosts"
done
openssl rand -hex 24 > "$state/password"
ip netns exec "$server" bash "$repo/tests/vpn-extended-setup.sh" "$installer" "$state" "$clients" > "$state/setup.log" 2>&1 || fail 'fixture setup failed'
ip netns exec "$server" /usr/local/sbin/ocserv -f -c /etc/ocserv/ocserv.conf > "$state/server.log" 2>&1 &
server_pid=$!
ip netns exec "$target" python3 "$repo/tests/vpn-workload.py" serve > "$state/target.log" 2>&1 &
target_pid=$!
for ((n=0; n<100; n++)); do
    [[ -S $state/occtl.socket ]] && grep -q '^ready' "$state/target.log" && break
    kill -0 "$server_pid" "$target_pid" || fail 'server or target exited'
    sleep .1
done
[[ -S $state/occtl.socket ]] && grep -q '^ready' "$state/target.log" || fail 'readiness timeout'
for candidate in /usr/share/vpnc-scripts/vpnc-script /etc/vpnc/vpnc-script /etc/openconnect/vpnc-script; do
    if [[ -x $candidate ]]; then export VPNC_REAL_SCRIPT=$candidate; break; fi
done
: "${VPNC_REAL_SCRIPT:?vpnc-script missing}"
stop_client() {
    local i=$1 pid=${client_pids[$1]}
    if ((pid)); then
        kill -INT "$pid" 2>/dev/null || true
        for ((n=0; n<50; n++)); do kill -0 "$pid" 2>/dev/null || break; sleep .1; done
        if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid"; fail 'client failed to stop cleanly'; fi
        wait "$pid" 2>/dev/null || true
        client_pids[$i]=0
    fi
}
connect_client() {
    local i=$1 mode=$2 c=${client_names[$1]}
    local extra=()
    stop_client "$i"
    # vpnc-script may remove its gateway exception on disconnect. Restore only
    # the declared underlay endpoint routes, never a route to the inner targets.
    ip -n "$c" route replace 203.0.113.2/32 via 192.0.2.1
    ip -n "$c" -6 route replace fd42:20::2/128 via fd42:10::1
    client_modes[$i]=$mode
    rm -f "$state/c$i/connected"
    [[ $mode != tls ]] || extra+=(--no-dtls)
    export VPNC_STATE_DIR="$state/c$i"
    ip netns exec "$c" openconnect --protocol anyconnect --non-inter --no-proxy \
        --no-system-trust --cafile /etc/ocserv/ssl/ca-cert.pem --user "load-$i" \
        --passwd-on-stdin --interface vpntest --reconnect-timeout 5 \
        --script "exec bash $repo/tests/vpn-vpnc.sh" "${extra[@]}" \
        https://vpn-fixture.invalid:4443/ < "$state/password" > "$state/c$i/client.log" 2>&1 &
    client_pids[$i]=$!
    for ((n=0; n<200; n++)); do
        [[ -e $state/c$i/connected ]] && break
        kill -0 "${client_pids[$i]}" 2>/dev/null || return 1
        sleep .1
    done
    [[ -e $state/c$i/connected ]] || return 1
    if [[ $mode == dtls ]]; then
        for ((n=0; n<150; n++)); do grep -q 'Established DTLS connection' "$state/c$i/client.log" && break; sleep .1; done
        grep -q 'Established DTLS connection' "$state/c$i/client.log" || return 1
    fi
}
unreachable() {
    local c=$1
    if ip netns exec "$c" curl --noproxy '*' -gfsS --connect-timeout 1 --max-time 2 \
        'http://[fd42:30::2]:8080/payload' -o /dev/null 2>/dev/null; then fail 'IPv6 bypass'; fi
}
require_route_device() {
    local c=$1 address=$2 device=$3 route
    # Capture all output before inspecting it. A short-circuiting grep can close
    # a pipe before ip writes its cache line, producing SIGPIPE under pipefail.
    route=$(ip -n "$c" -6 route get "$address") || fail "IPv6 route query failed: $address"
    [[ " $route " == *" dev $device "* ]] || fail "Unexpected IPv6 route for $address: $route"
}
traffic() {
    local i=$1 c=${client_names[$1]} url family expected actual before after counter_fw transport
    if ((i%2)); then counter_fw=ip6tables; else counter_fw=iptables; fi
    before=$(ip netns exec "$c" "$counter_fw" -nvxL VE_UDP | awk '$3=="RETURN" {print $2}')
    ip -n "$c" -6 addr show dev vpntest | grep 'fd42:70:' >/dev/null || fail 'IPv6 lease absent'
    require_route_device "$c" fd42:30::2 vpntest
    require_route_device "$c" fd42:99::1 vc
    for family in 4 6; do
        if ((family == 4)); then url=http://198.51.100.2:8080/payload; else url='http://[fd42:30::2]:8080/payload'; fi
        ip netns exec "$c" curl --noproxy '*' -gfsS --max-time 15 -D "$state/headers" "$url" -o "$state/payload"
        expected=$(python3 "$repo/tests/vpn-workload.py" digest)
        [[ $(sha256sum "$state/payload" | cut -d' ' -f1) == "$expected" ]] || fail 'payload integrity'
        if ((family == 4)); then grep -q 'X-Seen-Client-IP: 198.51.100.1' "$state/headers" || fail 'IPv4 NAT';
        else grep -q 'X-Seen-Client-IP: fd42:70:' "$state/headers" || fail 'IPv6 routed source'; fi
    done
    after=$(ip netns exec "$c" "$counter_fw" -nvxL VE_UDP | awk '$3=="RETURN" {print $2}')
    if [[ ${client_modes[$i]} == dtls ]]; then
        ((after-before > 200000)) || fail 'DTLS handshake did not carry the actual payload'
    else
        ((after == before)) || fail 'TLS-only/fallback case transmitted UDP data'
    fi
    for transport in '' '+tcp'; do
        # Query an IPv6 resolver over both UDP and TCP, require the AAAA result.
        ip netns exec "$c" dig $transport +short +time=2 +tries=1 @fd42:30::2 vpn-test.internal AAAA |
            grep -Fx fd42:30::2 >/dev/null || fail 'IPv6 DNS'
    done
    ip netns exec "$c" curl --noproxy '*' -6fsS --max-time 15 \
        -D "$logs/hostname-headers.txt" -w '%{remote_ip} %{http_code} %{size_download}\n' \
        http://vpn-test.internal:8080/payload -o "$state/payload" > "$logs/hostname-result.txt" ||
        fail 'normal AAAA HTTP request failed'
    actual=$(sha256sum "$state/payload" | cut -d' ' -f1)
    printf 'expected=%s\nactual=%s\nbytes=%s\n' "$expected" "$actual" \
        "$(wc -c < "$state/payload")" > "$logs/hostname-integrity.txt"
    [[ $actual == "$expected" ]] || fail 'normal AAAA payload integrity (see hostname-integrity.txt)'
}
# Positive and negative controls at two distinct firewall layers.
for i in 0 1; do
    c=${client_names[$i]}; unreachable "$c"
    ip netns exec "$c" ping -6 -c 1 -W 2 fd42:10::1 >/dev/null || fail 'IPv6 underlay router unreachable'
    if ((i)); then fw=ip6tables; endpoint=fd42:20::2; else fw=iptables; endpoint=203.0.113.2; fi
    connect_client "$i" dtls || fail 'dual-stack DTLS connection'
    traffic "$i"
    ip netns exec "$server" ip6tables -I FORWARD -i 'vpns+' -d fd42:30::2 -j DROP
    unreachable "$c"
    ip netns exec "$server" ip6tables -D FORWARD -i 'vpns+' -d fd42:30::2 -j DROP
    ip netns exec "$server" sysctl -qw net.ipv6.conf.all.forwarding=0
    unreachable "$c"
    ip netns exec "$server" sysctl -qw net.ipv6.conf.all.forwarding=1
    traffic "$i"
    stop_client "$i"; unreachable "$c"
    # Separate edge node, not the server firewall: blocked UDP must retain TLS data.
    ip netns exec "$edge" "$fw" -I FORWARD -d "$endpoint" -p udp --dport 4443 -j DROP
    connect_client "$i" fallback || fail 'UDP-blocked TLS fallback'
    traffic "$i"
    sleep 3
    ! grep -q 'Established DTLS connection' "$state/c$i/client.log" || fail 'blocked UDP unexpectedly negotiated DTLS'
    ip netns exec "$edge" "$fw" -nvxL FORWARD | awk '$3=="DROP" && $1>0 {ok=1} END {exit !ok}' || fail 'edge UDP drop not exercised'
    stop_client "$i"
    ip netns exec "$edge" "$fw" -D FORWARD -d "$endpoint" -p udp --dport 4443 -j DROP
    # The controlled network failure is not counted as an authentication rejection.
    ip netns exec "$edge" "$fw" -I FORWARD -d "$endpoint" -p tcp --dport 4443 -j DROP
    if connect_client "$i" tls; then fail 'blocked TCP established a tunnel'; fi
    pid=${client_pids[$i]}; kill -TERM "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; client_pids[$i]=0
    ip netns exec "$edge" "$fw" -nvxL FORWARD | awk '$3=="DROP" && $1>0 {ok=1} END {exit !ok}' || fail 'edge TCP drop not exercised'
    ip netns exec "$edge" "$fw" -D FORWARD -d "$endpoint" -p tcp --dport 4443 -j DROP
    connect_client "$i" dtls || fail 'edge ACL recovery'
    traffic "$i"; stop_client "$i"
done
printf 'PASS: IPv4/IPv6 outer connections, IPv6 payload/DNS/split routes, edge TCP/UDP ACLs and recovery\n'
# All sessions coexist; clients are not merely exercised one at a time.
for ((i=0; i<clients; i++)); do
    if ((i%2)); then mode=dtls; else mode=tls; fi
    connect_client "$i" "$mode" || fail "load client $i"
    traffic "$i"
done
printf 'sample,processes,rss_kib,open_fds,cpu_ticks\n' > "$logs/resources.csv"
start=$SECONDS
for ((i=0; i<clients; i++)); do
    family=$((4+2*(i%2)))
    ip netns exec "${client_names[$i]}" python3 "$repo/tests/vpn-workload.py" load \
        --seconds "$seconds" --family "$family" --report "$logs/client-$i.json" > "$state/worker-$i.log" 2>&1 &
    workers+=("$!")
done
while ((SECONDS-start < seconds)); do
    kill -0 "$server_pid" "$target_pid" || fail 'daemon exited under load'
    for pid in "${client_pids[@]}"; do kill -0 "$pid" || fail 'client exited under load'; done
    ip netns exec "$server" python3 - "$start" "$SECONDS" <<'PY' >> "$logs/resources.csv"
import os, sys
from pathlib import Path
# /proc membership is obtained from this network namespace, not host-wide process totals.
import subprocess
pids = subprocess.check_output(['ip', 'netns', 'identify', str(os.getpid())], text=True).strip()
ids = subprocess.check_output(['ip', 'netns', 'pids', pids], text=True).split()
rss = fds = count = ticks = 0
for pid in ids:
    try:
        status = Path('/proc', pid, 'status').read_text()
        rss += sum(int(x.split()[1]) for x in status.splitlines() if x.startswith('VmRSS:'))
        fds += len(list(Path('/proc', pid, 'fd').iterdir()))
        stat = Path('/proc', pid, 'stat').read_text().rsplit(')', 1)[1].split()
        ticks += int(stat[11]) + int(stat[12])
        count += 1
    except (FileNotFoundError, ProcessLookupError):
        pass
print(int(sys.argv[2])-int(sys.argv[1]), count, rss, fds, ticks, sep=',')
PY
    sleep 5
done
for pid in "${workers[@]}"; do wait "$pid" || fail 'load worker failed integrity, UDP or timing checks'; done
for ((i=0; i<clients; i++)); do stop_client "$i"; done
for ((n=0; n<100; n++)); do
    if ! ip -n "$server" -o link show | grep 'vpns' >/dev/null; then break; fi
    sleep .1
done
! ip -n "$server" -o link show | grep 'vpns' >/dev/null || fail 'TUN interfaces leaked after disconnect'
printf 'PASS: %s concurrent clients for %s seconds; bidirectional integrity and UDP echo\n' "$clients" "$seconds"

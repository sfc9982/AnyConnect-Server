#!/usr/bin/env bash
# Client(s) -> independent edge firewall -> ocserv -> private IPv4/IPv6 target.
set -Eeuo pipefail
[[ "${VPN_E2E_DISPOSABLE:-}" == 1 && "$EUID" -eq 0 && -c /dev/net/tun ]] || exit 1
repo=$(cd "$(dirname "$0")/../.." && pwd)
installer=${1:?installer required}
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
seconds=${VPN_SOAK_SECONDS:-60}; clients=${VPN_SOAK_CLIENTS:-4}
[[ "$seconds" =~ ^[0-9]+$ && "$clients" =~ ^[0-9]+$ ]] || exit 2
((seconds >= 1 && seconds <= 7200 && clients >= 2 && clients <= 8)) || exit 2
export LC_ALL=C TERM=xterm
state=$(mktemp -d /tmp/vpn-qualification.XXXXXX)
logs=${VPN_E2E_LOG_DIR:-/tmp/vpn-qualification-logs}/qualification-$installer
mkdir -p "$logs"
chmod 700 "$state"
failure_reason="unexpected command failure"
server=q-s-$$; edge=q-e-$$; target=q-t-$$
ns_list=("$server" "$edge" "$target")
client_pids=(); server_pid=''; metrics_pid=''; target_pid=''
fail() { failure_reason="$*"; echo "FAIL: $*" >&2; exit 1; }
cleanup() {
    local rc=$? ns pid
    trap - EXIT
    set +e
    touch "$state/metrics.stop"
    for ns in "${ns_list[@]}"; do
        for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -TERM "$pid" 2>/dev/null; done
    done
    sleep 1
    for ns in "${ns_list[@]}"; do
        for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -KILL "$pid" 2>/dev/null; done
        ip netns del "$ns" 2>/dev/null
        rm -rf "/etc/netns/$ns"
    done
    [[ -z "$metrics_pid" ]] || wait "$metrics_pid" 2>/dev/null
    # Only these diagnostic files are uploaded; credentials and raw logs are private.
    if ((rc != 0)); then
        for f in "$state"/*.log; do
            [[ -f "$f" ]] || continue
            sed -E '/cookie|password|passwd|BEGIN .*PRIVATE KEY/I d' "$f" | tail -60 >&2
        done
    fi
    python3 - "$logs/status.json" "$rc" "$failure_reason" "$seconds" "$clients" <<'STATUS'
import json, sys
from pathlib import Path
path, rc, reason, duration, clients = sys.argv[1:]
Path(path).write_text(json.dumps({"exit_code": int(rc), "passed": int(rc) == 0,
    "reason": reason if int(rc) else "all assertions completed",
    "requested_soak_seconds": int(duration), "requested_clients": int(clients)}, indent=2) + "\n")
STATUS
    rm -rf "$state"
    exit "$rc"
}
trap cleanup EXIT
for candidate in /usr/share/vpnc-scripts/vpnc-script /etc/vpnc/vpnc-script /etc/openconnect/vpnc-script; do
    if [[ -x "$candidate" ]]; then VPNC_REAL_SCRIPT=$candidate; break; fi
done
export VPNC_REAL_SCRIPT
: "${VPNC_REAL_SCRIPT:?missing stock vpnc script}"
for ((n=0; n<clients; n++)); do ns_list+=("q-c$n-$$"); done
for ns in "${ns_list[@]}"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
    ip netns exec "$ns" sysctl -qw net.ipv6.conf.default.disable_ipv6=0
done
ip -n "$edge" link add brc type bridge
ip -n "$edge" link set brc up
ip -n "$edge" addr add 192.0.2.254/24 dev brc
ip -n "$edge" -6 addr add 2001:db8:c::fe/64 dev brc nodad
for ((n=0; n<clients; n++)); do
    ns=q-c$n-$$
    ip link add qc type veth peer name qe
    ip link set qc netns "$ns"
    ip link set qe netns "$edge"
    ip -n "$edge" link set qe name "ec$n"
    ip -n "$edge" link set "ec$n" master brc
    ip -n "$edge" link set "ec$n" up
    ip -n "$ns" addr add "192.0.2.$((10+n))/24" dev qc
    ip -n "$ns" -6 addr add "2001:db8:c::$((10+n))/64" dev qc nodad
    ip -n "$ns" link set qc up
    ip -n "$ns" route add default via 192.0.2.254
    ip -n "$ns" -6 route add default via 2001:db8:c::fe
    mkdir -p "/etc/netns/$ns"
    printf 'nameserver 192.0.2.253\n' > "/etc/netns/$ns/resolv.conf"
    password=$(openssl rand -hex 24)
    printf '%s\n' "$password" > "$state/password-$n"
    printf 'qual-%s\n%s\n' "$n" "$password" > "$state/account-$n.input"
done
ip link add es type veth peer name vs
ip link set es netns "$edge"; ip link set vs netns "$server"
ip link add ve type veth peer name vt
ip link set ve netns "$server"; ip link set vt netns "$target"
ip -n "$edge" addr add 198.18.0.1/24 dev es
ip -n "$edge" -6 addr add 2001:db8:1::1/64 dev es nodad
ip -n "$server" addr add 198.18.0.2/24 dev vs
ip -n "$server" -6 addr add 2001:db8:1::2/64 dev vs nodad
ip -n "$server" addr add 198.51.100.1/24 dev ve
ip -n "$server" -6 addr add 2001:db8:2::1/64 dev ve nodad
ip -n "$target" addr add 198.51.100.2/24 dev vt
ip -n "$target" -6 addr add 2001:db8:2::2/64 dev vt nodad
ip -n "$edge" link set es up; ip -n "$server" link set vs up
ip -n "$server" link set ve up; ip -n "$target" link set vt up
ip -n "$server" route add 192.0.2.0/24 via 198.18.0.1
ip -n "$server" -6 route add 2001:db8:c::/64 via 2001:db8:1::1
ip -n "$server" route add default via 198.51.100.2
ip -n "$server" -6 route add default via 2001:db8:2::2
ip -n "$target" -6 route add fd42:7::/64 via 2001:db8:2::1
ip netns exec "$edge" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1
# The edge has no permitted forwarding path to either inner target.
edge_policy() {
    local policy=$1 tool family srv subnet n client
    for family in 4 6; do
        tool=iptables; srv=198.18.0.2; subnet=192.0.2.0/24
        if [[ "$family" == 6 ]]; then tool=ip6tables; srv=2001:db8:1::2; subnet=2001:db8:c::/64; fi
        ip netns exec "$edge" "$tool" -F FORWARD
        ip netns exec "$edge" "$tool" -P FORWARD DROP
        if [[ "$policy" == no-ipv6 && "$family" == 6 ]]; then
            ip netns exec "$edge" "$tool" -A FORWARD -m comment --comment blocked-ipv6 -j DROP
            continue
        fi
        if [[ "$policy" == tcp-blocked ]]; then
            ip netns exec "$edge" "$tool" -A FORWARD -p tcp -m comment --comment blocked-tcp -j DROP
        fi
        if [[ "$policy" == udp-blocked ]]; then
            ip netns exec "$edge" "$tool" -A FORWARD -p udp -m comment --comment blocked-udp -j DROP
        fi
        # Counter-only rules identify each outer flow; another busy client must
        # never hide a silent DTLS-to-TLS fallback in the sustained workload.
        for ((n=0; n<clients; n++)); do
            client="192.0.2.$((10+n))"
            [[ "$family" != 6 ]] || client="2001:db8:c::$((10+n))"
            ip netns exec "$edge" "$tool" -A FORWARD -s "$client" -d "$srv" \
                -p udp --dport 4443 -m comment --comment "qualification-udp-$n"
        done
        for protocol in tcp udp; do
            ip netns exec "$edge" "$tool" -A FORWARD -s "$subnet" -d "$srv" -p "$protocol" --dport 4443 -j ACCEPT
        done
        if [[ "$policy" == stateless ]]; then
            for protocol in tcp udp; do
                ip netns exec "$edge" "$tool" -A FORWARD -s "$srv" -d "$subnet" -p "$protocol" --sport 4443 --dport 1024:65535 -j ACCEPT
            done
        elif [[ "$policy" != missing-return ]]; then
            ip netns exec "$edge" "$tool" -A FORWARD -s "$srv" -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        fi
        if [[ "$family" == 6 ]]; then
            ip netns exec "$edge" "$tool" -A FORWARD -p ipv6-icmp -j ACCEPT
        fi
        ip netns exec "$edge" "$tool" -A FORWARD -m comment --comment blocked-unmatched -j DROP
    done
}
edge_policy stateful
head -c 1048576 /dev/urandom > "$state/payload"
ip netns exec "$target" python3 "$repo/tests/qualification/target.py" \
    --address 198.51.100.2 --address 2001:db8:2::2 --dns-port 53 --payload "$state/payload" > "$state/target.log" 2>&1 &
target_pid=$!
for ((i=0;i<100;i++)); do grep -q '^ready' "$state/target.log" && break; sleep .1; done
grep -q '^ready' "$state/target.log" || fail 'target not ready'
ip netns exec "$server" bash "$repo/tests/qualification/server.sh" "$installer" "$state" "$clients" > "$state/setup.log" 2>&1
# Configuration must be idempotent without duplicated rules.
ip netns exec "$server" ip6tables-save > "$state/rules-before"
ip netns exec "$server" bash "$repo/ocserv-network.sh" up > "$state/ipv6-reapply.log" 2>&1
ip netns exec "$server" ip6tables-save > "$state/rules-after"
diff -u <(grep -v '^#' "$state/rules-before") <(grep -v '^#' "$state/rules-after")
start_server() {
    ip netns exec "$server" /usr/local/sbin/ocserv -f -c /etc/ocserv/ocserv.conf > "$state/server.log" 2>&1 &
    server_pid=$!
    for ((i=0;i<100;i++)); do
        ip netns exec "$server" ss -ltn | grep -q ':4443' && return 0
        kill -0 "$server_pid" || fail 'server exited'
        sleep .1
    done
    fail 'server readiness timed out'
}
start_server
stop_clients() {
    local pid
    for pid in "${client_pids[@]}"; do kill -INT "$pid" 2>/dev/null || true; done
    for pid in "${client_pids[@]}"; do
        for ((i=0;i<50;i++)); do kill -0 "$pid" 2>/dev/null || break; sleep .1; done
        if kill -0 "$pid" 2>/dev/null; then fail 'client did not restore routes on disconnect'; fi
        wait "$pid" 2>/dev/null || true
    done
    client_pids=()
}
connect() {
    local n=$1 outer=$2 transport=$3 label=$4 ns address
    probe_transport=$transport
    ns=q-c$n-$$
    address=198.18.0.2; [[ "$outer" != 6 ]] || address=2001:db8:1::2
    printf '%s vpn-qualification.test\n' "$address" > "/etc/netns/$ns/hosts"
    mkdir -p "$state/client-$n"
    rm -f "$state/client-$n/connected"
    local -a args=(--protocol=anyconnect --non-inter --no-proxy --no-system-trust
        --cafile /etc/ocserv/ssl/ca-cert.pem --user "qual-$n" --passwd-on-stdin
        --interface vpntest --reconnect-timeout 5
        --script "exec bash $repo/tests/qualification/vpnc.sh")
    [[ "$transport" != tls ]] || args+=(--no-dtls)
    # Parse the actual argument vector without connecting. Unsupported client
    # options are setup errors, never an expected policy/authentication failure.
    openconnect "${args[@]}" --version > /dev/null 2> "$state/$label-cli.log" ||
        fail "$label unsupported OpenConnect arguments"
    ip netns exec "$ns" env VPNC_STATE_DIR="$state/client-$n" openconnect "${args[@]}" \
        https://vpn-qualification.test:4443/ < "$state/password-$n" > /dev/null 2> "$state/$label-$n.log" &
    client_pids+=("$!")
    for ((i=0;i<200;i++)); do
        [[ -f "$state/client-$n/connected" ]] && break
        kill -0 "${client_pids[-1]}" || fail "$label client exited"
        sleep .1
    done
    [[ -f "$state/client-$n/connected" ]] || fail "$label tunnel timed out"
    ip -n "$ns" route get 198.51.100.2 | grep -q 'dev vpntest' || fail 'IPv4 bypass'
    ip -n "$ns" -6 route get 2001:db8:2::2 | grep -q 'dev vpntest' || fail 'IPv6 bypass'
    ip -n "$ns" -6 addr show dev vpntest | grep -q 'fd42:7:' || fail 'missing IPv6 lease'
    if [[ "$transport" == dtls ]]; then
        for ((i=0;i<100;i++)); do grep -q 'Established DTLS connection' "$state/$label-$n.log" && break; sleep .1; done
        grep -q 'Established DTLS connection' "$state/$label-$n.log" || fail 'DTLS fallback hid a failure'
    fi
}
udp_accepted_bytes() {
    local n=$1
    { ip netns exec "$edge" iptables -nvxL FORWARD; ip netns exec "$edge" ip6tables -nvxL FORWARD; } |
        awk -v marker="qualification-udp-$n" '$NF == "*/" && $(NF-1) == marker {s += $2} END {printf "%.0f\n", s}'
}
probe() {
    local n=$1 label=$2 duration=$3 family=$4 ns url peer before after
    before=$(udp_accepted_bytes "$n")
    ns=q-c$n-$$
    url=http://198.51.100.2:8080; peer=198.51.100.1
    if [[ "$family" == 6 ]]; then
        url='http://[2001:db8:2::2]:8080'
        peer=$(cat "$state/client-$n/ipv6"); peer=${peer%%/*}
        [[ "${nat66:-0}" != 1 ]] || peer=2001:db8:2::1
    fi
    ip netns exec "$ns" python3 "$repo/tests/qualification/traffic.py" --url "$url" \
        --payload "$state/payload" --seconds "$duration" --workers 2 --expected-peer "$peer" \
        --output "$logs/$label-$n-v$family.json"
    after=$(udp_accepted_bytes "$n")
    if [[ "${probe_transport:-}" == dtls ]]; then
        ((after - before > 1048576)) || fail "DTLS negotiated but payload used TCP"
    elif [[ "${probe_transport:-}" == tls ]]; then
        ((after == before)) || fail "TCP-only test used outer UDP"
    fi
}
unreachable() {
    local family url
    for family in 4 6; do
        url=http://198.51.100.2:8080/payload
        [[ "$family" != 6 ]] || url='http://[2001:db8:2::2]:8080/payload'
        if ip netns exec "q-c0-$$" curl --noproxy '*' -gfsS --max-time 2 "$url" -o /dev/null 2>/dev/null; then
            fail "IPv$family target reachable outside authorized VPN path"
        fi
    done
}
unreachable
# Outer IPv4 and IPv6 x TLS/DTLS, and both inner address families.
for outer in 4 6; do
    for transport in tls dtls; do
        connect 0 "$outer" "$transport" "outer$outer-$transport"
        probe 0 "outer$outer-$transport" 1 4
        probe 0 "outer$outer-$transport" 1 6
        for resolver in 198.51.100.2 2001:db8:2::2; do
            for protocol in '' +tcp; do
                ip netns exec "q-c0-$$" dig $protocol +short +time=2 +tries=1 @"$resolver" vpn-test.internal AAAA |
                    grep -Fxq '2001:db8:2::2' || fail 'AAAA DNS through tunnel failed'
            done
        done
        ip netns exec "q-c0-$$" curl -6 --noproxy '*' -fsS --max-time 10 \
            http://vpn-test.internal:8080/payload -o "$state/dns-payload"
        cmp "$state/payload" "$state/dns-payload"
        ip netns exec "$server" ip6tables -I FORWARD -i vpns+ -d 2001:db8:2::2 -j DROP
        if ip netns exec "q-c0-$$" curl --noproxy '*' -gfsS --max-time 2 \
            'http://[2001:db8:2::2]:8080/payload' -o /dev/null 2>/dev/null; then
            fail 'IPv6 traffic bypassed the forwarding drop'
        fi
        ip netns exec "$server" ip6tables -D FORWARD -i vpns+ -d 2001:db8:2::2 -j DROP
        stop_clients
        unreachable
    done
done
# Sustained load is simultaneous across separate authenticated client namespaces.
soak_transports=()
for ((n=0;n<clients;n++)); do
    transport=tls; ((n%2 == 0)) || transport=dtls
    soak_transports+=("$transport")
    connect "$n" "$((n%2==0 ? 4 : 6))" "$transport" soak
done
python3 "$repo/tests/qualification/metrics.py" --pid "$server_pid" --stop "$state/metrics.stop" \
    --output "$logs/resources.jsonl" & metrics_pid=$!
ip -n "$server" link set ve mtu 1280
ip -n "$target" link set vt mtu 1280
load_pids=()
for ((n=0;n<clients;n++)); do
    probe_transport="${soak_transports[$n]}" probe "$n" soak "$seconds" "$((n%2==0 ? 4 : 6))" \
        > "$state/load-$n.log" 2>&1 & load_pids+=("$!")
done
load_ok=1
for pid in "${load_pids[@]}"; do wait "$pid" || load_ok=0; done
touch "$state/metrics.stop"
wait "$metrics_pid" || load_ok=0
metrics_pid=''
((load_ok)) || fail 'sustained traffic or process resource limit failed'
for pid in "${client_pids[@]}" "$server_pid"; do kill -0 "$pid" || fail 'process died under load'; done
stop_clients
# Stateful and stateless models are not labelled as real cloud certification.
edge_policy stateless
connect 0 6 dtls stateless; probe 0 stateless 1 6; stop_clients
edge_policy udp-blocked
connect 0 4 fallback udp-blocked; probe 0 udp-blocked 1 4
ip netns exec "$edge" iptables -nvxL FORWARD > "$logs/udp-blocked-counters.txt"
awk '$3 == "DROP" && $4 == "udp" {n += $1} END {exit !(n > 0)}' "$logs/udp-blocked-counters.txt" ||
    fail 'UDP fallback was not preceded by a real blocked DTLS attempt'
! grep -q 'Established DTLS connection' "$state/udp-blocked-0.log" || fail 'blocked UDP still established DTLS'
stop_clients
for policy in tcp-blocked missing-return no-ipv6; do
    edge_policy "$policy"
    printf '2001:db8:1::2 vpn-qualification.test\n' > "/etc/netns/q-c0-$$/hosts"
    if ip netns exec "q-c0-$$" timeout --kill-after=2 8 openconnect --non-inter --no-proxy \
        --no-system-trust --cafile /etc/ocserv/ssl/ca-cert.pem --user qual-0 --passwd-on-stdin \
        --cookieonly https://vpn-qualification.test:4443/ < "$state/password-0" > /dev/null 2> "$state/$policy.log"; then
        fail "$policy did not block the outer IPv6 connection"
    fi
    ip netns exec "$edge" ip6tables -nvxL FORWARD > "$logs/$policy-counters.txt"
    awk '$3 == "DROP" {n += $1} END {exit !(n > 0)}' "$logs/$policy-counters.txt" ||
        fail "$policy failed without a dropped packet at the edge"
    # A positive control after every fault distinguishes policy failures from a dead server.
    edge_policy stateful
    connect 0 6 dtls "$policy-control"; probe 0 "$policy-control" 1 6; stop_clients
done
# Explicit NAT66 mode: remove the target return route so routing cannot fake NAT.
kill -TERM "$server_pid"; wait "$server_pid" || true; server_pid=''
ip netns exec "$server" bash "$repo/ocserv-network.sh" remove > "$state/remove-profile.log" 2>&1
ip netns exec "$server" bash "$repo/ocserv-network.sh" configure --pool fd42:7::/64 --client-prefix 128 \
    --ingress vs --egress ve --mode nat66 > "$state/nat66.log" 2>&1
ip -n "$target" -6 route del fd42:7::/64
nat66=1
start_server
connect 0 6 dtls nat66; probe 0 nat66 1 6; stop_clients
unreachable
printf '{"passed":true,"clients":%d,"soak_seconds":%d,"firewall_scope":"local models, not live providers"}\n' \
    "$clients" "$seconds" > "$logs/summary.json"
echo "PASS: $installer IPv4/IPv6, routed/NAT66, sustained load and isolated upstream firewall policies"

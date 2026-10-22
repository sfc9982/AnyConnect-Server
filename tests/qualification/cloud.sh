#!/usr/bin/env bash
# Active acceptance against an explicitly configured, dedicated test VPS.
# Never changes provider policy, remote services, or the host's network namespace.
set -Eeuo pipefail
[[ "${VPN_E2E_DISPOSABLE:-}" == 1 && "$EUID" -eq 0 && -c /dev/net/tun ]] || exit 1
: "${VPN_CLOUD_SERVER:?}" "${VPN_CLOUD_USER:?}" "${VPN_CLOUD_PASSWORD:?}"
: "${VPN_CLOUD_CA:?}" "${VPN_CLOUD_TARGET4:?}" "${VPN_CLOUD_TARGET6:?}"
: "${VPN_CLOUD_PROVIDER:?}" "${VPN_CLOUD_POLICY_EVIDENCE:?}"
transport=${VPN_CLOUD_TRANSPORT:-dtls}; seconds=${VPN_SOAK_SECONDS:-60}
case "$transport" in tls|dtls|fallback) ;; *) exit 2 ;; esac
[[ "$seconds" =~ ^[0-9]+$ ]] && ((seconds >= 1 && seconds <= 7200)) || exit 2
repo=$(cd "$(dirname "$0")/../.." && pwd)
state=$(mktemp -d /tmp/vpn-cloud.XXXXXX); chmod 700 "$state"
logs=${VPN_E2E_LOG_DIR:-/tmp/vpn-cloud-logs}
mkdir -p "$logs"
client_pid=''
cleanup() {
    local rc=$?
    trap - EXIT
    if [[ -n "$client_pid" ]]; then
        kill -INT "$client_pid" 2>/dev/null || true
        for ((i=0;i<30;i++)); do kill -0 "$client_pid" 2>/dev/null || break; sleep .1; done
        kill -TERM "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
    fi
    rm -rf "$state"
    exit "$rc"
}
trap cleanup EXIT
fail() { echo "CLOUD ACCEPTANCE FAILED: $*" >&2; exit 1; }
printf '%s\n' "$VPN_CLOUD_CA" > "$state/ca.pem"
printf '%s\n' "$VPN_CLOUD_PASSWORD" > "$state/password"
unset VPN_CLOUD_PASSWORD VPN_CLOUD_CA
# Validate targets and bind evidence to this run without uploading policy/account secrets.
python3 - "$state" "$logs" <<'PY'
import hashlib, ipaddress, json, os, socket, sys
from pathlib import Path
from urllib.parse import urlsplit
state, logs = map(Path, sys.argv[1:])
server = urlsplit(os.environ['VPN_CLOUD_SERVER'])
if server.scheme != 'https' or not server.hostname or server.username or server.password:
    raise SystemExit('server must be an HTTPS URL without embedded credentials')
for name, family in [('VPN_CLOUD_TARGET4', socket.AF_INET), ('VPN_CLOUD_TARGET6', socket.AF_INET6)]:
    target = urlsplit(os.environ[name])
    if target.scheme != 'http' or not target.hostname or target.username or target.password:
        raise SystemExit('targets must be private HTTP fixture URLs without credentials')
    address = ipaddress.ip_address(target.hostname)
    expected = 4 if family == socket.AF_INET else 6
    if address.version != expected:
        raise SystemExit('fixture URL must contain a literal address of the requested family')
(state / 'payload').write_bytes(bytes(range(256)) * 4096)
evidence = json.loads(os.environ['VPN_CLOUD_POLICY_EVIDENCE'])
for key in ('provider', 'policy_id', 'captured_at', 'expected_transport'):
    if not evidence.get(key):
        raise SystemExit('missing policy evidence field: ' + key)
if evidence['provider'] != os.environ['VPN_CLOUD_PROVIDER']:
    raise SystemExit('policy/provider mismatch')
if evidence['expected_transport'] != os.environ.get('VPN_CLOUD_TRANSPORT', 'dtls'):
    raise SystemExit('policy/transport mismatch')
(logs / 'evidence.json').write_text(json.dumps({
    'provider': evidence['provider'], 'expected_transport': evidence['expected_transport'],
    'policy_evidence_sha256': hashlib.sha256(os.environ['VPN_CLOUD_POLICY_EVIDENCE'].encode()).hexdigest(),
    'provenance': 'operator-supplied export; no cloud API policy mutation or verification'
}, indent=2) + '\n')
PY
for url in "$VPN_CLOUD_TARGET4" "$VPN_CLOUD_TARGET6"; do
    if curl --noproxy '*' -gfsS --connect-timeout 2 --max-time 3 "${url%/}/payload" -o /dev/null 2>/dev/null; then
        fail 'private fixture is reachable before VPN connection; cannot prove tunnelling'
    fi
done
VPNC_REAL_SCRIPT=/usr/share/vpnc-scripts/vpnc-script
export VPNC_REAL_SCRIPT VPNC_STATE_DIR="$state"
args=(--non-inter --no-proxy --no-system-trust --cafile "$state/ca.pem" --user "$VPN_CLOUD_USER"
    --passwd-on-stdin --interface cloudvpn --dtls-attempt-period 3
    --script "exec bash $repo/tests/qualification/vpnc.sh")
[[ "$transport" != tls ]] || args+=(--no-dtls)
# Dedicated container counters; they do not modify the runner host firewall.
for tool in iptables ip6tables; do
    "$tool" -N CLOUD_UDP
    "$tool" -A CLOUD_UDP -j RETURN
    "$tool" -I INPUT -p udp -j CLOUD_UDP
done
udp_bytes() {
    { iptables -nvxL CLOUD_UDP; ip6tables -nvxL CLOUD_UDP; } |
        awk '$3 == "RETURN" {n += $2} END {printf "%.0f\n", n}'
}
openconnect "${args[@]}" "$VPN_CLOUD_SERVER" < "$state/password" > /dev/null 2> "$state/client.log" &
client_pid=$!
for ((i=0;i<300;i++)); do
    [[ -f "$state/connected" ]] && break
    kill -0 "$client_pid" || fail 'VPN connection failed; check CA, authentication, TCP policy and server health'
    sleep .1
done
[[ -f "$state/connected" ]] || fail 'tunnel setup deadline exceeded'
[[ -s "$state/ipv4" && -s "$state/ipv6" && -n "$(cat "$state/ipv6")" ]] || fail 'both address families are required'
if [[ "$transport" == dtls ]]; then
    for ((i=0;i<150;i++)); do grep -q 'Established DTLS connection' "$state/client.log" && break; sleep .1; done
    grep -q 'Established DTLS connection' "$state/client.log" || fail 'DTLS unavailable: inspect UDP policy and path'
elif [[ "$transport" == fallback ]]; then
    sleep 15
    ! grep -q 'Established DTLS connection' "$state/client.log" || fail 'expected blocked UDP, but DTLS established'
fi
before=$(udp_bytes)
for family in 4 6; do
    variable=VPN_CLOUD_TARGET$family
    url=${!variable}
    address=$(python3 - "$url" "$family" <<'PY'
import socket, sys
from urllib.parse import urlsplit
u = urlsplit(sys.argv[1]); family = socket.AF_INET6 if sys.argv[2] == '6' else socket.AF_INET
print(socket.getaddrinfo(u.hostname, u.port or 80, family, socket.SOCK_STREAM)[0][4][0])
PY
)
    ip -"$family" route get "$address" | grep -q 'dev cloudvpn' || fail "IPv$family target bypasses VPN"
    python3 "$repo/tests/qualification/traffic.py" --url "$url" --payload "$state/payload" \
        --seconds "$seconds" --workers 2 --output "$logs/traffic-v$family.json"
done
after=$(udp_bytes)
if [[ "$transport" == dtls ]]; then
    ((after - before > 1048576)) || fail 'DTLS negotiated without UDP payload evidence'
else
    ((after - before < 262144)) || fail 'expected TCP payload path but observed substantial UDP'
fi
kill -0 "$client_pid" || fail 'client died during transfer'
printf '{"passed":true,"scope":"configured live VPS path","transport":"%s","seconds_per_family":%d}\n' \
    "$transport" "$seconds" > "$logs/summary.json"
echo 'PASS: configured live VPS dual-stack path and requested transport; policy provenance is recorded separately'

#!/usr/bin/env bash
# Real ocserv/OpenConnect traffic, only in a disposable privileged container.
set -Eeuo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_dir"
installer="${1:?installer script required}"
case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
: "${VPN_E2E_DISPOSABLE:?Run through the documented disposable Docker command}"
[[ "$VPN_E2E_DISPOSABLE" == 1 && "$EUID" -eq 0 && -c /dev/net/tun ]] || exit 1
export LC_ALL=C TERM=xterm
log_root="${VPN_E2E_LOG_DIR:-/tmp/vpn-e2e-logs}"
mkdir -p "$log_root"
state_root="$(mktemp -d /tmp/vpn-e2e.XXXXXX)"
client_ns="vpn-client-$$"
server_ns="vpn-server-$$"
target_ns="vpn-target-$$"
client_pid='' server_pid='' target_pid=''

fail() { echo "FAIL: $*" >&2; exit 1; }
stop_client() {
    if [[ -n "$client_pid" ]]; then
        kill -INT "$client_pid" 2>/dev/null || true
        for ((i=0; i<30; i++)); do
            kill -0 "$client_pid" 2>/dev/null || break
            sleep 0.1
        done
        if kill -0 "$client_pid" 2>/dev/null; then
            kill -TERM "$client_pid" 2>/dev/null || true
            sleep 1
            kill -KILL "$client_pid" 2>/dev/null || true
        fi
        wait "$client_pid" 2>/dev/null || true
        client_pid=''
    fi
}
detach_client() {
    # SIGHUP restores local routes without logging off the server-side cookie.
    # SIGINT/SIGTERM here could hide a failed server-side cookie invalidation.
    [[ -n "$client_pid" ]] || return 0
    kill -HUP "$client_pid" 2>/dev/null || true
    for ((i=0; i<50; i++)); do
        kill -0 "$client_pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$client_pid" 2>/dev/null; then
        fail 'OpenConnect did not detach without logging off'
    fi
    wait "$client_pid" 2>/dev/null || true
    client_pid=''
}
cleanup() {
    local status=$?
    trap - EXIT
    set +e
    stop_client
    for ns in "$client_ns" "$server_ns" "$target_ns"; do
        while read -r pid; do
            [[ -n "$pid" ]] && kill -TERM "$pid" 2>/dev/null
        done < <(ip netns pids "$ns" 2>/dev/null)
        ip netns del "$ns" 2>/dev/null
    done
    rm -rf "$state_root"
    rm -rf "/etc/netns/$client_ns"
    # Some distro client builds log HTTP headers even at their default level.
    # Remove every cookie header before printing excerpts or uploading artifacts.
    for log in "$log_root"/*.log "$log_root"/*/*.log; do
        [[ -f "$log" ]] || continue
        if ! sed -i -E 's/^((Set-Cookie|Cookie):).*/\1 <redacted>/I' "$log"; then
            rm -f "$log"
            status=1
        fi
    done
    if ((status != 0)); then
        echo 'VPN E2E failed; final server/client log excerpts:' >&2
        for log in "$log_root"/*.log "$log_root"/*/*.log; do
            [[ -f "$log" ]] || continue
            echo "--- $log ---" >&2
            tail -60 "$log" >&2
        done
    fi
    exit "$status"
}
trap cleanup EXIT

for candidate in /usr/share/vpnc-scripts/vpnc-script /etc/vpnc/vpnc-script /etc/openconnect/vpnc-script; do
    if [[ -x "$candidate" ]]; then VPNC_REAL_SCRIPT="$candidate"; break; fi
done
: "${VPNC_REAL_SCRIPT:?distro vpnc-script is missing}"
export VPNC_REAL_SCRIPT

# There is no client-to-target link. The target has no return route to the VPN
# pool: successful round trips therefore require forwarding AND production NAT.
for ns in "$client_ns" "$server_ns" "$target_ns"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
done
ip link add vc type veth peer name vs
ip link set vc netns "$client_ns"
ip link set vs netns "$server_ns"
ip link add ve type veth peer name vt
ip link set ve netns "$server_ns"
ip link set vt netns "$target_ns"
ip -n "$client_ns" addr add 192.0.2.2/24 dev vc
ip -n "$server_ns" addr add 192.0.2.1/24 dev vs
ip -n "$server_ns" addr add 198.51.100.1/24 dev ve
ip -n "$target_ns" addr add 198.51.100.2/24 dev vt
ip -n "$client_ns" link set vc up
ip -n "$server_ns" link set vs up
ip -n "$server_ns" link set ve up
ip -n "$target_ns" link set vt up
# An unreachable original gateway lets stock vpnc-script preserve no-route
# exclusions, without giving the client a working direct path to the target.
ip -n "$client_ns" route add default via 192.0.2.254
ip -n "$server_ns" route add default via 198.51.100.2
mkdir -p "/etc/netns/$client_ns"
printf 'nameserver 192.0.2.254\n' > "/etc/netns/$client_ns/resolv.conf"
ip netns exec "$client_ns" iptables -N E2E_UDP
ip netns exec "$client_ns" iptables -A E2E_UDP -j RETURN
ip netns exec "$client_ns" iptables -A INPUT -s 192.0.2.1 -p udp --sport 4443 -j E2E_UDP
head -c 262144 /dev/urandom > "$state_root/payload"
expected_hash="$(sha256sum "$state_root/payload" | awk '{print $1}')"
ip netns exec "$target_ns" python3 "$repo_dir/tests/vpn-target.py" \
    --payload "$state_root/payload" > "$log_root/target.log" 2>&1 &
target_pid=$!
for ((i=0; i<50; i++)); do
    grep -q '^ready ' "$log_root/target.log" && break
    kill -0 "$target_pid" || fail 'HTTP/DNS target exited'
    sleep 0.1
done
grep -q '^ready ' "$log_root/target.log" || fail 'target readiness timed out'

server_action() {
    ip netns exec "$server_ns" bash "$repo_dir/tests/vpn-server.sh" "$script" "$1" "$state_dir"
}
target_unreachable() {
    if ip netns exec "$client_ns" curl --noproxy '*' -fsS --connect-timeout 1 --max-time 2 \
        http://198.51.100.2:8080/payload -o /dev/null 2>/dev/null; then
        fail 'target reachable without an authorized VPN tunnel'
    fi
}
udp_bytes() {
    ip netns exec "$client_ns" iptables -nvxL E2E_UDP | awk '$3 == "RETURN" {print $2}'
}
client_args() {
    connection=(openconnect --protocol=anyconnect --non-inter --no-proxy --no-system-trust
        --cafile "$state_dir/ca.pem" --user "$2" --reconnect-timeout 3)
    case "$1" in
        password) connection+=(--passwd-on-stdin) ;;
        certificate) connection+=(--no-passwd --certificate "$state_dir/client.cer" --sslkey "$state_dir/client-key.pem") ;;
        p12) connection+=(--no-passwd --certificate "$state_dir/client.p12" --key-password "$password") ;;
        cookie) connection+=(--no-passwd --cookie-on-stdin) ;;
        *) fail 'unknown authentication mode' ;;
    esac
}
auth_result() {
    local expectation="$1" mode="$2" user="$3" secret="$4" label="$5" status
    client_args "$mode" "$user"
    if ip netns exec "$client_ns" timeout --kill-after=3 20 "${connection[@]}" \
        --cookieonly https://192.0.2.1:4443/ <<< "$secret" \
        > /dev/null 2> "$log_dir/$label.log"; then
        status=0
    else
        status=$?
    fi
    [[ "$status" != 124 && "$status" != 137 ]] || fail "$label timed out; this is not an authentication rejection"
    if [[ "$expectation" == allow ]]; then
        [[ "$status" == 0 ]] || fail "$label: valid credentials rejected ($status)"
    else
        [[ "$status" != 0 ]] || fail "$label: invalid/revoked credentials accepted"
        grep -Eiq 'fail|denied|rejected|error|certificate|authentication' "$log_dir/$label.log" ||
            fail "$label failed without authentication/TLS rejection evidence"
        # A separate valid account proves a dead server cannot satisfy a denial.
        auth_result allow password e2e-control "$control_password" "$label-control"
    fi
    echo "PASS: $script $label"
}
connect_client() {
    local mode="$1" transport="$2" label="$3" secret="$password"
    stop_client
    VPNC_STATE_DIR="$state_dir/$label"
    export VPNC_STATE_DIR
    mkdir -p "$VPNC_STATE_DIR"
    client_args "$mode" e2e-susp-user
    if [[ "$mode" == cookie ]]; then
        [[ -s "${4:?saved cookie file required}" ]] || fail 'saved cookie is empty'
        secret="$(cat "$4")"
    fi
    [[ "$transport" == dtls ]] || connection+=(--no-dtls)
    ip netns exec "$client_ns" "${connection[@]}" --printcookie --interface vpntest \
        --script "exec bash $repo_dir/tests/vpn-vpnc.sh" https://192.0.2.1:4443/ \
        <<< "$secret" > "$state_dir/$label.cookie" 2> "$log_dir/$label.log" &
    client_pid=$!
    for ((i=0; i<150; i++)); do
        [[ -f "$VPNC_STATE_DIR/connected" ]] && break
        kill -0 "$client_pid" 2>/dev/null || fail "$label: OpenConnect exited before tunnel setup"
        sleep 0.1
    done
    [[ -f "$VPNC_STATE_DIR/connected" ]] || fail "$label: tunnel setup timed out"
    [[ "$(cat "$VPNC_STATE_DIR/device")" == vpntest ]] || fail 'unexpected tunnel interface'
    grep -Eq '^192\.168\.7\.[0-9]+$' "$VPNC_STATE_DIR/address" || fail 'lease outside production VPN pool'
    ip -n "$client_ns" -4 addr show dev vpntest | grep -q 'inet 192.168.7.' || fail 'lease not installed on TUN'
    ip -n "$client_ns" route get 198.51.100.2 | grep -q 'dev vpntest' || fail 'target route bypasses TUN'
    ip -n "$client_ns" route get 203.0.113.10 | grep -q 'via 192.0.2.254 dev vc' || fail 'production no-route exclusion lost'
    if [[ "$transport" == dtls ]]; then
        for ((i=0; i<100; i++)); do
            grep -q 'Established DTLS connection' "$log_dir/$label.log" && break
            kill -0 "$client_pid" 2>/dev/null || fail 'client exited before DTLS negotiation'
            sleep 0.1
        done
        grep -q 'Established DTLS connection' "$log_dir/$label.log" || fail 'DTLS silently fell back to TLS'
    fi
}
reject_saved_cookie() {
    local cookie_file="$1" label="$2" status
    [[ -s "$cookie_file" ]] || fail 'saved cookie is empty'
    VPNC_STATE_DIR="$state_dir/$label"
    export VPNC_STATE_DIR
    mkdir -p "$VPNC_STATE_DIR"
    client_args cookie e2e-susp-user
    # Attempt the actual tunnel phase, with no fresh authentication fallback.
    if ip netns exec "$client_ns" timeout --kill-after=3 15 "${connection[@]}" \
        --no-dtls --interface vpntest --script "exec bash $repo_dir/tests/vpn-vpnc.sh" \
        https://192.0.2.1:4443/ < "$cookie_file" > /dev/null 2> "$log_dir/$label.log"; then
        status=0
    else
        status=$?
    fi
    [[ ! -e "$VPNC_STATE_DIR/address" ]] || fail "$label: revoked cookie established a tunnel"
    [[ "$status" != 0 && "$status" != 124 && "$status" != 137 ]] ||
        fail "$label: expected cookie rejection, got status $status"
    grep -Eq 'Cookie was rejected by server; exiting\.|HTTP/1\.[01] 401 Cookie is not acceptable' "$log_dir/$label.log" ||
        fail "$label: no explicit server cookie rejection"
    auth_result allow password e2e-control "$control_password" "$label-control"
    echo "PASS: $script $label (saved session cannot reconnect)"
}
check_traffic() {
    local transport="$1" label="$2" dns before after received
    before="$(udp_bytes)"
    ip netns exec "$client_ns" curl --noproxy '*' -fsS --max-time 15 \
        -D "$state_dir/headers" http://198.51.100.2:8080/payload -o "$state_dir/received"
    received="$(sha256sum "$state_dir/received" | awk '{print $1}')"
    [[ "$received" == "$expected_hash" ]] || fail 'tunnel corrupted or truncated the HTTP payload'
    tr -d '\r' < "$state_dir/headers" | grep -Fqx 'X-Seen-Client-IP: 198.51.100.1' ||
        fail 'target did not observe server egress NAT address'
    after="$(udp_bytes)"
    if [[ "$transport" == dtls ]]; then
        ((after - before > 200000)) || fail 'payload did not actually travel over UDP/DTLS'
    else
        ((after == before)) || fail 'TCP-only connection unexpectedly used UDP'
    fi
    read -r dns _ < "$VPNC_STATE_DIR/dns"
    [[ "$dns" == 198.51.100.2 ]] || fail 'server did not advertise fixture DNS'
    ip netns exec "$client_ns" dig +short +time=2 +tries=1 @"$dns" vpn-test.internal A |
        grep -Fxq 198.51.100.2 || fail 'DNS over VPN failed'
    ip netns exec "$client_ns" dig +tcp +short +time=2 +tries=1 @"$dns" vpn-test.internal A |
        grep -Fxq 198.51.100.2 || fail 'TCP DNS over VPN failed'
    # Also exercise the client's normal resolver, not only a direct DNS query.
    ip netns exec "$client_ns" curl --noproxy '*' -fsS --max-time 15 \
        http://vpn-test.internal:8080/payload -o "$state_dir/resolved-payload"
    [[ "$(sha256sum "$state_dir/resolved-payload" | awk '{print $1}')" == "$expected_hash" ]] ||
        fail 'normal hostname resolution and download failed'
    # A targeted forwarding drop must break the request; this detects a bypass
    # even if a client has accidentally acquired another route to the fixture.
    ip netns exec "$server_ns" iptables -I FORWARD -i vpns+ -d 198.51.100.2 -j DROP
    target_unreachable
    ip netns exec "$server_ns" iptables -D FORWARD -i vpns+ -d 198.51.100.2 -j DROP
    echo "PASS: $script $label (lease, routes, 256 KiB HTTP, NAT, UDP/TCP DNS, no bypass)"
}

script="$installer"
echo "::group::Real VPN: $script"
state_dir="$state_root/$script"
log_dir="$log_root/$script"
mkdir -p "$state_dir" "$log_dir"
password="E2e-$(openssl rand -hex 16)"
control_password="Control-$(openssl rand -hex 16)"
printf 'e2e-susp-user\n%s\n' "$password" > "$state_dir/account.input"
printf 'e2e-control\n%s\n' "$control_password" > "$state_dir/control.input"
# These are exclusively disposable test-container paths, never a host install.
rm -rf /etc/ocserv /tmp/ssl
rm -f /var/run/ocserv.pid /var/run/ocserv-socket* /var/run/occtl.socket
server_action configure > "$log_dir/configure.log" 2>&1
server_action add > "$log_dir/accounts.log" 2>&1
server_action duplicate >> "$log_dir/accounts.log" 2>&1
openssl pkcs12 -in "$state_dir/client.p12" -passin "pass:$password" -noout
server_action firewall > "$log_dir/firewall.log" 2>&1
target_unreachable
ip netns exec "$server_ns" /usr/local/sbin/ocserv --foreground --debug 2 \
    --config /etc/ocserv/ocserv.conf > "$log_dir/server.log" 2>&1 &
server_pid=$!
for ((i=0; i<100; i++)); do
    ip netns exec "$server_ns" ss -ltn | grep -q '192.0.2.1:4443' && break
    kill -0 "$server_pid" 2>/dev/null || fail 'ocserv exited during startup'
    sleep 0.1
done
ip netns exec "$server_ns" ss -ltn | grep -q '192.0.2.1:4443' || fail 'server not listening'
auth_result allow password e2e-control "$control_password" initial-control
auth_result deny password e2e-susp-user wrong-password bad-password
auth_result deny password missing-user wrong-password unknown-user

connect_client password tls password-tls
check_traffic tls password-tls
stop_client
target_unreachable
connect_client certificate dtls certificate-dtls
check_traffic dtls certificate-dtls
detach_client
# Prove this cookie works before revocation, then leave it detached. A separate
# fresh active session cannot log it off on our behalf when the server kicks it.
connect_client cookie dtls certificate-cookie "$state_dir/certificate-dtls.cookie"
check_traffic dtls certificate-cookie
detach_client
connect_client certificate dtls certificate-live
check_traffic dtls certificate-live
server_action toggle > "$log_dir/disable.log" 2>&1
# Revocation changes are reloaded in the running server, not hidden by a restart.
sleep 1
target_unreachable
detach_client
[[ -s "$state_dir/certificate-live.cookie" ]] || fail 'active certificate cookie missing'
! cmp -s "$state_dir/certificate-dtls.cookie" "$state_dir/certificate-live.cookie" ||
    fail 'detached and active certificate sessions share a cookie'
reject_saved_cookie "$state_dir/certificate-dtls.cookie" disabled-cookie
auth_result deny password e2e-susp-user "$password" disabled-password
auth_result deny certificate e2e-susp-user '' disabled-certificate

server_action toggle > "$log_dir/restore.log" 2>&1
sleep 1
connect_client p12 tls restored-p12
check_traffic tls restored-p12
detach_client
connect_client cookie tls restored-cookie "$state_dir/restored-p12.cookie"
check_traffic tls restored-cookie
detach_client
connect_client p12 tls restored-live
check_traffic tls restored-live
auth_result allow password e2e-susp-user "$password" restored-password
server_action delete > "$log_dir/delete.log" 2>&1
sleep 1
target_unreachable
detach_client
[[ -s "$state_dir/restored-live.cookie" ]] || fail 'active restored cookie missing'
! cmp -s "$state_dir/restored-p12.cookie" "$state_dir/restored-live.cookie" ||
    fail 'detached and active restored sessions share a cookie'
reject_saved_cookie "$state_dir/restored-p12.cookie" deleted-cookie
auth_result deny password e2e-susp-user "$password" deleted-password
auth_result deny certificate e2e-susp-user '' revoked-certificate
target_unreachable

kill -TERM "$server_pid"
wait "$server_pid" || true
server_pid=''
echo "PASS: $script real VPN and account lifecycle"
echo '::endgroup::'
echo 'PASS: all real VPN end-to-end checks'

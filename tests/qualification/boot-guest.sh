#!/usr/bin/env bash
# This script is executed only inside the disposable, separately booted QEMU VM.
set -Eeuo pipefail
[[ "${VPN_E2E_DISPOSABLE:-}" == 1 && "$EUID" -eq 0 ]] || exit 1
repo=$(cd "$(dirname "$0")/../.." && pwd)
state=/etc/ocserv/.qualification
fail() { echo "boot qualification: $*" >&2; exit 1; }
topology() {
    ip netns add boot-client
    ip netns add boot-target
    ip -n boot-client link set lo up
    ip -n boot-target link set lo up
    ip link add bs type veth peer name bc
    ip link set bc netns boot-client
    ip addr add 192.0.2.1/24 dev bs
    ip -6 addr add 2001:db8:1::1/64 dev bs nodad
    ip link set bs up
    ip -n boot-client addr add 192.0.2.2/24 dev bc
    ip -n boot-client -6 addr add 2001:db8:1::2/64 dev bc nodad
    ip -n boot-client link set bc up
    ip -n boot-client route add default via 192.0.2.1
    ip -n boot-client -6 route add default via 2001:db8:1::1
    ip link add ve type veth peer name vt
    ip link set vt netns boot-target
    ip addr add 198.51.100.1/24 dev ve
    ip -6 addr add 2001:db8:2::1/64 dev ve nodad
    ip link set ve up
    ip -n boot-target addr add 198.51.100.2/24 dev vt
    ip -n boot-target -6 addr add 2001:db8:2::2/64 dev vt nodad
    ip -n boot-target link set vt up
    ip -n boot-target -6 route add fd42:7::/64 via 2001:db8:2::1
    mkdir -p /etc/netns/boot-client
    printf '192.0.2.1 vpn-boot.test\n' > /etc/netns/boot-client/hosts
    printf 'nameserver 192.0.2.253\n' > /etc/netns/boot-client/resolv.conf
    # Direct paths are forbidden. Only traffic that arrived through TUN may pass.
    iptables -I FORWARD -i bs -d 198.51.100.2 -j DROP
    ip6tables -I FORWARD -i bs -d 2001:db8:2::2 -j DROP
}
install_server() {
    local installer=${1:?} original_route
    case "$installer" in ocserv.sh|ocserv-en.sh) ;; *) exit 2 ;; esac
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y openconnect vpnc-scripts curl python3 iproute2 iptables openssl
    # shellcheck disable=SC1090
    source "$repo/$installer"
    check_sys
    mkdir -p "$state"
    chmod 700 "$state"
    openssl rand -hex 24 > "$state/password"
    printf 'boot-user\n%s\n4443\n4443\n' "$(cat "$state/password")" > "$state/install.input"
    cp "$repo/ocserv.conf" "$conf"
    # Supply only a fixture identity, rather than calling a public IP service.
    # All Install_ocserv stages, package/build commands and systemctl are real.
    Get_ip() { ip=vpn-boot.test; }
    Install_ocserv < "$state/install.input"
    rm -f "$state/install.input"
    head -c 1048576 /dev/urandom > "$state/payload"
    cat > /etc/systemd/system/vpn-qualification-topology.service <<EOF
[Unit]
Description=Disposable VPN qualification topology
After=network.target
Before=ocserv-firewall.service ocserv-ipv6.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/env VPN_E2E_DISPOSABLE=1 /bin/bash $repo/tests/qualification/boot-guest.sh topology
[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/vpn-qualification-target.service <<EOF
[Unit]
Description=Disposable VPN qualification HTTP target
Requires=vpn-qualification-topology.service
After=vpn-qualification-topology.service
[Service]
ExecStart=/usr/sbin/ip netns exec boot-target /usr/bin/python3 $repo/tests/qualification/target.py --address 198.51.100.2 --address 2001:db8:2::2 --payload $state/payload
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now vpn-qualification-topology vpn-qualification-target
    # Add a second, private fixture egress with the real production helper.
    # The installation itself already completed using its normal public uplink.
    original_route=$(ip -4 route show default | head -1)
    [[ -n "$original_route" ]] || fail 'VM has no installation uplink'
    ip -4 route del default
    ip -4 route add default via 198.51.100.2 dev ve
    Set_iptables
    ip -4 route del default
    local -a route_args
    read -r -a route_args <<< "$original_route"
    ip -4 route add "${route_args[@]}"
    Save_iptables
    systemctl stop ocserv
    bash "$repo/ocserv-network.sh" configure --pool fd42:7::/64 --ingress bs --egress ve --mode routed
    mkdir -p /etc/systemd/system/ocserv-ipv6.service.d
    cat > /etc/systemd/system/ocserv-ipv6.service.d/fixture.conf <<'EOF'
[Unit]
Requires=vpn-qualification-topology.service
After=vpn-qualification-topology.service
EOF
    systemctl daemon-reload
    systemctl restart ocserv
    (find /etc/ocserv/ssl -type f -exec sha256sum {} +; sha256sum /etc/ocserv/ocpasswd) | \
        sort | sha256sum | awk '{print $1}' > "$state/identity.sha256"
    systemd-analyze verify /etc/systemd/system/ocserv.service /etc/systemd/system/ocserv-firewall.service \
        /etc/systemd/system/ocserv-ipv6.service
}
verify_server() {
    local identity start firewall ipv6 client_pid
    for ((i=0;i<100;i++)); do
        curl --noproxy '*' -fsS --max-time 1 http://198.51.100.2:8080/payload -o /dev/null 2>/dev/null && break
        sleep .2
    done
    systemctl is-enabled ocserv ocserv-firewall ocserv-ipv6 >/dev/null
    for ((i=0;i<120;i++)); do systemctl is-active --quiet ocserv && break; sleep 1; done
    systemctl is-active --quiet ocserv
    systemctl is-active --quiet ocserv-firewall
    systemctl is-active --quiet ocserv-ipv6
    [[ "$(sysctl -n net.ipv4.ip_forward)" == 1 && "$(sysctl -n net.ipv6.conf.all.forwarding)" == 1 ]]
    identity=$({ find /etc/ocserv/ssl -type f -exec sha256sum {} +; sha256sum /etc/ocserv/ocpasswd; } | sort | sha256sum | awk '{print $1}')
    [[ "$identity" == "$(cat "$state/identity.sha256")" ]] || fail 'credentials changed across boot'
    start=$(systemctl show ocserv -p ExecMainStartTimestampMonotonic --value)
    firewall=$(systemctl show ocserv-firewall -p ActiveEnterTimestampMonotonic --value)
    ipv6=$(systemctl show ocserv-ipv6 -p ActiveEnterTimestampMonotonic --value)
    ((firewall > 0 && ipv6 > 0 && start >= firewall && start >= ipv6)) || fail 'VPN started before its firewalls'
    iptables -t nat -C POSTROUTING -s 192.168.7.0/24 -o ve -j MASQUERADE
    ip6tables -C FORWARD -i vpns+ -m comment --comment ocserv-ipv6-v1 -j OCSV6_FWD
    if ip netns exec boot-client curl --noproxy '*' -fsS --max-time 2 http://198.51.100.2:8080/payload -o /dev/null 2>/dev/null; then
        fail 'boot target bypasses the VPN'
    fi
    mkdir -p "$state/client"
    rm -f "$state/client/connected"
    export VPNC_REAL_SCRIPT=/usr/share/vpnc-scripts/vpnc-script VPNC_STATE_DIR="$state/client"
    ip netns exec boot-client openconnect --non-inter --no-proxy --no-system-trust \
        --cafile /etc/ocserv/ssl/ca-cert.pem --user boot-user --passwd-on-stdin --interface vpntest \
        --script "exec bash $repo/tests/qualification/vpnc.sh" https://vpn-boot.test:4443/ \
        < "$state/password" > /dev/null 2> "$state/client.log" & client_pid=$!
    trap 'kill -INT "$client_pid" 2>/dev/null || true; wait "$client_pid" 2>/dev/null || true' RETURN
    for ((i=0;i<150;i++)); do [[ -f "$state/client/connected" ]] && break; sleep .1; done
    [[ -f "$state/client/connected" ]] || fail 'post-boot VPN connection failed'
    for family in 4 6; do
        local url peer
        url=http://198.51.100.2:8080; peer=198.51.100.1
        if [[ "$family" == 6 ]]; then
            url='http://[2001:db8:2::2]:8080'
            peer=$(cat "$state/client/ipv6"); peer=${peer%%/*}
        fi
        ip netns exec boot-client python3 "$repo/tests/qualification/traffic.py" --url "$url" \
            --payload "$state/payload" --seconds 1 --workers 1 --expected-peer "$peer" \
            --output "$state/boot-v$family.json" >/dev/null
    done
    kill -INT "$client_pid"; wait "$client_pid" || true
    trap - RETURN
    printf 'PASS boot_id=%s main_pid=%s identity=%s\n' "$(cat /proc/sys/kernel/random/boot_id)" \
        "$(systemctl show ocserv -p MainPID --value)" "$identity"
}
service_lifecycle() {
    verify_server
    local before after
    before=$(systemctl show ocserv -p MainPID --value)
    systemctl reload ocserv
    [[ "$(systemctl show ocserv -p MainPID --value)" == "$before" ]] || fail 'reload replaced main PID'
    systemctl kill --kill-whom=main --signal=SIGKILL ocserv
    for ((i=0;i<90;i++)); do
        after=$(systemctl show ocserv -p MainPID --value)
        [[ "$after" != 0 && "$after" != "$before" ]] && break
        sleep 1
    done
    [[ "$after" != 0 && "$after" != "$before" ]] || fail 'Restart=on-failure did not recover'
    verify_server
    systemctl stop ocserv
    ! systemctl is-active --quiet ocserv || fail 'stop left service active'
    # A failed prerequisite must stop ocserv from starting, not merely log a warning.
    systemctl stop ocserv-firewall ocserv-ipv6
    cp /etc/iptables.up.rules "$state/firewall.saved"
    printf 'INVALID FIREWALL FILE\n' > /etc/iptables.up.rules
    if systemctl start ocserv; then fail 'firewall failure did not block VPN startup'; fi
    ! systemctl is-active --quiet ocserv || fail 'VPN running with failed firewall prerequisite'
    mv "$state/firewall.saved" /etc/iptables.up.rules
    systemctl reset-failed ocserv ocserv-firewall ocserv-ipv6
    systemctl start ocserv
    verify_server
}
case "${1:-}" in
    install) install_server "${2:?}" ;;
    topology) topology ;;
    verify) verify_server ;;
    lifecycle) service_lifecycle ;;
    *) exit 2 ;;
esac

#!/usr/bin/env bash
# Optional IPv6 network profile for an existing installation of either language.
# Does not allocate a cloud prefix or change a provider security group.
set -Eeuo pipefail

conf=/etc/ocserv/ocserv.conf
profile=/etc/ocserv/ipv6-network.profile
sysctl_file=/etc/sysctl.d/90-ocserv-ipv6.conf
installed=/usr/local/libexec/ocserv-network
marker=ocserv-ipv6-v1
fail() { echo "ocserv-network: $*" >&2; exit 1; }
get_conf() {
    awk -v key="$1" '$0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
        sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*(#.*)?$/, "");
        gsub(/^\"|\"$/, ""); print; exit
    }' "$conf"
}
validate() {
    python3 - "$pool" "$prefix" "$ingress" "$egress" "$mode" "$tcp" "$udp" <<'PY'
import ipaddress, re, sys
pool, prefix, ingress, egress, mode, tcp, udp = sys.argv[1:]
network = ipaddress.IPv6Network(pool, strict=True)
valid = (network.prefixlen >= 16 and network.prefixlen < int(prefix) <= 128
         and not network.is_multicast and not network.is_link_local and not network.is_loopback
         and mode in ('routed', 'nat66')
         and all(re.fullmatch(r'[A-Za-z0-9_-]{1,15}', name) for name in (ingress, egress))
         and all(re.fullmatch(r'[0-9]{1,5}', port) and 1 <= int(port) <= 65535 for port in (tcp, udp)))
if not valid:
    raise SystemExit('invalid IPv6 network profile')
PY
    [[ "$device" =~ ^[A-Za-z0-9_-]{1,12}$ ]] || fail 'invalid configured tunnel device prefix'
}
read_profile() {
    [[ -f "$profile" && ! -L "$profile" ]] || fail 'no regular IPv6 profile; run configure first'
    local key value
    pool='' prefix='' ingress='' egress='' mode='' tcp='' udp='' device=''
    while IFS='=' read -r key value; do
        case "$key" in
            pool) pool="$value" ;; prefix) prefix="$value" ;;
            ingress) ingress="$value" ;; egress) egress="$value" ;;
            mode) mode="$value" ;; tcp) tcp="$value" ;; udp) udp="$value" ;;
            device) device="$value" ;; *) fail 'invalid profile key' ;;
        esac
    done < "$profile"
    validate
}
profile_text() {
    printf '%s\n' "pool=$pool" "prefix=$prefix" "ingress=$ingress" "egress=$egress" \
        "mode=$mode" "tcp=$tcp" "udp=$udp" "device=$device"
}
rule() {
    local table="$1" chain="$2" rc
    shift 2
    if ip6tables -w 10 -t "$table" -C "$chain" "$@" 2>/dev/null; then return 0; else rc=$?; fi
    [[ "$rc" -eq 1 ]] || return "$rc"
    ip6tables -w 10 -t "$table" -A "$chain" "$@"
}
chain() {
    local table="$1" name="$2"
    if ! ip6tables -w 10 -t "$table" -S "$name" >/dev/null 2>&1; then
        ip6tables -w 10 -t "$table" -N "$name"
    fi
}
up() {
    read_profile
    ip link show dev "$ingress" >/dev/null
    ip link show dev "$egress" >/dev/null
    [[ "$(sysctl -n "net.ipv6.conf.$egress.disable_ipv6")" == 0 ]] || fail 'IPv6 is disabled on egress'
    # Preserve RA-learned uplinks when enabling forwarding; do not override an
    # administrator's accept_ra=0. Apply RA settings BEFORE forwarding.
    local iface staged
    staged=$(mktemp /etc/sysctl.d/.ocserv-ipv6.XXXXXX)
    for iface in $(printf '%s\n' "$ingress" "$egress" | sort -u); do
        if [[ "$(sysctl -n "net.ipv6.conf.$iface.accept_ra")" != 0 ]]; then
            printf 'net.ipv6.conf.%s.accept_ra=2\n' "$iface" >> "$staged"
        fi
    done
    printf 'net.ipv6.conf.all.forwarding=1\n' >> "$staged"
    chmod 644 "$staged"
    mv -f "$staged" "$sysctl_file"
    sysctl -p "$sysctl_file"
    chain filter OCSV6_IN
    chain filter OCSV6_FWD
    rule filter OCSV6_IN -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$marker" -j ACCEPT
    rule filter OCSV6_IN -p ipv6-icmp -m comment --comment "$marker" -j ACCEPT
    rule filter OCSV6_IN -p tcp --dport "$tcp" -m comment --comment "$marker" -j ACCEPT
    rule filter OCSV6_IN -p udp --dport "$udp" -m comment --comment "$marker" -j ACCEPT
    rule filter OCSV6_FWD -i "${device}+" -s "$pool" -o "$egress" \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED -m comment --comment "$marker" -j ACCEPT
    rule filter OCSV6_FWD -i "$egress" -o "${device}+" -d "$pool" \
        -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$marker" -j ACCEPT
    rule filter OCSV6_FWD -i "$egress" -o "${device}+" -d "$pool" \
        -p ipv6-icmp -m comment --comment "$marker" -j ACCEPT
    # Insert only our scoped jumps ahead of an existing final DROP.
    local -a input=(-i "$ingress" -m comment --comment "$marker" -j OCSV6_IN)
    local -a outgoing=(-i "${device}+" -m comment --comment "$marker" -j OCSV6_FWD)
    local -a incoming=(-o "${device}+" -m comment --comment "$marker" -j OCSV6_FWD)
    ip6tables -w 10 -C INPUT "${input[@]}" 2>/dev/null || ip6tables -w 10 -I INPUT "${input[@]}"
    ip6tables -w 10 -C FORWARD "${outgoing[@]}" 2>/dev/null || ip6tables -w 10 -I FORWARD "${outgoing[@]}"
    ip6tables -w 10 -C FORWARD "${incoming[@]}" 2>/dev/null || ip6tables -w 10 -I FORWARD "${incoming[@]}"
    if [[ "$mode" == nat66 ]]; then
        chain nat OCSV6_NAT
        rule nat OCSV6_NAT -s "$pool" -o "$egress" -m comment --comment "$marker" -j MASQUERADE
        rule nat POSTROUTING -s "$pool" -o "$egress" -m comment --comment "$marker" -j OCSV6_NAT
    fi
}
delete_rule() {
    local table="$1" chain="$2"
    shift 2
    while ip6tables -w 10 -t "$table" -C "$chain" "$@" 2>/dev/null; do
        ip6tables -w 10 -t "$table" -D "$chain" "$@"
    done
    ip6tables -w 10 -t "$table" -S "$chain" >/dev/null
}
down() {
    read_profile
    delete_rule filter INPUT -i "$ingress" -m comment --comment "$marker" -j OCSV6_IN
    delete_rule filter FORWARD -i "${device}+" -m comment --comment "$marker" -j OCSV6_FWD
    delete_rule filter FORWARD -o "${device}+" -m comment --comment "$marker" -j OCSV6_FWD
    if [[ "$mode" == nat66 ]]; then
        delete_rule nat POSTROUTING -s "$pool" -o "$egress" -m comment --comment "$marker" -j OCSV6_NAT
    fi
    local spec table name
    for spec in 'filter OCSV6_IN' 'filter OCSV6_FWD' 'nat OCSV6_NAT'; do
        read -r table name <<< "$spec"
        if ip6tables -w 10 -t "$table" -S "$name" >/dev/null 2>&1; then
            # Refuse to erase rules added by another administrator.
            if ip6tables -t "$table" -S "$name" | grep '^-A ' | grep -v -- "--comment $marker"; then
                fail "foreign rule in $name; remove it explicitly"
            fi
            ip6tables -w 10 -t "$table" -F "$name"
            ip6tables -w 10 -t "$table" -X "$name"
        fi
    done
}
configure() {
    local active_pid_file
    active_pid_file=$(get_conf pid-file)
    if [[ -n "$active_pid_file" && -s "$active_pid_file" ]] && kill -0 "$(cat "$active_pid_file")" 2>/dev/null; then
        fail 'stop ocserv before changing its IPv6 configuration'
    fi
    pool='' prefix=128 ingress='' egress='' mode=routed
    while (($#)); do
        [[ "$#" -ge 2 ]] || fail 'every option requires a value'
        case "$1" in
            --pool) pool="$2" ;; --client-prefix) prefix="$2" ;;
            --ingress) ingress="$2" ;; --egress) egress="$2" ;;
            --mode) mode="$2" ;; *) fail "unknown option: $1" ;;
        esac
        shift 2
    done
    ingress="${ingress:-$egress}"
    tcp=$(get_conf tcp-port); udp=$(get_conf udp-port); device=$(get_conf device)
    validate
    if [[ -e "$profile" ]]; then
        cmp -s <(profile_text) "$profile" || fail 'stop ocserv and remove the old profile before changing it'
    else
        local spec table name
        for spec in 'filter OCSV6_IN' 'filter OCSV6_FWD' 'nat OCSV6_NAT'; do
            read -r table name <<< "$spec"
            if ip6tables -t "$table" -S "$name" >/dev/null 2>&1; then
                fail "refusing to adopt existing chain $name"
            fi
        done
        (umask 077; profile_text > "$profile")
    fi
    local next
    next=$(mktemp /etc/ocserv/.ipv6-config.XXXXXX)
    awk '!/^[[:space:]]*ipv6-(network|subnet-prefix)[[:space:]]*=/' "$conf" > "$next"
    printf '\nipv6-network = %s\nipv6-subnet-prefix = %s\n' "$pool" "$prefix" >> "$next"
    /usr/local/sbin/ocserv --test-config -c "$next" >/dev/null
    # Keep the previous config available for an operator if network setup fails.
    cp -p "$conf" /etc/ocserv/ocserv.conf.before-ipv6
    chmod --reference="$conf" "$next"
    mv -f "$next" "$conf"
    install -d -m 755 /usr/local/libexec
    if [[ "$(readlink -f "$0")" != "$installed" ]]; then
        install -m 755 "$0" "$installed"
    fi
    up
    if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
        cat > /etc/systemd/system/ocserv-ipv6.service <<'EOF'
[Unit]
Description=Apply scoped ocserv IPv6 routing and firewall profile
Wants=network-online.target
After=network-online.target ocserv-firewall.service
Before=ocserv.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/libexec/ocserv-network up
[Install]
WantedBy=multi-user.target
EOF
        install -d -m 755 /etc/systemd/system/ocserv.service.d
        cat > /etc/systemd/system/ocserv.service.d/30-network.conf <<'EOF'
[Unit]
Requires=ocserv-ipv6.service
After=ocserv-ipv6.service
EOF
        if [[ -f /etc/systemd/system/ocserv-firewall.service ]]; then
            printf 'Requires=ocserv-firewall.service\nAfter=ocserv-firewall.service\n' >> \
                /etc/systemd/system/ocserv.service.d/30-network.conf
        fi
        systemctl daemon-reload
        systemctl enable ocserv-ipv6.service
    fi
    echo 'IPv6 profile applied. Restart ocserv to offer IPv6 leases. Verify the upstream route/firewall separately.'
}
remove_profile() {
    local pid
    pid=$(get_conf pid-file)
    if [[ -n "$pid" && -s "$pid" ]] && kill -0 "$(cat "$pid")" 2>/dev/null; then
        fail 'stop ocserv before removing its network profile'
    fi
    down
    if command -v systemctl >/dev/null && [[ -d /run/systemd/system ]]; then
        systemctl disable --now ocserv-ipv6.service
    fi
    sed -i '/^[[:space:]]*ipv6-network[[:space:]]*=/d; /^[[:space:]]*ipv6-subnet-prefix[[:space:]]*=/d' "$conf"
    rm -f "$profile" "$sysctl_file" /etc/systemd/system/ocserv-ipv6.service \
        /etc/systemd/system/ocserv.service.d/30-network.conf "$installed"
    if [[ -d /run/systemd/system ]]; then systemctl daemon-reload; fi
    # Do not disable global forwarding; unrelated routers/containers may use it.
}

[[ "$EUID" -eq 0 ]] || fail 'root is required'
[[ -s "$conf" ]] || fail 'install and configure ocserv first'
for tool in python3 ip ip6tables sysctl flock; do command -v "$tool" >/dev/null || fail "missing $tool"; done
exec 9> /etc/ocserv/.ipv6-network.lock
flock -w 30 9 || fail 'another network operation is in progress'
case "${1:-}" in
    configure) shift; configure "$@" ;;
    up) up ;;
    down) down ;;
    remove) remove_profile ;;
    *) fail 'usage: ocserv-network.sh configure --pool PREFIX --egress IFACE [--ingress IFACE] [--mode routed|nat66] [--client-prefix 128]; or up|down|remove' ;;
esac

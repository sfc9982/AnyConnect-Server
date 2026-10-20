#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="2.2.0"
file="/usr/local/sbin/ocserv"
conf_file="/etc/ocserv"
conf="/etc/ocserv/ocserv.conf"
passwd_file="/etc/ocserv/ocpasswd"
log_file="/tmp/ocserv.log"
ocserv_ver="1.5.0"
PID_FILE="/var/run/ocserv.pid"
SYSTEMD_UNIT_DIR="/etc/systemd/system"

# PKI files and directories
SSL_DIR="/etc/ocserv/ssl"
USERS_DIR="${SSL_DIR}/users"
DISABLED_DIR="${SSL_DIR}/disabled"
CA_CERT="${SSL_DIR}/ca-cert.pem"
CA_KEY="${SSL_DIR}/ca-key.pem"
CRL_PEM="${SSL_DIR}/crl.pem"
CRL_TMPL="${SSL_DIR}/crl.tmpl"
REVOKED_PEM="${SSL_DIR}/revoked.pem"
SUSPENDED_PEM="${SSL_DIR}/suspended.pem"
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[INFO]${Font_color_suffix}"
Error="${Red_font_prefix}[ERROR]${Font_color_suffix}"
Tip="${Green_font_prefix}[WARN]${Font_color_suffix}"

check_root(){
    if [[ $EUID != 0 ]]; then
        echo -e "${Error} Current user is not root or don't have root access，can't continue，please switch to root or use command: ${Green_background_prefix}sudo su${Font_color_suffix} to get a temp root privilege(may request user password)." >&2
        return 1
    fi
}

# Check system
check_sys(){
    # Detect distro and package manager: /etc/os-release first, legacy fallback second.
    # release: debian/ubuntu/rhel/rocky/almalinux/fedora/arch/opensuse...  pm: matching package manager
    release=""
    pm=""
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release 2>/dev/null
        release="${ID}"
        case "${release}" in
            debian|ubuntu|linuxmint|deepin|kali|raspbian)
                pm="apt-get" ;;
            rhel|centos|rocky|almalinux|anolis|openeuler|opencloudos|amzn)
                pm="dnf"
                command -v dnf >/dev/null 2>&1 || pm="yum" ;;
            fedora|mageia)
                pm="dnf" ;;
            arch|manjaro|endeavouros|artix)
                pm="pacman" ;;
            opensuse*|sles|suse)
                pm="zypper" ;;
        esac
    fi
    if [[ -z "${pm}" ]]; then
        if [[ -f /etc/redhat-release ]]; then
            release="rhel"
            pm="yum"; command -v dnf >/dev/null 2>&1 && pm="dnf"
        elif grep -q -E -i "debian" /etc/issue 2>/dev/null; then
            release="debian"; pm="apt-get"
        elif grep -q -E -i "ubuntu" /etc/issue 2>/dev/null; then
            release="ubuntu"; pm="apt-get"
        fi
    fi
}

check_installed_status(){
    [[ ! -e ${file} ]] && echo -e "${Error} ocserv haven't been installed, please check it!" && exit 1
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv config doesn't exist, please check it!" && [[ $1 != "un" ]] && exit 1
}

Configured_PID_File(){
    local configured
    configured=$(Get_Conf_Value pid-file) || return 2
    configured="${configured:-$PID_FILE}"
    if [[ "$configured" != /* || "$configured" == *$'\n'* || "$configured" == *$'\r'* ]]; then
        echo -e "${Error} pid-file must be an absolute path without line breaks" >&2
        return 2
    fi
    printf '%s\n' "$configured"
}
# 0: running ocserv; 1: absent/dead PID; 2: invalid configuration or lookup error.
Get_Ocserv_PID(){
    local pid_path candidate executable expected
    pid_path=$(Configured_PID_File) || return 2
    if [[ ! -e "$pid_path" ]]; then
        [[ ! -L "$pid_path" ]] || return 2
        return 1
    fi
    [[ -f "$pid_path" && -r "$pid_path" ]] || return 2
    candidate=$(cat "$pid_path") || return 2
    [[ "$candidate" =~ ^[1-9][0-9]*$ ]] || return 2
    if ! kill -0 "$candidate" 2>/dev/null; then
        [[ ! -d "/proc/$candidate" ]] || return 2
        return 1
    fi
    executable=$(readlink "/proc/$candidate/exe") || {
        ! kill -0 "$candidate" 2>/dev/null || return 2
        return 1
    }
    expected=$(readlink -f "$file") || return 2
    # A running daemon may still hold the previous binary after an upgrade.
    executable="${executable% (deleted)}"
    if [[ "$executable" != "$expected" ]]; then
        echo -e "${Error} Refusing to signal PID $candidate: it is not $file" >&2
        return 2
    fi
    printf '%s\n' "$candidate"
}
check_pid(){
    local status
    if PID=$(Get_Ocserv_PID); then
        return 0
    else
        status=$?
        PID=""
        [[ "$status" -eq 1 ]]
    fi
}

Get_ip(){
    ip=$(wget -qO- -t1 -T2 ipinfo.io/ip)
    if [[ -z "${ip}" ]]; then
        ip=$(wget -qO- -t1 -T2 api.ip.sb/ip)
        if [[ -z "${ip}" ]]; then
            ip=$(wget -qO- -t1 -T2 members.3322.org/dyndns/getip)
            if [[ -z "${ip}" ]]; then
                ip="VPS_IP"
            fi
        fi
    fi
}
Download_ocserv() (
    local build_dir config_next=""
    build_dir=$(mktemp -d "${TMPDIR:-/tmp}/ocserv-build.XXXXXX") || return 1
    trap 'rm -rf "$build_dir"; [[ -z "$config_next" ]] || rm -f "$config_next"' EXIT
    # Fetch configuration before publishing binaries; preserve an existing config on retry.
    if [[ ! -e "$conf" ]]; then
        wget -O "$build_dir/ocserv.conf" "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/ocserv.conf" || return 1
        [[ -s "$build_dir/ocserv.conf" ]] || return 1
    else
        [[ -f "$conf" && -s "$conf" ]] || return 1
    fi
    wget -O "$build_dir/ocserv-${ocserv_ver}.tar.xz" "https://www.infradead.org/ocserv/download/ocserv-${ocserv_ver}.tar.xz" || return 1
    [[ -s "$build_dir/ocserv-${ocserv_ver}.tar.xz" ]] || return 1
    tar -xJf "$build_dir/ocserv-${ocserv_ver}.tar.xz" -C "$build_dir" || return 1
    cd "$build_dir/ocserv-${ocserv_ver}" || return 1
    meson setup build --prefix=/usr/local --sysconfdir=/etc -Dfirewall-script=iptables || return 1
    ninja -C build || return 1
    mkdir -p "$conf_file" || return 1
    if [[ ! -e "$conf" ]]; then
        config_next=$(mktemp "$conf_file/.ocserv-conf.XXXXXX") || return 1
        install -m 644 "$build_dir/ocserv.conf" "$config_next" || return 1
        mv -f "$config_next" "$conf" || return 1
        config_next=""
    fi
    ninja -C build install || return 1
    [[ -x "$file" && -s "$conf" ]]
)
# Whether systemd is available for service management (default on mainstream distros)
have_systemd(){
    command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}
Install_Systemd_Unit(){
    local unit="$1" staged
    staged=$(mktemp "$SYSTEMD_UNIT_DIR/.$unit.XXXXXX") || return 1
    if ! cat > "$staged" || ! chmod 644 "$staged" ||
        ! mv -f "$staged" "$SYSTEMD_UNIT_DIR/$unit"; then
        rm -f "$staged"
        return 1
    fi
    systemctl daemon-reload || return $?
    systemctl enable "${unit%.service}" >/dev/null 2>&1
}
Service_ocserv(){
    local pid_path pid_option
    if have_systemd; then
        pid_path=$(Configured_PID_File) || return 1
        pid_path="${pid_path//\\/\\\\}"
        pid_path="${pid_path//%/%%}"
        pid_option="${pid_path//\"/\\\"}"
        pid_option="${pid_option//\$/\$\$}"
        Install_Systemd_Unit ocserv.service <<EOF || return $?
[Unit]
Description=OpenConnect SSL VPN server (Cisco AnyConnect compatible)
Documentation=https://ocserv.gitlab.io/www/
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=$pid_path
ExecStart=/usr/local/sbin/ocserv -c /etc/ocserv/ocserv.conf --pid-file="$pid_option"
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
        echo -e "${Info} ocserv systemd service unit installed and enabled at boot!"
    else
        echo -e "${Tip} systemd not detected, ocserv will be managed as a plain daemon (no boot autostart)."
    fi
}
Firewall_Service_ocserv(){
    have_systemd || return 0
    Install_Systemd_Unit ocserv-firewall.service <<EOF
[Unit]
Description=Restore ocserv iptables firewall rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'iptables-restore < /etc/iptables.up.rules'

[Install]
WantedBy=multi-user.target
EOF
}
rand(){
    min=10000
    max=$((60000-$min+1))
    num=$(date +%s%N)
    echo $(($num%$max+$min))
}
Generate_SSL() (
    # An explicit identity also supports private addresses and DNS deployments.
    local server_identity="${1:-}" san_key ssl_tmp ca_name
    if [[ -z "$server_identity" ]]; then
        Get_ip
        server_identity="$ip"
    fi
    if [[ -z "$server_identity" || "$server_identity" == "VPS_IP" ]]; then
        read -rp "Server IP address or hostname: " server_identity || return 1
    fi
    if [[ "$server_identity" =~ ^[0-9]+(\.[0-9]+){3}$ ||
        "$server_identity" =~ ^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+$ ]]; then
        san_key="ip_address"
    elif [[ "$server_identity" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
        san_key="dns_name"
    else
        echo -e "${Error} Invalid server IP address or hostname" >&2
        return 1
    fi
    ssl_tmp=$(mktemp -d "${TMPDIR:-/tmp}/ocserv-ssl.XXXXXX") || return 1
    trap 'rm -rf "$ssl_tmp"' EXIT
    umask 077
    ca_name=$(rand)
    cat > "$ssl_tmp/ca.tmpl" <<EOF || return 1
cn = "${ca_name}"
organization = "${ca_name}"
serial = 1
expiration_days = 365
ca
signing_key
cert_signing_key
crl_signing_key
EOF
    certtool --generate-privkey --outfile "$ssl_tmp/ca-key.pem" || return 1
    certtool --generate-self-signed --load-privkey "$ssl_tmp/ca-key.pem" \
        --template "$ssl_tmp/ca.tmpl" --outfile "$ssl_tmp/ca-cert.pem" || return 1
    cat > "$ssl_tmp/server.tmpl" <<EOF || return 1
cn = "${server_identity}"
${san_key} = "${server_identity}"
organization = "${ca_name}"
expiration_days = 365
signing_key
encryption_key
tls_www_server
EOF
    certtool --generate-privkey --outfile "$ssl_tmp/server-key.pem" || return 1
    certtool --generate-certificate --load-privkey "$ssl_tmp/server-key.pem" \
        --load-ca-certificate "$ssl_tmp/ca-cert.pem" --load-ca-privkey "$ssl_tmp/ca-key.pem" \
        --template "$ssl_tmp/server.tmpl" --outfile "$ssl_tmp/server-cert.pem" || return 1
    mkdir -p "$SSL_DIR" || return 1
    install -m 644 "$ssl_tmp/ca-cert.pem" "$CA_CERT" || return 1
    install -m 600 "$ssl_tmp/ca-key.pem" "$CA_KEY" || return 1
    install -m 644 "$ssl_tmp/server-cert.pem" "$SSL_DIR/server-cert.pem" || return 1
    install -m 600 "$ssl_tmp/server-key.pem" "$SSL_DIR/server-key.pem"
)
Installation_dependency(){
    [[ ! -e "/dev/net/tun" ]] && echo -e "${Error} Your VPS haven't enabled TUN function, please contact your IDC, or use VPS control pannel to manully enable TUN/TAP !" && exit 1
    case "${pm}" in
        apt-get)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update || return 1
            apt-get install -y util-linux diffutils tar xz-utils meson ninja-build protobuf-c-compiler vim net-tools pkg-config build-essential ca-certificates wget iproute2 procps iptables openssl libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc
            ;;
        dnf)
            # RHEL derivatives (CentOS/Rocky/Alma/OpenEuler...) get extra deps from EPEL
            if [[ "${release}" != "fedora" ]]; then
                dnf install -y epel-release || return 1
            fi
            local distro_version="${VERSION_ID:-}"
            case "${release}:${distro_version%%.*}" in
                rocky:9|almalinux:9)
                    # libev-devel is provided by CRB, which epel-release does not enable.
                    dnf install -y dnf-plugins-core || return 1
                    dnf config-manager --set-enabled crb || return 1
                    ;;
            esac
            dnf install -y util-linux diffutils tar xz meson ninja-build protobuf-c-compiler vim net-tools pkgconf-pkg-config gcc make ca-certificates wget iproute procps-ng iptables openssl gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel lz4-devel gnutls-utils ipcalc
            ;;
        yum)
            yum install -y epel-release >/dev/null 2>&1
            yum install -y util-linux diffutils tar xz meson ninja-build protobuf-c-compiler vim net-tools pkgconfig gcc make ca-certificates wget iproute procps-ng iptables openssl gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel lz4-devel gnutls-utils ipcalc
            ;;
        pacman)
            pacman -Syu --noconfirm util-linux diffutils tar xz meson ninja protobuf-c base-devel vim net-tools gnutls libseccomp libev libnl readline ca-certificates wget iproute2 procps-ng iptables openssl lz4 ipcalc
            ;;
        zypper)
            # Minimal SUSE images need the nobody user and daemon group used by ocserv.conf.
            zypper -n install system-user-nobody system-user-daemon util-linux diffutils tar xz meson ninja libprotobuf-c-devel gnutls gcc make vim net-tools pkg-config gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel liblz4-devel ca-certificates wget iproute2 procps iptables openssl ipcalc
            ;;
        *)
            echo -e "${Error} Unknown package manager, cannot install dependencies !" && exit 1 ;;
    esac
}
Install_Step(){
    local step="$1"
    shift
    [[ ! -f "$install_state/$step.done" ]] || return 0
    "$@" || return $?
    : > "$install_state/$step.done"
}
Install_SSL_Material(){
    local staged="$install_state/ssl" item destination mode pending
    if [[ ! -f "$install_state/ssl-generated.done" ]]; then
        (
            SSL_DIR="$staged"
            CA_CERT="$SSL_DIR/ca-cert.pem"
            CA_KEY="$SSL_DIR/ca-key.pem"
            Generate_SSL
        ) || return 1
        : > "$install_state/ssl-generated.done" || return 1
    fi
    mkdir -p "$SSL_DIR" || return 1
    for item in ca-cert.pem ca-key.pem server-cert.pem server-key.pem; do
        case "$item" in
            ca-cert.pem) destination="$CA_CERT"; mode=644 ;;
            ca-key.pem) destination="$CA_KEY"; mode=600 ;;
            *-cert.pem) destination="$SSL_DIR/$item"; mode=644 ;;
            *) destination="$SSL_DIR/$item"; mode=600 ;;
        esac
        [[ -s "$staged/$item" ]] || return 1
        if [[ -e "$destination" || -L "$destination" ]]; then
            # Never replace identity material published by an earlier attempt.
            cmp -s "$staged/$item" "$destination" || return 1
        else
            pending=$(mktemp "$destination.install.XXXXXX") || return 1
            if ! install -m "$mode" "$staged/$item" "$pending" ||
                ! mv -f "$pending" "$destination"; then
                rm -f "$pending"
                return 1
            fi
        fi
    done
}
Install_Initial_Account(){
    local candidate u
    # An account may have completed immediately before its progress stamp failed.
    for candidate in "$USERS_DIR"/*; do
        [[ -d "$candidate" ]] || continue
        u="${candidate##*/}"
        [[ -s "$candidate/$u.cer" && -s "$candidate/$u-key.pem" &&
            -s "$candidate/$u.p12" ]] && pw_user_exists "$u" || return 1
        return 0
    done
    Add_User
}
Install_Ports(){
    Set_tcp_port || return 1
    Set_udp_port || return 1
    Set_Conf_Value tcp-port "$set_tcp_port" || return 1
    Set_Conf_Value udp-port "$set_udp_port"
}
Install_ocserv() (
    check_root || return 1
    local install_state="$conf_file/.install-state"
    if [[ ! -d "$install_state" ]]; then
        # A completed or pre-existing installation never enters the resume path.
        if [[ -e "$file" || -e "$CA_CERT" || -e "$CA_KEY" ||
            -e "$passwd_file" || -e "$SSL_DIR/server-key.pem" ]]; then
            echo -e "${Error} Existing ocserv installation or credentials; refusing to initialize them again" >&2
            return 1
        fi
        mkdir -p "$conf_file" || return 1
        (umask 077; mkdir "$install_state") || return 1
    fi
    [[ ! -L "$install_state" ]] || return 1
    echo -e "${Info} Installing or resuming ocserv; completed credentials and configuration are preserved"
    # This phase also installs flock before it is needed for the remaining phases.
    Install_Step dependencies Installation_dependency || return 1
    exec 9> "$install_state/lock" || return 1
    flock -n 9 || { echo -e "${Error} Another installation is in progress" >&2; return 1; }
    Install_Step download Download_ocserv || return 1
    Install_Step service Service_ocserv || return 1
    Install_Step ssl Install_SSL_Material || return 1
    Install_Step crl Ensure_CRL || return 1
    Install_Step auth Configure_Auth || return 1
    Read_config || return 1
    Install_Step account Install_Initial_Account || return 1
    Install_Step ports Install_Ports || return 1
    set_tcp_port=$(Get_Conf_Value tcp-port) || return 1
    set_udp_port=$(Get_Conf_Value udp-port) || return 1
    [[ "$set_tcp_port" =~ ^[0-9]+$ && "$set_udp_port" =~ ^[0-9]+$ ]] || return 1
    Install_Step firewall Set_iptables || return 1
    Install_Step ports-firewall Add_iptables "$set_tcp_port" "$set_udp_port" || return 1
    Install_Step save-firewall Save_iptables || return 1
    check_pid || return 1
    if [[ -n "$PID" ]]; then
        if have_systemd; then
            systemctl is-active --quiet ocserv || return 1
        fi
        View_Config || return 1
    else
        # The daemon must not inherit the installation lock.
        Start_ocserv 9>&- || return $?
    fi
    rm -rf -- "$install_state"
)
Start_ocserv(){
    check_installed_status
    local pid_path
    check_pid || return 1
    if [[ -n "$PID" ]]; then
        echo -e "${Error} ocserv is already running" >&2
        return 1
    fi
    pid_path=$(Configured_PID_File) || return 1
    if have_systemd; then
        systemctl start ocserv || return $?
    else
        "$file" -c "$conf" --pid-file="$pid_path" || return $?
    fi
    sleep 2s
    check_pid || return 1
    if [[ -z "$PID" ]]; then
        echo -e "${Error} ocserv exited before startup completed" >&2
        return 1
    fi
    View_Config
}
Wait_For_Ocserv_Stop(){
    local attempt
    for attempt in {1..50}; do
        check_pid || return 1
        [[ -n "$PID" ]] || return 0
        sleep 0.1
    done
    echo -e "${Error} ocserv did not stop" >&2
    return 1
}
Stop_ocserv(){
    check_installed_status
    check_pid || return 1
    if [[ -z "$PID" ]]; then
        echo -e "${Error} ocserv is not running" >&2
        return 1
    fi
    if have_systemd; then
        systemctl stop ocserv || return $?
    else
        kill "$PID" || return $?
    fi
    Wait_For_Ocserv_Stop
}
Restart_ocserv(){
    check_installed_status
    if have_systemd; then
        systemctl restart ocserv || return $?
        sleep 2s
        check_pid || return 1
        [[ -n "$PID" ]] || return 1
        View_Config
    else
        check_pid || return 1
        if [[ -n "$PID" ]]; then
            Stop_ocserv || return $?
        fi
        Start_ocserv
    fi
}
Set_ocserv(){
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv config file doesn't exist !" && exit 1
    tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
    udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
    vim ${conf}
    set_tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
    set_udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
    Del_iptables "${tcp_port}" "${udp_port}"
    Add_iptables "${set_tcp_port}" "${set_udp_port}"
    Save_iptables
    echo "Restart ocserv ? (Y/n)"
    read -e -p "(Default: Y):" yn
    [[ -z ${yn} ]] && yn="y"
    if [[ ${yn} == [Yy] ]]; then
        Restart_ocserv
    fi
}
Set_tcp_port(){
    while true
    do
    echo -e "Please input VPN Server's TCP port"
    read -e -p "(Default: 443):" set_tcp_port
    [[ -z "$set_tcp_port" ]] && set_tcp_port="443"
    echo $((${set_tcp_port}+0)) &>/dev/null
    if [[ $? -eq 0 ]]; then
        if [[ ${set_tcp_port} -ge 1 ]] && [[ ${set_tcp_port} -le 65535 ]]; then
            echo && echo -e "   TCP Port : ${Red_font_prefix}${set_tcp_port}${Font_color_suffix}" && echo
            break
        else
            echo -e "${Error} Please input a valid number！"
        fi
    else
        echo -e "${Error} Please input a valid number！"
    fi
    done
}
Set_udp_port(){
    while true
    do
    echo -e "Please input VPN Server's UDP port"
    read -e -p "(Default: ${set_tcp_port}):" set_udp_port
    [[ -z "$set_udp_port" ]] && set_udp_port="${set_tcp_port}"
    echo $((${set_udp_port}+0)) &>/dev/null
    if [[ $? -eq 0 ]]; then
        if [[ ${set_udp_port} -ge 1 ]] && [[ ${set_udp_port} -le 65535 ]]; then
            echo && echo -e "   UDP Port : ${Red_font_prefix}${set_udp_port}${Font_color_suffix}" && echo
            break
        else
            echo -e "${Error} Please input a valid number！"
        fi
    else
        echo -e "${Error} Please input a valid number！"
    fi
    done
}
Get_Conf_Value(){
    awk -v key="$1" '
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            sub(/^[^=]*=[[:space:]]*/, "")
            sub(/[[:space:]]*(#.*)?$/, "")
            gsub(/^"|"$/, "")
            print
            exit
        }
    ' "$conf"
}
Set_Conf_Value(){
    # Safely rewrite a single key in ocserv.conf: replace in place if present, append otherwise.
    # Values are passed via awk -v, avoiding sed expression string-concatenation entirely.
    local key="$1" val="$2" tmp="${conf}.tmp"
    awk -v key="${key}" -v val="${val}" '
        BEGIN { found = 0 }
        $0 ~ "^" key " = " { print key " = " val; found = 1; next }
        { print }
        END { if (!found) print key " = " val }
    ' "${conf}" > "${tmp}" && cat "${tmp}" > "${conf}" && rm -f "${tmp}"
}
Set_Config(){
    Add_User || return 1
    Set_tcp_port
    Set_udp_port
    Set_Conf_Value "tcp-port" "${set_tcp_port}"
    Set_Conf_Value "udp-port" "${set_udp_port}"
}
Read_config(){
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv config file doesn't exist !" && exit 1
    conf_text=$(cat ${conf}|grep -v '#')
    tcp_port=$(echo -e "${conf_text}"|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
    udp_port=$(echo -e "${conf_text}"|grep "udp-port ="|awk -F ' = ' '{print $NF}')
    max_same_clients=$(echo -e "${conf_text}"|grep "max-same-clients ="|awk -F ' = ' '{print $NF}')
    max_clients=$(echo -e "${conf_text}"|grep "max-clients ="|awk -F ' = ' '{print $NF}')
}
List_User(){ With_Account_Lock _List_User "$@"; }
_List_User(){
    local -A seen=()
    local line u d base marker pw cert acc
    if [[ -f "$passwd_file" ]]; then
        while IFS='' read -r line || [[ -n "$line" ]]; do
            u="${line%%:*}"
            [[ -z "$u" ]] || seen["$u"]=1
        done < "$passwd_file"
    fi
    for d in "$USERS_DIR"/* "$USERS_DIR"/.[!.]* "$USERS_DIR"/..?*; do
        [[ -d "$d" ]] || continue
        u="${d##*/}"
        [[ ! -f "$d/$u.cer" ]] || seen["$u"]=1
    done
    for d in "$DISABLED_DIR"/*-susp-* "$DISABLED_DIR"/.*-susp-*; do
        [[ -d "$d" ]] || continue
        base="${d##*/}"
        u="${base%-susp-*}"
        [[ ! -f "$d/$u.cer" ]] || seen["$u"]=1
    done
    for marker in "$DISABLED_DIR"/.pending-disable-* "$DISABLED_DIR"/.pending-delete-*; do
        [[ -f "$marker" ]] || continue
        base="${marker##*/}"
        case "$base" in
            .pending-disable-*) u="${base#.pending-disable-}" ;;
            .pending-delete-*) u="${base#.pending-delete-}" ;;
        esac
        [[ -z "$u" ]] || seen["$u"]=1
    done
    if [[ ${#seen[@]} -eq 0 ]]; then
        echo -e "${Tip} No users yet."
        return 0
    fi
    while IFS= read -r u; do
        pw=$(_pw_status "$u")
        if _cert_enabled "$u"; then cert="Enable"
        else cert="Disable"; fi
        if [[ -f "$DISABLED_DIR/.pending-delete-$u" ]]; then
            acc="Pending deletion"
        elif [[ -f "$DISABLED_DIR/.pending-disable-$u" ]]; then
            acc="Pending disable"
        elif [[ "$pw" == "Enable" || "$cert" == "Enable" ]]; then
            acc="Enable"
        else
            acc="Disable"
        fi
        echo "Username: ${u} Account status: ${acc} Certificate: ${cert} Password: ${pw}"
    done < <(printf '%s\n' "${!seen[@]}" | sort)
}
Require_Terminate_Support(){
    local status socket commands
    if Get_Ocserv_PID >/dev/null; then
        :
    else
        status=$?
        [[ "$status" -eq 1 ]] && return 0
        return 1
    fi
    socket=$(Get_Conf_Value occtl-socket-file) || return 1
    local args=(--no-pager)
    [[ -z "$socket" ]] || args+=(--socket-file "$socket")
    commands=$(occtl "${args[@]}" help) || return 1
    if ! grep -qE '^[[:space:]]*terminate user[[:space:]]' <<< "$commands"; then
        echo -e "${Error} occtl must support 'terminate user' to invalidate saved session cookies; upgrade ocserv to 1.4.2 or later before disabling or deleting accounts." >&2
        return 1
    fi
    # Check control access before changing credentials or certificates.
    occtl "${args[@]}" show status >/dev/null
}
Disconnect_User(){ With_Account_Lock _Disconnect_User "$@"; }
_Disconnect_User(){
    local u="$1" status socket output active sessions
    sanitize_username "$u" || return 1
    Require_Terminate_Support || return 1
    if Get_Ocserv_PID >/dev/null; then
        :
    else
        status=$?
        [[ "$status" -eq 1 ]] && return 0
        return 1
    fi
    socket=$(Get_Conf_Value occtl-socket-file) || return 1
    local args=(--no-pager)
    [[ -z "$socket" ]] || args+=(--socket-file "$socket")
    # occtl does not support a standalone --; it treats it as help and returns success.
    if output=$(occtl "${args[@]}" terminate user "$u" 2>&1); then
        return 0
    fi
    # No active or resumable session is a successful no-op; control errors remain failures.
    active=$(occtl "${args[@]}" show users) || { printf '%s\n' "$output" >&2; return 1; }
    sessions=$(occtl "${args[@]}" show sessions valid) || { printf '%s\n' "$output" >&2; return 1; }
    active+=$'\n'"$sessions"
    if awk -v u="$u" '$1 != "id" && $1 != "session" && $2 == u { found = 1 } END { exit !found }' <<< "$active"; then
        printf '%s\n' "$output" >&2
        return 1
    fi
    return 0
}
Add_User(){ With_Account_Lock _Add_User "$@"; }
_Add_User(){
    local username userpass="" user_dir staged_dir staged_passwd status
    read -rp "Please input the username of VPN account
(Default: admin): " username || return 1
    [[ -n "$username" ]] || username="admin"
    sanitize_username "$username" || { echo -e "${Error} Invalid username"; return 1; }
    if pw_user_exists "$username"; then
        status=0
    else
        status=$?
        [[ "$status" -eq 1 ]] || return 1
    fi
    if [[ "$status" -eq 0 || -e "$USERS_DIR/$username" || -L "$USERS_DIR/$username" ||
          -e "$DISABLED_DIR/.pending-delete-$username" || -e "$DISABLED_DIR/.pending-disable-$username" ]] ||
        Find_Suspended_User "$username" >/dev/null; then
        echo -e "${Error} User already exists or has an incomplete deletion/disable; finish it before creating a replacement certificate" >&2
        return 1
    fi
    echo && echo -e "   Username : ${username}" && echo
    while [[ -z "$userpass" ]]; do
        read -rsp "Please input the password of VPN account (required, cannot be empty): " userpass || return 1
        echo
    done
    Ensure_CRL || return 1
    mkdir -p "$(dirname "$passwd_file")" || return 1
    staged_passwd=$(mktemp "$(dirname "$passwd_file")/.ocpasswd-stage.XXXXXX") || return 1
    staged_dir=$(mktemp -d "$USERS_DIR/.add-$username.XXXXXX") || {
        rm -f "$staged_passwd"
        return 1
    }
    user_dir="$USERS_DIR/$username"
    # Build everything privately. A late crypto/export failure must not publish a login.
    if ! (
        if [[ -e "$passwd_file" || -L "$passwd_file" ]]; then
            cat "$passwd_file" > "$staged_passwd" || exit 1
        fi
        printf '%s\n%s\n' "$userpass" "$userpass" |
            ocpasswd -c "$staged_passwd" -- "$username" || exit 1
        chmod 600 "$staged_passwd" || exit 1
        certtool --generate-privkey --outfile "$staged_dir/$username-key.pem" || exit 1
        cat > "$staged_dir/$username.tmpl" <<EOF || exit 1
cn = "${username}"
tls_www_client
encryption_key
signing_key
expiration_days = 825
EOF
        certtool --generate-certificate \
            --load-privkey "$staged_dir/$username-key.pem" \
            --load-ca-certificate "$CA_CERT" --load-ca-privkey "$CA_KEY" \
            --template "$staged_dir/$username.tmpl" \
            --outfile "$staged_dir/$username.cer" || exit 1
        openssl pkcs12 -export \
            -inkey "$staged_dir/$username-key.pem" -in "$staged_dir/$username.cer" \
            -certfile "$CA_CERT" -name "AnyConnect VPN – $username" \
            -out "$staged_dir/$username.p12" -passout pass:"$userpass" || exit 1
        [[ -s "$staged_dir/$username-key.pem" && -s "$staged_dir/$username.cer" &&
           -s "$staged_dir/$username.p12" ]] || exit 1
        chmod 600 "$staged_dir/$username-key.pem" "$staged_dir/$username.p12" || exit 1
    ); then
        rm -rf -- "$staged_dir"
        rm -f -- "$staged_passwd" "$staged_passwd.tmp"
        echo -e "${Error} Failed to prepare the account; no credentials were published." >&2
        return 1
    fi
    if ! mv -T -- "$staged_dir" "$user_dir"; then
        rm -rf -- "$staged_dir"
        rm -f -- "$staged_passwd" "$staged_passwd.tmp"
        return 1
    fi
    if ! mv -fT -- "$staged_passwd" "$passwd_file"; then
        rm -rf -- "$user_dir"
        rm -f -- "$staged_passwd" "$staged_passwd.tmp"
        return 1
    fi
    echo -e "${Info} Created user '${username}' with certificate and password."
    echo "  ${user_dir}/${username}.p12   (import to device; password is the one you just entered)"
    echo "  ${CA_CERT} (install/trust if prompted)"
}
Del_User(){ With_Account_Lock _Del_User "$@"; }
_Del_User(){
    local u
    List_User || return 1
    echo "Please input username of account to delete"
    read -rp "(Default canceling): " u || return 1
    [[ -n "$u" ]] || { echo "Canceled..."; return 1; }
    sanitize_username "$u" || { echo -e "${Error} Invalid username"; return 1; }
    Require_Terminate_Support || return 1
    Ensure_CRL || return 1
    : > "$DISABLED_DIR/.pending-delete-$u" || return 1
    # Record intent before removing access; retries must finish revocation, not add a replacement.
    pw_delete "$u" || return 1
    Delete_Cert_User "$u" || return 1
    echo -e "${Info} Deleted user '${u}' (certificate revoked and files removed; password account removed)."
}
Modify_User_disabled(){ With_Account_Lock _Modify_User_disabled "$@"; }
_Modify_User_disabled(){
    local u
    List_User || return 1
    echo "Please type Enable/Disable VPN account username"
    read -rp "(Default canceling): " u || return 1
    [[ -n "$u" ]] || { echo "Canceled..."; return 1; }
    sanitize_username "$u" || { echo -e "${Error} Invalid username"; return 1; }
    if [[ -e "$DISABLED_DIR/.pending-delete-$u" ]]; then
        echo -e "${Error} Deletion is incomplete for '$u'; retry deleting this user first." >&2
        return 1
    fi
    # Retry the intended disable, including failures after CRL publication or termination.
    if [[ -f "$DISABLED_DIR/.pending-disable-$u" || -f "$USERS_DIR/$u/$u.cer" ]]; then
        Require_Terminate_Support || return 1
        Ensure_CRL || return 1
        : > "$DISABLED_DIR/.pending-disable-$u" || return 1
        echo -e "${Info} Suspending certificate and disabling password for '${u}' ..."
        pw_lock "$u" || return 1
        Suspend_Cert_User "$u" || return 1
        echo -e "${Info} '${u}' is now Disabled (Certificate: Disable, Password: Disable)."
        return 0
    fi
    if Find_Suspended_User "$u" >/dev/null; then
        echo -e "${Info} Unsuspending certificate and enabling password for '${u}' ..."
        Unsuspend_Cert_User "$u" || return 1
        if ! pw_unlock "$u"; then
            : > "$DISABLED_DIR/.pending-disable-$u" || return 1
            Suspend_Cert_User "$u" || return 1
            return 1
        fi
        echo -e "${Info} '${u}' is now Enabled (Certificate: Enable, Password: Enable)."
        return 0
    fi
    echo -e "${Tip} No certificate found for '${u}'. Add the user first."
    return 1
}
Set_Pass(){
    check_installed_status
    echo -e "\n What wanna you do?\n\n  0. List users\n————————\n  1. Add users\n  2. Delete users\n————————\n  3. Enable/Disable users\n"
    read -e -p "Choice [0-3]: " set_num
    case "$set_num" in
      0) List_User ;;
      1) Add_User ;;
      2) Del_User ;;
      3) Modify_User_disabled ;;
      *) echo "Canceled..." ;;
    esac
}
# Helpers for unified manager

With_Account_Lock(){
    if [[ "${_ACCOUNT_LOCK_PID:-}" == "$BASHPID" ]]; then
        "$@"
        return $?
    fi
    # A fork must release its inherited descriptor before waiting for its own lock.
    if [[ "${_ACCOUNT_LOCK_FD:-}" =~ ^[0-9]+$ ]]; then
        exec {_ACCOUNT_LOCK_FD}>&-
    fi
    (
        umask 077
        mkdir -p "$SSL_DIR" || return 1
        local _ACCOUNT_LOCK_FD _ACCOUNT_LOCK_PID
        exec {_ACCOUNT_LOCK_FD}>>"$SSL_DIR/.accounts.lock" || return 1
        flock -x "$_ACCOUNT_LOCK_FD" || return 1
        _ACCOUNT_LOCK_PID=$BASHPID
        "$@"
    )
}
sanitize_username() {
  local u="$1"
  [[ "$u" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || return 1
  [[ "$u" != "." && "$u" != ".." ]] || return 1
  return 0
}
pw_user_exists() {
  local u="$1" found
  [[ -e "$passwd_file" || -L "$passwd_file" ]] || return 1
  [[ -f "$passwd_file" ]] || return 2
  found=$(awk -F: -v u="$u" '$1==u{found=1} END{if(found) print "yes"}' "$passwd_file") || return 2
  [[ -n "$found" ]]
}
pw_action(){ With_Account_Lock _pw_action "$@"; }
_pw_action() {
  local action="$1" u="$2" found
  [[ -e "${passwd_file}" || -L "${passwd_file}" ]] || return 0
  [[ -f "${passwd_file}" ]] || return 1
  # Scan the entire file to distinguish absence from read errors; END preserves awk failures.
  found=$(awk -F: -v u="$u" '$1==u{found=1} END{if(found) print "yes"}' "${passwd_file}") || return 1
  [[ -n "$found" ]] || return 0
  ocpasswd -c "${passwd_file}" "$action" -- "$u" >/dev/null 2>&1
}
pw_lock()   { pw_action -l "$1"; }
pw_unlock() { pw_action -u "$1"; }
pw_delete() { pw_action -d "$1"; }
_pw_status(){
    local u="$1"
    if [[ -f "${passwd_file}" ]]; then
        local line; line=$(awk -F':*:' -v u="$u" '$1==u {print $0}' "${passwd_file}")
        if [[ -n "$line" ]]; then
            local st; st=$(echo "$line" | awk -F':*:' '{print $NF}' | cut -c1)
            [[ "$st" == "!" ]] && echo "Disable" || echo "Enable"
            return
        fi
    fi
    echo "Disable"
}
Find_Suspended_User(){
    local u="$1" candidate base latest=""
    for candidate in "$DISABLED_DIR/$u-susp-"*; do
        [[ -d "$candidate" ]] || continue
        base="${candidate##*/}"
        [[ "${base%-susp-*}" == "$u" ]] || continue
        if [[ -z "$latest" || "$candidate" > "$latest" ]]; then
            latest="$candidate"
        fi
    done
    [[ -n "$latest" ]] || return 1
    printf '%s\n' "$latest"
}
_cert_enabled(){ [[ -f "${USERS_DIR}/$1/$1.cer" ]]; }
_cert_suspended(){ Find_Suspended_User "$1" >/dev/null; }
View_Config(){
    Get_ip
    Read_config
    clear && echo "===================================================" && echo
    echo -e " AnyConnect Conf：" && echo
    echo -e " I  P\t\t  : ${Green_font_prefix}${ip}${Font_color_suffix}"
    echo -e " TCP Port\t  : ${Green_font_prefix}${tcp_port}${Font_color_suffix}"
    echo -e " UDP Port\t  : ${Green_font_prefix}${udp_port}${Font_color_suffix}"
    echo -e " Single user device limit : ${Green_font_prefix}${max_same_clients}${Font_color_suffix}"
    echo -e " Total user device limit : ${Green_font_prefix}${max_clients}${Font_color_suffix}"
    echo -e "\n Link for clients : ${Green_font_prefix}${ip}:${tcp_port}${Font_color_suffix}"
    echo && echo "==================================================="
}
View_Log(){
    if have_systemd; then
        echo && echo -e "${Tip} Press ${Red_font_prefix}Ctrl+C${Font_color_suffix} to stop viewing logs" && echo
        journalctl -u ocserv -f --no-pager
    else
        [[ ! -e ${log_file} ]] && echo -e "${Error} ocserv log doesn't exist !" && exit 1
        echo && echo -e "${Tip} Press ${Red_font_prefix}Ctrl+C${Font_color_suffix} Stop View log" && echo -e "If you want to View all log, please use ${Red_font_prefix}cat ${log_file}${Font_color_suffix} command。" && echo
        tail -f ${log_file}
    fi
}
Uninstall_ocserv(){
    check_installed_status "un"
    echo "Are you sure uninstall ocserv ? (y/N)"
    echo
    read -e -p "(Default: n):" unyn
    [[ -z ${unyn} ]] && unyn="n"
    if [[ ${unyn} == [Yy] ]]; then
        check_pid
        [[ ! -z $PID ]] && kill -9 ${PID} && rm -f ${PID_FILE}
        Read_config
        Del_iptables "${tcp_port}" "${udp_port}"
        Save_iptables
        if have_systemd; then
            systemctl disable --now ocserv ocserv-firewall >/dev/null 2>&1
            rm -f /etc/systemd/system/ocserv.service /etc/systemd/system/ocserv-firewall.service
            systemctl daemon-reload
        fi
        rm -rf "${conf_file}"
        rm -f "${log_file}"
        rm -f /usr/local/bin/occtl /usr/local/bin/ocpasswd /usr/local/bin/ocserv-fw
        rm -f /usr/local/sbin/ocserv
        rm -f /usr/local/share/man/man8/ocserv.8 /usr/local/share/man/man8/ocpasswd.8 /usr/local/share/man/man8/occtl.8
        echo && echo "ocserv uninstall completed !" && echo
    else
        echo && echo "uninstall canceled..." && echo
    fi
}
over(){
    if have_systemd; then
        systemctl disable --now ocserv ocserv-firewall >/dev/null 2>&1
        rm -f /etc/systemd/system/ocserv.service /etc/systemd/system/ocserv-firewall.service
        systemctl daemon-reload
    fi
    rm -rf "${conf_file}"
    rm -f "${log_file}"
    rm -f /usr/local/bin/occtl /usr/local/bin/ocpasswd /usr/local/bin/ocserv-fw
    rm -f /usr/local/sbin/ocserv
    rm -f /usr/local/share/man/man8/ocserv.8 /usr/local/share/man/man8/ocpasswd.8 /usr/local/share/man/man8/occtl.8
    echo && echo "install failed，ocserv uninstalled !" && echo
}
Add_iptables(){
    # Ports passed as arguments; existence check before insert to avoid duplicate rules
    local tcp_port="${1:-${set_tcp_port}}"
    local udp_port="${2:-${set_udp_port}}"
    iptables -C INPUT -m state --state NEW -m tcp -p tcp --dport ${tcp_port} -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${tcp_port} -j ACCEPT
    iptables -C INPUT -m state --state NEW -m udp -p udp --dport ${udp_port} -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${udp_port} -j ACCEPT
}
Del_iptables(){
    local tcp_port="${1:-${tcp_port}}"
    local udp_port="${2:-${udp_port}}"
    iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${tcp_port} -j ACCEPT 2>/dev/null
    iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${udp_port} -j ACCEPT 2>/dev/null
    return 0
}
Save_iptables(){
    iptables-save > /etc/iptables.up.rules
}
Set_iptables(){
    local vpn_network vpn_netmask vpn_subnet vpn_device
    vpn_network=$(Get_Conf_Value ipv4-network) || return 1
    vpn_netmask=$(Get_Conf_Value ipv4-netmask) || return 1
    vpn_device=$(Get_Conf_Value device) || return 1
    if [[ -z "$vpn_network" || -z "$vpn_device" ||
        ( "$vpn_network" != */* && -z "$vpn_netmask" ) ]]; then
        echo -e "${Error} Missing VPN IPv4 network, netmask, or device in configuration" >&2
        return 1
    fi
    vpn_subnet="$vpn_network"
    [[ "$vpn_subnet" == */* ]] || vpn_subnet="$vpn_network/$vpn_netmask"

    touch /etc/sysctl.conf || return 1
    if grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=' /etc/sysctl.conf; then
        sed -i 's/^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf || return 1
    else
        printf '\nnet.ipv4.ip_forward=1\n' >> /etc/sysctl.conf || return 1
    fi
    sysctl -w net.ipv4.ip_forward=1 || return 1
    Network_card=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')
    if [[ -z "$Network_card" ]]; then
        ip -o addr 2>/dev/null || ifconfig
        read -rp "Egress interface (e.g. eth0): " Network_card || return 1
        [[ -n "$Network_card" ]] || return 1
    fi
    # Allow VPN traffic only on its tunnel interfaces and configured IPv4 subnet.
    iptables -C FORWARD -i "${vpn_device}+" -s "$vpn_subnet" -o "$Network_card" \
        -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
        iptables -I FORWARD -i "${vpn_device}+" -s "$vpn_subnet" -o "$Network_card" \
            -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT || return 1
    iptables -C FORWARD -i "$Network_card" -o "${vpn_device}+" -d "$vpn_subnet" \
        -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
        iptables -I FORWARD -i "$Network_card" -o "${vpn_device}+" -d "$vpn_subnet" \
            -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT || return 1
    iptables -t nat -C POSTROUTING -s "$vpn_subnet" -o "$Network_card" -j MASQUERADE 2>/dev/null ||
        iptables -t nat -A POSTROUTING -s "$vpn_subnet" -o "$Network_card" -j MASQUERADE || return 1
    Save_iptables || return 1
    Firewall_Service_ocserv
}
# Ensure CRL files exist and minimal template
Ensure_CRL(){ With_Account_Lock _Ensure_CRL "$@"; }
_Ensure_CRL(){
    mkdir -p "$SSL_DIR" "$USERS_DIR" "$DISABLED_DIR" || return 1
    if [[ ! -s "$CRL_TMPL" ]]; then
        printf 'crl_next_update = 365\n' > "$CRL_TMPL" || return 1
    fi
    touch "$REVOKED_PEM" "$SUSPENDED_PEM" || return 1
    if [[ ! -s "$CRL_PEM" ]]; then
        Rebuild_CRL || return 1
    fi
}
# Rebuild suspended list from disabled/*-susp-* directories
Rebuild_SUSPENDED_PEM(){ With_Account_Lock _Rebuild_SUSPENDED_PEM "$@"; }
_Rebuild_SUSPENDED_PEM(){
    local d base u suspended_next
    suspended_next=$(mktemp "$SSL_DIR/.suspended-next.XXXXXX") || return 1
    for d in "$DISABLED_DIR"/*-susp-* "$DISABLED_DIR"/.*-susp-*; do
        [[ -d "$d" ]] || continue
        base="${d##*/}"
        u="${base%-susp-*}"
        if [[ -f "$d/$u.cer" ]]; then
            if ! cat "$d/$u.cer" >> "$suspended_next"; then
                rm -f "$suspended_next"
                return 1
            fi
        fi
    done
    if ! mv -f "$suspended_next" "$SUSPENDED_PEM"; then
        rm -f "$suspended_next"
        return 1
    fi
}
# Rebuild CRL from permanent + suspended lists
Rebuild_CRL(){ With_Account_Lock _Rebuild_CRL "$@"; }
_Rebuild_CRL(){
    local crl_input crl_next server_pid status
    if server_pid=$(Get_Ocserv_PID); then
        :
    else
        status=$?
        [[ "$status" -eq 1 ]] || return 1
    fi
    crl_input=$(mktemp "$SSL_DIR/.crl-input.XXXXXX") || return 1
    crl_next=$(mktemp "$SSL_DIR/.crl-next.XXXXXX") || { rm -f "$crl_input"; return 1; }
    if ! cat "$REVOKED_PEM" "$SUSPENDED_PEM" > "$crl_input"; then
        rm -f "$crl_input" "$crl_next"
        return 1
    fi
    local args=(--generate-crl --load-ca-privkey "$CA_KEY"
        --load-ca-certificate "$CA_CERT" --template "$CRL_TMPL")
    [[ ! -s "$crl_input" ]] || args+=(--load-certificate "$crl_input")
    if ! certtool "${args[@]}" --outfile "$crl_next"; then
        rm -f "$crl_input" "$crl_next"
        return 1
    fi
    rm -f "$crl_input"
    if ! chmod 644 "$crl_next" || ! mv -f "$crl_next" "$CRL_PEM"; then
        rm -f "$crl_next"
        return 1
    fi
    if server_pid=$(Get_Ocserv_PID); then
        kill -HUP "$server_pid" || return 1
    else
        status=$?
        [[ "$status" -eq 1 ]] || return 1
    fi
    return 0
}
# Configure auth to certificate default + plain fallback (OR)
Configure_Auth(){ With_Account_Lock _Configure_Auth "$@"; }
_Configure_Auth(){
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv config file doesn't exist !" && return 1
    # Delete every script-managed entry first, then append once (config is order-independent)
    sed -i '/^\s*ca-cert\s*=/d; /^\s*crl\s*=/d; /^\s*cert-user-oid\s*=/d; /^\s*auth\s*=/d; /^\s*enable-auth\s*=/d' "${conf}" || return 1
    cat >> "${conf}" <<EOF || return 1
ca-cert = ${CA_CERT}
crl = ${CRL_PEM}
cert-user-oid = 2.5.4.3
auth = "certificate"
enable-auth = "plain[passwd=${passwd_file}]"
EOF
    echo -e "${Info} Enabled certificate default + password fallback in ${conf}"
}
# Certificate user management
Delete_Cert_User(){ With_Account_Lock _Delete_Cert_User "$@"; }
_Delete_Cert_User(){
    local u="${1:-}" d
    if [[ -z "$u" ]]; then
        echo "Delete which username? (revokes active cert first)"
        read -rp "(Default canceling): " u || return 1
    fi
    [[ -n "$u" ]] || { echo "Canceled..."; return 1; }
    sanitize_username "$u" || { echo -e "${Error} Invalid username"; return 1; }
    Require_Terminate_Support || return 1
    Ensure_CRL || return 1
    : > "$DISABLED_DIR/.pending-delete-$u" || return 1
    if [[ -f "$USERS_DIR/$u/$u.cer" ]]; then
        cat "$USERS_DIR/$u/$u.cer" >> "$REVOKED_PEM" || return 1
        rm -rf -- "$USERS_DIR/$u" || return 1
    fi
    for d in "$DISABLED_DIR/$u-susp-"*; do
        [[ -f "$d/$u.cer" ]] || continue
        cat "$d/$u.cer" >> "$REVOKED_PEM" || return 1
        rm -rf -- "$d" || return 1
    done
    # A retry must apply saved revocations even when the certificate directories are gone.
    Rebuild_SUSPENDED_PEM || return 1
    Rebuild_CRL || return 1
    Disconnect_User "$u" || return 1
    rm -f -- "$DISABLED_DIR/.pending-delete-$u" "$DISABLED_DIR/.pending-disable-$u" || return 1
    echo -e "${Info} Deleted ${u} (revocation persists in CRL)."
}
Suspend_Cert_User(){ With_Account_Lock _Suspend_Cert_User "$@"; }
_Suspend_Cert_User(){
    local u="${1:-}" user_dir ts pending
    if [[ -z "$u" ]]; then
        echo "Suspend (temporarily disable) which cert username?"
        read -rp "(Default canceling): " u || return 1
    fi
    [[ -n "$u" ]] || { echo "Canceled..."; return 1; }
    sanitize_username "$u" || { echo -e "${Error} Invalid username"; return 1; }
    if [[ -e "$DISABLED_DIR/.pending-delete-$u" ]]; then
        echo -e "${Error} Deletion is incomplete for '$u'; retry deleting this user first." >&2
        return 1
    fi
    Require_Terminate_Support || return 1
    user_dir="$USERS_DIR/$u"
    pending="$DISABLED_DIR/.pending-disable-$u"
    if [[ ! -f "$user_dir/$u.cer" ]]; then
        [[ -f "$pending" ]] && Find_Suspended_User "$u" >/dev/null || {
            echo -e "${Error} No active or pending suspended certificate found: $u" >&2
            return 1
        }
    fi
    Ensure_CRL || return 1
    : > "$pending" || return 1
    if [[ -f "$user_dir/$u.cer" ]]; then
        ts=$(date +%Y%m%d-%H%M%S) || return 1
        mv -T -- "$user_dir" "$DISABLED_DIR/$u-susp-$ts" || return 1
    fi
    # Keep the marker until both CRL reload and saved-cookie invalidation finish.
    Rebuild_SUSPENDED_PEM || return 1
    Rebuild_CRL || return 1
    Disconnect_User "$u" || return 1
    rm -f -- "$pending" || return 1
    echo -e "${Info} Suspended ${u}."
}
Unsuspend_Cert_User(){ With_Account_Lock _Unsuspend_Cert_User "$@"; }
_Unsuspend_Cert_User(){
    local u="${1:-}" last_dir
    if [[ -z "$u" ]]; then
        echo "Unsuspend (re-enable same certificate) which username?"
        read -rp "(Default canceling): " u || return 1
    fi
    [[ -n "$u" ]] || { echo "Canceled..."; return 1; }
    sanitize_username "$u" || { echo -e "${Error} Invalid username"; return 1; }
    if [[ -e "$DISABLED_DIR/.pending-delete-$u" || -e "$DISABLED_DIR/.pending-disable-$u" ]]; then
        echo -e "${Error} An account operation is incomplete for '$u'; finish the pending disable or deletion before restoring it." >&2
        return 1
    fi
    last_dir=$(Find_Suspended_User "$u") || {
        echo -e "${Error} No suspended certificate found: $u" >&2
        return 1
    }
    mv -T -- "$last_dir" "$USERS_DIR/$u" || return 1
    if ! Rebuild_SUSPENDED_PEM || ! Rebuild_CRL; then
        # A failed restore must finish disabling before it can be restored again.
        : > "$DISABLED_DIR/.pending-disable-$u" || return 1
        Suspend_Cert_User "$u" || return 1
        return 1
    fi
    echo -e "${Info} Unsuspended ${u}."
}
Update_Shell(){
    # Self-update only from this repo's same-named script; never overwrite with the upstream version
    local self_name; self_name="$(basename "$0")"
    sh_new_ver=$(wget -qO- -t1 -T5 "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/${self_name}"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
    [[ -z ${sh_new_ver} ]] && echo -e "${Error} Unable to connect to Github !" && exit 0
    if [[ "${sh_new_ver}" == "${sh_ver}" ]]; then
        echo -e "${Info} Already the latest version [ ${sh_ver} ] !" && exit 0
    fi
    wget -O "${self_name}.new" "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/${self_name}" && chmod +x "${self_name}.new"
    bash -n "${self_name}.new" || { echo -e "${Error} Downloaded version failed syntax check, update aborted !"; rm -f "${self_name}.new"; exit 1; }
    mv -f "${self_name}.new" "${self_name}"
    echo -e "${Info} Script updated to latest [ ${sh_new_ver} ], please re-run it !" && exit 0
}
# Sourcing loads production helpers without entering the interactive menu.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

check_sys
[[ -z "${pm}" ]] && echo -e "${Error} Your distro is not supported (unknown distro or package manager)! Supported: Debian/Ubuntu, RHEL family (CentOS/Rocky/Alma/Fedora...), Arch, openSUSE." && exit 1
echo && echo -e " ocserv 1key install and conf script ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  -- Toyo | doub.io/vpnzy-7 --
  
 ${Green_font_prefix}0.${Font_color_suffix} Upgrade Script
————————————
 ${Green_font_prefix}1.${Font_color_suffix} install ocserv
 ${Green_font_prefix}2.${Font_color_suffix} uninstall ocserv
————————————
 ${Green_font_prefix}3.${Font_color_suffix} Start ocserv
 ${Green_font_prefix}4.${Font_color_suffix} Stop ocserv
 ${Green_font_prefix}5.${Font_color_suffix} Restart ocserv
————————————
 ${Green_font_prefix}6.${Font_color_suffix} Manage users
 ${Green_font_prefix}7.${Font_color_suffix} View conf
 ${Green_font_prefix}8.${Font_color_suffix} Edit config file 
 ${Green_font_prefix}9.${Font_color_suffix} View log
————————————" && echo
if [[ -e ${file} ]]; then
    check_pid
    if [[ ! -z "${PID}" ]]; then
        echo -e " Current status: ${Green_font_prefix}installed${Font_color_suffix} and ${Green_font_prefix}running${Font_color_suffix}"
    else
        echo -e " Current status: ${Green_font_prefix}installed ${Font_color_suffix} but ${Red_font_prefix} NOT running${Font_color_suffix}"
    fi
else
    echo -e " Current status: ${Red_font_prefix}not installed${Font_color_suffix}"
fi
echo
read -e -p " Please input number [0-9]:" num
case "$num" in
    0)
    Update_Shell
    ;;
    1)
    Install_ocserv
    ;;
    2)
    Uninstall_ocserv
    ;;
    3)
    Start_ocserv
    ;;
    4)
    Stop_ocserv
    ;;
    5)
    Restart_ocserv
    ;;
    6)
    Set_Pass
    ;;
    7)
    View_Config
    ;;
    8)
    Set_ocserv
    ;;
    9)
    View_Log
    ;;
    *)
    echo "Please input current number [0-9]"
    ;;
esac

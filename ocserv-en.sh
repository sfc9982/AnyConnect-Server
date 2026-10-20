#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="2.1.0"
file="/usr/local/sbin/ocserv"
conf_file="/etc/ocserv"
conf="/etc/ocserv/ocserv.conf"
passwd_file="/etc/ocserv/ocpasswd"
log_file="/tmp/ocserv.log"
ocserv_ver="1.3.0"
PID_FILE="/var/run/ocserv.pid"

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

check_pid(){
    if [[ ! -e ${PID_FILE} ]]; then
        PID=""
    else
        PID=$(cat ${PID_FILE})
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
Download_ocserv(){
    build_dir="/tmp/ocserv-build"
    rm -rf "${build_dir}"
    mkdir -p "${build_dir}" || return 1
    wget -O "${build_dir}/ocserv-${ocserv_ver}.tar.xz" "https://ftp.infradead.org/pub/ocserv/ocserv-${ocserv_ver}.tar.xz" || return 1
    [[ ! -s "${build_dir}/ocserv-${ocserv_ver}.tar.xz" ]] && echo -e "${Error} ocserv source download failed!" && rm -rf "${build_dir}" && exit 1
    tar -xJf "${build_dir}/ocserv-${ocserv_ver}.tar.xz" -C "${build_dir}" || return 1
    cd "${build_dir}/ocserv-${ocserv_ver}" || return 1
    ./configure || return 1
    make || return 1
    make install || return 1
    cd / || return 1
    rm -rf "${build_dir}"
    
    if [[ -e ${file} ]]; then
        mkdir -p "${conf_file}" || return 1
        wget -N -P "${conf_file}" "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/ocserv.conf" || return 1
        [[ ! -s "${conf}" ]] && echo -e "${Error} ocserv config download failed!" && rm -rf "${conf_file}" && exit 1
    else
        echo -e "${Error} ocserv compiled failed!" && exit 1
    fi
}
# Whether systemd is available for service management (default on mainstream distros)
have_systemd(){
    command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}
Service_ocserv(){
    # Inline systemd unit files replace the third-party init.d download (no external supply chain)
    if have_systemd; then
        cat > /etc/systemd/system/ocserv.service <<EOF
[Unit]
Description=OpenConnect SSL VPN server (Cisco AnyConnect compatible)
Documentation=https://ocserv.gitlab.io/www/
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/var/run/ocserv.pid
ExecStart=/usr/local/sbin/ocserv -c /etc/ocserv/ocserv.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable ocserv >/dev/null 2>&1
        echo -e "${Info} ocserv systemd service unit installed and enabled at boot!"
    else
        # Minimal environments without systemd (Docker/OpenVZ): manage the daemon directly
        echo -e "${Tip} systemd not detected, ocserv will be managed as a plain daemon (no boot autostart)."
    fi
}
Firewall_Service_ocserv(){
    # Boot-time iptables restore unit (replaces the Debian-only if-pre-up.d hook; distro-agnostic)
    have_systemd || return 0
    cat > /etc/systemd/system/ocserv-firewall.service <<EOF
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
    systemctl daemon-reload
    systemctl enable ocserv-firewall >/dev/null 2>&1
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
            apt-get install -y tar xz-utils vim net-tools pkg-config build-essential ca-certificates wget iproute2 procps iptables openssl libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc
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
            dnf install -y tar xz vim net-tools pkgconf-pkg-config gcc make ca-certificates wget iproute procps-ng iptables openssl gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel lz4-devel gnutls-utils ipcalc
            ;;
        yum)
            yum install -y epel-release >/dev/null 2>&1
            yum install -y tar xz vim net-tools pkgconfig gcc make ca-certificates wget iproute procps-ng iptables openssl gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel lz4-devel gnutls-utils ipcalc
            ;;
        pacman)
            pacman -Syu --noconfirm tar xz base-devel vim net-tools gnutls libseccomp libev libnl readline ca-certificates wget iproute2 procps-ng iptables openssl lz4 ipcalc
            ;;
        zypper)
            zypper -n install tar xz gnutls gcc make vim net-tools pkg-config gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel liblz4-devel ca-certificates wget iproute2 procps iptables openssl ipcalc
            ;;
        *)
            echo -e "${Error} Unknown package manager, cannot install dependencies !" && exit 1 ;;
    esac
}
Install_ocserv(){
    check_root || return 1
    [[ -e ${file} ]] && echo -e "${Error} ocserv is already installed !" && exit 1
    echo -e "${Info} Start to install/config dependencies..."
    Installation_dependency || return 1
    echo -e "${Info} Start to download/install config file..."
    Download_ocserv || return 1
    echo -e "${Info} Start to install systemd service units..."
    Service_ocserv || return 1
    echo -e "${Info} Start to self-sign SSL cert..."
    Generate_SSL || return 1
    echo -e "${Info} Enforcing CRL and certificate-default + password-fallback auth..."
    Ensure_CRL || return 1
    Configure_Auth || return 1
    echo -e "${Info} Start to set account settings..."
    Read_config || return 1
    Set_Config || return 1
    echo -e "${Info} Start to set iptables firewall ..."
    Set_iptables || return 1
    echo -e "${Info} Start to add iptables firewall rules..."
    Add_iptables "${set_tcp_port}" "${set_udp_port}" || return 1
    echo -e "${Info} Start to save iptables firewall rules..."
    Save_iptables || return 1
    echo -e "${Info} All progress installed completed, now starting..."
    Start_ocserv
}
Start_ocserv(){
    check_installed_status
    check_pid
    [[ ! -z ${PID} ]] && echo -e "${Error} ocserv is running !" && exit 1
    if have_systemd; then
        systemctl start ocserv
    else
        ${file} -c ${conf}
    fi
    sleep 2s
    check_pid
    [[ ! -z ${PID} ]] && View_Config
}
Stop_ocserv(){
    check_installed_status
    check_pid
    [[ -z ${PID} ]] && echo -e "${Error} ocserv is NOT running !" && exit 1
    if have_systemd; then
        systemctl stop ocserv
    else
        [[ ! -z ${PID} ]] && kill ${PID}
    fi
}
Restart_ocserv(){
    check_installed_status
    if have_systemd; then
        systemctl restart ocserv
    else
        check_pid
        [[ ! -z ${PID} ]] && kill ${PID}
        ${file} -c ${conf}
    fi
    sleep 2s
    check_pid
    [[ ! -z ${PID} ]] && View_Config
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
List_User(){
    declare -A seen
    if [[ -f "${passwd_file}" ]]; then
        while IFS='' read -r line || [[ -n "$line" ]]; do
            u=$(echo "$line" | awk -F':*:' '{print $1}')
            [[ -n "$u" ]] && seen["$u"]=1
        done < "${passwd_file}"
    fi
    if [[ -d "${USERS_DIR}" ]]; then
        for d in $(find "${USERS_DIR}" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null); do
            seen["$d"]=1
        done
    fi
    if [[ -d "${DISABLED_DIR}" ]]; then
        for d in $(find "${DISABLED_DIR}" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null); do
            u="${d%-susp-*}"; [[ -n "$u" ]] && seen["$u"]=1
        done
    fi
    if [[ ${#seen[@]} -eq 0 ]]; then echo -e "${Tip} No users yet."; return; fi
    for u in $(printf "%s\n" "${!seen[@]}" | sort); do
        pw=$(_pw_status "$u")
        if _cert_enabled "$u"; then cert="Enable"
        elif _cert_suspended "$u"; then cert="Disable"
        else cert="Disable"; fi
        [[ "$pw" == "Enable" || "$cert" == "Enable" ]] && acc="Enable" || acc="Disable"
        echo "Username: ${u} Account status: ${acc} Certificate: ${cert} Password: ${pw}"
    done
}
Disconnect_User(){
    local u="$1" server_pid socket output active
    [[ -s "$PID_FILE" ]] || return 0
    server_pid=$(cat "$PID_FILE") || return 1
    [[ "$server_pid" =~ ^[1-9][0-9]*$ ]] || return 1
    kill -0 "$server_pid" 2>/dev/null || return 0
    socket=$(Get_Conf_Value occtl-socket-file) || return 1
    local args=(--no-pager)
    [[ -z "$socket" ]] || args+=(--socket-file "$socket")
    if output=$(occtl "${args[@]}" -- disconnect user "$u" 2>&1); then
        return 0
    fi
    # No active session is a successful no-op; control errors remain failures.
    active=$(occtl "${args[@]}" show users) || { printf '%s\n' "$output" >&2; return 1; }
    if awk -v u="$u" '$2 == u { found = 1 } END { exit !found }' <<< "$active"; then
        printf '%s\n' "$output" >&2
        return 1
    fi
}
Add_User(){
    read -rp "Please input the username of VPN account
(Default: admin): " username
    [[ -z "${username}" ]] && username="admin"
    sanitize_username "${username}" || { echo -e "${Error} Invalid username"; return 1; }
    if pw_user_exists "$username" || [[ -e "$USERS_DIR/$username" ]] ||
        Find_Suspended_User "$username" >/dev/null; then
        echo -e "${Error} User already exists; delete it before creating a replacement certificate" >&2
        return 1
    fi
    echo && echo -e "   Username : ${username}" && echo
    # No default password anymore: force interactive input to avoid weak default accounts
    userpass=""
    while [[ -z "${userpass}" ]]; do
        read -rsp "Please input the password of VPN account (required, cannot be empty): " userpass || return 1
        echo
    done

    mkdir -p "$(dirname "${passwd_file}")" || return 1
    printf "%s\n%s\n" "${userpass}" "${userpass}" | ocpasswd -c "${passwd_file}" -- "${username}" || { echo -e "${Error} Failed to create password account!"; return 1; }
    chmod 600 "${passwd_file}" || return 1

    Ensure_CRL || return 1
    user_dir="${USERS_DIR}/${username}"
    mkdir -p "${user_dir}" && chmod 700 "${user_dir}" || return 1
    certtool --generate-privkey --outfile "${user_dir}/${username}-key.pem" || { echo -e "${Error} Failed to generate user private key!"; return 1; }
    cat > "${user_dir}/${username}.tmpl" <<EOF || return 1
cn = "${username}"
tls_www_client
encryption_key
signing_key
expiration_days = 825
EOF
    certtool --generate-certificate \
      --load-privkey "${user_dir}/${username}-key.pem" \
      --load-ca-certificate "${CA_CERT}" \
      --load-ca-privkey "${CA_KEY}" \
      --template "${user_dir}/${username}.tmpl" \
      --outfile "${user_dir}/${username}.cer" || { echo -e "${Error} Failed to generate user certificate!"; return 1; }

    openssl pkcs12 -export \
      -inkey "${user_dir}/${username}-key.pem" \
      -in "${user_dir}/${username}.cer" \
      -certfile "${CA_CERT}" \
      -name "AnyConnect VPN – ${username}" \
      -out "${user_dir}/${username}.p12" \
      -passout pass:"${userpass}" || { echo -e "${Error} Failed to export p12 bundle!"; return 1; }

    chmod 600 "${user_dir}/${username}-key.pem" "${user_dir}/${username}.p12" || return 1
    echo -e "${Info} Created user '${username}' with certificate and password."
    echo "  ${user_dir}/${username}.p12   (import to device; password is the one you just entered)"
    echo "  ${CA_CERT} (install/trust if prompted)"
}
Del_User(){
    List_User
    echo "Please input username of account to delete"
    read -rp "(Default canceling): " u
    [[ -z "${u}" ]] && echo "Canceled..." && return 1

	sanitize_username "${u}" || { echo -e "${Error} Invalid username"; return 1; }

    # Remove password access before revoking certificates and disconnecting sessions
    pw_delete "${u}" || return 1

    # Revoke active and suspended certificates
    Delete_Cert_User "${u}" || return 1
    echo -e "${Info} Deleted user '${u}' (certificate revoked and files removed; password account removed)."
}
Modify_User_disabled(){
  List_User
    echo "Please type Enable/Disable VPN account username"
    read -rp "(Default canceling): " u
    [[ -z "${u}" ]] && echo "Canceled..." && return 1

	sanitize_username "${u}" || { echo -e "${Error} Invalid username"; return 1; }

    if [[ -f "${USERS_DIR}/${u}/${u}.cer" ]]; then
        echo -e "${Info} Suspending certificate and disabling password for '${u}' ..."
        pw_lock "${u}" || return 1
        Suspend_Cert_User "${u}" || return 1
        echo -e "${Info} '${u}' is now Disabled (Certificate: Disable, Password: Disable)."
        return 0
    fi

    last_dir=$(Find_Suspended_User "${u}" || true)
    if [[ -n "${last_dir}" ]]; then
        echo -e "${Info} Unsuspending certificate and enabling password for '${u}' ..."
        Unsuspend_Cert_User "${u}" || return 1
        pw_unlock "${u}" || return 1
        echo -e "${Info} '${u}' is now Enabled (Certificate: Enable, Password: Enable)."
        return 0
    fi

    echo -e "${Tip} No certificate found for '${u}'. Add the user first."
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

sanitize_username() {
  local u="$1"
  [[ "$u" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || return 1
  [[ "$u" != "." && "$u" != ".." ]] || return 1
  return 0
}
pw_user_exists() {
  local u="$1"
  [[ -f "${passwd_file}" ]] || return 1
  awk -F':*:' -v u="$u" '$1==u{found=1} END{exit found?0:1}' "${passwd_file}"
}
pw_lock()   { local u="$1"; pw_user_exists "$u" && ocpasswd -c "${passwd_file}" -l -- "$u" >/dev/null 2>&1; }
pw_unlock() { local u="$1"; pw_user_exists "$u" && ocpasswd -c "${passwd_file}" -u -- "$u" >/dev/null 2>&1; }
pw_delete() { local u="$1"; pw_user_exists "$u" && ocpasswd -c "${passwd_file}" -d -- "$u" >/dev/null 2>&1; }
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
Ensure_CRL(){
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
Rebuild_SUSPENDED_PEM(){
    local d base u
    : > "$SUSPENDED_PEM" || return 1
    for d in "$DISABLED_DIR"/*-susp-*; do
        [[ -d "$d" ]] || continue
        base="${d##*/}"
        u="${base%-susp-*}"
        if [[ -f "$d/$u.cer" ]]; then
            cat "$d/$u.cer" >> "$SUSPENDED_PEM" || return 1
        fi
    done
}
# Rebuild CRL from permanent + suspended lists
Rebuild_CRL(){
    local crl_input crl_next server_pid
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
    if [[ -s "$PID_FILE" ]]; then
        server_pid=$(cat "$PID_FILE") || return 1
        [[ "$server_pid" =~ ^[1-9][0-9]*$ ]] || return 1
        kill -HUP "$server_pid" || return 1
    fi
}
# Configure auth to certificate default + plain fallback (OR)
Configure_Auth(){
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
Delete_Cert_User(){
    local u="${1:-}"
    if [[ -z "$u" ]]; then
      echo "Delete which username? (revokes active cert first)"
      read -e -p "(Default canceling): " u
    fi
    [[ -z "$u" ]] && echo "Canceled..." && return 1
    sanitize_username "$u" || { echo -e "${Error} Invalid username"; return 1; }
    Ensure_CRL || return 1
    added=0
    if [[ -f "${USERS_DIR}/${u}/${u}.cer" ]]; then
        cat "${USERS_DIR}/${u}/${u}.cer" >> "${REVOKED_PEM}" || return 1
        rm -rf "${USERS_DIR}/${u}" || return 1
        added=1
    fi
    local d
    for d in "${DISABLED_DIR}/${u}-susp-"*; do
        [[ -f "$d/$u.cer" ]] || continue
        cat "$d/$u.cer" >> "$REVOKED_PEM" || return 1
        rm -rf "$d" || return 1
        added=1
    done
    if [[ $added -eq 1 ]]; then
        Rebuild_SUSPENDED_PEM || return 1
        Rebuild_CRL || return 1
    fi
    Disconnect_User "$u" || return 1
    echo -e "${Info} Deleted ${u} (revocation persists in CRL)."
}
Suspend_Cert_User(){
    local u="${1:-}"
    if [[ -z "$u" ]]; then
      echo "Suspend (temporarily disable) which cert username?"
      read -e -p "(Default canceling): " u
    fi
    [[ -z "$u" ]] && echo "Canceled..." && return 1
    sanitize_username "$u" || { echo -e "${Error} Invalid username"; return 1; }
    user_dir="${USERS_DIR}/${u}"
    [[ ! -f "${user_dir}/${u}.cer" ]] && echo -e "${Error} ${user_dir}/${u}.cer not found" && return 1
    Ensure_CRL || return 1
    ts=$(date +%Y%m%d-%H%M%S)
    mkdir -p "${DISABLED_DIR}" || return 1
    mv "${user_dir}" "${DISABLED_DIR}/${u}-susp-${ts}" || return 1
    Rebuild_SUSPENDED_PEM || return 1
    Rebuild_CRL || return 1
    Disconnect_User "$u" || return 1
    echo -e "${Info} Suspended ${u}."
}
Unsuspend_Cert_User(){
    local u="${1:-}"
    if [[ -z "$u" ]]; then
      echo "Unsuspend (re-enable same certificate) which username?"
      read -e -p "(Default canceling): " u
    fi
    [[ -z "$u" ]] && echo "Canceled..." && return 1
    sanitize_username "$u" || { echo -e "${Error} Invalid username"; return 1; }
    local last_dir
    last_dir=$(Find_Suspended_User "$u") || { echo -e "${Error} No suspended certificate found: $u" >&2; return 1; }
    [[ -z "${last_dir}" ]] && echo -e "${Error} No suspended archive found for ${u}" && return 1
    mv "${last_dir}" "${USERS_DIR}/${u}" || return 1
    Rebuild_SUSPENDED_PEM || return 1
    Rebuild_CRL || return 1
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

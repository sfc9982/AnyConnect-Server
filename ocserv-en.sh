#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="2.0.0"
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
    [[ $EUID != 0 ]] && echo -e "${Error} Current user is not root or don't have root access，can't continue，please switch to root or use command: ${Green_background_prefix}sudo su${Font_color_suffix} to get a temp root privilege(may request user password)." && exit 1
}

# Check system
check_sys(){
    if [[ -f /etc/redhat-release ]]; then
        release="centos"
    elif cat /etc/issue | grep -q -E -i "debian"; then
        release="debian"
    elif cat /etc/issue | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    elif cat /proc/version | grep -q -E -i "debian"; then
        release="debian"
    elif cat /proc/version | grep -q -E -i "ubuntu"; then
        release="ubuntu"
    elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
        release="centos"
    fi
    #bit=`uname -m`
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
    mkdir -p "${build_dir}"
    wget -O "${build_dir}/ocserv-${ocserv_ver}.tar.xz" "https://ftp.infradead.org/pub/ocserv/ocserv-${ocserv_ver}.tar.xz"
    [[ ! -s "${build_dir}/ocserv-${ocserv_ver}.tar.xz" ]] && echo -e "${Error} ocserv source download failed!" && rm -rf "${build_dir}" && exit 1
    tar -xJf "${build_dir}/ocserv-${ocserv_ver}.tar.xz" -C "${build_dir}"
    cd "${build_dir}/ocserv-${ocserv_ver}"
    ./configure
    make
    make install
    cd /
    rm -rf "${build_dir}"
    
    if [[ -e ${file} ]]; then
        mkdir -p "${conf_file}"
        wget -N -P "${conf_file}" "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/ocserv.conf"
        [[ ! -s "${conf}" ]] && echo -e "${Error} ocserv config download failed!" && rm -rf "${conf_file}" && exit 1
    else
        echo -e "${Error} ocserv compiled failed!" && exit 1
    fi
}
Service_ocserv(){
    if ! wget https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ocserv_debian -O /etc/init.d/ocserv; then
        echo -e "${Error} ocserv service management script downloadf failed!" && over
    fi
    chmod +x /etc/init.d/ocserv
    update-rc.d -f ocserv defaults
    echo -e "${Info} ocserv service management script download successfully."
}
rand(){
    min=10000
    max=$((60000-$min+1))
    num=$(date +%s%N)
    echo $(($num%$max+$min))
}
Generate_SSL(){
    lalala=$(rand)
    mkdir /tmp/ssl && cd /tmp/ssl
    echo -e 'cn = "'${lalala}'"
organization = "'${lalala}'"
serial = 1
expiration_days = 365
ca
signing_key
cert_signing_key
crl_signing_key' > ca.tmpl
    [[ $? != 0 ]] && echo -e "${Error} Write SSL cert signature template failed (ca.tmpl) !" && over
    certtool --generate-privkey --outfile ca-key.pem
    [[ $? != 0 ]] && echo -e "${Error} Generate SSL cert private key failed (ca-key.pem) !" && over
    certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem
    [[ $? != 0 ]] && echo -e "${Error} Generate SSL cert file failed (ca-cert.pem) !" && over
    
    Get_ip
    if [[ -z "$ip" ]]; then
        echo -e "${Error} get WAN IP failed !"
        read -e -p "Please manully input your WAN IP:" ip
        [[ -z "${ip}" ]] && echo "取消..." && over
    fi
    echo -e 'cn = "'${ip}'"
organization = "'${lalala}'"
expiration_days = 365
signing_key
encryption_key
tls_www_server' > server.tmpl
    [[ $? != 0 ]] && echo -e "${Error} Write SSL cert signature template failed (server.tmpl) !" && over
    certtool --generate-privkey --outfile server-key.pem
    [[ $? != 0 ]] && echo -e "${Error} Generate SSL cert private key failed (server-key.pem) !" && over
    certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem
    [[ $? != 0 ]] && echo -e "${Error} Generate SSL cert file failed (server-cert.pem) !" && over
    
    mkdir -p /etc/ocserv/ssl
    mv ca-cert.pem /etc/ocserv/ssl/ca-cert.pem
    mv ca-key.pem /etc/ocserv/ssl/ca-key.pem
    mv server-cert.pem /etc/ocserv/ssl/server-cert.pem
    mv server-key.pem /etc/ocserv/ssl/server-key.pem
    chmod 600 /etc/ocserv/ssl/ca-key.pem /etc/ocserv/ssl/server-key.pem
    cd .. && rm -rf /tmp/ssl/
}
Installation_dependency(){
    [[ ! -e "/dev/net/tun" ]] && echo -e "${Error} Your VPS haven't enabled TUN function, please contact your IDC, or use VPS control pannel to manully enable TUN/TAP !" && exit 1
    if [[ ${release} = "centos" ]]; then
        echo -e "${Error} CentOS is not offically supported, but you can edit my script !" && exit 1
    elif [[ ${release} = "debian" ]]; then
        cat /etc/issue |grep 9\..*>/dev/null
        if [[ $? = 0 ]]; then
            apt-get update
            apt-get install vim net-tools pkg-config build-essential ca-certificates iproute2 libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc -y
        else
            mv /etc/apt/sources.list /etc/apt/sources.list.bak
            wget -O "/etc/apt/sources.list" "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/sources/us.sources.list"
            apt-get update
            apt-get install vim net-tools pkg-config build-essential ca-certificates iproute2 libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc -y
            rm -rf /etc/apt/sources.list
            mv /etc/apt/sources.list.bak /etc/apt/sources.list
            apt-get update
        fi
    else
        apt-get update
        apt-get install vim net-tools pkg-config build-essential ca-certificates iproute2 libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc -y
    fi
}
Install_ocserv(){
    check_root
    [[ -e ${file} ]] && echo -e "${Error} ocserv is already installed !" && exit 1
    echo -e "${Info} Start to install/config dependencies..."
    Installation_dependency
    echo -e "${Info} Start to download/install config file..."
    Download_ocserv
    echo -e "${Info} Start to download/install service script(init)..."
    Service_ocserv
    echo -e "${Info} Start to self-sign SSL cert..."
    Generate_SSL
    echo -e "${Info} Enforcing CRL and certificate-default + password-fallback auth..."
    Ensure_CRL
    Configure_Auth
    echo -e "${Info} Start to set account settings..."
    Read_config
    Set_Config
    echo -e "${Info} Start to set iptables firewall ..."
    Set_iptables
    echo -e "${Info} Start to add iptables firewall rules..."
    Add_iptables "${set_tcp_port}" "${set_udp_port}"
    echo -e "${Info} Start to save iptables firewall rules..."
    Save_iptables
    echo -e "${Info} All progress installed completed, now starting..."
    Start_ocserv
}
Start_ocserv(){
    check_installed_status
    check_pid
    [[ ! -z ${PID} ]] && echo -e "${Error} ocserv is running !" && exit 1
    /etc/init.d/ocserv start
    sleep 2s
    check_pid
    [[ ! -z ${PID} ]] && View_Config
}
Stop_ocserv(){
    check_installed_status
    check_pid
    [[ -z ${PID} ]] && echo -e "${Error} ocserv is NOT running !" && exit 1
    /etc/init.d/ocserv stop
}
Restart_ocserv(){
    check_installed_status
    check_pid
    [[ ! -z ${PID} ]] && /etc/init.d/ocserv stop
    /etc/init.d/ocserv start
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
            u="${d%%-susp-*}"; [[ -n "$u" ]] && seen["$u"]=1
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
Add_User(){
    read -rp "Please input the username of VPN account
(Default: admin): " username
    [[ -z "${username}" ]] && username="admin"
    sanitize_username "${username}" || { echo -e "${Error} Invalid username"; return 1; }
    echo && echo -e "   Username : ${username}" && echo
    # No default password anymore: force interactive input to avoid weak default accounts
    userpass=""
    while [[ -z "${userpass}" ]]; do
        read -rsp "Please input the password of VPN account (required, cannot be empty): " userpass
        echo
    done

    mkdir -p "$(dirname "${passwd_file}")"
    printf "%s\n%s\n" "${userpass}" "${userpass}" | ocpasswd -c "${passwd_file}" "${username}" || { echo -e "${Error} Failed to create password account!"; return 1; }
    chmod 600 "${passwd_file}"

    Ensure_CRL
    user_dir="${USERS_DIR}/${username}"
    mkdir -p "${user_dir}"; chmod 700 "${user_dir}"
    certtool --generate-privkey --outfile "${user_dir}/${username}-key.pem" || { echo -e "${Error} Failed to generate user private key!"; return 1; }
    cat > "${user_dir}/${username}.tmpl" <<EOF
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

    chmod 600 "${user_dir}/${username}-key.pem" "${user_dir}/${username}.p12"
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

    # Cert side (revoke + remove files, including suspended)
    Delete_Cert_User "${u}"

    # Password side
    pw_delete "${u}"
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
        Suspend_Cert_User "${u}"
        pw_lock "${u}"
        echo -e "${Info} '${u}' is now Disabled (Certificate: Disable, Password: Disable)."
        return 0
    fi

    last_dir=$(ls -1dt "${DISABLED_DIR}/${u}-susp-"* 2>/dev/null | head -n1 || true)
    if [[ -n "${last_dir}" ]]; then
        echo -e "${Info} Unsuspending certificate and enabling password for '${u}' ..."
        Unsuspend_Cert_User "${u}"
        pw_unlock "${u}"
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
pw_lock()   { local u="$1"; pw_user_exists "$u" && ocpasswd -c "${passwd_file}" -l "$u" >/dev/null 2>&1; }
pw_unlock() { local u="$1"; pw_user_exists "$u" && ocpasswd -c "${passwd_file}" -u "$u" >/dev/null 2>&1; }
pw_delete() { local u="$1"; pw_user_exists "$u" && ocpasswd -c "${passwd_file}" -d "$u" >/dev/null 2>&1; }
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
_cert_enabled(){ [[ -f "${USERS_DIR}/$1/$1.cer" ]]; }
_cert_suspended(){ ls -1 "${DISABLED_DIR}/$1-susp-"* >/dev/null 2>&1; }
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
    [[ ! -e ${log_file} ]] && echo -e "${Error} ocserv log doesn't exist !" && exit 1
    echo && echo -e "${Tip} Press ${Red_font_prefix}Ctrl+C${Font_color_suffix} Stop View log" && echo -e "If you want to View all log, please use ${Red_font_prefix}cat ${log_file}${Font_color_suffix} command。" && echo
    tail -f ${log_file}
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
        update-rc.d -f ocserv remove
        rm -rf /etc/init.d/ocserv
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
    update-rc.d -f ocserv remove
    rm -rf /etc/init.d/ocserv
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
    grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf || echo -e "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p
    # Prefer the default route to detect the egress NIC (eth0/ens3/enpXsX/venet0 all covered)
    Network_card=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')
    if [[ -z "${Network_card}" ]]; then
        echo -e "${Tip} Failed to detect NIC via default route, please input manually:"
        ip -o addr 2>/dev/null || ifconfig
        read -e -p "NIC name (e.g. eth0 / ens3 / enpXsX / venet0):" Network_card
        [[ -z "${Network_card}" ]] && echo "Canceled..." && exit 1
    fi
    iptables -t nat -C POSTROUTING -o ${Network_card} -j MASQUERADE 2>/dev/null || \
        iptables -t nat -A POSTROUTING -o ${Network_card} -j MASQUERADE
    
    iptables-save > /etc/iptables.up.rules
    echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
    chmod +x /etc/network/if-pre-up.d/iptables
}
# Ensure CRL files exist and minimal template
Ensure_CRL(){
    mkdir -p "${SSL_DIR}" "${USERS_DIR}" "${DISABLED_DIR}"
    [[ ! -f "${CRL_TMPL}" ]] && echo -e "crl_next_update = 365\ncrl_number = 1" > "${CRL_TMPL}"
    touch "${REVOKED_PEM}" "${SUSPENDED_PEM}"
    if [[ ! -f "${CRL_PEM}" ]]; then
        certtool --generate-crl \
            --load-ca-privkey "${CA_KEY}" \
            --load-ca-certificate "${CA_CERT}" \
            --template "${CRL_TMPL}" \
            --outfile "${CRL_PEM}" >/dev/null 2>&1
    fi
}
# Rebuild suspended list from disabled/*-susp-* directories
Rebuild_SUSPENDED_PEM(){
    : > "${SUSPENDED_PEM}"
    if [[ -d "${DISABLED_DIR}" ]]; then
        shopt -s nullglob
        for d in "${DISABLED_DIR}"/*-susp-*; do
            base="$(basename "$d")"
            u="${base%%-susp-*}"
            if [[ -f "${d}/${u}.cer" ]]; then
                cat "${d}/${u}.cer" >> "${SUSPENDED_PEM}"
            fi
        done
        shopt -u nullglob
    fi
}
# Rebuild CRL from permanent + suspended lists
Rebuild_CRL(){
    tmp="${SSL_DIR}/.crl-input.tmp"
    : > "${tmp}"
    [[ -s "${REVOKED_PEM}" ]] && cat "${REVOKED_PEM}" >> "${tmp}"
    [[ -s "${SUSPENDED_PEM}" ]] && cat "${SUSPENDED_PEM}" >> "${tmp}"
    if [[ -s "${tmp}" ]]; then
        certtool --generate-crl \
          --load-ca-privkey "${CA_KEY}" \
          --load-ca-certificate "${CA_CERT}" \
          --template "${CRL_TMPL}" \
          --load-certificate "${tmp}" \
          --outfile "${CRL_PEM}"
    else
        certtool --generate-crl \
          --load-ca-privkey "${CA_KEY}" \
          --load-ca-certificate "${CA_CERT}" \
          --template "${CRL_TMPL}" \
          --outfile "${CRL_PEM}"
    fi
    rm -f "${tmp}"
    [[ -e ${PID_FILE} ]] && kill -HUP $(cat ${PID_FILE}) 2>/dev/null
}
# Configure auth to certificate default + plain fallback (OR)
Configure_Auth(){
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv config file doesn't exist !" && exit 1
    # Delete every script-managed entry first, then append once (config is order-independent)
    sed -i '/^\s*ca-cert\s*=/d; /^\s*crl\s*=/d; /^\s*cert-user-oid\s*=/d; /^\s*auth\s*=/d; /^\s*enable-auth\s*=/' "${conf}"
    cat >> "${conf}" <<EOF

# === Managed by AnyConnect-Server: certificate default + password fallback ===
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
    Ensure_CRL
    added=0
    if [[ -f "${USERS_DIR}/${u}/${u}.cer" ]]; then
        cat "${USERS_DIR}/${u}/${u}.cer" >> "${REVOKED_PEM}"
        rm -rf "${USERS_DIR}/${u}"
        added=1
    fi
    shopt -s nullglob
    for d in "${DISABLED_DIR}/${u}-susp-"*; do
        [[ -f "${d}/${u}.cer" ]] && cat "${d}/${u}.cer" >> "${REVOKED_PEM}" && rm -rf "${d}" && added=1
    done
    shopt -u nullglob
    if [[ $added -eq 1 ]]; then
        Rebuild_SUSPENDED_PEM
        Rebuild_CRL
    fi
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
    Ensure_CRL
    ts=$(date +%Y%m%d-%H%M%S)
    mkdir -p "${DISABLED_DIR}"
    mv "${user_dir}" "${DISABLED_DIR}/${u}-susp-${ts}"
    Rebuild_SUSPENDED_PEM
    Rebuild_CRL
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
    last_dir=$(ls -1dt "${DISABLED_DIR}/${u}-susp-"* 2>/dev/null | head -n1 || true)
    [[ -z "${last_dir}" ]] && echo -e "${Error} No suspended archive found for ${u}" && return 1
    mv "${last_dir}" "${USERS_DIR}/${u}"
    Rebuild_SUSPENDED_PEM
    Rebuild_CRL
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
check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && echo -e "${Error} OS is not supported ${release} !" && exit 1
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

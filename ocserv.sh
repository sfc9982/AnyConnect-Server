#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

sh_ver="2.1.0"
file="/usr/local/sbin/ocserv"
conf_file="/etc/ocserv"
conf="/etc/ocserv/ocserv.conf"
passwd_file="/etc/ocserv/ocpasswd"
log_file="/tmp/ocserv.log"
ocserv_ver="1.5.0"
PID_FILE="/var/run/ocserv.pid"

# === PKI/CRL 文件与目录（新增，匹配 ocserv-en.sh）===
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
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

check_root(){
    if [[ $EUID != 0 ]]; then
        echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" >&2
        return 1
    fi
}
#检查系统
check_sys(){
	# 识别发行版与包管理器：优先 /etc/os-release，旧系统回退传统检测
	# release: debian/ubuntu/rhel/rocky/almalinux/fedora/arch/opensuse...  pm: 对应包管理器
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
	[[ ! -e ${file} ]] && echo -e "${Error} ocserv 没有安装，请检查 !" && exit 1
	[[ ! -e ${conf} ]] && echo -e "${Error} ocserv 配置文件不存在，请检查 !" && [[ $1 != "un" ]] && exit 1
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
	wget -O "${build_dir}/ocserv-${ocserv_ver}.tar.xz" "https://www.infradead.org/ocserv/download/ocserv-${ocserv_ver}.tar.xz" || return 1
	[[ ! -s "${build_dir}/ocserv-${ocserv_ver}.tar.xz" ]] && echo -e "${Error} ocserv 源码文件下载失败 !" && rm -rf "${build_dir}" && exit 1
	tar -xJf "${build_dir}/ocserv-${ocserv_ver}.tar.xz" -C "${build_dir}" || return 1
	cd "${build_dir}/ocserv-${ocserv_ver}" || return 1
	meson setup build --prefix=/usr/local --sysconfdir=/etc -Dfirewall-script=iptables || return 1
	ninja -C build || return 1
	ninja -C build install || return 1
	cd / || return 1
	rm -rf "${build_dir}"
	
	if [[ -e ${file} ]]; then
		mkdir -p "${conf_file}" || return 1
		wget -N -P "${conf_file}" "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/ocserv.conf" || return 1
		[[ ! -s "${conf}" ]] && echo -e "${Error} ocserv 配置文件下载失败 !" && rm -rf "${conf_file}" && exit 1
	else
		echo -e "${Error} ocserv 编译安装失败，请检查！" && exit 1
	fi
	return 0
}
# 是否使用 systemd 管理服务（主流发行版默认具备）
have_systemd(){
	command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]
}
Service_ocserv(){
	# 内联 systemd 单元文件，替代原先下载第三方 init.d 脚本（消除外部供应链依赖）
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
		echo -e "${Info} ocserv systemd 服务单元已安装并设置开机启动 !"
	else
		# 无 systemd 的极简环境(Docker/OpenVZ等)：退化为直接守护进程，由 start/stop 函数管理
		echo -e "${Tip} 未检测到 systemd，将以守护进程方式直接管理 ocserv（无开机自启）。"
	fi
}
Firewall_Service_ocserv(){
	# 开机恢复 iptables 规则的 systemd 单元（替代 Debian 专属的 if-pre-up.d 钩子，跨发行版通用）
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
        read -rp "请输入服务器 IP 地址或主机名：" server_identity || return 1
    fi
    if [[ "$server_identity" =~ ^[0-9]+(\.[0-9]+){3}$ ||
        "$server_identity" =~ ^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]+$ ]]; then
        san_key="ip_address"
    elif [[ "$server_identity" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
        san_key="dns_name"
    else
        echo -e "${Error} 服务器 IP 地址或主机名不合法" >&2
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
	[[ ! -e "/dev/net/tun" ]] && echo -e "${Error} 你的VPS没有开启TUN，请联系IDC或通过VPS控制面板打开TUN/TAP开关 !" && exit 1
	case "${pm}" in
		apt-get)
			export DEBIAN_FRONTEND=noninteractive
			apt-get update || return 1
			apt-get install -y tar xz-utils meson ninja-build protobuf-c-compiler vim net-tools pkg-config build-essential ca-certificates wget iproute2 procps iptables openssl libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc
			;;
		dnf)
			# RHEL 及其衍生版(CentOS/Rocky/Alma/OpenEuler等)经 EPEL 获取部分依赖
			if [[ "${release}" != "fedora" ]]; then
			    dnf install -y epel-release || return 1
			fi
			local distro_version="${VERSION_ID:-}"
			case "${release}:${distro_version%%.*}" in
			    rocky:9|almalinux:9)
			        # libev-devel 位于 CRB；安装 epel-release 不会自动启用它。
			        dnf install -y dnf-plugins-core || return 1
			        dnf config-manager --set-enabled crb || return 1
			        ;;
			esac
			dnf install -y tar xz meson ninja-build protobuf-c-compiler vim net-tools pkgconf-pkg-config gcc make ca-certificates wget iproute procps-ng iptables openssl gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel lz4-devel gnutls-utils ipcalc
			;;
		yum)
			yum install -y epel-release >/dev/null 2>&1
			yum install -y tar xz meson ninja-build protobuf-c-compiler vim net-tools pkgconfig gcc make ca-certificates wget iproute procps-ng iptables openssl gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel lz4-devel gnutls-utils ipcalc
			;;
		pacman)
			pacman -Syu --noconfirm tar xz meson ninja protobuf-c base-devel vim net-tools gnutls libseccomp libev libnl readline ca-certificates wget iproute2 procps-ng iptables openssl lz4 ipcalc
			;;
		zypper)
			zypper -n install tar xz meson ninja libprotobuf-c-devel gnutls gcc make vim net-tools pkg-config gnutls-devel libseccomp-devel libev-devel libnl3-devel readline-devel liblz4-devel ca-certificates wget iproute2 procps iptables openssl ipcalc
			;;
		*)
			echo -e "${Error} 未识别的包管理器，无法安装依赖 !" && exit 1 ;;
	esac
}

# === 新增：CRL/证书认证 相关函数（与 ocserv-en.sh 对齐） ===
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
Configure_Auth(){
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv 配置文件不存在 !" && return 1
    # 先删除所有由脚本管理的条目，再统一追加（ocserv 配置与行序无关，取代原来的 sed 行首插入）
    sed -i '/^\s*ca-cert\s*=/d; /^\s*crl\s*=/d; /^\s*cert-user-oid\s*=/d; /^\s*auth\s*=/d; /^\s*enable-auth\s*=/d' "${conf}" || return 1
    cat >> "${conf}" <<EOF || return 1
ca-cert = ${CA_CERT}
crl = ${CRL_PEM}
cert-user-oid = 2.5.4.3
auth = "certificate"
enable-auth = "plain[passwd=${passwd_file}]"
EOF
    echo -e "${Info} 已启用 证书默认 + 密码备用 认证模式"
}

Install_ocserv(){
	check_root || return 1
	[[ -e ${file} ]] && echo -e "${Error} ocserv 已安装，请检查 !" && exit 1
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency || return 1
	echo -e "${Info} 开始下载/安装 配置文件..."
	Download_ocserv || return 1
	echo -e "${Info} 开始安装 systemd 服务单元..."
	Service_ocserv || return 1
	echo -e "${Info} 开始自签SSL证书..."
	Generate_SSL || return 1
	# 新增：安装后立刻启用 CRL + 证书优先+密码备用
	echo -e "${Info} 启用 CRL 并设置 证书优先 + 密码备用..."
	Ensure_CRL || return 1
	Configure_Auth || return 1
	echo -e "${Info} 开始设置账号配置..."
	Read_config || return 1
	Set_Config || return 1
	echo -e "${Info} 开始设置 iptables防火墙..."
	Set_iptables || return 1
	echo -e "${Info} 开始添加 iptables防火墙规则..."
	Add_iptables "${set_tcp_port}" "${set_udp_port}" || return 1
	echo -e "${Info} 开始保存 iptables防火墙规则..."
	Save_iptables || return 1
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	Start_ocserv
}
Start_ocserv(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ocserv 正在运行，请检查 !" && exit 1
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
	[[ -z ${PID} ]] && echo -e "${Error} ocserv 没有运行，请检查 !" && exit 1
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
	[[ ! -e ${conf} ]] && echo -e "${Error} ocserv 配置文件不存在 !" && exit 1
	tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
	udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
	vim ${conf}
	set_tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
	set_udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
	Del_iptables "${tcp_port}" "${udp_port}"
	Add_iptables "${set_tcp_port}" "${set_udp_port}"
	Save_iptables
	echo "是否重启 ocserv ? (Y/n)"
	read -e -p "(默认: Y):" yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_ocserv
	fi
}
# 账号交互已统一收敛到 Add_User()（证书 + 密码一次性创建），此处移除历史遗留的 Set_username/Set_passwd
Set_tcp_port(){
	while true
	do
	echo -e "请输入VPN服务端的TCP端口"
	read -e -p "(默认: 443):" set_tcp_port
	[[ -z "$set_tcp_port" ]] && set_tcp_port="443"
	echo $((${set_tcp_port}+0)) &>/dev/null
	if [[ $? -eq 0 ]]; then
		if [[ ${set_tcp_port} -ge 1 ]] && [[ ${set_tcp_port} -le 65535 ]]; then
			echo && echo -e "	TCP端口 : ${Red_font_prefix}${set_tcp_port}${Font_color_suffix}" && echo
			break
		else
			echo -e "${Error} 请输入正确的数字！"
		fi
	else
		echo -e "${Error} 请输入正确的数字！"
	fi
	done
}
Set_udp_port(){
	while true
	do
	echo -e "请输入VPN服务端的UDP端口"
	read -e -p "(默认: ${set_tcp_port}):" set_udp_port
	[[ -z "$set_udp_port" ]] && set_udp_port="${set_tcp_port}"
	echo $((${set_udp_port}+0)) &>/dev/null
	if [[ $? -eq 0 ]]; then
		if [[ ${set_udp_port} -ge 1 ]] && [[ ${set_udp_port} -le 65535 ]]; then
			echo && echo -e "	TCP端口 : ${Red_font_prefix}${set_udp_port}${Font_color_suffix}" && echo
			break
		else
			echo -e "${Error} 请输入正确的数字！"
		fi
	else
		echo -e "${Error} 请输入正确的数字！"
	fi
	done
}
# 安装流程里，首次账号：用统一新增（证书+密码）
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
	# 安全改写 ocserv.conf 单个键值：存在则原位替换，不存在则追加。
	# 通过 awk -v 传参，杜绝 sed 表达式字符串拼接（旧写法在值含特殊字符时会破坏配置）
	local key="$1" val="$2" tmp="${conf}.tmp"
	awk -v key="${key}" -v val="${val}" '
		BEGIN { found = 0 }
		$0 ~ "^" key " = " { print key " = " val; found = 1; next }
		{ print }
		END { if (!found) print key " = " val }
	' "${conf}" > "${tmp}" && cat "${tmp}" > "${conf}" && rm -f "${tmp}"
}
Set_Config(){
	# 兼容性保留：可直接调用新增用户（会创建证书+密码）
	Add_User || return 1
	Set_tcp_port
	Set_udp_port
	Set_Conf_Value "tcp-port" "${set_tcp_port}"
	Set_Conf_Value "udp-port" "${set_udp_port}"
}
Read_config(){
	[[ ! -e ${conf} ]] && echo -e "${Error} ocserv 配置文件不存在 !" && exit 1
	conf_text=$(cat ${conf}|grep -v '#')
	tcp_port=$(echo -e "${conf_text}"|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
	udp_port=$(echo -e "${conf_text}"|grep "udp-port ="|awk -F ' = ' '{print $NF}')
	max_same_clients=$(echo -e "${conf_text}"|grep "max-same-clients ="|awk -F ' = ' '{print $NF}')
	max_clients=$(echo -e "${conf_text}"|grep "max-clients ="|awk -F ' = ' '{print $NF}')
}

# === 统一用户管理：状态/增/删/启用禁用（证书+密码） ===

# --- 安全与账户助手函数 ---
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
            [[ "$st" == "!" ]] && echo "禁用" || echo "启用"
            return
        fi
    fi
    echo "禁用"
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

List_User(){
	# 合并 ocpasswd + 证书目录 + disabled 归档 的用户集合
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
	if [[ ${#seen[@]} -eq 0 ]]; then echo -e "${Tip} 暂无用户。"; return; fi
	for u in $(printf "%s\n" "${!seen[@]}" | sort); do
		pw=$(_pw_status "$u")
		if _cert_enabled "$u"; then cert="启用"
		elif _cert_suspended "$u"; then cert="禁用"
		else cert="禁用"; fi
		[[ "$pw" == "启用" || "$cert" == "启用" ]] && acc="启用" || acc="禁用"
		echo "用户名: ${u} 账号状态: ${acc} 证书: ${cert} 密码: ${pw}"
	done
}

Disconnect_User(){
    local u="$1" server_pid socket output active commands action="disconnect" sessions
    [[ -s "$PID_FILE" ]] || return 0
    server_pid=$(cat "$PID_FILE") || return 1
    [[ "$server_pid" =~ ^[1-9][0-9]*$ ]] || return 1
    kill -0 "$server_pid" 2>/dev/null || return 0
    socket=$(Get_Conf_Value occtl-socket-file) || return 1
    local args=(--no-pager)
    [[ -z "$socket" ]] || args+=(--socket-file "$socket")
    commands=$(occtl "${args[@]}" help) || return 1
    if grep -qE '^[[:space:]]*terminate user[[:space:]]' <<< "$commands"; then
        action="terminate"
    else
        echo -e "${Tip} 当前 ocserv 只能断开连接；请升级到 1.4.2 或更高版本以同时作废会话 cookie。" >&2
    fi
    # occtl does not support a standalone --; it treats it as help and returns success.
    if output=$(occtl "${args[@]}" "$action" user "$u" 2>&1); then
        return 0
    fi
    # No active or resumable session is a successful no-op; control errors remain failures.
    active=$(occtl "${args[@]}" show users) || { printf '%s\n' "$output" >&2; return 1; }
    if [[ "$action" == "terminate" ]]; then
        sessions=$(occtl "${args[@]}" show sessions valid) || { printf '%s\n' "$output" >&2; return 1; }
        active+=$'\n'"$sessions"
    fi
    if awk -v u="$u" '$1 != "id" && $1 != "session" && $2 == u { found = 1 } END { exit !found }' <<< "$active"; then
        printf '%s\n' "$output" >&2
        return 1
    fi
    return 0
}
Add_User(){
	# 统一新增：创建 证书 + 密码（同名/同密码）
	read -rp "请输入 要添加的VPN账号 用户名
(默认: admin): " username
	[[ -z "${username}" ]] && username="admin"
	sanitize_username "${username}" || { echo -e "${Error} 用户名不合法"; return 1; }
    if pw_user_exists "$username" || [[ -e "$USERS_DIR/$username" ]] ||
        Find_Suspended_User "$username" >/dev/null; then
        echo -e "${Error} 用户已存在；请先删除旧用户，再创建替换证书" >&2
        return 1
    fi
	echo && echo -e "   用户名 : ${username}" && echo
	# 移除默认口令，强制交互输入，避免 admin/doub.io 这类默认弱账户
	userpass=""
	while [[ -z "${userpass}" ]]; do
		read -rsp "请输入 要添加的VPN账号 密码(不可为空): " userpass || return 1
		echo
	done

	# 密码账户
	mkdir -p "$(dirname "${passwd_file}")" || return 1
	printf "%s\n%s\n" "${userpass}" "${userpass}" | ocpasswd -c "${passwd_file}" -- "${username}" || { echo -e "${Error} 密码账户创建失败 !"; return 1; }
	chmod 600 "${passwd_file}" || return 1

	# 证书账户
	Ensure_CRL || return 1
	user_dir="${USERS_DIR}/${username}"
	mkdir -p "${user_dir}" && chmod 700 "${user_dir}" || return 1
	certtool --generate-privkey --outfile "${user_dir}/${username}-key.pem" || { echo -e "${Error} 生成用户私钥失败 !"; return 1; }
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
	  --outfile "${user_dir}/${username}.cer" || { echo -e "${Error} 生成用户证书失败 !"; return 1; }

	openssl pkcs12 -export \
	  -inkey "${user_dir}/${username}-key.pem" \
	  -in "${user_dir}/${username}.cer" \
	  -certfile "${CA_CERT}" \
	  -name "AnyConnect VPN – ${username}" \
	  -out "${user_dir}/${username}.p12" \
	  -passout pass:"${userpass}" || { echo -e "${Error} 导出 p12 证书包失败 !"; return 1; }

	chmod 600 "${user_dir}/${username}-key.pem" "${user_dir}/${username}.p12" || return 1
	echo -e "${Info} 已创建用户 '${username}' 的 证书 + 密码。"
	echo "  ${user_dir}/${username}.p12   (导入到设备；密码为刚才输入的账号密码)"
	echo "  ${CA_CERT} (若提示，请信任/安装根证书)"
}

# 证书侧：删除（永久吊销）
Delete_Cert_User(){
    local u="${1:-}"
    if [[ -z "$u" ]]; then
      echo "删除哪个证书用户？（会先吊销）"
      read -e -p "(默认取消): " u
    fi
    [[ -z "$u" ]] && echo "已取消..." && return 1
    sanitize_username "$u" || { echo -e "${Error} 用户名不合法"; return 1; }
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
    echo -e "${Info} 已删除 ${u}（吊销记录已写入CRL）。"
}

# 证书侧：临时禁用/恢复（可复用同一证书）
Suspend_Cert_User(){
    local u="${1:-}"
    if [[ -z "$u" ]]; then
      echo "临时禁用哪个证书用户？"
      read -e -p "(默认取消): " u
    fi
    [[ -z "$u" ]] && echo "已取消..." && return 1
    sanitize_username "$u" || { echo -e "${Error} 用户名不合法"; return 1; }
    user_dir="${USERS_DIR}/${u}"
    [[ ! -f "${user_dir}/${u}.cer" ]] && echo -e "${Error} 未找到证书：${user_dir}/${u}.cer" && return 1
    Ensure_CRL || return 1
    ts=$(date +%Y%m%d-%H%M%S)
    mkdir -p "${DISABLED_DIR}" || return 1
    mv "${user_dir}" "${DISABLED_DIR}/${u}-susp-${ts}" || return 1
    Rebuild_SUSPENDED_PEM || return 1
    Rebuild_CRL || return 1
    Disconnect_User "$u" || return 1
    echo -e "${Info} 已临时禁用 ${u}。"
}
Unsuspend_Cert_User(){
    local u="${1:-}"
    if [[ -z "$u" ]]; then
      echo "恢复哪个证书用户？（恢复后同一证书可继续使用）"
      read -e -p "(默认取消): " u
    fi
    [[ -z "$u" ]] && echo "已取消..." && return 1
    sanitize_username "$u" || { echo -e "${Error} 用户名不合法"; return 1; }
    local last_dir
    last_dir=$(Find_Suspended_User "$u") || { echo -e "${Error} 未找到临时禁用的证书：$u" >&2; return 1; }
    [[ -z "${last_dir}" ]] && echo -e "${Error} 未找到 ${u} 的临时禁用归档" && return 1
    mv "${last_dir}" "${USERS_DIR}/${u}" || return 1
    Rebuild_SUSPENDED_PEM || return 1
    Rebuild_CRL || return 1
    echo -e "${Info} 已恢复 ${u}。"
}

Del_User(){
	List_User
	echo "请输入要删除的VPN账号的用户名"
	read -e -p "(默认取消):" Del_username
	[[ -z "${Del_username}" ]] && echo "已取消..." && return 1

	sanitize_username "${Del_username}" || { echo -e "${Error} 用户名不合法"; return 1; }

	# 先移除密码登录能力，再吊销证书并断开会话
	pw_delete "${Del_username}" || return 1

	# 吊销有效和临时禁用的证书
	Delete_Cert_User "${Del_username}" || return 1
	echo -e "${Info} 已删除用户 '${Del_username}'（证书已吊销/清理；密码账户已删除）。"
}

Modify_User_disabled(){
	List_User
	echo -e "请输入要 启用/禁用 的VPN账号用户名（证书 + 密码 联动）"
	read -e -p "(默认取消):" Modify_username
	[[ -z "${Modify_username}" ]] && echo "已取消..." && return 1

	sanitize_username "${Modify_username}" || { echo -e "${Error} 用户名不合法"; return 1; }

	# 如果证书启用 -> 临时禁用证书 + 禁用密码
	if [[ -f "${USERS_DIR}/${Modify_username}/${Modify_username}.cer" ]]; then
		echo -e "${Info} 正在临时禁用证书并禁用密码：'${Modify_username}' ..."
		pw_lock "${Modify_username}" || return 1
		Suspend_Cert_User "${Modify_username}" || return 1
		echo -e "${Info} '${Modify_username}' 已禁用（证书：禁用，密码：禁用）。"
		return 0
	fi

	# 如果证书处于临时禁用 -> 恢复证书 + 启用密码
	last_dir=$(Find_Suspended_User "${Modify_username}" || true)
	if [[ -n "${last_dir}" ]]; then
		echo -e "${Info} 正在恢复证书并启用密码：'${Modify_username}' ..."
		Unsuspend_Cert_User "${Modify_username}" || return 1
		pw_unlock "${Modify_username}" || return 1
		echo -e "${Info} '${Modify_username}' 已启用（证书：启用，密码：启用）。"
		return 0
	fi

	echo -e "${Tip} 未找到该用户证书，请先添加用户。"
}

Set_Pass(){
	check_installed_status
	echo && echo -e " 你要做什么？
	
 ${Green_font_prefix} 0.${Font_color_suffix} 列出 账号配置
————————
 ${Green_font_prefix} 1.${Font_color_suffix} 添加 账号配置
 ${Green_font_prefix} 2.${Font_color_suffix} 删除 账号配置
————————
 ${Green_font_prefix} 3.${Font_color_suffix} 启用/禁用 账号配置
 
 注意：添加/修改/删除 账号配置后，VPN服务端会实时读取，无需重启服务端 !" && echo
	read -e -p "(默认: 取消):" set_num
	[[ -z "${set_num}" ]] && echo "已取消..." && exit 1
	if [[ ${set_num} == "0" ]]; then
		List_User
	elif [[ ${set_num} == "1" ]]; then
		Add_User
	elif [[ ${set_num} == "2" ]]; then
		Del_User
	elif [[ ${set_num} == "3" ]]; then
		Modify_User_disabled
	else
		echo -e "${Error} 请输入正确的数字[0-3]" && exit 1
	fi
}

View_Config(){
	Get_ip
	Read_config
	clear && echo "===================================================" && echo
	echo -e " AnyConnect 配置信息：" && echo
	echo -e " I  P\t\t  : ${Green_font_prefix}${ip}${Font_color_suffix}"
	echo -e " TCP端口\t  : ${Green_font_prefix}${tcp_port}${Font_color_suffix}"
	echo -e " UDP端口\t  : ${Green_font_prefix}${udp_port}${Font_color_suffix}"
	echo -e " 单用户设备数限制 : ${Green_font_prefix}${max_same_clients}${Font_color_suffix}"
	echo -e " 总用户设备数限制 : ${Green_font_prefix}${max_clients}${Font_color_suffix}"
	echo -e "\n 客户端链接请填写 : ${Green_font_prefix}${ip}:${tcp_port}${Font_color_suffix}"
	echo && echo "==================================================="
}
View_Log(){
	if have_systemd; then
		echo && echo -e "${Tip} 按 ${Red_font_prefix}Ctrl+C${Font_color_suffix} 终止查看日志" && echo
		journalctl -u ocserv -f --no-pager
	else
		[[ ! -e ${log_file} ]] && echo -e "${Error} ocserv 日志文件不存在 !" && exit 1
		echo && echo -e "${Tip} 按 ${Red_font_prefix}Ctrl+C${Font_color_suffix} 终止查看日志" && echo -e "如果需要查看完整日志内容，请用 ${Red_font_prefix}cat ${log_file}${Font_color_suffix} 命令。" && echo
		tail -f ${log_file}
	fi
}
Uninstall_ocserv(){
	check_installed_status "un"
	echo "确定要卸载 ocserv ? (y/N)"
	echo
	read -e -p "(默认: n):" unyn
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
		echo && echo "ocserv 卸载完成 !" && echo
	else
		echo && echo "卸载已取消..." && echo
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
	echo && echo "安装过程错误，ocserv 卸载完成 !" && echo
}
Add_iptables(){
	# 端口以参数传入，避免跨函数依赖全局变量；插入前做存在性检查，防止重复规则
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
        echo -e "${Error} 配置中缺少 VPN IPv4 网段、掩码或设备名称" >&2
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
        read -rp "出口网卡名称（如 eth0）：" Network_card || return 1
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

Update_Shell(){
	# 自更新只从本项目仓库拉取同名脚本，避免误覆盖为上游版本而丢失证书/CRL 功能
	local self_name; self_name="$(basename "$0")"
	sh_new_ver=$(wget -qO- -t1 -T5 "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/${self_name}"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1)
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 无法链接到 Github !" && exit 0
	if [[ "${sh_new_ver}" == "${sh_ver}" ]]; then
		echo -e "${Info} 当前已是最新版本[ ${sh_ver} ] !" && exit 0
	fi
	wget -O "${self_name}.new" "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/${self_name}" && chmod +x "${self_name}.new"
	bash -n "${self_name}.new" || { echo -e "${Error} 下载的新版本未通过语法检查，已放弃更新 !"; rm -f "${self_name}.new"; exit 1; }
	mv -f "${self_name}.new" "${self_name}"
	echo -e "${Info} 脚本已更新为最新版本[ ${sh_new_ver} ]，请重新运行 !" && exit 0
}

# Sourcing loads production helpers without entering the interactive menu.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

check_sys
[[ -z "${pm}" ]] && echo -e "${Error} 不支持当前系统(未识别的发行版或包管理器)！支持 Debian/Ubuntu、RHEL 系(CentOS/Rocky/Alma/Fedora等)、Arch、openSUSE。" && exit 1
echo && echo -e " ocserv 一键安装管理脚本 ${Red_font_prefix}[v${sh_ver}]${Font_color_suffix}
  -- Toyo | doub.io/vpnzy-7 --
  
 ${Green_font_prefix}0.${Font_color_suffix} 升级脚本
————————————
 ${Green_font_prefix}1.${Font_color_suffix} 安装 ocserv
 ${Green_font_prefix}2.${Font_color_suffix} 卸载 ocserv
————————————
 ${Green_font_prefix}3.${Font_color_suffix} 启动 ocserv
 ${Green_font_prefix}4.${Font_color_suffix} 停止 ocserv
 ${Green_font_prefix}5.${Font_color_suffix} 重启 ocserv
————————————
 ${Green_font_prefix}6.${Font_color_suffix} 设置 账号配置
 ${Green_font_prefix}7.${Font_color_suffix} 查看 配置信息
 ${Green_font_prefix}8.${Font_color_suffix} 修改 配置文件
 ${Green_font_prefix}9.${Font_color_suffix} 查看 日志信息
————————————" && echo
if [[ -e ${file} ]]; then
	check_pid
	if [[ ! -z "${PID}" ]]; then
		echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} 并 ${Green_font_prefix}已启动${Font_color_suffix}"
	else
		echo -e " 当前状态: ${Green_font_prefix}已安装${Font_color_suffix} 但 ${Red_font_prefix}未启动${Font_color_suffix}"
	fi
else
	echo -e " 当前状态: ${Red_font_prefix}未安装${Font_color_suffix}"
fi
echo
read -e -p " 请输入数字 [0-9]:" num
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
	echo "请输入正确数字 [0-9]"
	;;
esac

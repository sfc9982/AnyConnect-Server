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
	[[ $EUID != 0 ]] && echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_background_prefix}sudo su${Font_color_suffix} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。" && exit 1
}
#检查系统
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
	mkdir "ocserv" && cd "ocserv"
	wget "ftp://ftp.infradead.org/pub/ocserv/ocserv-${ocserv_ver}.tar.xz"
	[[ ! -s "ocserv-${ocserv_ver}.tar.xz" ]] && echo -e "${Error} ocserv 源码文件下载失败 !" && rm -rf "ocserv/" && rm -rf "ocserv-${ocserv_ver}.tar.xz" && exit 1
	tar -xJf ocserv-${ocserv_ver}.tar.xz && cd ocserv-${ocserv_ver}
	./configure
	make
	make install
	cd .. && cd ..
	rm -rf ocserv/
	
	if [[ -e ${file} ]]; then
		mkdir "${conf_file}"
		wget --no-check-certificate -N -P "${conf_file}" "https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/ocserv.conf"
		[[ ! -s "${conf}" ]] && echo -e "${Error} ocserv 配置文件下载失败 !" && rm -rf "${conf_file}" && exit 1
	else
		echo -e "${Error} ocserv 编译安装失败，请检查！" && exit 1
	fi
}
Service_ocserv(){
	if ! wget --no-check-certificate https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/service/ocserv_debian -O /etc/init.d/ocserv; then
		echo -e "${Error} ocserv 服务 管理脚本下载失败 !" && over
	fi
	chmod +x /etc/init.d/ocserv
	update-rc.d -f ocserv defaults
	echo -e "${Info} ocserv 服务 管理脚本下载完成 !"
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
	[[ $? != 0 ]] && echo -e "${Error} 写入SSL证书签名模板失败(ca.tmpl) !" && over
	certtool --generate-privkey --outfile ca-key.pem
	[[ $? != 0 ]] && echo -e "${Error} 生成SSL证书密匙文件失败(ca-key.pem) !" && over
	certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem
	[[ $? != 0 ]] && echo -e "${Error} 生成SSL证书文件失败(ca-cert.pem) !" && over
	
	Get_ip
	if [[ -z "$ip" ]]; then
		echo -e "${Error} 检测外网IP失败 !"
		read -e -p "请手动输入你的服务器外网IP:" ip
		[[ -z "${ip}" ]] && echo "取消..." && over
	fi
	echo -e 'cn = "'${ip}'"
organization = "'${lalala}'"
expiration_days = 365
signing_key
encryption_key
tls_www_server' > server.tmpl
	[[ $? != 0 ]] && echo -e "${Error} 写入SSL证书签名模板失败(server.tmpl) !" && over
	certtool --generate-privkey --outfile server-key.pem
	[[ $? != 0 ]] && echo -e "${Error} 生成SSL证书密匙文件失败(server-key.pem) !" && over
	certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem
	[[ $? != 0 ]] && echo -e "${Error} 生成SSL证书文件失败(server-cert.pem) !" && over
	
	mkdir -p /etc/ocserv/ssl
	mv ca-cert.pem /etc/ocserv/ssl/ca-cert.pem
	mv ca-key.pem /etc/ocserv/ssl/ca-key.pem
	mv server-cert.pem /etc/ocserv/ssl/server-cert.pem
	mv server-key.pem /etc/ocserv/ssl/server-key.pem
	cd .. && rm -rf /tmp/ssl/
}
Installation_dependency(){
	[[ ! -e "/dev/net/tun" ]] && echo -e "${Error} 你的VPS没有开启TUN，请联系IDC或通过VPS控制面板打开TUN/TAP开关 !" && exit 1
	if [[ ${release} = "centos" ]]; then
		echo -e "${Error} 本脚本不支持 CentOS 系统 !" && exit 1
	elif [[ ${release} = "debian" ]]; then
		cat /etc/issue |grep 9\..*>/dev/null
		if [[ $? = 0 ]]; then
			apt-get update
			apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc ipcalc-ng -y
		else
			mv /etc/apt/sources.list /etc/apt/sources.list.bak
			wget --no-check-certificate -O "/etc/apt/sources.list" "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/sources/us.sources.list"
			apt-get update
			apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc ipcalc-ng -y
			rm -rf /etc/apt/sources.list
			mv /etc/apt/sources.list.bak /etc/apt/sources.list
			apt-get update
		fi
	else
		apt-get update
		apt-get install vim net-tools pkg-config build-essential libgnutls28-dev libwrap0-dev liblz4-dev libseccomp-dev libreadline-dev libnl-nf-3-dev libev-dev gnutls-bin ipcalc ipcalc-ng -y
	fi
}

# === 新增：CRL/证书认证 相关函数（与 ocserv-en.sh 对齐） ===
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
Configure_Auth(){
    [[ ! -e ${conf} ]] && echo -e "${Error} ocserv 配置文件不存在 !" && exit 1
    # 确保 CA/CRL 路径
    if grep -qE '^\s*ca-cert\s*=' "${conf}"; then
        sed -i "s|^\s*ca-cert\s*=.*|ca-cert = ${CA_CERT}|" "${conf}"
    else
        sed -i "1ica-cert = ${CA_CERT}" "${conf}"
    fi
    if grep -qE '^\s*crl\s*=' "${conf}"; then
        sed -i "s|^\s*crl\s*=.*|crl = ${CRL_PEM}|" "${conf}"
    else
        sed -i "1icrl = ${CRL_PEM}" "${conf}"
    fi
    # 用户名从证书 CN 提取
    grep -qE '^\s*cert-user-oid\s*=' "${conf}" || sed -i "1icert-user-oid = 2.5.4.3" "${conf}"
    # 证书优先 + 密码备用（避免重复项）
    sed -i '/^\s*auth\s*= /d' "${conf}"
    sed -i '/^\s*enable-auth\s*= /d' "${conf}"
    sed -i '1iauth = "certificate"' "${conf}"
    sed -i '1ienable-auth = "plain[passwd=/etc/ocserv/ocpasswd]"' "${conf}"
    echo -e "${Info} 已启用 证书默认 + 密码备用 认证模式"
}

Install_ocserv(){
	check_root
	[[ -e ${file} ]] && echo -e "${Error} ocserv 已安装，请检查 !" && exit 1
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency
	echo -e "${Info} 开始下载/安装 配置文件..."
	Download_ocserv
	echo -e "${Info} 开始下载/安装 服务脚本(init)..."
	Service_ocserv
	echo -e "${Info} 开始自签SSL证书..."
	Generate_SSL
	# 新增：安装后立刻启用 CRL + 证书优先+密码备用
	echo -e "${Info} 启用 CRL 并设置 证书优先 + 密码备用..."
	Ensure_CRL
	Configure_Auth
	echo -e "${Info} 开始设置账号配置..."
	Read_config
	Set_Config
	echo -e "${Info} 开始设置 iptables防火墙..."
	Set_iptables
	echo -e "${Info} 开始添加 iptables防火墙规则..."
	Add_iptables
	echo -e "${Info} 开始保存 iptables防火墙规则..."
	Save_iptables
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	Start_ocserv
}
Start_ocserv(){
	check_installed_status
	check_pid
	[[ ! -z ${PID} ]] && echo -e "${Error} ocserv 正在运行，请检查 !" && exit 1
	/etc/init.d/ocserv start
	sleep 2s
	check_pid
	[[ ! -z ${PID} ]] && View_Config
}
Stop_ocserv(){
	check_installed_status
	check_pid
	[[ -z ${PID} ]] && echo -e "${Error} ocserv 没有运行，请检查 !" && exit 1
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
	[[ ! -e ${conf} ]] && echo -e "${Error} ocserv 配置文件不存在 !" && exit 1
	tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
	udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
	vim ${conf}
	set_tcp_port=$(cat ${conf}|grep "tcp-port ="|awk -F ' = ' '{print $NF}')
	set_udp_port=$(cat ${conf}|grep "udp-port ="|awk -F ' = ' '{print $NF}')
	Del_iptables
	Add_iptables
	Save_iptables
	echo "是否重启 ocserv ? (Y/n)"
	read -e -p "(默认: Y):" yn
	[[ -z ${yn} ]] && yn="y"
	if [[ ${yn} == [Yy] ]]; then
		Restart_ocserv
	fi
}
Set_username(){
	echo "请输入 要添加的VPN账号 用户名"
	read -e -p "(默认: admin):" username
	[[ -z "${username}" ]] && username="admin"
	echo && echo -e "	用户名 : ${Red_font_prefix}${username}${Font_color_suffix}" && echo
}
Set_passwd(){
	echo "请输入 要添加的VPN账号 密码"
	read -e -p "(默认: doub.io):" userpass
	[[ -z "${userpass}" ]] && userpass="password"
	echo && echo -e "	密码 : ${Red_font_prefix}${userpass}${Font_color_suffix}" && echo
}
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
Set_Config(){
	# 兼容性保留：可直接调用新增用户（会创建证书+密码）
	Add_User
	Set_tcp_port
	Set_udp_port
	sed -i 's/tcp-port = '"$(echo ${tcp_port})"'/tcp-port = '"$(echo ${set_tcp_port})"'/g' ${conf}
	sed -i 's/udp-port = '"$(echo ${udp_port})"'/udp-port = '"$(echo ${set_udp_port})"'/g' ${conf}
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
_cert_enabled(){ [[ -f "${USERS_DIR}/$1/$1.cer" ]]; }
_cert_suspended(){ ls -1 "${DISABLED_DIR}/$1-susp-"* >/dev/null 2>&1; }

List_User(){
	# 合并 ocpasswd + 证书目录 + disabled 归档 的用户集合
	declare -A seen
	if [[ -f "${passwd_file}" ]]; then
		while IFS='' read -r line; do
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

Add_User(){
	# 统一新增：创建 证书 + 密码（同名/同密码）
	read -rp "请输入 要添加的VPN账号 用户名
(默认: admin): " username
	[[ -z "${username}" ]] && username="admin"
	echo && echo -e "   用户名 : ${username}" && echo
	read -rsp "请输入 要添加的VPN账号 密码
(默认: doub.io): " userpass
	echo
	[[ -z "${userpass}" ]] && userpass="doub.io"

	# 密码账户
	mkdir -p "$(dirname "${passwd_file}")"
	printf "%s\n%s\n" "${userpass}" "${userpass}" | ocpasswd -c "${passwd_file}" "${username}"

	# 证书账户
	Ensure_CRL
	user_dir="${USERS_DIR}/${username}"
	mkdir -p "${user_dir}"; chmod 700 "${user_dir}"
	certtool --generate-privkey --outfile "${user_dir}/${username}-key.pem"
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
	  --outfile "${user_dir}/${username}.cer"

	openssl pkcs12 -export \
	  -inkey "${user_dir}/${username}-key.pem" \
	  -in "${user_dir}/${username}.cer" \
	  -certfile "${CA_CERT}" \
	  -name "AnyConnect VPN – ${username}" \
	  -out "${user_dir}/${username}.p12" \
	  -passout pass:"${userpass}"

	chmod 600 "${user_dir}/${username}-key.pem" "${user_dir}/${username}.p12"
	echo -e "${Info} 已创建用户 '${username}' 的 证书 + 密码。"
	echo "  ${user_dir}/${username}.p12   (导入到设备；密码: ${userpass})"
	echo "  ${CA_CERT} (若提示，请信任/安装根证书)"
}

# 证书侧：删除（永久吊销）
Delete_Cert_User(){
    echo "删除哪个证书用户？（会先吊销）"
    read -e -p "(默认取消): " u
    [[ -z "${u}" ]] && echo "已取消..." && exit 1
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
    echo -e "${Info} 已删除 ${u}（吊销记录已写入CRL）。"
}

# 证书侧：临时禁用/恢复（可复用同一证书）
Suspend_Cert_User(){
    echo "临时禁用哪个证书用户？"
    read -e -p "(默认取消): " u
    [[ -z "${u}" ]] && echo "已取消..." && return 1
    user_dir="${USERS_DIR}/${u}"
    [[ ! -f "${user_dir}/${u}.cer" ]] && echo -e "${Error} 未找到证书：${user_dir}/${u}.cer" && return 1
    Ensure_CRL
    ts=$(date +%Y%m%d-%H%M%S)
    mkdir -p "${DISABLED_DIR}"
    mv "${user_dir}" "${DISABLED_DIR}/${u}-susp-${ts}"
    Rebuild_SUSPENDED_PEM
    Rebuild_CRL
    echo -e "${Info} 已临时禁用 ${u}。"
}
Unsuspend_Cert_User(){
    echo "恢复哪个证书用户？（恢复后同一证书可继续使用）"
    read -e -p "(默认取消): " u
    [[ -z "${u}" ]] && echo "已取消..." && return 1
    last_dir=$(ls -1dt "${DISABLED_DIR}/${u}-susp-"* 2>/dev/null | head -n1 || true)
    [[ -z "${last_dir}" ]] && echo -e "${Error} 未找到 ${u} 的临时禁用归档" && return 1
    mv "${last_dir}" "${USERS_DIR}/${u}"
    Rebuild_SUSPENDED_PEM
    Rebuild_CRL
    echo -e "${Info} 已恢复 ${u}。"
}

Del_User(){
	List_User
	echo "请输入要删除的VPN账号的用户名"
	read -e -p "(默认取消):" Del_username
	[[ -z "${Del_username}" ]] && echo "已取消..." && return 1

	# 证书侧（吊销+删除，含 suspended 归档）
	Delete_Cert_User <<EOF
${Del_username}
EOF

	# 密码侧
	if grep -q "^${Del_username}:*:" "${passwd_file}" 2>/dev/null; then
	  ocpasswd -c "${passwd_file}" -d "${Del_username}" || true
	fi
	echo -e "${Info} 已删除用户 '${Del_username}'（证书已吊销/清理；密码账户已删除）。"
}

Modify_User_disabled(){
	List_User
	echo -e "请输入要 启用/禁用 的VPN账号用户名（证书 + 密码 联动）"
	read -e -p "(默认取消):" Modify_username
	[[ -z "${Modify_username}" ]] && echo "已取消..." && return 1

	# 如果证书启用 -> 临时禁用证书 + 禁用密码
	if [[ -f "${USERS_DIR}/${Modify_username}/${Modify_username}.cer" ]]; then
		echo -e "${Info} 正在临时禁用证书并禁用密码：'${Modify_username}' ..."
		Suspend_Cert_User <<EOF
${Modify_username}
EOF
		if grep -q "^${Modify_username}:*:" "${passwd_file}" 2>/dev/null; then
		  ocpasswd -c "${passwd_file}" -l "${Modify_username}" || true
		fi
		echo -e "${Info} '${Modify_username}' 已禁用（证书：禁用，密码：禁用）。"
		return 0
	fi

	# 如果证书处于临时禁用 -> 恢复证书 + 启用密码
	last_dir=$(ls -1dt "${DISABLED_DIR}/${Modify_username}-susp-"* 2>/dev/null | head -n1 || true)
	if [[ -n "${last_dir}" ]]; then
		echo -e "${Info} 正在恢复证书并启用密码：'${Modify_username}' ..."
		Unsuspend_Cert_User <<EOF
${Modify_username}
EOF
		if grep -q "^${Modify_username}:*:" "${passwd_file}" 2>/dev/null; then
		  ocpasswd -c "${passwd_file}" -u "${Modify_username}" || true
		fi
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
		echo -e "${Error} 请输入正确的数字[1-3]" && exit 1
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
	[[ ! -e ${log_file} ]] && echo -e "${Error} ocserv 日志文件不存在 !" && exit 1
	echo && echo -e "${Tip} 按 ${Red_font_prefix}Ctrl+C${Font_color_suffix} 终止查看日志" && echo -e "如果需要查看完整日志内容，请用 ${Red_font_prefix}cat ${log_file}${Font_color_suffix} 命令。" && echo
	tail -f ${log_file}
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
		Del_iptables
		Save_iptables
		update-rc.d -f ocserv remove
		rm -rf /etc/init.d/ocserv
		rm -rf "${conf_file}"
		rm -rf "${log_file}"
		cd '/usr/local/bin' && rm -f occtl
		rm -f ocpasswd
		cd '/usr/local/bin' && rm -f ocserv-fw
		cd '/usr/local/sbin' && rm -f ocserv
		cd '/usr/local/share/man/man8' && rm -f ocserv.8
		rm -f ocpasswd.8
		rm -f occtl.8
		echo && echo "ocserv 卸载完成 !" && echo
	else
		echo && echo "卸载已取消..." && echo
	fi
}
over(){
	update-rc.d -f ocserv remove
	rm -rf /etc/init.d/ocserv
	rm -rf "${conf_file}"
	rm -rf "${log_file}"
	cd '/usr/local/bin' && rm -f occtl
	rm -f ocpasswd
	cd '/usr/local/bin' && rm -f ocserv-fw
	cd '/usr/local/sbin' && rm -f ocserv
	cd '/usr/local/share/man/man8' && rm -f ocserv.8
	rm -f ocpasswd.8
	rm -f occtl.8
	echo && echo "安装过程错误，ocserv 卸载完成 !" && echo
}
Add_iptables(){
	iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${set_tcp_port} -j ACCEPT
	iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${set_udp_port} -j ACCEPT
}
Del_iptables(){
	iptables -D INPUT -m state --state NEW -m tcp -p tcp --dport ${tcp_port} -j ACCEPT
	iptables -D INPUT -m state --state NEW -m udp -p udp --dport ${udp_port} -j ACCEPT
}
Save_iptables(){
	iptables-save > /etc/iptables.up.rules
}
Set_iptables(){
	echo -e "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
	sysctl -p
	ifconfig_status=$(ifconfig)
	if [[ -z ${ifconfig_status} ]]; then
		echo -e "${Error} ifconfig 未安装 !"
		read -e -p "请手动输入你的网卡名(一般情况下，网卡名为 eth0，Debian9 则为 ens3，CentOS Ubuntu 最新版本可能为 enpXsX(X代表数字或字母)，OpenVZ 虚拟化则为 venet0):" Network_card
		[[ -z "${Network_card}" ]] && echo "取消..." && exit 1
	else
		Network_card=$(ifconfig|grep "eth0")
		if [[ ! -z ${Network_card} ]]; then
			Network_card="eth0"
		else
			Network_card=$(ifconfig|grep "ens3")
			if [[ ! -z ${Network_card} ]]; then
				Network_card="ens3"
			else
				Network_card=$(ifconfig|grep "venet0")
				if [[ ! -z ${Network_card} ]]; then
					Network_card="venet0"
				else
					ifconfig
					read -e -p "检测到本服务器的网卡非 eth0 \ ens3(Debian9) \ venet0(OpenVZ) \ enpXsX(CentOS Ubuntu 最新版本，X代表数字或字母)，请根据上面输出的网卡信息手动输入你的网卡名:" Network_card
					[[ -z "${Network_card}" ]] && echo "取消..." && exit 1
				fi
			fi
		fi
	fi
	iptables -t nat -A POSTROUTING -o ${Network_card} -j MASQUERADE
	
	iptables-save > /etc/iptables.up.rules
	echo -e '#!/bin/bash\n/sbin/iptables-restore < /etc/iptables.up.rules' > /etc/network/if-pre-up.d/iptables
	chmod +x /etc/network/if-pre-up.d/iptables
}

Update_Shell(){
	sh_new_ver=$(wget --no-check-certificate -qO- -t1 -T3 "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ocserv.sh"|grep 'sh_ver="'|awk -F "=" '{print $NF}'|sed 's/\"//g'|head -1) && sh_new_type="github"
	[[ -z ${sh_new_ver} ]] && echo -e "${Error} 无法链接到 Github !" && exit 0
	if [[ -e "/etc/init.d/ocserv" ]]; then
		rm -rf /etc/init.d/ocserv
		Service_ocserv
	fi
	wget -N --no-check-certificate "https://raw.githubusercontent.com/ToyoDAdoubiBackup/doubi/master/ocserv.sh" && chmod +x ocserv.sh
	echo -e "脚本已更新为最新版本[ ${sh_new_ver} ] !(注意：因为更新方式为直接覆盖当前运行的脚本，所以可能下面会提示一些报错，无视即可)" && exit 0
}

check_sys
[[ ${release} != "debian" ]] && [[ ${release} != "ubuntu" ]] && echo -e "${Error} 本脚本不支持当前系统 ${release} !" && exit 1
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
set 限制解除 

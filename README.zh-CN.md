<div align="center">

<a href="https://github.com/sfc9982/AnyConnect-Server"><img src="https://img.shields.io/badge/SELF--HOSTED-SSL%20VPN-0F766E?style=for-the-badge&logo=linux&logoColor=white" alt="Self-hosted SSL VPN"></a>

<h1>AnyConnect-Server</h1>

<p><strong>在 Linux 上快速部署可控、可维护、可验证的 SSL VPN 服务。</strong></p>
<p>基于 <a href="https://www.infradead.org/ocserv/">ocserv</a> · 兼容 AnyConnect 协议 · TLS / DTLS · 证书与密码账号</p>

<p>
<a href="https://github.com/sfc9982/AnyConnect-Server/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-334155?style=flat-square" alt="MIT License"></a>
<img src="https://img.shields.io/badge/ocserv-1.5.0-2563EB?style=flat-square" alt="ocserv 1.5.0">
<img src="https://img.shields.io/badge/Installer-Bash-0F766E?style=flat-square&logo=gnubash&logoColor=white" alt="Bash installer">
<img src="https://img.shields.io/badge/IPv6-Opt--in-7C3AED?style=flat-square" alt="IPv6 opt-in">
</p>

<p><a href="#快速开始"><strong>快速开始</strong></a> · <a href="#ci-状态">CI 状态</a> · <a href="#支持的系统">支持的系统</a> · <a href="#安全说明">安全说明</a> · <a href="README.md">English</a></p>

</div>

> [!NOTE]
> 本项目使用开源 ocserv 实现 AnyConnect 协议，与 Cisco 官方不存在隶属或背书关系。CI 使用 OpenConnect 客户端验证；不同版本的 Cisco 客户端可能存在兼容性差异。

## 核心特性

<table>
<tr>
<td width="50%" valign="top"><strong>一键部署</strong><p>识别 Linux 发行版、编译 ocserv、配置证书、防火墙与服务。</p></td>
<td width="50%" valign="top"><strong>账号全生命周期</strong><p>为用户签发独立 .p12 证书，支持禁用、恢复和永久吊销。</p></td>
</tr>
<tr>
<td width="50%" valign="top"><strong>TLS + DTLS</strong><p>加密隧道、默认分流以及可选的 IPv6 路由转发。</p></td>
<td width="50%" valign="top"><strong>真实集成测试</strong><p>发行版矩阵、IPv6 边界测试、持续压测和 systemd 虚拟机重启。</p></td>
</tr>
</table>

## 运行要求

| 项目 | 要求 |
|---|---|
| 服务器 | 一台有独立公网 IP 的 VPS（KVM / Xen 等全虚拟化架构） |
| 系统 | 见下方支持列表，使用 systemd（主流发行版默认具备） |
| 虚拟网卡 | 已开启 TUN/TAP（安装时脚本会自动检测，未开启会给出提示） |
| 权限 | 能以 root 身份执行命令（或拥有 sudo 权限的账号） |
| 域名 | 可选。直接使用 IP 即可连接；有域名体验更好（证书可绑定域名） |

## 支持的系统

| 发行版 | 版本 | 包管理器 |
|---|---|---|
| Debian | 11 / 12 | apt |
| Ubuntu | 20.04 / 22.04 / 24.04 | apt |
| RHEL / CentOS / Rocky / AlmaLinux / OpenEuler 等 | 8 / 9 及以后 | dnf / yum（依赖 EPEL） |
| Fedora | 38+ | dnf |
| Arch Linux / Manjaro | rolling | pacman |
| openSUSE Leap | 15 | zypper |

说明：没有 systemd 的环境可能无法开机自启。CI 实际覆盖 Ubuntu 22.04/24.04、Debian 11/12、Fedora 40、Rocky 9、AlmaLinux 9、Arch Linux 和 openSUSE Leap；表内其他版本并非全部经过测试。

## 快速开始

在自己管理且支持 TUN/TAP 的 VPS 上执行。首次编译耗时取决于 CPU 性能和网络。

```bash
# 1. SSH 登录服务器，切换为 root
sudo su

# 2. 下载并运行脚本
wget -N https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/ocserv.sh
chmod +x ocserv.sh
bash ocserv.sh
```

首次运行输入 `1` 开始安装。安装过程中脚本会依次询问几件事：

| 询问项 | 说明 | 建议 |
|---|---|---|
| VPN 账号用户名 | 第一个管理员账号，默认 admin | 改成一个只有你知道的名称 |
| VPN 账号密码 | 必填，输入时不显示 | 设置强密码；该密码同时是证书包（.p12）的导出密码 |
| TCP 端口 | 默认 443 | 保持 443，最不易被阻断 |
| UDP 端口 | 默认与 TCP 相同 | 保持默认；UDP 通道影响语音 / 视频流畅度 |

安装结束后脚本会打印服务器信息，客户端里填写的地址形如 `123.45.67.89:443`。

> [!TIP]
> 在以 root 执行前，建议先查看下载的脚本。确保 VPS 安全组和主机防火墙均放通 VPN 端口的 TCP 与 UDP。

<!-- ci-status:start -->

## CI 状态

实时显示 `main` 分支最近一次 `push` 触发的检查结果。点击状态徽章可查看对应工作流的运行记录。

<table>
  <tr>
    <td width="50%" align="center">
      <p><strong>代码质量</strong><br><sub>ShellCheck · Bash / Python 语法</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/lint.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/lint.yml/badge.svg?branch=main&amp;event=push" alt="代码质量 · main · push">
      </a>
    </td>
    <td width="50%" align="center">
      <p><strong>安装器回归</strong><br><sub>故障恢复 · 受测源码快照</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-source.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-source.yml/badge.svg?branch=main&amp;event=push" alt="安装器回归 · main · push">
      </a>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <p><strong>发行版 smoke 测试</strong><br><sub>9 个 Linux 发行版 · 中英文脚本</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/distro-test.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/distro-test.yml/badge.svg?branch=main&amp;event=push" alt="发行版 smoke 测试 · main · push">
      </a>
    </td>
    <td width="50%" align="center">
      <p><strong>真实 VPN 端到端测试</strong><br><sub>TLS / DTLS · DNS / NAT · 账号生命周期</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-e2e.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-e2e.yml/badge.svg?branch=main&amp;event=push" alt="真实 VPN 端到端测试 · main · push">
      </a>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <p><strong>原生 IPv6 与开机启动</strong><br><sub>IPv6 路由转发 · Ubuntu 22.04 虚拟机重启</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-native.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-native.yml/badge.svg?branch=main&amp;event=push" alt="原生 IPv6 与开机启动 · main · push">
      </a>
    </td>
    <td width="50%" align="center">
      <p><strong>扩展 VPN 验证</strong><br><sub>双栈传输 · 边界 ACL · Ubuntu 24.04 重启</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-production.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-production.yml/badge.svg?branch=main&amp;event=push" alt="扩展 VPN 验证 · main · push">
      </a>
    </td>
  </tr>
</table>

<details>
<summary>定时压测与手动验证（展开）</summary>

<table>
  <tr>
    <td width="50%" align="center">
      <p><strong>定时持续压测</strong><br><sub>20 个客户端 · 常规 30 分钟，周日 2 小时</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-production.yml?query=branch%3Amain+event%3Aschedule">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-production.yml/badge.svg?branch=main&amp;event=schedule" alt="定时持续压测 · main · schedule">
      </a>
    </td>
    <td width="50%" align="center">
      <p><strong>真实 VPS 外部验证</strong><br><sub>手动授权 · 自有可销毁测试端点</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-vps.yml?query=branch%3Amain+event%3Aworkflow_dispatch">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-vps.yml/badge.svg?branch=main&amp;event=workflow_dispatch" alt="真实 VPS 外部验证 · main · workflow_dispatch">
      </a>
    </td>
  </tr>
</table>

这里单独展示定时任务和手动任务的状态。常规 CI 通过不代表长时压测或 VPS 验证已经执行；没有匹配记录或任务被跳过均不等于通过，实际范围与时长以任务结果和测试产物为准。

</details>

[全部工作流](https://github.com/sfc9982/AnyConnect-Server/actions?query=branch%3Amain) · [基础测试覆盖](tests/README.md) · [扩展测试与边界](tests/EXTENDED-TESTS.md)<!-- ci-status:end -->

## 工作原理

~~~mermaid
flowchart LR
    A["VPN 客户端"] --> B{"客户端路由策略"}
    B -->|"进入 VPN"| C["TLS / DTLS"]
    B -->|"排除地址"| D["本地直连"]
    C --> E["ocserv"]
    E --> F["IPv4 NAT / routed IPv6"]
    F --> G["目标网络"]
~~~

分流决策发生在客户端：被排除的地址继续走本地网络。IPv6 需显式启用，并配置 VPN 前缀和上游回程路由；安装脚本不会自动执行 NAT66。

## 安装过程做了什么

按顺序执行，必要步骤失败时停止安装：

1. 检测系统与 TUN/TAP
2. 安装编译依赖（gnutls、libev、seccomp、libnl 等）及 iptables、openssl
3. 从官方网站下载 ocserv 1.5.0 源码，通过 Meson 和 Ninja 编译安装
4. 生成自签名 CA 与服务器证书（服务器证书绑定你的 IP）
5. 生成证书吊销列表（CRL），启用「证书优先 + 密码兜底」认证
6. 创建第一个账号（证书 + 密码同时生成）
7. 开启内核转发与 iptables NAT，放行服务端口，写入开机恢复规则
8. 启动服务并自检，打印连接信息

## 客户端连接

服务端为每个用户生成一个 `.p12` 证书包，位于 `/etc/ocserv/ssl/users/<用户名>/<用户名>.p12`，需要先把它下载到要连接的设备上。

### 第一步：导入证书包

导入时需要输入密码，即该用户的 VPN 密码。

- **Windows**：双击 `.p12` 文件 → 存储位置选择「当前用户」→ 输入密码 → 按向导完成。
- **macOS**：双击导入「登录」钥匙串，在「钥匙串访问」中确认该证书存在。
- **Android**：将文件放到手机存储 → 设置 → 安全 → 加密与凭据 → 从存储设备安装（部分机型在「更多安全设置」内）→ 输入密码。
- **iOS / iPadOS**：将文件发送到设备（AirDrop / 文件 App / 邮件均可）→ 点击文件 → 设置 → 通用 → VPN 与设备管理 → 安装描述文件。如还需信任私有服务器 CA，请另行导入核验过的 CA 证书；iOS 的根 CA 信任设置不适用于客户端 `.p12`。

### 第二步：连接

1. 打开 AnyConnect，地址栏填写 `服务器IP:端口`（例如 `123.45.67.89:443`；有域名则填域名）
2. 如果服务器证书不受信任，请通过可信渠道核对 `/etc/ocserv/ssl/ca-cert.pem` 并在客户端信任该 CA，不要直接忽略未知警告
3. 当客户端要求选择证书时，选择你的用户名对应的证书
4. 输入账号密码，连接
5. 状态显示「已连接」即表示成功

### 连接后的行为

- 国内网站与 App 直连（走本地网络，不经 VPN）
- 其余流量经 VPN 到服务器后访问互联网
- 如需改为全局走 VPN：编辑 `/etc/ocserv/ocserv.conf`，删除所有 `no-route` 行，然后重启服务

## 日常管理

再次执行 `bash ocserv.sh` 进入管理菜单：

| 选项 | 功能 |
|---|---|
| 0 | 从本仓库升级脚本（通过语法校验后才覆盖） |
| 1 / 2 | 安装 / 卸载 |
| 3 / 4 / 5 | 启动 / 停止 / 重启 |
| 6 | 账号管理：0 列表、1 添加、2 删除、3 启用 / 禁用 |
| 7 | 查看服务器地址、端口等信息 |
| 8 | 编辑配置文件（vim），端口变更后防火墙自动同步 |
| 9 | 查看实时日志 |

账号管理的几个关键点：

- **添加用户**：证书与密码一次性生成。把生成的 `.p12` 文件通过安全渠道发给使用者
- **删除用户**：证书写入 CRL 永久吊销并删除本地文件，密码账户同步删除，该设备上已导入的证书立即失效
- **禁用 / 启用**：证书进入临时封存状态，可随时恢复；恢复后同一份证书继续有效，用户无需重新导入
- 以上操作均实时生效，不需要重启 VPN 服务

## 文件与命令速查

| 内容 | 位置 / 命令 |
|---|---|
| 主配置 | `/etc/ocserv/ocserv.conf` |
| CA 证书 / 私钥 | `/etc/ocserv/ssl/ca-cert.pem` / `ca-key.pem`（私钥切勿外传） |
| 用户证书包 | `/etc/ocserv/ssl/users/<用户名>/<用户名>.p12` |
| 密码文件 | `/etc/ocserv/ocpasswd` |
| 吊销列表 | `/etc/ocserv/ssl/crl.pem` |
| 服务控制 | `systemctl start \| stop \| restart \| status ocserv` |
| 日志 | `journalctl -u ocserv -f` |
| 防火墙规则 | `/etc/iptables.up.rules`（开机由 ocserv-firewall.service 恢复） |

## 升级与卸载

- **升级脚本**：菜单 0。仅从本仓库拉取同名脚本，且通过语法检查才会覆盖
- **升级 ocserv 版本**：先执行卸载（菜单 2），再重新安装（菜单 1）。建议先备份 `/etc/ocserv` 目录
- **卸载**：菜单 2。会停止服务、移除 systemd 单元、清理防火墙规则与配置文件，不影响系统其他组件

## 安全说明

> [!IMPORTANT]
> **先核实服务器证书，再建立信任。** 安装脚本默认生成私有 CA。请通过可信渠道获取 `ca-cert.pem`，核对服务器身份；遇到未知证书警告不要直接忽略。

- 保护 `ca-key.pem` 私钥，不要将凭据、`.p12` 证书包或会话 Cookie 上传到公开日志。
- 通过可信渠道分发用户证书，发现泄露及时吊销。
- VPN 提供加密传输而非匿名；默认分流中的排除流量走本地网络。
- 定期更新系统、设置强密码、限制管理入口并核查云防火墙规则。

## 常见问题

<details>
<summary><strong>Q：安装时提示没有 TUN/TAP？</strong></summary>

A：脚本未检测到 `/dev/net/tun`。请在 VPS 控制面板确认已开启 TUN/TAP；OpenVZ 架构需联系服务商开启，若不支持则需更换 KVM / Xen 架构的 VPS。

</details>

<details>
<summary><strong>Q：客户端连上了，但打不开网页？</strong></summary>

A：多数是 VPS 提供商的「安全组 / 防火墙」未放行端口。请到提供商控制台放行 TCP 与 UDP 的 443（或你自定义的端口）。

</details>

<details>
<summary><strong>Q：提示「证书不受信任 / 无法验证服务器」？</strong></summary>

A：先通过可信渠道核对并导入服务器的 `ca-cert.pem`，确认服务器身份与地址匹配，不要关闭证书校验。

</details>

<details>
<summary><strong>Q：客户端提示没有可用证书？</strong></summary>

A：确认 `.p12` 已正确导入并可供 VPN 应用使用；iOS 的根 CA 信任设置与客户端证书导入是两回事。

</details>

<details>
<summary><strong>Q：手机频繁断线，或视频卡顿？</strong></summary>

A：确认 UDP 端口已放行（DTLS 数据走 UDP）。部分网络对 UDP 限速时，可在客户端设置中切换为仅使用 TCP。

</details>

<details>
<summary><strong>Q：更换服务器或 IP 后怎么办？</strong></summary>

A：服务器证书绑定 IP，需要在新服务器上重新安装，并重新分发证书包。

</details>

<details>
<summary><strong>Q：忘记账号密码？</strong></summary>

A：菜单 6 → 删除该用户 → 重新添加。旧证书会同时被吊销。

</details>

<details>
<summary><strong>Q：想更换端口？</strong></summary>

A：菜单 8 编辑配置文件，修改 `tcp-port` / `udp-port`，防火墙规则会自动同步，随后重启服务。

</details>

<details>
<summary><strong>Q：如何完整备份？</strong></summary>

A：备份整个 `/etc/ocserv` 目录即可（含配置、证书与账号）。

</details>

<details>
<summary><strong>Q：如何升级 ocserv 本身？</strong></summary>

A：本菜单的「升级脚本」只更新管理脚本。升级 ocserv 需先卸载再重装，卸载前请备份 `/etc/ocserv`。

</details>

## 测试与验证

GitHub Actions 除静态检查外还运行真实 VPN 端到端测试。上面的徽章代表工作流结果，不代表所有生产环境均已验证。

| 测试项目 | 验证范围 |
|---|---|
| Distro smoke | 9 个 Linux 发行版，中英文安装脚本 |
| VPN E2E | 真实连接、账号生命周期、DNS / NAT |
| IPv6 / Edge ACL | IPv6 路由、转发及模拟云防火墙 |
| systemd / Reboot | QEMU 开机与服务恢复 |
| Soak | TLS / DTLS 并发会话与流量完整性 |

独立网络环境检查 IPv4 NAT、IPv6 路由、DNS、TLS/DTLS、转发失败及并发会话。QEMU 虚拟机验证服务启停与系统重启；持续压测记录真实并发数和传输数据。**模拟的边界 ACL 不能保证真实云厂商安全组行为。** VPS 探测为手动授权，仅面向自有可销毁测试实例。

[基础测试](tests/README.md) · [扩展测试文档](tests/EXTENDED-TESTS.md)

## 致谢与许可

- 服务端基于 GNU ocserv，密码管理基于其自带的 ocpasswd
- 脚本框架继承自 ToyoDAdoubi 的一键脚本传统，向其工作致谢
- 多用户可视化管理可参考社区项目：<https://github.com/mmtaee/ocserv-users-management>
- 本项目以 MIT 许可发布，Copyright (c) 2023 sfc9982

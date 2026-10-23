<div align="center">

<a href="https://github.com/sfc9982/AnyConnect-Server"><img src="https://img.shields.io/badge/SELF--HOSTED-SSL%20VPN-0F766E?style=for-the-badge&logo=linux&logoColor=white" alt="Self-hosted SSL VPN"></a>

<h1>AnyConnect-Server</h1>

<p><strong>Deploy and manage your own SSL VPN on Linux.</strong></p>
<p>Powered by <a href="https://www.infradead.org/ocserv/">ocserv</a> · AnyConnect-compatible protocol · TLS / DTLS · Certificate + password</p>

<p>
<a href="https://github.com/sfc9982/AnyConnect-Server/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-334155?style=flat-square" alt="MIT License"></a>
<img src="https://img.shields.io/badge/ocserv-1.5.0-2563EB?style=flat-square" alt="ocserv 1.5.0">
<img src="https://img.shields.io/badge/Installer-Bash-0F766E?style=flat-square&logo=gnubash&logoColor=white" alt="Bash installer">
<img src="https://img.shields.io/badge/IPv6-Opt--in-7C3AED?style=flat-square" alt="IPv6 opt-in">
</p>

<p><a href="#quick-start"><strong>Quick start</strong></a> · <a href="#ci-status">CI status</a> · <a href="#supported-systems">Supported systems</a> · <a href="#security-notes">Security notes</a> · <a href="README.zh-CN.md">简体中文</a> · <a href="README.fa-IR.md" lang="fa" dir="rtl">فارسی</a></p>

</div>

> [!NOTE]
> This project uses open-source ocserv, not Cisco's proprietary server. It is not affiliated with or endorsed by Cisco. CI tests OpenConnect clients; behavior of specific Cisco client versions may differ.

## Highlights

<table>
<tr>
<td width="50%" valign="top"><strong>One-command setup</strong><p>Detect Linux, build ocserv, configure certificates, firewall and service.</p></td>
<td width="50%" valign="top"><strong>Account lifecycle</strong><p>Issue per-user .p12 certificates; suspend, restore or revoke access.</p></td>
</tr>
<tr>
<td width="50%" valign="top"><strong>TLS + DTLS</strong><p>Encrypted tunneling with optional IPv6 routing and default split routes.</p></td>
<td width="50%" valign="top"><strong>Real integration tests</strong><p>Linux distro matrix, IPv6 edge tests, soak tests and systemd VM reboot checks.</p></td>
</tr>
</table>

## Requirements

| Item | Requirement |
|---|---|
| Server | A VPS with a dedicated public IP (KVM / Xen or other full virtualization) |
| OS | See the supported list below; systemd-based (default on mainstream distros) |
| Virtual NIC | TUN/TAP enabled (checked automatically during install) |
| Privileges | Able to run commands as root (or an account with sudo) |
| Domain name | Optional. A plain IP works; a domain name makes certificates and daily use nicer |

## Supported systems

| Distro | Versions | Package manager |
|---|---|---|
| Debian | 11 / 12 | apt |
| Ubuntu | 20.04 / 22.04 / 24.04 | apt |
| RHEL / CentOS / Rocky / AlmaLinux / OpenEuler etc. | 8 / 9 and later | dnf / yum (EPEL) |
| Fedora | 38+ | dnf |
| Arch Linux / Manjaro | rolling | pacman |
| openSUSE Leap | 15 | zypper |

Note: systems without systemd may lack boot autostart. CI explicitly covers Ubuntu 22.04/24.04, Debian 11/12, Fedora 40, Rocky 9, AlmaLinux 9, Arch Linux and openSUSE Leap; not every listed variant is tested.

## Quick start

Run the installer on a VPS you control with TUN/TAP enabled. Build time depends on your CPU and network.

```bash
# 1. SSH into the server and become root
sudo su

# 2. Download and run the script
wget -N https://raw.githubusercontent.com/sfc9982/AnyConnect-Server/main/ocserv-en.sh
chmod +x ocserv-en.sh
bash ocserv-en.sh
```

Enter `1` to start the installation. The script will ask a few questions along the way:

| Prompt | Meaning | Suggestion |
|---|---|---|
| VPN username | The first account, default `admin` | Pick a name only you know |
| VPN password | Required, hidden while typing | Use a strong password; it doubles as the .p12 export password |
| TCP port | Default 443 | Keep 443 — the least likely to be blocked |
| UDP port | Same as TCP by default | Keep the default; the UDP channel affects voice/video quality |

When the installation finishes, the script prints your server info. The address to enter in the client looks like `123.45.67.89:443`.

> [!TIP]
> Review the script before running it as root. Allow incoming TCP and UDP on your chosen VPN port in both the host firewall and provider security group.

<!-- ci-status:start -->

## CI status

Live status of the latest `push` runs on `main`. Click a badge to open the matching workflow history.

<table>
  <tr>
    <td width="50%" align="center">
      <p><strong>Code quality</strong><br><sub>ShellCheck · Bash and Python syntax</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/lint.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/lint.yml/badge.svg?branch=main&amp;event=push" alt="Code quality · main · push">
      </a>
    </td>
    <td width="50%" align="center">
      <p><strong>Installer regressions</strong><br><sub>Failure recovery · exact tested source</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-source.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-source.yml/badge.svg?branch=main&amp;event=push" alt="Installer regressions · main · push">
      </a>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <p><strong>Distro smoke tests</strong><br><sub>9 Linux distributions · both installers</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/distro-test.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/distro-test.yml/badge.svg?branch=main&amp;event=push" alt="Distro smoke tests · main · push">
      </a>
    </td>
    <td width="50%" align="center">
      <p><strong>Real VPN end-to-end</strong><br><sub>TLS / DTLS · DNS / NAT · account lifecycle</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-e2e.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-e2e.yml/badge.svg?branch=main&amp;event=push" alt="Real VPN end-to-end · main · push">
      </a>
    </td>
  </tr>
  <tr>
    <td width="50%" align="center">
      <p><strong>Native IPv6 &amp; boot</strong><br><sub>Routed IPv6 · Ubuntu 22.04 VM reboots</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-native.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-native.yml/badge.svg?branch=main&amp;event=push" alt="Native IPv6 &amp; boot · main · push">
      </a>
    </td>
    <td width="50%" align="center">
      <p><strong>Extended VPN validation</strong><br><sub>Dual-stack traffic · edge ACLs · Ubuntu 24.04 reboots</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-production.yml?query=branch%3Amain+event%3Apush">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-production.yml/badge.svg?branch=main&amp;event=push" alt="Extended VPN validation · main · push">
      </a>
    </td>
  </tr>
</table>

<details>
<summary>Scheduled and manual validation</summary>

<table>
  <tr>
    <td width="50%" align="center">
      <p><strong>Scheduled soak</strong><br><sub>20 clients · 30 minutes; 2 hours on Sundays</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-production.yml?query=branch%3Amain+event%3Aschedule">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-production.yml/badge.svg?branch=main&amp;event=schedule" alt="Scheduled soak · main · schedule">
      </a>
    </td>
    <td width="50%" align="center">
      <p><strong>External VPS probe</strong><br><sub>Manual authorization · disposable owned endpoint</sub></p>
      <a href="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-vps.yml?query=branch%3Amain+event%3Aworkflow_dispatch">
        <img src="https://github.com/sfc9982/AnyConnect-Server/actions/workflows/vpn-vps.yml/badge.svg?branch=main&amp;event=workflow_dispatch" alt="External VPS probe · main · workflow_dispatch">
      </a>
    </td>
  </tr>
</table>

These badges track scheduled and manually dispatched workflows separately. A passing regular CI run does not mean a long soak or VPS probe ran. No matching run or a skipped job is not a pass; check job results and artifacts for the actual scope and duration.

</details>

[All workflow runs](https://github.com/sfc9982/AnyConnect-Server/actions?query=branch%3Amain) · [Core test coverage](tests/README.md) · [Extended tests and limitations](tests/EXTENDED-TESTS.md)

<!-- ci-status:end -->

## How it works

~~~mermaid
flowchart LR
    A["VPN client"] --> B{"Client routing policy"}
    B -->|"VPN routes"| C["TLS / DTLS"]
    B -->|"Excluded routes"| D["Local network"]
    C --> E["ocserv"]
    E --> F["IPv4 NAT / routed IPv6"]
    F --> G["Destinations"]
~~~

The routing decision happens on the client: excluded prefixes stay local. IPv6 is opt-in; it requires a routed VPN prefix and upstream return route, and does not automatically configure NAT66.

## What the installer does

Steps run in order; installation stops when a required step fails:

1. Detect the OS and TUN/TAP
2. Install build dependencies (gnutls, libev, seccomp, libnl, ...) plus iptables and openssl
3. Download the ocserv 1.5.0 source from the official site and compile it with Meson and Ninja
4. Generate a self-signed CA and server certificate (bound to your IP)
5. Generate the CRL and enable "certificate first, password fallback" authentication
6. Create the first account (certificate and password together)
7. Enable IP forwarding and iptables NAT, open the service ports, persist rules for boot
8. Start the service, self-check, and print connection info

## Connecting from a client

The server generates one `.p12` certificate bundle per user at `/etc/ocserv/ssl/users/<username>/<username>.p12`. Download it to the device you want to connect from.

### Step 1: import the certificate bundle

The import password is that user's VPN password.

- **Windows**: double-click the `.p12` → Current User → enter the password → finish the wizard.
- **macOS**: double-click to import into the "login" keychain, then confirm it exists in Keychain Access.
- **Android**: copy the file to phone storage → Settings → Security → Encryption & credentials → Install from storage (some vendors put this under "More security settings") → enter the password.
- **iOS / iPadOS**: send the file to the device (AirDrop / Files app / mail) → tap it → Settings → General → VPN & Device Management → install the profile. Import the verified server CA separately if needed; the iOS root-CA trust switch does not apply to the client `.p12`.

### Step 2: connect

1. Open AnyConnect and enter `server-IP:port` (e.g. `123.45.67.89:443`; use the domain name if you have one)
2. If the server certificate is untrusted, obtain and verify `/etc/ocserv/ssl/ca-cert.pem` via a trusted channel before trusting that CA; do not dismiss an unexpected warning
3. When asked to pick a certificate, choose the one named after your username
4. Enter your username and password, then connect
5. "Connected" means success

### After connecting

- Domestic sites and apps go directly through your local network
- Everything else goes through the VPN to your server and out to the internet
- To route everything through the VPN: edit `/etc/ocserv/ocserv.conf`, delete every `no-route` line, then restart the service

## Day-to-day management

Run `bash ocserv-en.sh` again to open the menu:

| Option | Function |
|---|---|
| 0 | Update the script from this repo (overwritten only after a syntax check passes) |
| 1 / 2 | Install / uninstall |
| 3 / 4 / 5 | Start / stop / restart |
| 6 | Accounts: 0 list, 1 add, 2 delete, 3 enable/disable |
| 7 | Show server address, ports and other info |
| 8 | Edit the config file (vim); firewall rules sync automatically on port changes |
| 9 | View live logs |

Key points about account management:

- **Add**: certificate and password are generated together. Send the resulting `.p12` to the user over a secure channel
- **Delete**: the certificate is written into the CRL (permanently revoked) and local files are removed; the password account is removed as well, and any already-imported certificate on the device stops working immediately
- **Disable / enable**: the certificate is archived temporarily and can be restored at any time; after restore the same certificate keeps working, no re-import needed
- All account operations take effect immediately — no service restart required

## Files and commands cheat sheet

| Content | Location / command |
|---|---|
| Main config | `/etc/ocserv/ocserv.conf` |
| CA cert / key | `/etc/ocserv/ssl/ca-cert.pem` / `ca-key.pem` (never share the key) |
| User bundles | `/etc/ocserv/ssl/users/<username>/<username>.p12` |
| Password file | `/etc/ocserv/ocpasswd` |
| Revocation list | `/etc/ocserv/ssl/crl.pem` |
| Service control | `systemctl start \| stop \| restart \| status ocserv` |
| Logs | `journalctl -u ocserv -f` |
| Firewall rules | `/etc/iptables.up.rules` (restored at boot by ocserv-firewall.service) |

## Upgrading and uninstalling

- **Update the script**: menu 0. Only the same-named script from this repo is fetched, and only installed if it passes a syntax check
- **Upgrade ocserv itself**: uninstall first (menu 2), then install again (menu 1). Back up `/etc/ocserv` beforehand
- **Uninstall**: menu 2. Stops the service, removes the systemd units, cleans firewall rules and config files; the rest of the system is untouched

## Security notes

> [!IMPORTANT]
> **Verify the server certificate before trusting it.** The installer creates a private CA. Obtain `ca-cert.pem` through a trusted channel and confirm the server identity; do not blindly bypass unexpected warnings.

- Keep `ca-key.pem` private. Never upload credentials, `.p12` bundles or session cookies to public logs.
- Distribute client bundles securely and revoke exposed certificates.
- VPN encrypts traffic but is not anonymity software; split-tunnel exclusions remain on the local network.
- Maintain OS updates, strong passwords, restricted admin access and cloud firewall rules.

## FAQ

<details>
<summary><strong>Q: The installer says TUN/TAP is missing?</strong></summary>

A: `/dev/net/tun` was not found. Enable TUN/TAP in your VPS control panel; on OpenVZ ask your provider to enable it, or move to a KVM / Xen based VPS.

</details>

<details>
<summary><strong>Q: The client connects but web pages will not load?</strong></summary>

A: Usually the provider's security group / firewall has not opened the port. Allow TCP and UDP 443 (or your custom port) in the provider console.

</details>

<details>
<summary><strong>Q: "Certificate untrusted / unable to verify server"?</strong></summary>

A: Verify and import the server's CA through a trusted channel, then check its hostname/IP; do not bypass verification.

</details>

<details>
<summary><strong>Q: The client says no certificate is available?</strong></summary>

A: Re-import the `.p12` and ensure the VPN app can use the client identity. The iOS root-CA trust switch is separate.

</details>

<details>
<summary><strong>Q: Frequent disconnects or choppy video on mobile?</strong></summary>

A: Make sure the UDP port is open (DTLS uses UDP). On networks that throttle UDP, switch the client to TCP-only.

</details>

<details>
<summary><strong>Q: What if I change server or IP?</strong></summary>

A: The server certificate is bound to the IP, so reinstall on the new server and redistribute the certificate bundles.

</details>

<details>
<summary><strong>Q: I forgot my account password?</strong></summary>

A: Menu 6 → delete the user → add a new one. The old certificate is revoked at the same time.

</details>

<details>
<summary><strong>Q: How do I change the port?</strong></summary>

A: Menu 8, edit `tcp-port` / `udp-port` in the config; firewall rules sync automatically, then restart the service.

</details>

<details>
<summary><strong>Q: How do I back everything up?</strong></summary>

A: Back up the entire `/etc/ocserv` directory (config, certificates and accounts).

</details>

<details>
<summary><strong>Q: How do I upgrade ocserv itself?</strong></summary>

A: Menu 0 only updates the management script. To upgrade ocserv, uninstall and reinstall — back up `/etc/ocserv` first.

</details>

## Testing and verification

GitHub Actions runs real end-to-end VPN clients as well as static checks. These badges report workflows, not universal production readiness.

| Suite | Coverage |
|---|---|
| Distro smoke | 9 Linux distributions, both installers |
| VPN E2E | Real connections, account lifecycle, DNS / NAT |
| IPv6 / Edge ACL | IPv6 routes, forwarding and simulated external firewall |
| systemd / Reboot | QEMU boot and service recovery |
| Soak | Mixed TLS / DTLS concurrent clients and traffic integrity |

The network fixtures validate IPv4 NAT, routed IPv6, DNS, TLS/DTLS, forwarding failures and independent client sessions. Real QEMU guests check service restart and reboot behavior. CI soak tests report concurrent clients and actual transferred bytes. **No simulated edge ACL guarantees the behavior of an actual cloud provider.** VPS probing is manual, authorized and limited to disposable endpoints.

[Core tests](tests/README.md) · [Extended test details](tests/EXTENDED-TESTS.md)

## Credits and license

- Server side is GNU ocserv; password management uses its bundled ocpasswd
- The script framework inherits the tradition of ToyoDAdoubi's one-click scripts, whose work is gratefully acknowledged
- For multi-user visual management, see the community project: <https://github.com/mmtaee/ocserv-users-management>
- Released under the MIT License, Copyright (c) 2023 sfc9982

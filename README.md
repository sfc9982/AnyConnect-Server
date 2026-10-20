# AnyConnect-Server

[简体中文](/README.zh-CN.md)

One-click deployment of an **SSL VPN server compatible with the official Cisco AnyConnect client** on Linux. Once deployed, phones and computers connect using Cisco's official AnyConnect client — no third-party app required.

- Server: ocserv 1.5.0 (the official OpenConnect server implementation, compiled from source into /usr/local)
- Client: the official Cisco AnyConnect client (Windows / macOS / Android / iOS / Linux)
- Accounts: client certificate + password, two independent channels; deleting a user permanently revokes the certificate, suspension can be lifted at any time
- Auth and revocation changes take effect immediately — no service restart needed

## Features

- One command deploys everything: build, certificates, firewall NAT, systemd service, first account
- One client certificate bundle (.p12) per user, imported directly by the Cisco client
- Full certificate lifecycle: add / delete (permanent revoke) / suspend / restore
- The Certificate Revocation List (CRL) is rebuilt automatically and hot-reloaded by the server
- Split tunneling by default: a built-in direct-route table keeps domestic traffic off the VPN while the rest goes through it
- Cross-distro: Debian / Ubuntu / RHEL family / Fedora / Arch / openSUSE
- No third-party script is downloaded during installation (systemd units are generated inline)

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

Note: minimal environments without systemd (Docker / OpenVZ) still work, but without boot autostart.

## Quick start (about 5 minutes)

Most of the time is spent waiting for the build.

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
- **iOS / iPadOS**: send the file to the device (AirDrop / Files app / mail) → tap it → Settings → General → VPN & Device Management → install the profile; then go to Settings → General → About → Certificate Trust Settings and enable trust for that certificate.

### Step 2: connect

1. Open AnyConnect and enter `server-IP:port` (e.g. `123.45.67.89:443`; use the domain name if you have one)
2. The first connection may warn that the certificate is untrusted — this is expected with a self-signed CA; choose to continue (to remove the warning, also import and trust `/etc/ocserv/ssl/ca-cert.pem` on the client)
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

1. **A certificate is an identity**: obtaining a user's `.p12` and password lets you connect as that user. Distribute bundles over secure channels; if one leaks, delete the user immediately (which revokes the certificate)
2. **The CA private key stays on the server**: `/etc/ocserv/ssl/ca-key.pem` is mode 600. Anyone holding it can forge your VPN server — do not share it or back it up to untrusted locations
3. **The protocol is fingerprintable**: traffic is encrypted, but the AnyConnect protocol itself is relatively easy to identify with deep packet inspection (DPI). If VPN usage is monitored or restricted in your environment, evaluate the risks before deploying. This tool provides transport encryption, not anonymity
4. **Self-signed certificates**: no CA backing, so clients cannot verify the server's authenticity. Accept the first-connection warning, or replace with a trusted certificate once you have a domain name
5. **Other advice**: use strong passwords; remove accounts you no longer need; keep the system and ocserv reasonably up to date

## FAQ

**Q: The installer says TUN/TAP is missing?**
A: `/dev/net/tun` was not found. Enable TUN/TAP in your VPS control panel; on OpenVZ ask your provider to enable it, or move to a KVM / Xen based VPS.

**Q: The client connects but web pages will not load?**
A: Usually the provider's security group / firewall has not opened the port. Allow TCP and UDP 443 (or your custom port) in the provider console.

**Q: "Certificate untrusted / unable to verify server"?**
A: Expected with a self-signed CA — continue at the connection prompt, or import the server's `ca-cert.pem` on the client to silence the warning.

**Q: The client says no certificate is available?**
A: The `.p12` was not imported correctly. Re-import following the platform steps above; on iOS also enable trust in Certificate Trust Settings.

**Q: Frequent disconnects or choppy video on mobile?**
A: Make sure the UDP port is open (DTLS uses UDP). On networks that throttle UDP, switch the client to TCP-only.

**Q: What if I change server or IP?**
A: The server certificate is bound to the IP, so reinstall on the new server and redistribute the certificate bundles.

**Q: I forgot my account password?**
A: Menu 6 → delete the user → add a new one. The old certificate is revoked at the same time.

**Q: How do I change the port?**
A: Menu 8, edit `tcp-port` / `udp-port` in the config; firewall rules sync automatically, then restart the service.

**Q: How do I back everything up?**
A: Back up the entire `/etc/ocserv` directory (config, certificates and accounts).

**Q: How do I upgrade ocserv itself?**
A: Menu 0 only updates the management script. To upgrade ocserv, uninstall and reinstall — back up `/etc/ocserv` first.

## Tests

CI includes distro smoke checks and real VPN end-to-end tests. The latter builds
ocserv from each installer, connects with OpenConnect, verifies TCP/DTLS traffic,
DNS and NAT, and exercises account disable/restore/delete and saved-session
cookie invalidation. See
[tests/README.md](tests/README.md) for coverage, local commands, and test boundaries.
Fault-injection and concurrent-account checks cover interrupted operations and
safe retries. The traffic fixture uses production helpers and starts the daemon
directly; systemd boot behavior is outside this suite.

## Credits and license

- Server side is GNU ocserv; password management uses its bundled ocpasswd
- The script framework inherits the tradition of ToyoDAdoubi's one-click scripts, whose work is gratefully acknowledged
- For multi-user visual management, see the community project: <https://github.com/mmtaee/ocserv-users-management>
- Released under the MIT License, Copyright (c) 2023 sfc9982

# VPN tests

The quick smoke suite checks script syntax and helpers. The end-to-end suite
uses the production dependency/build and configuration helpers, starts ocserv
as a foreground daemon, and connects with the distro's OpenConnect client and
routing script. Separate fault-injection tests exercise the normal
`Install_ocserv` sequence with controlled dependencies and service commands.

## Run the quick checks

```bash
bash tests/smoke.sh apt-get
```

Use the package manager expected on the current distro: `apt-get`, `dnf`,
`pacman`, or `zypper`.

Installer control-flow regressions use temporary paths and controlled commands:

```bash
bash tests/installer-regressions.sh
```

## Run a real VPN test

Run this from the repository root on a Linux machine with Docker and TUN support:

```bash
sudo modprobe tun
mkdir -p /tmp/anyconnect-e2e-logs
docker run --rm --privileged --device /dev/net/tun \
  --volume "$PWD:/workspace:ro" \
  --volume /tmp/anyconnect-e2e-logs:/logs \
  --workdir /workspace \
  --env VPN_E2E_DISPOSABLE=1 --env VPN_E2E_LOG_DIR=/logs \
  ubuntu:24.04 bash -c \
  'set -e; for script in ocserv.sh ocserv-en.sh; do
    bash tests/vpn-install.sh "$script"
    bash tests/vpn-e2e.sh "$script"
  done'
```

These scripts install packages and replace `/etc/ocserv` inside the test
container. Run them in a disposable container, not on a deployed VPN server.
The repository is mounted read-only. Namespace setup requires the container's
privileges; traffic tests run in separate client, server, and target namespaces.

The workflow runs this for the same nine distro images as the smoke suite. Each
installer language performs its own dependency installation and source build,
then runs account-concurrency checks with real certificates/password tools and
the complete connection and account lifecycle checks. No production
credentials or external VPN server are required.

Legacy fixture preparation is confined to the disposable test container. Debian
11 security packages use Debian's signed archive because the regular mirror's
indexes reference removed packages. The Leap 15.6 image's ncurses runtime
`6.1-150000.5.33.1` is aligned with the development package available in its signed
`repo-sle-update` repository. This older test dependency does not retain the
newer runtime's security fixes; the workaround is guarded by that exact image
package version and is not part of either production installer. Repository
signature and TLS verification stay enabled.

## What must pass

| Area | Assertion |
|---|---|
| Source installation | Real dependency installation and ocserv build from the version in the selected installer |
| Installer control flow | Failed setup/start stages propagate errors; retrying a partial installation preserves completed credential stages; service-command failures cannot report success |
| Configuration | The checked-out `ocserv.conf` is used; repeated auth configuration leaves one managed entry per key; `ocserv --test-config` accepts it |
| Server identity | Normal CA and IP-name validation succeeds; no certificate-pin or trust bypass |
| Password login | Valid account establishes a real TCP/TLS tunnel; incorrect passwords and missing users are rejected |
| Certificate login | A certificate establishes a real DTLS tunnel without password fallback |
| Address and routes | The negotiated address is installed on TUN; target traffic uses TUN; a production `no-route` exclusion keeps its original route |
| Data transfer | A random 256 KiB payload arrives with the exact SHA-256 hash |
| Forwarding and NAT | The server starts with forwarding disabled and `FORWARD DROP`; the target observes the server's NAT address |
| Persistent forwarding | After resetting runtime forwarding, loading `/etc/sysctl.conf` restores it |
| DTLS | Negotiation succeeds and more than 200,000 additional outer UDP bytes carry the payload, so TCP fallback cannot satisfy the check |
| DNS | Advertised resolver answers over UDP and TCP; the client's normal resolver also supports a hostname-based download |
| Disable and restore | Disable terminates the active tunnel and rejects fresh password/certificate logins; restore reconnects with the original exported PKCS#12 bundle |
| Delete and revoke | Delete terminates the active tunnel; the saved client certificate and password no longer authenticate |
| Session cookies | A saved cookie first reconnects and transfers real data; after disable/delete it cannot create a tunnel, even when it belonged to a separate detached session |
| Account identity | A username containing `-susp-` survives the complete lifecycle; duplicate creation cannot overwrite existing credentials |
| Certificate-only accounts | Removing the password record still permits certificate traffic, disable, restore, and permanent revocation |
| Failed creation | A deliberate client-certificate generation failure publishes no usable password account; the same username can be created successfully on retry |
| Disable retry | Deliberately failed CRL generation or session termination reports failure; repeating the menu operation completes disable without restoring credentials |
| Restore rollback | Reload failure after a restoring CRL is published, followed by rollback reload failure, stays pending; the next toggle finishes disable and rejects real password/certificate logins before a later successful restoration |
| Deletion retry | A deliberate CRL-generation failure is reported and preserves the live CRL; retrying deletion revokes the certificate, and repeated deletion succeeds |
| Concurrent mutations | Contending account creation has one consistent winner; restore/delete ordering cannot escape permanent revocation; concurrent CRL publication retains all revocations |
| Server control paths | Revocation works with a custom `pid-file` and a separate custom `occtl-socket-file`; missing cookie-invalidation capability is rejected before account changes |
| Failure controls | Target access fails before connection, after disconnect, and when tunnel forwarding is deliberately blocked; every negative login is followed by a valid control login |

The target has no route back to the VPN address pool and is never connected
directly to the client. A passing transfer therefore requires the actual VPN,
IP forwarding, and NAT. The target supplies local HTTP and DNS services; the
test does not depend on a public website staying reachable.

Fixture addresses, service ports, DNS endpoints, and PID/control-socket paths are
substituted in the production configuration. The login ban threshold is disabled for the deliberate
bad-password/revoked-certificate checks. Production TLS policy, authentication
methods, VPN pool, and split-route list remain in use.

## Logs and scope

CI uploads diagnostic logs for seven days, including on failures. Temporary
password files, CA/private keys, exported bundles, and client state are outside
the uploaded log directory and are removed when the test exits. Authentication
cookies are captured only in private temporary state, never printed in CI logs
or uploaded. Timeouts fail the suite and cannot count
as successful credential rejection.

The jobs use each distro's userspace on the GitHub runner's Linux kernel. They
validate fresh authentication, live-session termination, saved-cookie invalidation,
and IPv4 data flow with OpenConnect. The traffic fixture invokes production
helpers and launches the daemon directly; the separate installer tests control
system commands and do not boot systemd. They do not certify every Cisco Secure Client version, desktop or
mobile certificate-import UI, IPv6, throughput under load, reboot/systemd
persistence, cloud security groups, or a particular VPS/network path. Historical
distro images may also fail installation if their upstream repositories retire;
the workflow reports that failure instead of skipping it.

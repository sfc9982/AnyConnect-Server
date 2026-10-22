# Production qualification

This suite supplements, rather than replaces, the nine-distro IPv4 E2E tests.
A passing local firewall model is **not** a live provider result, and a
60-second CI run is **not** a 30-minute soak result. Check the completed run
and its exact commit before describing any scenario as verified.

## IPv6 network profile

Both installer languages support the optional `ocserv-network.sh` add-on.
The original single-file installer still defaults to IPv4. Install ocserv,
inspect the actual uplink and your assigned/routed IPv6 prefix, stop the daemon,
and explicitly apply a profile from a checked-out repository:

```bash
sudo systemctl stop ocserv
sudo bash ocserv-network.sh configure \
  --pool YOUR_ROUTED_IPV6_PREFIX/64 --client-prefix 128 \
  --ingress eth0 --egress eth0 --mode routed
sudo systemctl restart ocserv
```

Replace the placeholder prefix and interfaces. `routed` adds no NAT: the
upstream router must route the pool to this server. Do not assume the provider's
on-link interface /64 is delegated to VPN clients. Where an explicitly chosen
ULA pool must use the server's egress address, select `--mode nat66`. NAT66 is
opt-in, not native routed IPv6. Provider anti-spoofing/source-destination checks
and upstream rules must be verified separately.

The helper installs scoped IPv6 INPUT/FORWARD rules and ICMPv6 handling,
preserves RA reception on interfaces where it was already enabled, and persists
forwarding. On systemd hosts, ocserv requires the IPv6 and existing IPv4 firewall
units before starting. `OCSV6_IN`, `OCSV6_FWD` and `OCSV6_NAT` are reserved chains:
existing chains are not adopted and foreign rules prevent destructive cleanup.
Reapplying `up` is idempotent. Minimal images need not already contain
`/etc/sysctl.d`; the helper creates it before writing the persistent settings.

Changing a profile requires stopping ocserv, removing the previous profile,
and configuring the replacement. Before using the original uninstaller:

```bash
sudo systemctl stop ocserv
sudo bash ocserv-network.sh remove
```

Removal deletes this add-on's rules, units, drop-in, profile and active IPv6
pool settings; it does not disable global forwarding used by other applications.
Failed configuration returns nonzero and preserves `ocserv.conf.before-ipv6` for
manual recovery. It is not live transactional network reconfiguration. Do not
restart ocserv after a failed configure until the error is resolved.
Firewalld/UFW/nftables managers that replace iptables compatibility rules need
separate integration; this helper does not manage their policy lifecycle.

## Automated network and sustained-load checks

`VPN production qualification` runs Ubuntu 24.04, Debian 12 and Rocky 9, each
with both installer languages. Isolated jobs build the real server and test:

* Outer IPv4 and IPv6, each with TLS and DTLS; both inner families, TUN routes
  and leases, byte-exact bidirectional transfers, DNS AAAA over IPv4/IPv6 UDP
  and TCP, and normal IPv6 hostname resolution. Per-client UDP counters require
  actual DTLS payload; another busy client cannot hide a silent TLS fallback.
* Native routed IPv6 and explicit NAT66 with the return route removed; no
  direct target access, an IPv6 forwarding-drop control, and a 1280-byte path.
* Four independently authenticated client namespaces using mixed TLS/DTLS,
  each with two continuous upload/download workers. Every cycle verifies size
  and SHA-256. Reports record per-worker errors, bytes, duration, throughput and
  bounded-memory latency histograms. The server process tree is sampled for
  RSS, file descriptors, CPU ticks, unexpected exit and resource ceilings.
* An independent upstream firewall: stateful policy, stateless ephemeral
  return ports, UDP blocking with real TLS fallback, missing return rules,
  blocked TCP and absent IPv6 permission. Each negative connection requires
  dropped-packet evidence and a subsequent successful control connection.

The PR/push matrix uses 60 seconds of concurrent load per job. A separate
Ubuntu/English job requests **1800 seconds** on every PR/push. Manual runs
also default to **1800 seconds**, support 2..8 authenticated clients and up to
7200 seconds. This is bounded sustained workload, not a capacity rating.
Inspect measurements before describing saturation. RSS/FD ceilings catch gross
regressions; they do not prove absence of long-term leaks. Interrupted or failed
runs are not counted as completed soak tests.

Local example, on a disposable Linux Docker host only:

```bash
for module in tun iptable_filter iptable_nat ip6table_filter ip6table_nat; do
  sudo modprobe "$module"
done
mkdir -p /tmp/vpn-qualification-logs
docker run --rm --privileged --device /dev/net/tun \
  -v "$PWD:/workspace:ro" -v /tmp/vpn-qualification-logs:/logs -w /workspace \
  -e VPN_E2E_DISPOSABLE=1 -e VPN_E2E_LOG_DIR=/logs \
  -e VPN_SOAK_SECONDS=1800 -e VPN_SOAK_CLIENTS=4 ubuntu:24.04 bash -c \
  'set -e; bash tests/vpn-install.sh ocserv.sh; bash tests/qualification/network.sh ocserv.sh'
```

Host modules are loaded before starting containers because minimal distro
containers do not contain modules matching the runner's kernel. Counter parsing
is regression-tested with symbolic `udp` and numeric `17` protocol output.

## Real boot tests

The boot jobs use QEMU/KVM and the official Ubuntu 24.04 cloud image. They verify
its publisher-provided SHA-256 over HTTPS and record the exact hash. The image
URL moves; its recorded hash identifies the tested image. Missing KVM fails the
prerequisite. The disposable VM is deleted after the job.

The normal `Install_ocserv` runs with real packages, source build and systemctl.
Only fixture server identity replaces the public-IP lookup. Assertions cover
enabled/active units, firewall-before-daemon ordering, reload, stop/start, crash
recovery, firewall-prerequisite failure, unchanged credential digests and actual
dual-stack traffic. Reboot and complete poweroff/relaunch must produce new kernel
boot IDs. After each boot, no manual service start is performed: enabled units
must restore the VPN, forwarding and firewall rules. This validates the exercised
Ubuntu/systemd VM, not every distribution's init or firewall stack.

## Live VPS acceptance: opt-in and not run by PRs

`Live VPS acceptance (opt-in)` is manual, default-branch-only and uses the
`vpn-cloud-acceptance` environment. Configure required reviewers and restrict
allowed deployment branches before storing credentials. Use a dedicated test
VPS/account and private fixture, never production users. No VM purchase,
provider API mutation, remote reboot or firewall widening is performed.
Missing configuration is an error, not a skipped success. Until a real run
completes, live provider coverage is **NOT RUN**.

Environment variables: `VPN_CLOUD_SERVER` (HTTPS VPN URL), `VPN_CLOUD_USER`,
`VPN_CLOUD_TARGET4`, `VPN_CLOUD_TARGET6` (HTTP fixture base URLs with literal
IPv4/IPv6 addresses, unreachable without the VPN), and `VPN_CLOUD_PROVIDER`.
Environment secrets: `VPN_CLOUD_PASSWORD`, `VPN_CLOUD_CA` (PEM CA), and
`VPN_CLOUD_POLICY_EVIDENCE` (JSON metadata containing `provider`, `policy_id`,
`captured_at` and `expected_transport`: `dtls`, `tls` or `fallback`). Evidence
hash and provenance are recorded. This client does not independently verify
that export against a cloud API and cannot distinguish a cloud rule from an
identical intermediate firewall based solely on packet behaviour.

Prepare a private target behind the VPN server:

```bash
python3 -c 'from pathlib import Path; Path("payload.bin").write_bytes(bytes(range(256))*4096)'
sudo python3 tests/qualification/target.py --payload payload.bin \
  --address PRIVATE_IPV4 --address PRIVATE_IPV6
```

Run a TCP+UDP baseline with separate IPv6 permission. Then, on a dedicated
provider policy, block only UDP and run `fallback` without forcing `--no-dtls`.
For stateless ACLs permit ephemeral return ports explicitly. Leave SSH and
management rules unchanged. Preserve each export/run pair and restore the
baseline between experiments. Use local models for destructive TCP/return-path
fault injection; the live probe does not treat arbitrary timeouts as proof of a
specific provider rule.

The live probe requires pre-VPN unreachability, normal CA/name validation, both
leases/routes, bidirectional integrity and UDP payload evidence. Each provider,
region, image, policy version and client path needs its own recorded result.

## Evidence and limits

Uploaded diagnostics contain metric JSON/JSONL, filtered transport messages,
namespace routes/firewall state, boot IDs, image hashes and pass summaries.
Raw installation/authentication logs, passwords, private keys, cookies and SSH
keys remain in temporary private state and are removed. A missing summary is
not a pass. Existing nine-distro smoke/E2E tests are retained.

Reference semantics: ocserv's `ipv6-network` and `ipv6-subnet-prefix`, OpenConnect
DTLS and CA validation, Linux `accept_ra=2` with forwarding, systemd network-online
ordering, and provider distinctions between stateful security groups, stateless
network ACLs and independent IPv6 permissions.

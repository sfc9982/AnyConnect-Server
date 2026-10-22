# Production qualification

This suite supplements, rather than replaces, the nine-distro IPv4 E2E tests.
It separates four kinds of evidence. A passing local firewall model is **not**
a live provider result, and a 60-second CI run is **not** a 30-minute soak result.

## IPv6 network profile

Both installer languages can be used with the optional `ocserv-network.sh`
add-on. The original single-file installer continues to default to IPv4. Install
ocserv first, inspect the actual uplink and your assigned/routed IPv6 prefix,
stop the daemon, and explicitly apply a profile from a checked-out repository:

```bash
sudo systemctl stop ocserv
sudo bash ocserv-network.sh configure \
  --pool YOUR_ROUTED_IPV6_PREFIX/64 --client-prefix 128 \
  --ingress eth0 --egress eth0 --mode routed
sudo systemctl restart ocserv
```

Replace the placeholder prefix and interfaces. `routed` does **not** add NAT;
the upstream router must route the pool to this server. Do not assume the
provider's on-link interface /64 is delegated to VPN clients. Where an explicitly
chosen ULA pool must use the server's egress address, use `--mode nat66` instead.
NAT66 is opt-in; it is not advertised as native routed IPv6. Keep provider IPv6
anti-spoofing/source-destination restrictions in mind.

The helper installs scoped IPv6 INPUT/FORWARD rules and essential ICMPv6
handling, preserves RA reception on interfaces where it was already enabled,
and enables persistent IPv6 forwarding. It installs `ocserv-ipv6.service` and
an ocserv drop-in requiring the IPv6 service and the existing IPv4 firewall
service to complete before ocserv starts. It does not flush unrelated rules.
The named `OCSV6_*` chains are reserved for this profile. Do not add your own
rules to them. Reapplying `up` is idempotent. Changing a profile requires stopping
ocserv, removing the previous profile, and configuring the replacement.

Before using the original uninstaller, stop ocserv and run:

```bash
sudo bash ocserv-network.sh remove
```

Removal deletes this add-on's rules, units, drop-in, profile and active IPv6 pool
settings; it does not disable global forwarding used by unrelated applications.
A failed configuration returns nonzero and preserves `ocserv.conf.before-ipv6`
for manual recovery. It is not a live, transactional network reconfiguration.
Do not restart ocserv after a failed configure until the error has been resolved.
Firewalld/UFW/nftables managers that replace iptables compatibility rules require
separate integration; this helper does not claim to manage their policy lifecycle.

## Automated network and sustained-load checks

`VPN production qualification` runs Ubuntu 24.04, Debian 12 and Rocky 9, with
both installer languages. Each isolated job builds the real server and tests:

* Outer IPv4 and outer IPv6, each with TLS and DTLS; both inner address families,
  real TUN routes/leases, byte-exact bidirectional transfers, UDP payload counters,
  DNS AAAA over IPv4/IPv6 UDP and TCP, and normal IPv6 hostname resolution.
* Native routed IPv6 and explicit NAT66 (with the return route removed), no
  direct target access, a forwarding-drop control, and a 1280-byte target path.
* Four independent authenticated client namespaces, each with two continuous
  upload/download workers. Every cycle verifies the exact size and SHA-256.
  Reports contain per-worker errors, bytes, elapsed time, aggregate throughput
  and bounded-memory latency histograms. The server process tree is sampled
  for RSS, descriptors, CPU ticks, unexpected exit and generous resource ceilings.
* A separate upstream router/firewall: stateful policy, explicit stateless
  ephemeral return ports, UDP blocking with real TLS fallback, missing return
  rules, blocked TCP and missing IPv6 permission. Negative connection tests
  require dropped-packet evidence and a subsequent successful control connection.

PR/push matrix runs use 60 seconds of concurrent load per job. A separate
Ubuntu/English job runs **1800 seconds** on every PR/push. Manual workflow
runs also default to **1800 seconds**, with 2..8 authenticated clients and durations
up to 7200 seconds. This is bounded sustained workload, not a capacity rating.
Inspect measured throughput before describing a run as saturation. RSS/FD limits
catch gross regressions; they do not prove the absence of long-term leaks.

Local example (disposable Linux Docker host only):

```bash
sudo modprobe tun
mkdir -p /tmp/vpn-qualification-logs
docker run --rm --privileged --device /dev/net/tun \
  -v "$PWD:/workspace:ro" -v /tmp/vpn-qualification-logs:/logs -w /workspace \
  -e VPN_E2E_DISPOSABLE=1 -e VPN_E2E_LOG_DIR=/logs \
  -e VPN_SOAK_SECONDS=1800 -e VPN_SOAK_CLIENTS=4 ubuntu:24.04 bash -c \
  'set -e; bash tests/vpn-install.sh ocserv.sh; bash tests/qualification/network.sh ocserv.sh'
```

## Real boot tests

The separate `boot` jobs use QEMU/KVM and the official Ubuntu 24.04 cloud image.
They verify its publisher-provided SHA-256 over HTTPS and record the exact hash;
the image URL is a moving release URL, so the recorded hash, not the URL alone,
identifies the tested image. A missing KVM device fails the prerequisite rather
than claiming success. The VM is deleted after the job.

The test invokes the normal `Install_ocserv` with real package installation,
source build and systemctl commands. Only the server identity is supplied by the
fixture instead of a public-IP lookup. It then verifies enabled/active units,
firewall-before-daemon ordering, reload, stop/start, crash recovery, failure of a
firewall prerequisite, unchanged credential digests, and real dual-stack traffic.
Both `reboot` and complete poweroff/relaunch must produce new kernel boot IDs.
After each boot there is no manual service start: enabled units must recover
service, forwarding and firewall rules themselves. This certifies the exercised
Ubuntu/systemd VM and configuration, not every distribution's init/firewall stack.

## Live VPS/cloud-provider acceptance (not run by PRs)

`Live VPS acceptance (opt-in)` is manual, default-branch-only, and uses the
`vpn-cloud-acceptance` environment. Configure required reviewers and restrict its
allowed deployment branch to the default branch before storing credentials.
Use a dedicated test VPS/account and private fixtures, never production users.
No VM purchase, provider API mutation, remote reboot or firewall widening is
performed by this workflow. Missing configuration is an error, not a skipped
success. Until an actual run completes, live provider coverage is **NOT RUN**.

Environment variables: `VPN_CLOUD_SERVER` (HTTPS VPN URL), `VPN_CLOUD_USER`,
`VPN_CLOUD_TARGET4` and `VPN_CLOUD_TARGET6` (HTTP fixture base URLs with literal IPv4/IPv6 addresses, unreachable
without the tunnel), and `VPN_CLOUD_PROVIDER` (provider label).
Environment secrets: `VPN_CLOUD_PASSWORD`, `VPN_CLOUD_CA` (PEM CA), and
`VPN_CLOUD_POLICY_EVIDENCE` (JSON export metadata with `provider`, `policy_id`,
`captured_at`, and `expected_transport`: `dtls`, `tls`, or `fallback`). The evidence
hash and provenance are recorded; the client does not independently authenticate
that export against a cloud API. It cannot distinguish a cloud rule from an
identical intermediate firewall purely by packet behaviour.

Prepare the fixture in a private target host/network behind the VPN server:

```bash
python3 -c 'from pathlib import Path; Path("payload.bin").write_bytes(bytes(range(256))*4096)'
sudo python3 tests/qualification/target.py --payload payload.bin \
  --address PRIVATE_IPV4 --address PRIVATE_IPV6
```

Run a baseline with TCP+UDP and separate IPv6 permission; then, in a dedicated
provider policy, block only UDP and run `fallback` without forcing `--no-dtls`.
For stateless ACLs, explicitly permit ephemeral return ports in both directions.
Keep SSH/management rules unchanged. Preserve each export/run pair and restore
the baseline between experiments. Use the local models for destructive blocked
TCP/return-path fault injection; the live probe reports those failures but does
not interpret arbitrary timeouts as proof of a particular cloud rule.

The live probe checks pre-VPN unreachability, normal CA/name validation, both
leases/routes, upload/download integrity and UDP payload evidence. It does not
skip certificate validation. Report each provider, image, region, policy version,
client path and run separately; do not extrapolate one result to all providers.

## Evidence and limits

Only metric JSON/JSONL, filtered firewall counters, boot IDs, image hashes and
pass summaries are uploaded. Raw installation/authentication logs, passwords,
private keys, cookies and SSH keys remain in temporary private state and are
removed. A missing `summary.json` is not a pass. The pre-existing nine-distro
smoke/E2E suite remains unchanged.

Protocol references: ocserv's official manual (`ipv6-network`,
`ipv6-subnet-prefix`), OpenConnect's manual (DTLS and normal CA validation),
Linux `ip-sysctl` (`accept_ra=2` when forwarding), systemd's network-online
semantics, and AWS's documented distinction between stateful security groups,
stateless network ACLs and independent IPv6 rules.

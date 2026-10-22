# Extended VPN validation

These are executable additions to the original nine-distro IPv4 matrix. A test being implemented is not evidence of a passing run. Consult the workflow for the exact commit and its artifacts.

## Dual-stack network and edge firewall

`vpn-extended.sh` starts independent client, edge-router, server and target network namespaces. Real distro OpenConnect clients use the stock vpnc routing script and CA/hostname verification. Clients alternate IPv4/IPv6 server access. The inner tunnel is dual stack; checks require an IPv6 lease and route, a preserved IPv6 split exclusion, byte-exact IPv4 and IPv6 HTTP payloads, IPv4 NAT, routed IPv6 source addresses, UDP/TCP DNS over IPv6, and normal AAAA resolution. DTLS must carry the payload according to packet counters, not just a handshake log. The fixture uses a 1420-byte server link MTU, leaving room for encapsulation above the IPv6 minimum. The native helper suite also exercises a 1400-byte underlay and requires the negotiated tunnel MTU to remain at least 1280; it does not pretend that a 1280-byte outer path leaves 1280 bytes for an encapsulated IPv6 packet.

Both a server FORWARD drop and disabled IPv6 forwarding must break access. A separate edge ACL drops TCP to require connection failure, or drops UDP to require TLS fallback. Removing the ACL must restore real DTLS traffic. Local edge behavior is a controlled model, **not certification of any provider's security groups**.

The current installer/template remains IPv4-by-default. The extended fixture explicitly enables an IPv6 VPN prefix and supplies its routed IPv6 return path. The production installer helpers enable/persist IPv6 forwarding and install scoped IPv6 INPUT/FORWARD rules under a deny policy; the fixture does not add replacement ACCEPT rules. It does not prove provider prefix delegation, NAT66, a client's OS-wide kill switch, or arbitrary Internet PMTUD. The native IPv6 suite additionally checks rule cleanup and sysctl reload.

PR/push matrix: Ubuntu 24.04, Debian 12 and Rocky 9, both installer languages; six simultaneous clients and a 60-second regression workload. This is not called a long soak.

## Sustained load

After the edge cases, all configured clients connect simultaneously with independent synthetic password identities and leases. TLS and DTLS sessions carry continuous 1 MiB downloads, uploads and nonce-checked UDP echoes. Every transfer is hash checked; timeouts, corrupt data, daemon/client exits and remaining server TUN devices fail the run. The original E2E suite retains certificate/account lifecycle coverage; the load identities do not replace those tests.

Each client writes JSON containing requested/actual duration, iterations, byte counts, application throughput, UDP completion counts and latency percentiles. Latency statistics cover the last 4096 iterations to bound memory. `resources.csv` records namespace process count, RSS, file descriptors and cumulative CPU ticks every five seconds. These are observations, not a hardware-independent throughput SLA or proof that every possible memory leak is absent.

`Extended VPN validation` exposes 1800/7200-second manual runs with 10/20/50/100 sessions. Applying the `vpn-soak` PR label opts into a 30-minute, 20-session run after the network matrix passes. Scheduled runs use 20 sessions, 30 minutes Monday-Saturday and two hours Sunday (02:17 UTC), for each installer language. Schedules only take effect on the default branch. Jobs have a 150-minute ceiling, and runtime inputs reject larger duration/concurrency. Resource exhaustion is a failed run, not an excuse to silently reduce concurrency.

Local reproduction, only on a disposable host with Docker:

```bash
mkdir -p results
docker run --rm --privileged --device /dev/net/tun \
  -v "$PWD:/workspace:ro" -v "$PWD/results:/reports" -w /workspace \
  -e VPN_E2E_DISPOSABLE=1 -e VPN_E2E_LOG_DIR=/reports \
  -e VPN_SOAK_SECONDS=1800 -e VPN_SOAK_CLIENTS=20 ubuntu:24.04 \
  bash -c 'set -e; bash tests/vpn-install.sh ocserv.sh; bash tests/vpn-extended.sh ocserv.sh'
```

## Real systemd VM lifecycle

`systemd-vm.sh` downloads an official Ubuntu 24.04 cloud image over HTTPS and verifies its published SHA-256 checksum, which is saved in artifacts. The image is mutable upstream; the recorded digest identifies the bytes actually tested. QEMU boots a copy-on-write guest with systemd PID 1 (KVM when available, otherwise software emulation). Generated SSH host keys are pinned; password SSH and root SSH are disabled.

The real `Install_ocserv` sequence runs with controlled account/port input. Only public-address discovery is replaced with the VM's externally reachable test address; service commands, source build, PKI, firewall setup and installer orchestration are not mocked. A separate Docker client outside the VM tests TLS and DTLS with real data.

Assertions cover unit enablement and syntax, active PID, sysctl and saved firewall state, start/stop/restart, automatic recovery after killing the service main process, and full guest reboot. A changed kernel boot ID is mandatory. After boot, the service must accept new TLS and DTLS clients without a manual start, and credentials and firewall rules must be unchanged. Uninstall must preserve unrelated rules; a second reboot must leave the service and ports absent. VM/credential cleanup is trapped, including failed runs. The runner itself is never rebooted. The second boot workflow runs the same lifecycle assertions on Ubuntu 22.04 with its own guest kernel. These cover Ubuntu 22.04/24.04 x86-64 in both languages, not nine different distro kernels.

## Authorized real VPS observations

`Authorized external VPS validation` is manual-only, restricted to the default branch, with the explicit input `TEST_DISPOSABLE_VPS`. It does not provision machines, access provider APIs, alter cloud firewall rules, reboot a VPS or spend a cloud budget. No external VPS has been tested merely by adding this workflow.

Create the GitHub Environment `vpn-vps-validation`, restrict deployment branches to the default branch and configure required reviewers **before storing credentials**. The YAML names the environment; it cannot create approval protection by itself. Store these environment secrets:

- `VPN_VALIDATION_CA`: the test VPN CA PEM.
- `VPN_VALIDATION_PASSWORD`: a dedicated disposable test user's password.
- `VPN_VALIDATION_CONFIG`: JSON with `endpoint`, `username`, numeric `target_ip`, matching numeric `target_url`, `expected_sha256`, and `metadata` containing `provider`, `region`, `image`, `firewall_profile`.

For a target accessible only through the VPN set `require_unreachable: true`. For a public target use `false` and supply `expected_source`; the HTTP target must return `X-Seen-Client-IP` with the expected VPS egress address. Every case checks the TUN route and payload hash. A simple owned target is available with `python3 tests/vpn-workload.py http --bind 0.0.0.0 --port 18080`; obtain its payload hash with the `digest` subcommand. Restrict that target's ingress to the test VPS and probe runner, and remove it after testing.

Run `dtls` with TCP and UDP allowed; apply the provider's UDP-blocked profile yourself and run `fallback`; restore the profile and rerun `dtls`. `tls` explicitly disables DTLS and is only a TCP control. Metadata is labeled operator-supplied. A fallback observation alone cannot locate a block at the provider rather than the OS firewall; retain provider rule exports and correlate them with server-side counters separately. Repeat the same protocol across the providers and regions that actually matter to deployment.

Only structured probe results are uploaded. CA/password/config files are removed on every job exit path; raw external authentication logs and cookies are never artifacts. Local isolated-fixture failure logs are redacted before upload. No production credentials are necessary.

# Production-oriented VPN verification plan

The existing `vpn-e2e.yml` validates IPv4 traffic in isolated network namespaces, but does not certify IPv6, sustained load, a cloud provider's security-group path, or reboot-time systemd behavior. The following are **acceptance criteria**, not claims of passing tests.

## IPv6: fail closed if unsupported
- Use a dual-stack server and an independently routed IPv6-only target. Ensure the client cannot reach the target before connecting.
- Confirm the server advertises a distinct IPv6 VPN prefix, DNS AAAA answers, and an IPv6 route through the tunnel; verify source and destination addresses with `ip -6 route get`.
- Download a deterministic payload over IPv6 TCP and test UDP/DTLS transport independently. Verify bytes and hash, and inspect counters to rule out IPv4 fallback.
- Test IPv6 DNS over UDP and TCP, IPv6 leak behavior under split-tunnel and full-tunnel settings, and connectivity after reconnect.
- Assert that disabling IPv6 forwarding or blocking IPv6 FORWARD rules prevents target access; restore rules and verify recovery.
- Ensure `ip6tables`/nftables changes are scoped, persist appropriately, and are removed by uninstall without modifying unrelated rules.

## Sustained load
- Run a 30-minute minimum soak and a separate 2-hour scheduled soak, with simultaneous TCP/TLS and DTLS clients.
- Test 1, 10, 50, and 100 concurrent connections, subject to runner/VPS capacity; record achieved rather than assumed concurrency.
- Use `iperf3` for bidirectional throughput and `ping`/application requests for latency, jitter, packet loss, and disconnects; compare against an untunneled baseline.
- Capture process RSS, CPU, file descriptors, conntrack entries, packet drops, and server logs at fixed intervals.
- Assert no unexpected daemon exits, failed authentication for valid users, routing leaks, stuck TUN interfaces, or unbounded growth after disconnect.
- Include reconnect churn, mixed password/certificate users, CRL update during load, and client restarts.
- Set thresholds only after collecting baseline distributions on a named VM size; avoid arbitrary throughput gates on shared runners.

## Real VPS / cloud firewall
- Run an **opt-in** environment against a disposable VPS with explicit operator-provided host, provider, image, and security group IDs. Never point destructive tests at a production server.
- Record provider and region, OS, kernel, public IPv4/IPv6, NAT placement, and relevant firewall/security-group rules.
- Validate TCP and UDP VPN listener reachability **from a separate external machine**, not from localhost or the same VPC.
- Exercise closed TCP/UDP port failures, allowed inbound rules, return traffic, asymmetric routing, MTU/PMTUD, and security-group statefulness.
- Verify server-side OS firewall separately from cloud ingress/egress controls. Distinguish provider blocks from ocserv authentication or tunnel failures.
- Provision/teardown using least-privilege short-lived credentials and ensure teardown runs on failures; keep credentials and private keys out of artifacts.
- Require explicit budget approval and provider-specific provisioning configuration before running.

## systemd and reboot
- Use a VM with systemd as PID 1, not a container that merely has `systemctl` installed.
- Invoke the **normal** `Install_ocserv` sequence, then verify `systemctl is-enabled`, `is-active`, unit dependencies, and `ExecStart` behavior.
- Connect an external client, transfer data, and verify the journal is free of unexpected errors.
- Restart the service and assert reconnection; stop the service and assert no VPN access; start again and assert recovery.
- Reboot the VM, wait for SSH/agent recovery, then verify service is active **without manual intervention**, routes and sysctls persist, firewall rules are not duplicated, and a fresh client can connect.
- Inject failures in unit creation, daemon-reload, enable, and start; verify accurate installer exit codes and safe retries.
- Uninstall, reboot again, and verify service is absent/disabled, VPN ports are closed, and unrelated firewall rules remain.

## CI policy
- Keep current fast per-PR IPv4 matrix mandatory.
- Add an opt-in or scheduled dedicated IPv6/systemd/load workflow with clear runner requirements and artifact retention.
- Keep real-VPS testing opt-in, approval-gated, budget-limited, and explicitly scoped to disposable infrastructure.
- Publish environment metadata and test evidence for every result. Report **not run** separately from **passed**.

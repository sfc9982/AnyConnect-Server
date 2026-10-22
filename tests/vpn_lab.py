#!/usr/bin/env python3
"""Disposable dual-stack VPN lab, upstream firewall profiles and bounded traffic soak.

Requires root, TUN and network-namespace capabilities. Never run on a VPN host.
The four namespaces model an upstream firewall; they are NOT a cloud-provider test.
Only sanitized diagnostics and aggregate measurements are exported.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
V4_TARGET = "198.51.100.2"
V6_TARGET = "fd42:2::2"
V6_POOL = ipaddress.ip_network("fd42:7::/48")


def run(args, ns=None, check=True, timeout=30, **kwargs):
    command = (["ip", "netns", "exec", ns] if ns else []) + [str(x) for x in args]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {command!r}: "
                           f"{result.stderr.decode(errors='replace')[-1500:]}")
    return result


def text(args, **kwargs):
    return run(args, **kwargs).stdout.decode().strip()


def version_line(command):
    # ocserv writes --version to stderr, OpenConnect uses stdout.
    result = run([command, "--version"])
    lines = (result.stdout + result.stderr).decode(errors="replace").strip().splitlines()
    if not lines:
        raise RuntimeError(f"{command} --version produced no version output")
    return lines[0]


def wait_for(predicate, seconds, description):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise RuntimeError(f"timed out: {description}")


def stop_process(process, sig=signal.SIGTERM):
    if process is None or process.poll() is not None:
        return
    process.send_signal(sig)
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def redact(data, password):
    data = data.replace(password, "<redacted>")
    return re.sub(r"(?im)^.*(?:set-cookie:|cookie:|authorization:|webvpn=).*$",
                  "<redacted credential header>", data)


class Client:
    def __init__(self, lab, number):
        self.lab, self.number = lab, number
        self.ns = f"{lab.tag}-c{number}"
        self.state = lab.state / f"client-{number}"
        self.state.mkdir(mode=0o700)
        self.process = None
        self.family = 4
        self.dtls = False
        self.log = self.state / "openconnect.log"
        lab.namespace(self.ns)
        peer = f"p{number}"
        lab.link(self.ns, "vc", lab.edge, peer)
        lab.ip(lab.edge, "link", "set", peer, "master", "bridge0")
        lab.address(self.ns, "vc", f"192.0.2.{number+2}/24", f"fd42:1::{number+2:x}/64")
        lab.ip(self.ns, "route", "add", "192.0.2.1/32", "via", "192.0.2.254")
        lab.ip(self.ns, "route", "add", "default", "via", "192.0.2.253")
        lab.ip(self.ns, "-6", "route", "add", "fd42:1::1/128", "via", "fd42:1::fe")
        lab.ip(self.ns, "-6", "route", "add", "default", "via", "fd42:1::fd")
        netdir = Path("/etc/netns") / self.ns
        netdir.mkdir(parents=True)
        (netdir / "resolv.conf").write_text("nameserver 192.0.2.253\n")
        for tool in ("iptables", "ip6tables"):
            run([tool, "-N", "QA_UDP"], ns=self.ns)
            run([tool, "-A", "QA_UDP", "-j", "RETURN"], ns=self.ns)
            run([tool, "-A", "INPUT", "-p", "udp", "--sport", "4443", "-j", "QA_UDP"], ns=self.ns)

    def counter(self):
        tool = "ip6tables" if self.family == 6 else "iptables"
        lines = text([tool, "-nvxL", "QA_UDP"], ns=self.ns).splitlines()
        return sum(int(line.split()[1]) for line in lines if len(line.split()) > 2 and line.split()[2] == "RETURN")

    def start(self, family=4, dtls=True, password=False, expect_dtls=True):
        self.stop()
        self.family, self.dtls = family, dtls
        for filename in ("connected", "address", "address6", "dns", "dns6"):
            if (self.state / filename).exists():
                (self.state / filename).unlink()
        endpoint = "fd42:1::1" if family == 6 else "192.0.2.1"
        (Path("/etc/netns") / self.ns / "hosts").write_text(f"127.0.0.1 localhost\n{endpoint} vpn-server.test\n")
        args = ["ip", "netns", "exec", self.ns, "openconnect", "--protocol=anyconnect",
                "--non-inter", "--no-proxy", "--no-system-trust", "--cafile", str(self.lab.state / "ca.pem"),
                "--user", "qa-user", "--reconnect-timeout", "3", "--interface", "vpntest",
                "--script", f"exec bash {ROOT}/tests/vpn-vpnc.sh"]
        if password:
            args += ["--passwd-on-stdin"]
        else:
            args += ["--no-passwd", "--certificate", str(self.lab.state / "client.cer"),
                     "--sslkey", str(self.lab.state / "client-key.pem")]
        if not dtls:
            args += ["--no-dtls"]
        args += ["https://vpn-server.test:4443/"]
        env = dict(os.environ, VPNC_REAL_SCRIPT=self.lab.vpnc, VPNC_STATE_DIR=str(self.state))
        with self.log.open("wb") as log:
            self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=log,
                                            stderr=log, env=env)
        self.process.stdin.write((self.lab.password + "\n").encode() if password else b"\n")
        self.process.stdin.close()
        def connected():
            if self.process.poll() is not None:
                raise RuntimeError(f"OpenConnect exited ({self.process.returncode}); see client-{self.number}.log")
            return (self.state / "connected").exists()
        wait_for(connected, 25, "negotiated VPN tunnel")
        self.check_routes()
        if dtls and expect_dtls:
            wait_for(lambda: "Established DTLS connection" in self.log.read_text(errors="replace"),
                     20, "real DTLS negotiation")
        if family == 6:
            if not re.search(r"\[?fd42:1::1\]?:4443", text(["ss", "-Htn"], ns=self.ns)):
                raise RuntimeError("IPv6 server connection fell back to IPv4")

    def check_routes(self):
        for target, family in ((V4_TARGET, "-4"), (V6_TARGET, "-6")):
            if "dev vpntest" not in text(["ip", family, "route", "get", target], ns=self.ns):
                raise RuntimeError(f"{target} does not use the VPN interface")
        addresses = json.loads(text(["ip", "-j", "-6", "addr", "show", "dev", "vpntest"], ns=self.ns))
        if not any(ipaddress.ip_address(a["local"]) in V6_POOL
                   for link in addresses for a in link["addr_info"] if a["family"] == "inet6"):
            raise RuntimeError("missing negotiated IPv6 lease")

    def transfer(self, family=6, upload=False, hostname=False):
        target = "vpn-test.internal" if hostname else (f"[{V6_TARGET}]" if family == 6 else V4_TARGET)
        output = self.state / ("upload-reply" if upload else "received")
        headers = self.state / "headers"
        args = ["curl", f"-{family}", "--noproxy", "*", "-fsS", "--connect-timeout", "3",
                "--max-time", "15", "-D", str(headers), "-o", str(output)]
        if upload:
            args += ["--data-binary", f"@{self.lab.state / 'payload'}"]
        args += [f"http://{target}:8080/payload"]
        start = time.monotonic()
        run(args, ns=self.ns, timeout=20)
        body = output.read_bytes()
        if (body.decode().strip() if upload else hashlib.sha256(body).hexdigest()) != self.lab.digest:
            raise RuntimeError("VPN payload hash mismatch")
        if not upload:
            seen = re.search(r"(?im)^X-Seen-Client-IP: (\S+)", headers.read_text())
            if not seen:
                raise RuntimeError("target source-address evidence missing")
            address = ipaddress.ip_address(seen.group(1).strip())
            if (family == 4 and str(address) != "198.51.100.1") or (family == 6 and address not in V6_POOL):
                raise RuntimeError(f"incorrect {'NAT' if family == 4 else 'routed IPv6'} source: {address}")
        return time.monotonic() - start

    def unreachable(self, family=6):
        target = f"[{V6_TARGET}]" if family == 6 else V4_TARGET
        result = run(["curl", f"-{family}", "--noproxy", "*", "-fsS", "--connect-timeout", "1",
                      "--max-time", "2", f"http://{target}:8080/payload", "-o", "/dev/null"], ns=self.ns, check=False)
        if result.returncode == 0:
            raise RuntimeError("target accessible without the required forwarding/tunnel path")

    def dns(self):
        for family, resolver in ((4, V4_TARGET), (6, V6_TARGET)):
            for transport in ([], ["+tcp"]):
                for kind, expected in (("A", V4_TARGET), ("AAAA", V6_TARGET)):
                    output = text(["dig", f"-{family}", "+short", "+time=2", "+tries=1", *transport,
                                   f"@{resolver}", "vpn-test.internal", kind], ns=self.ns)
                    if expected not in output.splitlines():
                        raise RuntimeError(f"DNS {kind} over IPv{family}/{transport or 'UDP'} failed")
        self.transfer(family=6, hostname=True)

    def stop(self):
        stop_process(self.process, signal.SIGINT)
        self.process = None


class Lab:
    def __init__(self, args):
        self.args = args
        self.tag = f"qa{os.getpid()}"
        self.server, self.edge, self.target = [f"{self.tag}-{s}" for s in ("server", "edge", "target")]
        self.namespaces, self.clients, self.processes = [], [], []
        self.state = Path(tempfile.mkdtemp(prefix="vpn-production-"))
        self.password = secrets.token_hex(24)
        self.logs = Path(args.log_dir).resolve()
        self.logs.mkdir(parents=True, exist_ok=True)
        self.report = {"status": "running", "installer": args.installer, "kernel": os.uname().release,
                       "cloud_provider": "not-tested: isolated upstream firewall simulation", "checks": [],
                       "requested_clients": args.clients, "requested_seconds": args.duration}
        self.vpnc = next((p for p in ("/usr/share/vpnc-scripts/vpnc-script", "/etc/vpnc/vpnc-script",
                                     "/etc/openconnect/vpnc-script") if os.access(p, os.X_OK)), None)
        if not self.vpnc:
            raise RuntimeError("stock distro vpnc-script not found")

    def passed(self, name):
        self.report["checks"].append(name)
        print(f"PASS: {name}", flush=True)
        self.save_report()

    def save_report(self):
        (self.logs / "result.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def namespace(self, name):
        run(["ip", "netns", "add", name])
        self.namespaces.append(name)
        self.ip(name, "link", "set", "lo", "up")
        run(["sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0", "net.ipv6.conf.default.disable_ipv6=0"], ns=name)

    @staticmethod
    def ip(ns, *args):
        run(["ip", "-n", ns, *args])

    def link(self, first_ns, first, second_ns, second):
        run(["ip", "-n", first_ns, "link", "add", first, "type", "veth", "peer", "name", second])
        run(["ip", "-n", first_ns, "link", "set", second, "netns", second_ns])
        self.ip(first_ns, "link", "set", first, "up")
        self.ip(second_ns, "link", "set", second, "up")

    def address(self, ns, interface, ipv4, ipv6):
        self.ip(ns, "addr", "add", ipv4, "dev", interface)
        self.ip(ns, "-6", "addr", "add", ipv6, "dev", interface, "nodad")

    def bootstrap(self, action):
        with (self.state / f"{action}.log").open("wb") as log:
            result = subprocess.run(["ip", "netns", "exec", self.server, "bash",
                                     str(ROOT / "tests/vpn-production-server.sh"), self.args.installer,
                                     action, str(self.state)], stdout=log, stderr=subprocess.STDOUT,
                                    env=dict(os.environ, VPN_E2E_DISPOSABLE="1", TERM="xterm"), timeout=120)
        if result.returncode:
            raise RuntimeError(f"production helper {action} failed: see {action}.log")

    def setup(self):
        # This fixture intentionally uses the installer's real /etc/ocserv paths.
        if Path("/etc/ocserv/ssl/ca-key.pem").exists() or Path("/etc/ocserv/ocpasswd").exists():
            raise RuntimeError("refusing to overwrite existing VPN credentials")
        for ns in (self.server, self.edge, self.target):
            self.namespace(ns)
        self.ip(self.edge, "link", "add", "bridge0", "type", "bridge")
        self.ip(self.edge, "link", "set", "bridge0", "up")
        self.address(self.edge, "bridge0", "192.0.2.254/24", "fd42:1::fe/64")
        self.link(self.server, "wan", self.edge, "to-server")
        self.address(self.server, "wan", "198.18.0.1/24", "fd42:3::1/64")
        self.address(self.edge, "to-server", "198.18.0.254/24", "fd42:3::fe/64")
        self.address(self.server, "lo", "192.0.2.1/32", "fd42:1::1/128")
        self.ip(self.edge, "route", "add", "192.0.2.1/32", "via", "198.18.0.1")
        self.ip(self.edge, "-6", "route", "add", "fd42:1::1/128", "via", "fd42:3::1")
        self.ip(self.server, "route", "add", "192.0.2.0/24", "via", "198.18.0.254")
        self.ip(self.server, "-6", "route", "add", "fd42:1::/64", "via", "fd42:3::fe")
        self.link(self.server, "ve", self.target, "vt")
        self.address(self.server, "ve", "198.51.100.1/24", "fd42:2::1/64")
        self.address(self.target, "vt", "198.51.100.2/24", "fd42:2::2/64")
        self.ip(self.server, "route", "add", "default", "via", V4_TARGET)
        self.ip(self.server, "-6", "route", "add", "default", "via", V6_TARGET)
        self.ip(self.target, "-6", "route", "add", "fd42:7::/48", "via", "fd42:2::1")
        run(["sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"], ns=self.edge)
        for n in range(self.args.clients):
            self.clients.append(Client(self, n))
        payload = secrets.token_bytes(1024 * 1024)
        (self.state / "payload").write_bytes(payload)
        self.digest = hashlib.sha256(payload).hexdigest()
        (self.state / "account.input").write_text(f"qa-user\n{self.password}\n")
        with (self.state / "target.log").open("wb") as log:
            target = subprocess.Popen(["ip", "netns", "exec", self.target, "python3",
                                       str(ROOT / "tests/vpn-target.py"), "--payload", str(self.state / "payload"),
                                       "--address6", V6_TARGET], stdout=log, stderr=subprocess.STDOUT)
        self.processes.append(target)
        wait_for(lambda: "ready " in (self.state / "target.log").read_text(), 10, "dual-stack target")
        self.bootstrap("configure")
        self.profile("stateful")
        self.clients[0].unreachable(4)
        self.clients[0].unreachable(6)
        with (self.state / "server.log").open("wb") as log:
            server = subprocess.Popen(["ip", "netns", "exec", self.server, "/usr/local/sbin/ocserv",
                                       "--foreground", "--debug", "1", "-c", "/etc/ocserv/ocserv.conf"],
                                      stdout=log, stderr=subprocess.STDOUT)
        self.daemon = server
        self.processes.append(server)
        wait_for(lambda: ":4443" in text(["ss", "-Hltn"], ns=self.server), 20, "ocserv listener")
        self.report["versions"] = {name: version_line(name)
                                   for name in ("openconnect", "/usr/local/sbin/ocserv")}
        self.report["os_release"] = Path("/etc/os-release").read_text()
        self.passed("IPv4/IPv6 forwarding persisted; firewall rules idempotent; no pre-tunnel target access")

    def profile(self, name):
        for family, tool, destination in ((4, "iptables", "192.0.2.1"), (6, "ip6tables", "fd42:1::1")):
            run([tool, "-F", "FORWARD"], ns=self.edge)
            run([tool, "-P", "FORWARD", "DROP"], ns=self.edge)
            if name == "no-ipv6" and family == 6:
                continue
            if name == "tcp-closed":
                continue
            if name == "udp-closed":
                run([tool, "-A", "FORWARD", "-p", "udp", "--dport", "4443", "-j", "DROP"], ns=self.edge)
            for protocol in ("tcp", "udp"):
                run([tool, "-A", "FORWARD", "-d", destination, "-p", protocol, "--dport", "4443", "-j", "ACCEPT"], ns=self.edge)
                if name == "stateless":
                    run([tool, "-A", "FORWARD", "-s", destination, "-p", protocol, "--sport", "4443",
                         "--dport", "1024:65535", "-j", "ACCEPT"], ns=self.edge)
            if name not in ("stateless", "no-return"):
                run([tool, "-A", "FORWARD", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], ns=self.edge)
            run([tool, "-A", "FORWARD", "-p", "ipv6-icmp" if family == 6 else "icmp", "-j", "ACCEPT"], ns=self.edge)

    def tcp_blocked(self, family):
        address = "fd42:1::1" if family == 6 else "192.0.2.1"
        probe = ("import socket,sys; s=socket.socket(socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET); "
                 "s.settimeout(2); sys.exit(0 if s.connect_ex((sys.argv[1],4443)) else 1)")
        run(["python3", "-c", probe, address], ns=self.clients[0].ns)
        tool = "ip6tables" if family == 6 else "iptables"
        policy = text([tool, "-nvxL", "FORWARD"], ns=self.edge).splitlines()[0]
        if not re.search(r"policy DROP [1-9][0-9]* packets", policy):
            raise RuntimeError("expected upstream-drop counter did not increase")

    def functional(self):
        client = self.clients[0]
        for family in (4, 6):
            for dtls in (False, True):
                client.start(family, dtls, password=not dtls)
                before = client.counter()
                for payload_family in (4, 6):
                    client.transfer(payload_family)
                    client.transfer(payload_family, upload=True)
                delta = client.counter() - before
                if (dtls and delta < 1_500_000) or (not dtls and delta != 0):
                    raise RuntimeError("data plane transport did not match TLS/DTLS assertion")
                client.dns()
                self.passed(f"IPv{family} underlay / {'DTLS' if dtls else 'TLS'}: dual-stack uploads, downloads, DNS and source addresses")
                client.stop()
                client.unreachable(6)
        client.start(6)
        run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=0"], ns=self.server)
        client.unreachable(6)
        run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"], ns=self.server)
        client.transfer(6)
        run(["ip6tables", "-I", "FORWARD", "-i", "vpns+", "-d", V6_TARGET, "-j", "DROP"], ns=self.server)
        client.unreachable(6)
        run(["ip6tables", "-D", "FORWARD", "-i", "vpns+", "-d", V6_TARGET, "-j", "DROP"], ns=self.server)
        client.transfer(6)
        self.passed("IPv6 runtime forwarding and scoped FORWARD drops break data; restoring each restores data")
        client.stop()
        for profile, family in (("tcp-closed", 4), ("no-return", 4), ("no-ipv6", 6)):
            self.profile(profile)
            self.tcp_blocked(family)
            self.profile("stateful")
            client.start(family)
            client.transfer(6)
            client.stop()
            self.passed(f"upstream {profile}: counter-backed denial and successful recovery")
        self.profile("udp-closed")
        client.start(4, dtls=True, expect_dtls=False)
        time.sleep(2)
        before = client.counter()
        client.transfer(6)
        if client.counter() != before or "Established DTLS connection" in client.log.read_text(errors="replace"):
            raise RuntimeError("blocked UDP profile unexpectedly used DTLS")
        client.stop()
        self.passed("upstream UDP blocked: real TCP fallback transfers IPv6 payload")
        self.profile("stateless")
        client.start(6)
        client.transfer(6)
        client.stop()
        self.passed("stateless upstream requires explicit ephemeral-port return rules")
        self.profile("stateful")
        for ns, dev in ((self.edge, "to-server"), (self.server, "wan")):
            self.ip(ns, "link", "set", dev, "mtu", "1280")
        client.start(6)
        client.transfer(6)
        client.transfer(6, upload=True)
        client.stop()
        self.passed("1280-byte IPv6 underlay supports large, hash-verified transfers")
        for ns, dev in ((self.edge, "to-server"), (self.server, "wan")):
            self.ip(ns, "link", "set", dev, "mtu", "1500")

    def telemetry(self):
        rss, fds, ticks = 0, 0, 0
        for pid in text(["ip", "netns", "pids", self.server]).splitlines():
            try:
                proc = Path("/proc") / pid
                if "ocserv" not in (proc / "comm").read_text():
                    continue
                status = (proc / "status").read_text()
                value = re.search(r"^VmRSS:\s+(\d+)", status, re.M)
                rss += int(value.group(1)) if value else 0
                fds += len(list((proc / "fd").iterdir()))
                fields = (proc / "stat").read_text().rsplit(")", 1)[1].split()
                ticks += int(fields[11]) + int(fields[12])
            except (FileNotFoundError, ProcessLookupError):
                continue
        return {"seconds": round(time.monotonic() - self.started, 2), "rss_kib": rss,
                "fds": fds, "cpu_ticks": ticks,
                "conntrack": text(["sysctl", "-n", "net.netfilter.nf_conntrack_count"], ns=self.server)}

    def soak(self):
        self.started = time.monotonic()
        # Mix transport, authentication and server address families concurrently.
        leases4, leases6 = set(), set()
        for number, client in enumerate(self.clients):
            client.start(6 if number % 2 else 4, dtls=bool(number % 2), password=not bool(number % 2))
            leases4.add((client.state / "address").read_text().strip())
            leases6.add((client.state / "address6").read_text().strip())
        if len(leases4) != len(self.clients) or len(leases6) != len(self.clients) or "" in leases6:
            raise RuntimeError("concurrent clients did not receive distinct IPv4/IPv6 leases")
        self.report["achieved_clients"] = len(leases4)
        counters = [c.counter() for c in self.clients]
        stats = [{"client": c.number, "cycles": 0, "bytes": 0, "max_request_seconds": 0.0} for c in self.clients]
        deadline = time.monotonic() + self.args.duration
        stop = threading.Event()
        def worker(client, stat):
            while time.monotonic() < deadline and not stop.is_set():
                for family in (4, 6):
                    for upload in (False, True):
                        delay = client.transfer(family, upload=upload)
                        stat["max_request_seconds"] = max(stat["max_request_seconds"], delay)
                        stat["bytes"] += 1024 * 1024
                stat["cycles"] += 1
            return stat
        samples = []
        load_start = time.monotonic()
        with ThreadPoolExecutor(max_workers=len(self.clients)) as executor:
            futures = [executor.submit(worker, c, s) for c, s in zip(self.clients, stats)]
            try:
                while time.monotonic() < deadline:
                    for future in futures:
                        if future.done() and future.exception():
                            raise future.exception()
                    if self.daemon.poll() is not None:
                        raise RuntimeError("ocserv exited during sustained traffic")
                    samples.append(self.telemetry())
                    time.sleep(min(1, max(0, deadline - time.monotonic())))
                for future in futures:
                    future.result(timeout=30)
            finally:
                stop.set()
        actual = time.monotonic() - load_start
        for c, before, stat in zip(self.clients, counters, stats):
            if stat["cycles"] < 1:
                raise RuntimeError("an authenticated client never completed a load cycle")
            delta = c.counter() - before
            if c.dtls and delta < stat["bytes"] / 4:
                raise RuntimeError("DTLS client silently used TCP during the soak")
            if not c.dtls and delta:
                raise RuntimeError("TCP-only client sent VPN data over UDP")
            stat["udp_received_bytes"] = delta
            c.stop()
        wait_for(lambda: "qa-user" not in text(["occtl", "--socket-file", str(self.state / "occtl.socket"), "show", "users"], ns=self.server),
                 15, "session cleanup after soak")
        wait_for(lambda: "vpns" not in text(["ip", "-o", "link", "show"], ns=self.server),
                 15, "TUN cleanup after disconnect")
        time.sleep(2)
        after = self.telemetry()
        self.report["soak"] = {"elapsed_seconds": round(actual, 3), "clients": stats, "samples": samples,
                               "after_disconnect": after,
                               "aggregate_mbit_per_second": round(sum(s["bytes"] for s in stats) * 8 / actual / 1e6, 3)}
        # A bounded post-disconnect regression budget, not a claim of no memory leaks.
        if samples and after["rss_kib"] > samples[0]["rss_kib"] + 65536:
            raise RuntimeError("quiescent RSS exceeds warm connected RSS by more than 64 MiB")
        self.passed(f"{len(self.clients)} concurrent mixed clients, {actual:.1f}s continuous bidirectional dual-stack traffic; sessions and TUNs cleaned")

    def close(self):
        for client in self.clients:
            client.stop()
        for process in reversed(self.processes):
            stop_process(process)
        for ns in reversed(self.namespaces):
            try:
                for pid in text(["ip", "netns", "pids", ns]).splitlines():
                    run(["kill", "-TERM", pid], check=False)
                run(["ip", "netns", "del", ns], check=False)
            except Exception:
                pass
            shutil.rmtree(Path("/etc/netns") / ns, ignore_errors=True)
        for path in self.state.rglob("*.log"):
            relative = str(path.relative_to(self.state)).replace("/", "-")
            (self.logs / relative).write_text(redact(path.read_text(errors="replace"), self.password))
        self.save_report()
        shutil.rmtree(self.state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installer", choices=["ocserv.sh", "ocserv-en.sh"], required=True)
    parser.add_argument("--clients", type=int, default=4)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--log-dir", required=True)
    args = parser.parse_args()
    if not (1 <= args.clients <= 100 and 1 <= args.duration <= 7200):
        parser.error("clients must be 1..100 and duration 1..7200 seconds")
    if os.geteuid() != 0 or os.environ.get("VPN_E2E_DISPOSABLE") != "1" or not Path("/dev/net/tun").exists():
        parser.error("requires root, TUN and VPN_E2E_DISPOSABLE=1 on a disposable system")
    for command in ("ip", "iptables", "ip6tables", "openconnect", "curl", "dig", "ss", "occtl"):
        if not shutil.which(command):
            parser.error(f"missing dependency: {command}")
    def interrupted(signum, frame):
        raise InterruptedError(f"received signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    lab = Lab(args)
    try:
        lab.setup()
        lab.functional()
        lab.soak()
        stop_process(lab.daemon)
        lab.bootstrap("cleanup")
        lab.passed("IPv6 rule removal is idempotent and saved/reloaded unrelated rules survive")
        lab.report["status"] = "passed"
    except BaseException as exc:
        lab.report["status"] = "failed"
        lab.report["error"] = redact(str(exc), lab.password)
        raise
    finally:
        lab.close()


if __name__ == "__main__":
    main()

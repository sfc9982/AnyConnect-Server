#!/usr/bin/env python3
"""Boot a checksum-verified Ubuntu cloud image in QEMU and test the real installer.

No cloud account, existing VPS or production SSH key is used. SSH host identity is
pinned to an ephemeral key injected into the private NoCloud seed. The guest is
actually rebooted; changed boot IDs and automatic service activation are required.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import shlex
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time

from vpn_lab import ROOT, redact, run, stop_process, text, wait_for


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class VM:
    def __init__(self, args):
        self.args = args
        self.state = Path(tempfile.mkdtemp(prefix="vpn-qemu-"))
        self.logs = Path(args.log_dir).resolve()
        self.logs.mkdir(parents=True, exist_ok=True)
        ports = set()
        while len(ports) < 3:
            ports.add(free_port())
        self.port, self.target_port, self.dns_port = sorted(ports)
        self.password = secrets.token_hex(24)
        self.qemu, self.target = None, None
        self.report = {"status": "running", "image": args.image, "installer": args.installer,
                       "checks": [], "boot_ids": [], "scope": "real QEMU guest boot and IPv4 VPN egress, not a public VPS"}
        self.ssh = ["ssh", "-i", str(self.state / "client-key"), "-p", str(self.port),
                    "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
                    "-o", f"UserKnownHostsFile={self.state / 'known_hosts'}", "-o", "ConnectTimeout=3",
                    "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "root@127.0.0.1"]

    def remote(self, command, **kwargs):
        return run(self.ssh + [command], **kwargs)

    def copy(self, path, destination):
        # SFTP is provided by the standard cloud image; use the same pinned host key.
        options = self.ssh[1:-1]
        options[options.index("-p")] = "-P"
        run(["scp", *options, str(path), f"root@127.0.0.1:{destination}"], timeout=120)

    def ready(self, previous=None):
        if self.qemu.poll() is not None:
            raise RuntimeError("QEMU exited before guest became ready")
        try:
            result = self.remote("cat /proc/sys/kernel/random/boot_id", check=False, timeout=10)
        except subprocess.TimeoutExpired:
            return False
        if result.returncode:
            return False
        boot = result.stdout.decode().strip()
        if previous and boot == previous:
            return False
        self.boot_id = boot
        return True

    def passed(self, check):
        self.report["checks"].append(check)
        print(f"PASS: {check}", flush=True)
        self.save()

    def save(self):
        (self.logs / "result.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def guest(self, action, *args, timeout=90):
        command = shlex.join(["env", "VPN_E2E_DISPOSABLE=1", "bash", "/root/vpn-src/tests/vpn-boot-guest.sh",
                              self.args.installer, action, "/root/vpn-state", *args])
        result = self.remote(command, check=False, timeout=timeout)
        (self.logs / f"guest-{action}.log").write_text(redact(
            (result.stdout + result.stderr).decode(errors="replace"), self.password))
        if result.returncode:
            raise RuntimeError(f"guest {action} failed ({result.returncode}); see guest-{action}.log")
        return result.stdout.decode()

    def download(self):
        name = f"{self.args.image}-server-cloudimg-amd64.img"
        base = f"https://cloud-images.ubuntu.com/{self.args.image}/current"
        for remote, local in (("SHA256SUMS", "checksums"), (name, "base.img")):
            run(["curl", "--fail", "--location", "--retry", "3", "--proto", "=https", "--proto-redir", "=https",
                 "--connect-timeout", "20", "--max-time", "900", "-o", str(self.state / local), f"{base}/{remote}"], timeout=1000)
        expected = [line.split()[0] for line in (self.state / "checksums").read_text().splitlines()
                    if line.split()[-1].lstrip("*") == name]
        actual = hashlib.sha256()
        with (self.state / "base.img").open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                actual.update(block)
        if len(expected) != 1 or actual.hexdigest() != expected[0]:
            raise RuntimeError("official cloud-image SHA256 verification failed")
        self.report.update(image_url=f"{base}/{name}", image_sha256=actual.hexdigest())
        info = json.loads(text(["qemu-img", "info", "--output=json", self.state / "base.img"]))
        run(["qemu-img", "create", "-f", "qcow2", "-F", info["format"], "-b", self.state / "base.img", self.state / "guest.qcow2", "20G"])

    def start(self):
        self.download()
        for key in ("client-key", "host-key"):
            run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", self.state / key])
        client = (self.state / "client-key.pub").read_text().strip()
        host = (self.state / "host-key.pub").read_text().strip()
        (self.state / "known_hosts").write_text(f"[127.0.0.1]:{self.port} {host}\n")
        host_private = "\n".join("    " + line for line in (self.state / "host-key").read_text().splitlines())
        user_data = ("#cloud-config\ndisable_root: false\nssh_pwauth: false\nssh_deletekeys: true\n"
                     f"users:\n  - name: root\n    ssh_authorized_keys:\n      - {client}\n"
                     f"ssh_keys:\n  ed25519_private: |\n{host_private}\n  ed25519_public: {host}\n"
                     "ssh_quiet_keygen: true\nssh_publish_hostkeys:\n  enabled: false\n")
        (self.state / "user-data").write_text(user_data)
        (self.state / "meta-data").write_text(f"instance-id: vpn-qa-{secrets.token_hex(8)}\nlocal-hostname: vpn-qa\n")
        run(["cloud-localds", self.state / "seed.img", self.state / "user-data", self.state / "meta-data"])
        payload = secrets.token_bytes(1024 * 1024)
        (self.state / "payload").write_bytes(payload)
        with (self.state / "target.log").open("wb") as log:
            self.target = subprocess.Popen(["python3", str(ROOT / "tests/vpn-target.py"), "--address", "127.0.0.1",
                                            "--http-port", str(self.target_port), "--dns-port", str(self.dns_port),
                                            "--payload", str(self.state / "payload")], stdout=log, stderr=subprocess.STDOUT)
        wait_for(lambda: "ready " in (self.state / "target.log").read_text(), 10, "host target")
        accelerator = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg,thread=multi"
        self.report["accelerator"] = accelerator
        with (self.state / "console.log").open("wb") as log:
            self.qemu = subprocess.Popen(["qemu-system-x86_64", "-accel", accelerator, "-m", "2048", "-smp", "2",
                "-drive", f"file={self.state / 'guest.qcow2'},format=qcow2,if=virtio",
                "-drive", f"file={self.state / 'seed.img'},format=raw,if=virtio",
                "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.port}-:22",
                "-nographic", "-monitor", "none"], stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
        wait_for(self.ready, 420, "first systemd guest boot with pinned SSH host key")
        self.remote("cloud-init status --wait", timeout=240)
        self.remote("test \"$(cat /proc/1/comm)\" = systemd && mkdir -m 700 /root/vpn-state /root/vpn-src")
        self.report["boot_ids"].append(self.boot_id)
        # Archive only tracked project paths; never include host keys, images or private state.
        with tarfile.open(self.state / "source.tar", "w") as archive:
            for path in (list(ROOT.glob("ocserv*.sh")) + [ROOT / "ocserv.conf", ROOT / "tests"]):
                archive.add(path, arcname=path.name, filter=lambda item: None if "__pycache__" in item.name else item)
        self.copy(self.state / "source.tar", "/root/source.tar")
        self.remote("tar -xf /root/source.tar -C /root/vpn-src")
        fixtures = {"install.input": f"qa-user\n{self.password}\n4443\n4443\n", "password": self.password + "\n",
                    "target-port": str(self.target_port), "expected-sha256": hashlib.sha256(payload).hexdigest()}
        for name, value in fixtures.items():
            path = self.state / name
            path.write_text(value)
            path.chmod(0o600)
            self.copy(path, f"/root/vpn-state/{name}")
        self.passed("checksum-verified guest boots with systemd PID 1; SSH host key verified")

    def reboot(self):
        previous = self.boot_id
        self.remote("systemctl reboot", check=False, timeout=20)
        wait_for(lambda: self.ready(previous), 300, "a different kernel boot ID after reboot")
        self.report["boot_ids"].append(self.boot_id)

    def tests(self):
        self.guest("install", timeout=1200)
        self.guest("inspect")
        self.guest("probe", "tls")
        self.passed("normal Install_ocserv sequence, real units, automatic dependencies and TLS egress")
        self.remote("systemctl restart ocserv")
        self.guest("probe", "dtls")
        self.passed("real service restart restores DTLS data plane")
        previous_pid = self.remote("systemctl show ocserv -p MainPID --value").stdout.strip()
        self.remote("systemctl kill --kill-who=main --signal=SIGKILL ocserv")
        def restarted():
            result = self.remote("systemctl is-active --quiet ocserv && systemctl show ocserv -p MainPID --value", check=False)
            return result.returncode == 0 and result.stdout.strip() not in (b"0", previous_pid)
        wait_for(restarted, 45, "Restart=on-failure replaces the killed daemon")
        self.guest("probe", "dtls")
        self.passed("unexpected daemon death is automatically recovered by systemd")
        self.remote("systemctl stop ocserv")
        self.guest("stopped")
        self.remote("systemctl start ocserv")
        self.guest("probe", "tls")
        self.passed("explicit stop closes listeners; explicit start restores traffic")
        self.reboot()
        self.guest("inspect")
        self.guest("probe", "dtls")
        self.passed("real kernel reboot: no manual start, unchanged credentials and firewall rules, live forwarding and traffic")
        self.guest("uninstall")
        self.reboot()
        self.guest("stopped")
        self.remote("test ! -e /etc/systemd/system/ocserv.service && test ! -e /usr/local/sbin/ocserv")
        self.passed("uninstall followed by another real reboot does not resurrect VPN service")
        self.report["status"] = "passed"

    def close(self):
        if self.qemu is not None and self.qemu.poll() is None:
            try:
                result = self.remote("journalctl -b -u ocserv -u ocserv-firewall --no-pager; uname -a", check=False)
                (self.logs / "journal.log").write_text(redact((result.stdout + result.stderr).decode(errors="replace"), self.password))
            except Exception:
                pass
        stop_process(self.qemu)
        stop_process(self.target)
        for name in ("console.log", "target.log"):
            if (self.state / name).exists():
                (self.logs / name).write_text(redact((self.state / name).read_text(errors="replace"), self.password))
        self.save()
        shutil.rmtree(self.state)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", choices=["noble", "jammy"], default="noble")
    parser.add_argument("--installer", choices=["ocserv.sh", "ocserv-en.sh"], required=True)
    parser.add_argument("--log-dir", required=True)
    args = parser.parse_args()
    for command in ("qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh", "scp", "ssh-keygen", "curl"):
        if not shutil.which(command):
            parser.error(f"missing dependency: {command}")
    def interrupted(signum, frame):
        raise InterruptedError(f"received signal {signum}")
    signal.signal(signal.SIGTERM, interrupted)
    vm = VM(args)
    try:
        vm.start()
        vm.tests()
    except BaseException as exc:
        vm.report.update(status="failed", error=redact(str(exc), vm.password))
        raise
    finally:
        vm.close()


if __name__ == "__main__":
    main()

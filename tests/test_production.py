"""Fast protocol/fixture regressions; no root or external networking required."""
import errno
import hashlib
import http.client
import importlib.util
import ipaddress
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from vpn_lab import redact, stop_process, wait_for, version_line

spec = importlib.util.spec_from_file_location("target", Path(__file__).with_name("vpn-target.py"))
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)
probe_spec = importlib.util.spec_from_file_location("probe", Path(__file__).with_name("vpn-probe.py"))
probe = importlib.util.module_from_spec(probe_spec)
probe_spec.loader.exec_module(probe)


def question(kind=1, name="vpn-test.internal"):
    labels = b"".join(bytes([len(x)]) + x.encode("ascii") for x in name.split("."))
    return struct.pack("!6H", 42, 256, 1, 0, 0, 0) + labels + b"\0" + struct.pack("!HH", kind, 1)


class ProductionTests(unittest.TestCase):
    def test_external_preflight_rejects_reachable_http(self):
        for code in (301, 401, 404, 500):
            with patch.object(probe, 'download', side_effect=urllib.error.HTTPError(
                    'http://127.0.0.1/payload', code, 'test', {}, None)):
                with self.assertRaisesRegex(RuntimeError, 'returned HTTP'):
                    probe.require_target_unreachable('http://127.0.0.1/payload')
        with patch.object(probe, 'download', side_effect=urllib.error.URLError(
                OSError(errno.ENETUNREACH, 'network unreachable'))):
            probe.require_target_unreachable('http://127.0.0.1/payload')
        with patch.object(probe, 'download', side_effect=urllib.error.URLError('bad certificate')):
            with self.assertRaisesRegex(RuntimeError, 'non-network'):
                probe.require_target_unreachable('https://127.0.0.1/payload')
        self.assertIsNone(probe.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://other.invalid'))

    def test_external_readiness_accepts_missing_route_until_connected(self):
        address = ipaddress.ip_address('fd42:2::2')
        for status, route, expected in ((2, '', False), (0, 'dev eth0', False), (0, 'dev vpntest', True)):
            with patch.object(probe.subprocess, 'run', return_value=
                    subprocess.CompletedProcess([], status, route, '')):
                self.assertEqual(probe.route_uses_tunnel(address), expected)

    def test_version_output_on_either_stream(self):
        for stdout, stderr in ((b'OpenConnect 9.12\n', b''),
                               (b'', b'OpenConnect VPN Server 1.5.0\n')):
            with self.subTest(stdout=stdout), patch('vpn_lab.run', return_value=
                    subprocess.CompletedProcess([], 0, stdout, stderr)):
                self.assertEqual(version_line('test-client'), (stdout + stderr).decode().strip())
        with patch('vpn_lab.run', return_value=subprocess.CompletedProcess([], 0, b'', b'')):
            with self.assertRaisesRegex(RuntimeError, 'no version output'):
                version_line('test-client')

    def test_dns_records_and_failure_codes(self):
        address = ipaddress.ip_address("198.51.100.2")
        address6 = ipaddress.ip_address("fd42:2::2")
        for kind, expected in ((1, address), (28, address6)):
            answer = target.dns_reply(question(kind), address, address6)
            self.assertEqual(struct.unpack("!6H", answer[:12])[3], 1)
            self.assertTrue(answer.endswith(expected.packed))
        self.assertEqual(struct.unpack("!6H", target.dns_reply(question(28), address)[:12])[3], 0)
        for data, code in ((b"bad", 1), (question(name="outside.example"), 3)):
            self.assertEqual(struct.unpack("!6H", target.dns_reply(data, address)[:12])[1] & 15, code)

    def test_redaction(self):
        value = redact("password=secret\nSet-Cookie: credential\nwebvpn=abc\nAuthorization: xyz\nokay", "secret")
        for secret in ("secret", "credential\n", "abc", "xyz"):
            self.assertNotIn(secret, value)
        self.assertIn("okay", value)

    def test_real_dual_stack_http_upload_and_dns(self):
        def port():
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                return sock.getsockname()[1]
        ports = set()
        while len(ports) < 2:
            ports.add(port())
        http_port, dns_port = sorted(ports)
        payload = os.urandom(32768)
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            (state / "payload").write_bytes(payload)
            with (state / "log").open("wb") as log:
                process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("vpn-target.py")),
                    "--address", "127.0.0.1", "--address6", "::1", "--http-port", str(http_port),
                    "--dns-port", str(dns_port), "--payload", str(state / "payload")], stdout=log, stderr=log)
            try:
                wait_for(lambda: "ready " in (state / "log").read_text(), 5, "local fixture readiness")
                for host, family in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)):
                    connection = http.client.HTTPConnection(host, http_port, timeout=3)
                    connection.request("GET", "/payload")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), payload)
                    connection.close()
                    for data, code in ((payload, 200), (b"x" * len(payload), 422), (b"x", 400)):
                        connection = http.client.HTTPConnection(host, http_port, timeout=3)
                        connection.request("POST", "/payload", data)
                        response = connection.getresponse()
                        self.assertEqual(response.status, code)
                        answer = response.read()
                        if code == 200:
                            self.assertEqual(answer.decode().strip(), hashlib.sha256(payload).hexdigest())
                        connection.close()
                    with socket.socket(family, socket.SOCK_DGRAM) as sock:
                        sock.settimeout(2)
                        sock.sendto(question(28), (host, dns_port))
                        self.assertTrue(sock.recv(4096).endswith(ipaddress.ip_address("::1").packed))
                    with socket.socket(family, socket.SOCK_STREAM) as sock:
                        sock.settimeout(2)
                        sock.connect((host, dns_port))
                        query = question(1)
                        sock.sendall(struct.pack("!H", len(query)) + query)
                        length = struct.unpack("!H", target.receive_exact(sock, 2))[0]
                        self.assertTrue(target.receive_exact(sock, length).endswith(ipaddress.ip_address("127.0.0.1").packed))
            finally:
                stop_process(process)


if __name__ == "__main__":
    unittest.main()

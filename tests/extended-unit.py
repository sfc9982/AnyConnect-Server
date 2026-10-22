#!/usr/bin/env python3
"""Unprivileged regression tests for the data fixture and report primitives."""
import hashlib
import http.server
import importlib.util
import os
import re
import subprocess
import socket
import struct
import threading
import unittest
import urllib.request
from pathlib import Path

spec = importlib.util.spec_from_file_location('workload', Path(__file__).with_name('vpn-workload.py'))
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


def query(name, kind):
    return struct.pack('!HHHHHH', 42, 0x100, 1, 0, 0, 0) + b''.join(
        bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\0' + struct.pack('!HH', kind, 1)


class FixtureTests(unittest.TestCase):
    def test_route_assertion_consumes_output_and_rejects_wrong_devices(self):
        # Exercise the same Bash assertion used in the network job, without root.
        source = Path(__file__).with_name('vpn-extended.sh').read_text()
        function = re.search(r'(?ms)^require_route_device\(\) \{\n.*?^\}', source)
        self.assertIsNotNone(function)
        script = """set -euo pipefail
fail() { printf '%s\\n' "$*" >&2; exit 1; }
ip() {
    printf '%s\\n' "$TEST_ROUTE"
    sleep .05
    printf '    cache\\n'
    return "$TEST_STATUS"
}
""" + function.group() + '\nrequire_route_device fixture fd42:99::1 vc\n'
        for route, status, passed in (
                ('fd42:99::1 via fd42:10::ffff dev vc src fd42:10::10', '0', True),
                ('fd42:99::1 dev vpntest src fd42:70::1', '0', False),
                ('fd42:99::1 dev vc-extra src fd42:10::10', '0', False),
                ('fd42:99::1 dev vc src fd42:10::10', '2', False)):
            with self.subTest(route=route, status=status):
                result = subprocess.run(['bash', '-c', script], capture_output=True,
                    env=dict(os.environ, TEST_ROUTE=route, TEST_STATUS=status), timeout=5)
                self.assertEqual(result.returncode == 0, passed, result.stderr.decode())

    def test_a(self):
        reply = w.dns_reply(query(w.NAME, 1))
        self.assertEqual(reply[-4:], socket.inet_aton(w.V4))
        self.assertEqual(struct.unpack('!H', reply[6:8])[0], 1)

    def test_aaaa(self):
        reply = w.dns_reply(query(w.NAME, 28))
        self.assertEqual(reply[-16:], socket.inet_pton(socket.AF_INET6, w.V6))
        self.assertEqual(struct.unpack('!H', reply[6:8])[0], 1)

    def test_unknown_name(self):
        reply = w.dns_reply(query('other.invalid', 1))
        self.assertEqual(reply[3] & 15, 3)
        self.assertEqual(struct.unpack('!H', reply[6:8])[0], 0)

    def test_unknown_type(self):
        reply = w.dns_reply(query(w.NAME, 15))
        self.assertEqual(struct.unpack('!H', reply[6:8])[0], 0)

    def test_malformed(self):
        for data in (b'', b'\0'*12, query(w.NAME, 28)[:-1], query(w.NAME, 1)[:14],
                     query(w.NAME, 1)[:12] + b'\xc0\x0c\0\1\0\1'):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    w.dns_reply(data)

    def test_http_integrity_and_upload(self):
        with http.server.ThreadingHTTPServer(('127.0.0.1', 0), w.HTTP) as server:
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            try:
                base = 'http://127.0.0.1:' + str(server.server_port)
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(base + '/payload', timeout=5) as response:
                    data = response.read()
                    self.assertEqual(response.headers['X-Seen-Client-IP'], '127.0.0.1')
                self.assertEqual(len(data), 1048576)
                self.assertEqual(hashlib.sha256(data).hexdigest(), w.DIGEST)
                with opener.open(urllib.request.Request(base + '/upload', data=data), timeout=5) as response:
                    self.assertEqual(response.read().decode(), w.DIGEST)
            finally:
                server.shutdown()
                thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Unit checks for the qualification tools; these are not VPN acceptance."""
import importlib.util
from pathlib import Path
import socket
import selectors
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('traffic', ROOT / 'traffic.py')
traffic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(traffic)

spec = importlib.util.spec_from_file_location('target', ROOT / 'target.py')
target = importlib.util.module_from_spec(spec)
spec.loader.exec_module(target)


spec = importlib.util.spec_from_file_location('diagnostics', ROOT / 'diagnostics.py')
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class FixtureTests(unittest.TestCase):
    def test_integrity_ipv4_ipv6_and_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = bytes(range(256)) * 256
            path = Path(temporary) / 'payload'
            path.write_bytes(payload)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                dns_port = sock.getsockname()[1]
            process = subprocess.Popen([sys.executable, str(ROOT / 'target.py'),
                '--address', '127.0.0.1', '--address', '::1', '--port', str(port),
                '--payload', str(path), '--dns-port', str(dns_port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with selectors.DefaultSelector() as ready:
                    ready.register(process.stdout, selectors.EVENT_READ)
                    self.assertTrue(ready.select(5), 'fixture readiness timed out')
                    self.assertEqual(process.stdout.readline(), b'ready\n')
                query = (struct.pack('!6H', 123, 0x0100, 1, 0, 0, 0)
                         + b'\x08vpn-test\x08internal\x00' + struct.pack('!HH', 28, 1))
                for family, host in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                        with socket.socket(family, kind) as sock:
                            sock.settimeout(2)
                            sock.connect((host, dns_port))
                            if kind == socket.SOCK_DGRAM:
                                sock.send(query)
                                response = sock.recv(1024)
                            else:
                                sock.sendall(struct.pack('!H', len(query)) + query)
                                def receive(length):
                                    data = b''
                                    while len(data) < length:
                                        piece = sock.recv(length - len(data))
                                        if not piece:
                                            self.fail('short TCP DNS reply')
                                        data += piece
                                    return data
                                length = struct.unpack('!H', receive(2))[0]
                                response = receive(length)
                            header = struct.unpack('!6H', response[:12])
                            self.assertEqual((header[0], header[1] & 15, header[3]), (123, 0, 1))
                            self.assertEqual(response[-16:], socket.inet_pton(socket.AF_INET6, '::1'))
                for host in ('127.0.0.1', '[::1]'):
                    count, peer = traffic.transfer(f'http://{host}:{port}', payload, 2)
                    self.assertEqual(count, 2 * len(payload))
                    self.assertIn(peer, ('127.0.0.1', '::1'))
                with self.assertRaises(ValueError):
                    traffic.transfer(f'http://127.0.0.1:{port}', b'x' * len(payload), 2)
                result = subprocess.run([sys.executable, str(ROOT / 'traffic.py'),
                    '--url', f'http://127.0.0.1:{port}', '--payload', str(path),
                    '--seconds', '1', '--workers', '2', '--output', str(Path(temporary) / 'result.json')],
                    capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())
            finally:
                process.terminate()
                process.communicate(timeout=5)

    def test_startup_never_needs_reverse_dns(self):
        from http.server import BaseHTTPRequestHandler
        with patch('socket.getfqdn', side_effect=AssertionError('external DNS lookup')):
            for cls, address in ((target.FixtureServer, '127.0.0.1'), (target.IPv6Server, '::1')):
                with cls((address, 0), BaseHTTPRequestHandler) as server:
                    self.assertEqual(server.server_name, address)

    def test_url_and_metric_bounds(self):
        with self.assertRaises(ValueError):
            traffic.transfer('ftp://127.0.0.1', b'x' * 1024, 1)
        self.assertIsNone(traffic.quantile([0, 0], .95))
        self.assertIsNone(traffic.quantile([0] * 2000 + [1], .95))
        self.assertEqual(traffic.quantile([1, 0, 1], .95), .03)

    def test_ipv6_sysctl_directory_created_on_minimal_images(self):
        # Exercise up() unchanged except redirecting filesystem paths into a
        # temporary tree; networking commands are controlled unit-test stubs.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / 'sysctl.d'
            helper = (ROOT.parent.parent / 'ocserv-network.sh').read_text()
            definitions = helper.split('\n[[ "$EUID" -eq 0 ]]', 1)[0]
            definitions = definitions.replace('/etc/sysctl.d', str(directory))
            setup = r"""
read_profile() { ingress=wan; egress=wan; device=vpns; pool=fd42:7::/64; tcp=4443; udp=4443; mode=routed; }
ip() { :; }
ip6tables() { :; }
chain() { :; }
rule() { :; }
sysctl() { if [[ "$1" == -n ]]; then printf '0\n'; fi; }
up
up
"""
            result = subprocess.run(['bash', '-c', definitions + setup],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((directory / '90-ocserv-ipv6.conf').read_text(),
                             'net.ipv6.conf.all.forwarding=1\n')
            self.assertEqual(len(list(directory.iterdir())), 1)

    def test_udp_drop_counter_formats(self):
        # Exercise the exact parser used by the network test, with both the
        # nft numeric-protocol output and legacy symbolic-protocol output.
        line = next(line for line in (ROOT / 'network.sh').read_text().splitlines()
                    if line.startswith("awk '") and 'blocked-udp' in line)
        program = line.split("'")[1]
        for protocol in ('udp', '17'):
            for packets, expected in ((4, 0), (0, 1)):
                row = (f'{packets} 784 DROP {protocol} -- * * 0.0.0.0/0 '
                       '0.0.0.0/0 /* blocked-udp */\n')
                result = subprocess.run(['awk', program], input=row, text=True,
                                        capture_output=True, timeout=2)
                self.assertEqual(result.returncode, expected)

    def test_transport_diagnostics_exclude_secrets_and_route_noise(self):
        lines = ['Established DTLS connection', 'Failed TLS handshake',
                 'DTLS password sentinel', 'DTLS session ID sentinel',
                 'X-DTLS-Master-Secret: sentinel', '< DTLS token sentinel',
                 'X-CSTP-Split-Exclude: 192.0.2.0/24']
        self.assertEqual(diagnostics.transport_lines('\n'.join(lines)), lines[:2])


if __name__ == '__main__':
    unittest.main()

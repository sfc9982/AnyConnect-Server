#!/usr/bin/env python3
"""Unit checks for the qualification tools; these are not VPN acceptance."""
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('traffic', ROOT / 'traffic.py')
traffic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(traffic)


class FixtureTests(unittest.TestCase):
    def test_integrity_ipv4_ipv6_and_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload = bytes(range(256)) * 256
            path = Path(temporary) / 'payload'
            path.write_bytes(payload)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            process = subprocess.Popen([sys.executable, str(ROOT / 'target.py'),
                '--address', '127.0.0.1', '--address', '::1', '--port', str(port),
                '--payload', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if process.poll() is not None:
                        self.fail(process.stderr.read().decode())
                    try:
                        connection = socket.create_connection(('127.0.0.1', port), timeout=.1)
                        connection.close()
                        break
                    except OSError:
                        if time.monotonic() > deadline:
                            self.fail('fixture readiness timed out')
                        time.sleep(.05)
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

    def test_url_and_metric_bounds(self):
        with self.assertRaises(ValueError):
            traffic.transfer('ftp://127.0.0.1', b'x' * 1024, 1)
        self.assertIsNone(traffic.quantile([0, 0], .95))
        self.assertEqual(traffic.quantile([1, 0, 1], .95), .03)


if __name__ == '__main__':
    unittest.main()

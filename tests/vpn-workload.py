#!/usr/bin/env python3
"""Isolated dual-stack HTTP/DNS/UDP fixtures and bounded integrity workloads.

No third-party Python dependencies. Reports contain measurements, not credentials.
"""
import argparse
import hashlib
import http.server
import ipaddress
import json
import os
import socket
import socketserver
import statistics
import struct
import threading
import time
import urllib.request
from collections import deque
from pathlib import Path

V4 = '198.51.100.2'
V6 = 'fd42:30::2'
NAME = 'vpn-test.internal'
PAYLOAD = hashlib.shake_256(b'AnyConnect-Server extended traffic fixture v1').digest(1048576)
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def dns_reply(data):
    if len(data) < 12 or struct.unpack('!H', data[4:6])[0] != 1:
        raise ValueError('one DNS question required')
    pos, labels = 12, []
    while True:
        if pos >= len(data):
            raise ValueError('short DNS question')
        size = data[pos]
        pos += 1
        if size == 0:
            break
        if size > 63 or pos + size > len(data):
            raise ValueError('invalid DNS label')
        labels.append(data[pos:pos + size].decode('ascii').lower())
        pos += size
    if pos + 4 > len(data):
        raise ValueError('missing DNS type/class')
    kind, cls = struct.unpack('!HH', data[pos:pos + 4])
    question = data[12:pos + 4]
    address = {1: V4, 28: V6}.get(kind)
    known = '.'.join(labels) == NAME and cls == 1
    answer = b''
    if known and address:
        packed = ipaddress.ip_address(address).packed
        answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 0, len(packed)) + packed
    flags = 0x8180 if known else 0x8183
    return data[:2] + struct.pack('!HHHHH', flags, 1, bool(answer), 0, 0) + question + answer


def read_exact(stream, count):
    result = bytearray()
    while len(result) < count:
        part = stream.read(count - len(result))
        if not part:
            raise ValueError('short frame')
        result.extend(part)
    return bytes(result)


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/payload':
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(PAYLOAD)))
        self.send_header('X-Seen-Client-IP', self.client_address[0])
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def do_POST(self):
        size = int(self.headers.get('Content-Length', '0'))
        if self.path != '/upload' or not 0 < size <= 4 * len(PAYLOAD):
            self.send_error(400)
            return
        self.connection.settimeout(15)
        body = hashlib.sha256(read_exact(self.rfile, size)).hexdigest().encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class DNSUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        try:
            sock.sendto(dns_reply(data), self.client_address)
        except (ValueError, UnicodeError):
            pass


class DNSTCP(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        try:
            size = struct.unpack('!H', read_exact(self.rfile, 2))[0]
            if not 0 < size <= 4096:
                return
            answer = dns_reply(read_exact(self.rfile, size))
            self.wfile.write(struct.pack('!H', len(answer)) + answer)
        except (ValueError, UnicodeError, OSError):
            pass


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if len(data) <= 1400:
            sock.sendto(data, self.client_address)


def serve():
    servers = []
    for family, host in ((socket.AF_INET, V4), (socket.AF_INET6, V6)):
        for base, handler, port in (
            (http.server.ThreadingHTTPServer, HTTP, 8080),
            (socketserver.ThreadingUDPServer, DNSUDP, 53),
            (socketserver.ThreadingTCPServer, DNSTCP, 53),
            (socketserver.ThreadingUDPServer, Echo, 9009),
        ):
            server_type = type('FixtureServer', (base,), {
                'address_family': family, 'allow_reuse_address': True,
                'daemon_threads': True, 'request_queue_size': 256,
            })
            server = server_type((host, port), handler)
            servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
    print('ready', flush=True)
    threading.Event().wait()


def load(duration, family, report):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    host = V4 if family == 4 else V6
    base = 'http://' + (host if family == 4 else '[' + host + ']') + ':8080'
    start = time.monotonic()
    latencies = deque(maxlen=4096)
    completed = 0
    with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as udp:
        udp.settimeout(5)
        udp.connect((host, 9009))
        while time.monotonic() - start < duration:
            then = time.monotonic()
            with opener.open(base + '/payload', timeout=15) as response:
                data = response.read(len(PAYLOAD) + 1)
            if len(data) != len(PAYLOAD) or hashlib.sha256(data).hexdigest() != DIGEST:
                raise RuntimeError('download integrity failure')
            request = urllib.request.Request(base + '/upload', data=PAYLOAD, method='POST')
            with opener.open(request, timeout=15) as response:
                if response.read(128).decode() != DIGEST:
                    raise RuntimeError('upload integrity failure')
            nonce = os.urandom(512)
            udp.send(nonce)
            if udp.recv(1400) != nonce:
                raise RuntimeError('UDP echo integrity failure')
            latencies.append((time.monotonic() - then) * 1000)
            completed += 1
    elapsed = time.monotonic() - start
    if not completed:
        raise RuntimeError('no completed work')
    ordered = sorted(latencies)
    result = dict(status='passed', address_family=family, requested_seconds=duration,
                  elapsed_seconds=elapsed, iterations=completed, udp_sent=completed,
                  udp_received=completed, downloaded_bytes=completed * len(PAYLOAD),
                  uploaded_bytes=completed * len(PAYLOAD),
                  application_mbps=completed * len(PAYLOAD) * 16 / elapsed / 1e6,
                  latency_sample_count=len(ordered), latency_window='last 4096 iterations',
                  latency_p50_ms=statistics.median(ordered),
                  latency_p95_ms=ordered[int((len(ordered) - 1) * .95)])
    Path(report).write_text(json.dumps(result, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('serve')
    sub.add_parser('digest')
    http_only = sub.add_parser('http')
    http_only.add_argument('--bind', default='127.0.0.1')
    http_only.add_argument('--port', type=int, default=18080)
    worker = sub.add_parser('load')
    worker.add_argument('--seconds', type=int, required=True, choices=range(1, 7201), metavar='1..7200')
    worker.add_argument('--family', type=int, choices=(4, 6), required=True)
    worker.add_argument('--report', required=True)
    args = parser.parse_args()
    if args.command == 'serve':
        serve()
    elif args.command == 'http':
        ipaddress.ip_address(args.bind)
        if not 1 <= args.port <= 65535:
            parser.error('invalid port')
        family = socket.AF_INET6 if ':' in args.bind else socket.AF_INET
        cls = type('HTTPFixture', (http.server.ThreadingHTTPServer,), {'address_family': family})
        with cls((args.bind, args.port), HTTP) as server:
            server.serve_forever()
    elif args.command == 'digest':
        print(DIGEST)
    else:
        load(args.seconds, args.family, args.report)


if __name__ == '__main__':
    main()

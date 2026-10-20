#!/usr/bin/env python3
"""Isolated HTTP and DNS destination for the real VPN integration tests."""

import argparse
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
from pathlib import Path
import signal
import socketserver
import struct
import threading


def dns_reply(packet, address):
    """Answer the test hostname without consulting any external resolver."""
    query_id = packet[:2].ljust(2, b"\0")
    flags = 0x8400  # Response from the authoritative test resolver.
    question = b""
    answer = b""
    rcode = 0
    try:
        _, request_flags, count, _, _, _ = struct.unpack("!6H", packet[:12])
        flags |= request_flags & 0x0100  # Preserve the recursion-desired bit.
        if count != 1 or request_flags & 0x8000:
            raise ValueError("expected one DNS question")
        if request_flags & 0x7800:
            rcode = 4  # Only standard queries are supported.
        else:
            offset = 12
            labels = []
            while True:
                length = packet[offset]
                offset += 1
                if length == 0:
                    break
                if length > 63 or offset + length > len(packet):
                    raise ValueError("invalid query name")
                labels.append(packet[offset:offset + length].decode("ascii"))
                offset += length
            qtype, qclass = struct.unpack("!2H", packet[offset:offset + 4])
            question = packet[12:offset + 4]
            if ".".join(labels).lower() != "vpn-test.internal":
                rcode = 3  # NXDOMAIN for every other hostname.
            elif qclass != 1:
                rcode = 4
            elif qtype == 1:
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 0, 4) + address.packed
    except (IndexError, UnicodeError, ValueError, struct.error):
        question = b""
        rcode = 1  # Malformed query; do not crash the test fixture.
    return query_id + struct.pack("!5H", flags | rcode, bool(question), bool(answer), 0, 0) + question + answer


def receive_exact(connection, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = connection.recv(length - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default="198.51.100.2", type=ipaddress.IPv4Address)
    parser.add_argument("--payload", required=True, type=Path)
    parser.add_argument("--http-port", default=8080, type=int)
    parser.add_argument("--dns-port", default=53, type=int)
    args = parser.parse_args()
    payload = args.payload.read_bytes()

    class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True

    class HTTPHandler(BaseHTTPRequestHandler):
        def respond(self, include_body):
            if self.path != "/payload":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Seen-Client-IP", self.client_address[0])
            self.end_headers()
            if include_body:
                self.wfile.write(payload)

        def do_GET(self):
            self.respond(True)

        def do_HEAD(self):
            self.respond(False)

    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, connection = self.request
            connection.sendto(dns_reply(packet, args.address), self.client_address)

    class TCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            try:
                while True:
                    prefix = receive_exact(self.request, 2)
                    if prefix is None:
                        return
                    packet = receive_exact(self.request, struct.unpack("!H", prefix)[0])
                    if packet is None:
                        return
                    response = dns_reply(packet, args.address)
                    self.request.sendall(struct.pack("!H", len(response)) + response)
            except (TimeoutError, ConnectionError):
                return

    class TCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    stopped = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())

    with ExitStack() as stack:
        # Bind every listener before announcing readiness. A bind failure is fatal.
        servers = [
            stack.enter_context(ThreadingHTTPServer((str(args.address), args.http_port), HTTPHandler)),
            stack.enter_context(socketserver.UDPServer((str(args.address), args.dns_port), UDPHandler)),
            stack.enter_context(TCPServer((str(args.address), args.dns_port), TCPHandler)),
        ]
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
        for thread in threads:
            thread.start()
        print(f"ready http={args.address}:{args.http_port} dns={args.address}:{args.dns_port} payload_bytes={len(payload)}", flush=True)
        try:
            while not stopped.wait(0.25):
                if not all(thread.is_alive() for thread in threads):
                    raise RuntimeError("a fixture listener stopped unexpectedly")
        finally:
            for server in servers:
                server.shutdown()
            for thread in threads:
                thread.join()


if __name__ == "__main__":
    main()

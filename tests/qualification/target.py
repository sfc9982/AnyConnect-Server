#!/usr/bin/env python3
"""Dual-stack private HTTP fixture: bounded uploads and exact payload hashes."""
import argparse
from contextlib import ExitStack
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ipaddress
import socketserver
import struct
from pathlib import Path
import signal
import socket
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", action="append", required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--dns-port", type=int, default=0)
    args = parser.parse_args()
    payload = args.payload.read_bytes()
    if not 1024 <= len(payload) <= 16 * 1024 * 1024:
        parser.error("payload must be 1 KiB..16 MiB")

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(20)

        def do_GET(self):
            if self.path != "/payload":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Seen-Client-IP", self.client_address[0])
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def do_POST(self):
            if self.path != "/upload":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                length = -1
            if length != len(payload):
                self.send_error(413)
                return
            received = self.rfile.read(length)
            if len(received) != length:
                self.send_error(400)
                return
            reply = json.dumps({"bytes": length, "sha256": hashlib.sha256(received).hexdigest()}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)

        def log_message(self, *_):
            pass  # Do not fill CI storage at sustained load.

    class IPv6Server(ThreadingHTTPServer):
        address_family = socket.AF_INET6

    def dns_reply(packet):
        question = answer = b""
        query_id = packet[:2].ljust(2, b"\0")
        flags = 0x8400
        rcode = 0
        try:
            _, request_flags, count, _, _, _ = struct.unpack("!6H", packet[:12])
            if count != 1 or request_flags & 0xF800:
                raise ValueError("invalid query")
            flags |= request_flags & 0x0100
            offset = 12
            labels = []
            while packet[offset]:
                length = packet[offset]
                offset += 1
                if length > 63 or offset + length > len(packet):
                    raise ValueError("invalid name")
                labels.append(packet[offset:offset + length].decode("ascii"))
                offset += length
            offset += 1
            qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
            question = packet[12:offset + 4]
            if ".".join(labels).lower() != "vpn-test.internal":
                rcode = 3
            elif qclass != 1:
                rcode = 4
            elif qtype in (1, 28):
                version = 4 if qtype == 1 else 6
                address = next((ipaddress.ip_address(value) for value in args.address
                                if ipaddress.ip_address(value).version == version), None)
                if address is not None:
                    answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 0, len(address.packed)) + address.packed
        except (ValueError, IndexError, UnicodeError, struct.error):
            question = b""
            rcode = 1
        return query_id + struct.pack("!5H", flags | rcode, bool(question), bool(answer), 0, 0) + question + answer

    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, connection = self.request
            connection.sendto(dns_reply(packet), self.client_address)

    class TCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(3)
            def receive(length):
                data = b""
                while len(data) < length:
                    piece = self.request.recv(length - len(data))
                    if not piece:
                        raise ConnectionError("short DNS request")
                    data += piece
                return data
            try:
                length = struct.unpack("!H", receive(2))[0]
                reply = dns_reply(receive(length))
                self.request.sendall(struct.pack("!H", len(reply)) + reply)
            except (OSError, ConnectionError):
                return

    class TCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    class TCP6Server(TCPServer):
        address_family = socket.AF_INET6

    class UDP6Server(socketserver.UDPServer):
        address_family = socket.AF_INET6

    stopped = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stopped.set())
    with ExitStack() as stack:
        servers = [stack.enter_context((IPv6Server if ":" in address else ThreadingHTTPServer)(
                   (address, args.port), Handler)) for address in args.address]
        if args.dns_port:
            for address in args.address:
                udp = UDP6Server if ":" in address else socketserver.UDPServer
                tcp = TCP6Server if ":" in address else TCPServer
                servers.extend([stack.enter_context(udp((address, args.dns_port), UDPHandler)),
                                stack.enter_context(tcp((address, args.dns_port), TCPHandler))])
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
        for thread in threads:
            thread.start()
        print("ready", flush=True)
        try:
            while not stopped.wait(.25):
                if not all(thread.is_alive() for thread in threads):
                    raise RuntimeError("fixture listener died")
        finally:
            for server in servers:
                server.shutdown()
            for thread in threads:
                thread.join()


if __name__ == "__main__":
    main()

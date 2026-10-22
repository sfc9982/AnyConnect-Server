#!/usr/bin/env python3
"""One authorized external VPN endpoint; run only in a disposable privileged container.

Input JSON names endpoint, username, password_file, ca_file, target_url, target_ip,
expected_sha256 and transport (tls/dtls/fallback). Never uploads OpenConnect logs.
"""
import argparse
import errno
import hashlib
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # The route assertion applies to the authorized numeric target only.
        return None


def download(url):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=10) as response:
        body = response.read(4 * 1024 * 1024 + 1)
        if len(body) > 4 * 1024 * 1024:
            raise RuntimeError('target payload exceeds 4 MiB limit')
        return body, response.headers.get('X-Seen-Client-IP')


def require_target_unreachable(url):
    try:
        download(url)
    except urllib.error.HTTPError:
        # A 3xx/4xx/5xx response proves the private HTTP service is reachable.
        raise RuntimeError('private target returned HTTP before VPN connection') from None
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, TimeoutError) or (isinstance(reason, OSError) and reason.errno in
                (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.ETIMEDOUT)):
            return
        raise RuntimeError('private-target preflight failed for a non-network reason') from None
    except TimeoutError:
        return
    raise RuntimeError('private target was reachable before VPN connection')


def route_uses_tunnel(target_ip):
    result = subprocess.run(['ip', '-6' if target_ip.version == 6 else '-4', 'route', 'get', str(target_ip)],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=5)
    return result.returncode == 0 and 'dev vpntest' in result.stdout


def probe(cfg):
    if os.environ.get('VPN_E2E_DISPOSABLE') != '1' or os.geteuid() != 0 or not Path('/.dockerenv').exists():
        raise RuntimeError('requires a disposable Docker container with TUN and NET_ADMIN')
    endpoint = urllib.parse.urlsplit(cfg['endpoint'])
    target = urllib.parse.urlsplit(cfg['target_url'])
    if (endpoint.scheme != 'https' or not endpoint.hostname or endpoint.username or endpoint.password
            or endpoint.query or endpoint.fragment or endpoint.path not in ('', '/')
            or target.scheme not in ('http', 'https') or target.username or target.password):
        raise ValueError('invalid endpoint or target URL')
    target_ip = ipaddress.ip_address(cfg['target_ip'])
    # A numeric target prevents DNS changes from silently altering the probed destination.
    if str(target_ip) != target.hostname:
        raise ValueError('target_url must use target_ip as its numeric host')
    if not re.fullmatch(r'[a-fA-F0-9]{64}', cfg['expected_sha256']):
        raise ValueError('expected_sha256 is required')
    transport = cfg['transport']
    if transport not in ('tls', 'dtls', 'fallback'):
        raise ValueError('unsupported transport')
    private = cfg.get('require_unreachable', True)
    if not private and not cfg.get('expected_source'):
        raise ValueError('public targets require expected_source to prove VPN egress')
    if private:
        require_target_unreachable(cfg['target_url'])
    routing = next((p for p in ('/usr/share/vpnc-scripts/vpnc-script', '/etc/vpnc/vpnc-script',
                                '/etc/openconnect/vpnc-script') if os.access(p, os.X_OK)), None)
    if not routing:
        raise RuntimeError('vpnc-script missing')
    password = Path(cfg['password_file']).read_bytes().rstrip(b'\n') + b'\n'
    command = ['openconnect', '--protocol=anyconnect', '--non-inter', '--no-proxy',
               '--no-system-trust', '--cafile', cfg['ca_file'], '--user', cfg['username'],
               '--passwd-on-stdin', '--reconnect-timeout=5', '--interface=vpntest',
               '--script', routing, cfg['endpoint']]
    if transport == 'tls':
        command.insert(-1, '--no-dtls')
    rules = []
    proc = None
    start = time.monotonic()
    try:
        for fw in ('iptables', 'ip6tables'):
            run(fw, '-N', 'VPNE_PROBE')
            rules.append(fw)
            run(fw, '-A', 'VPNE_PROBE', '-j', 'RETURN')
            run(fw, '-A', 'INPUT', '-p', 'udp', '--sport', str(endpoint.port or 443), '-j', 'VPNE_PROBE')
        def udp_bytes():
            return sum(int(line.split()[1]) for fw in rules
                       for line in run(fw, '-nvxL', 'VPNE_PROBE').splitlines()
                       if len(line.split()) > 2 and line.split()[2] == 'RETURN')
        with tempfile.TemporaryDirectory(prefix='vpn-probe-') as temp:
            log = Path(temp, 'client.log')
            with log.open('wb') as output:
                proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=output, stderr=output)
                proc.stdin.write(password)
                proc.stdin.close()
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        raise RuntimeError('VPN process exited before connection')
                    # An IPv6 route may not exist at all before tunnel setup.
                    ready = route_uses_tunnel(target_ip)
                    if ready and (transport != 'dtls' or 'Established DTLS connection' in log.read_text(errors='replace')):
                        break
                    time.sleep(.25)
                else:
                    raise RuntimeError('tunnel/DTLS readiness deadline exceeded')
                if transport == 'fallback':
                    time.sleep(10)  # permit real UDP negotiation attempts, do not disable DTLS
                before = udp_bytes()
                total = 0
                for _ in range(3):
                    if not route_uses_tunnel(target_ip):
                        raise RuntimeError('protected target lost its tunnel route')
                    body, source = download(cfg['target_url'])
                    if hashlib.sha256(body).hexdigest() != cfg['expected_sha256'].lower():
                        raise RuntimeError('VPN payload hash mismatch')
                    if cfg.get('expected_source') and source != cfg['expected_source']:
                        raise RuntimeError('target observed the wrong egress address')
                    total += len(body)
                delta = udp_bytes() - before
                if transport == 'dtls' and delta < total // 2:
                    raise RuntimeError('DTLS did not carry the payload')
                if transport != 'dtls' and delta != 0:
                    raise RuntimeError('TLS-only/fallback case received UDP data')
                if transport == 'fallback' and 'Established DTLS connection' in log.read_text(errors='replace'):
                    raise RuntimeError('expected UDP block was not observed')
                if proc.poll() is not None:
                    raise RuntimeError('client exited during data verification')
        return dict(status='passed', transport=transport, payload_bytes=total,
                    outer_udp_bytes=delta, inner_family=target_ip.version,
                    elapsed_seconds=time.monotonic()-start,
                    provider_metadata=cfg.get('metadata', {}), metadata_source='operator-supplied',
                    scope='external endpoint and data-plane observation; not cloud rule attribution')
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
        for fw in rules:
            subprocess.run([fw, '-D', 'INPUT', '-p', 'udp', '--sport', str(endpoint.port or 443),
                            '-j', 'VPNE_PROBE'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([fw, '-F', 'VPNE_PROBE'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([fw, '-X', 'VPNE_PROBE'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('config')
    parser.add_argument('--report', required=True)
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise RuntimeError('probe interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        result = probe(json.loads(Path(args.config).read_text()))
    except Exception as exc:
        # Exception class only: command errors/URLs can contain private deployment details.
        result = dict(status='failed', error_type=type(exc).__name__)
        Path(args.report).write_text(json.dumps(result, indent=2) + '\n')
        raise SystemExit('VPN probe failed; inspect the endpoint and local credentials (raw logs not uploaded)')
    Path(args.report).write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()

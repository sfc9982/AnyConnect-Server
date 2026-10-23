#!/usr/bin/env python3
"""Bounded integrity/throughput probe for a test target, not a public benchmark."""
import argparse
import concurrent.futures
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import time
from urllib.parse import urlsplit


def transfer(url, payload, timeout):
    """One verified download and upload. Never use environment HTTP proxies."""
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("use an explicit HTTP fixture URL without userinfo")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
    expected = hashlib.sha256(payload).hexdigest()
    try:
        connection.request("GET", "/payload")
        response = connection.getresponse()
        # Bound the response even when a fixture is accidentally misconfigured.
        body = response.read(len(payload) + 1)
        if response.status != 200 or hashlib.sha256(body).hexdigest() != expected:
            raise ValueError("download status, size or SHA-256 mismatch")
        peer = response.getheader("X-Seen-Client-IP", "")
        connection.close()
        connection = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=timeout)
        connection.request("POST", "/upload", body=payload,
                           headers={"Content-Type": "application/octet-stream"})
        response = connection.getresponse()
        reply = json.loads(response.read(4096))
        if response.status != 200 or reply != {"bytes": len(payload), "sha256": expected}:
            raise ValueError("upload status, size or SHA-256 mismatch")
        return len(payload) * 2, peer
    finally:
        connection.close()


def worker(index, url, payload, deadline, timeout, expected_peer, minimum):
    count = byte_count = 0
    # Fixed-size histogram: memory use must not grow with a 30-minute test.
    histogram = [0] * 2001  # 10 ms buckets, last bucket >= 20 seconds.
    errors = []
    started = time.monotonic()
    while time.monotonic() < deadline or count < minimum:
        before = time.monotonic()
        try:
            transferred, peer = transfer(url, payload, timeout)
            if expected_peer and ipaddress.ip_address(peer) != ipaddress.ip_address(expected_peer):
                raise ValueError("unexpected source address at target")
            elapsed = time.monotonic() - before
            histogram[min(2000, int(elapsed * 100))] += 1
            byte_count += transferred
            count += 1
        except Exception as exc:  # Retain failure evidence; never retry away a failure.
            errors.append(type(exc).__name__ + ": " + str(exc))
            break
    return {"worker": index, "cycles": count, "bytes": byte_count,
            "elapsed_seconds": time.monotonic() - started,
            "histogram_10ms": histogram, "errors": errors}


def quantile(histogram, fraction):
    if not sum(histogram):
        return None
    threshold = math.ceil(sum(histogram) * fraction)
    count = 0
    for bucket, value in enumerate(histogram):
        count += value
        if count >= threshold:
            if bucket == 2000:
                return None  # Overflow bucket has no finite upper bound.
            return round((bucket + 1) / 100, 2)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--minimum-cycles", type=int, default=2)
    parser.add_argument("--minimum-mbps", type=float, default=0)
    parser.add_argument("--expected-peer", default="")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not (1 <= args.seconds <= 7200 and 1 <= args.workers <= 32 and
            1 <= args.timeout <= 60 and 1 <= args.minimum_cycles <= 1000):
        parser.error("seconds 1..7200, workers 1..32, timeout 1..60, cycles 1..1000 required")
    if not math.isfinite(args.minimum_mbps) or args.minimum_mbps < 0:
        parser.error("minimum-mbps must be finite and nonnegative")
    payload = args.payload.read_bytes()
    if not 1024 <= len(payload) <= 16 * 1024 * 1024:
        parser.error("payload must be 1 KiB..16 MiB")
    start = time.monotonic()
    deadline = start + args.seconds
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        results = list(executor.map(lambda i: worker(i, args.url, payload, deadline,
                          args.timeout, args.expected_peer, args.minimum_cycles), range(args.workers)))
    elapsed = time.monotonic() - start
    histogram = [sum(row["histogram_10ms"][i] for row in results) for i in range(2001)]
    for row in results:
        del row["histogram_10ms"]
    byte_count = sum(row["bytes"] for row in results)
    mbps = byte_count * 8 / elapsed / 1_000_000
    passed = (all(not row["errors"] and row["cycles"] >= args.minimum_cycles and
                  row["elapsed_seconds"] >= args.seconds * 0.95 for row in results)
              and mbps >= args.minimum_mbps)
    report = {"schema": 1, "passed": passed, "requested_seconds": args.seconds,
              "elapsed_seconds": elapsed, "workers": args.workers, "bytes": byte_count,
              "aggregate_mbps": mbps, "minimum_mbps": args.minimum_mbps,
              "cycle_latency_p50_seconds_upper_bound": quantile(histogram, .50),
              "cycle_latency_p95_seconds_upper_bound": quantile(histogram, .95),
              "cycles_over_20_seconds": histogram[2000], "results": results}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key != "results"}))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()

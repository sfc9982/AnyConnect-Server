#!/usr/bin/env python3
"""Sample the ocserv process tree, bounded by a stop file and a hard deadline."""
import argparse
import json
import os
from pathlib import Path
import time


def sample(root):
    children, records = {}, {}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = entry.joinpath('stat').read_text().rsplit(')', 1)[1].split()
            parent = int(fields[1])
            children.setdefault(parent, []).append(int(entry.name))
            rss = int(fields[21]) * os.sysconf('SC_PAGE_SIZE')
            ticks = int(fields[11]) + int(fields[12])
            fds = len(list(entry.joinpath('fd').iterdir()))
            records[int(entry.name)] = (rss, ticks, fds)
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    pending = [root]
    result = {'rss_bytes': 0, 'cpu_ticks': 0, 'fds': 0, 'processes': 0, 'alive': root in records}
    while pending:
        pid = pending.pop()
        pending.extend(children.get(pid, []))
        if pid in records:
            rss, ticks, fds = records[pid]
            result['rss_bytes'] += rss
            result['cpu_ticks'] += ticks
            result['fds'] += fds
            result['processes'] += 1
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--stop', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--limit-seconds', type=int, default=7500)
    parser.add_argument('--max-rss-mib', type=int, default=512)
    parser.add_argument('--max-fds', type=int, default=4096)
    args = parser.parse_args()
    start = time.monotonic()
    passed = True
    with args.output.open('w') as stream:
        while not args.stop.exists():
            row = sample(args.pid)
            row['seconds'] = time.monotonic() - start
            print(json.dumps(row), file=stream, flush=True)
            if not row['alive'] or row['rss_bytes'] > args.max_rss_mib * 1024**2 or row['fds'] > args.max_fds:
                passed = False
            if row['seconds'] > args.limit_seconds:
                passed = False
                break
            time.sleep(1)
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()

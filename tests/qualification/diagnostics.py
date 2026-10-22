#!/usr/bin/env python3
"""Emit only selected transport messages, never raw logs or credentials."""
import re
import sys
from pathlib import Path

INTERESTING = re.compile(r"DTLS|CSTP|UDP|handshake|Failed|failed|Connected|Connecting|Attempting")
SENSITIVE = re.compile(r"cookie|password|passwd|secret|session|authorization|certificate|private|token|X-DTLS-.*ID", re.I)


def transport_lines(text: str) -> list[str]:
    return [line for line in text.splitlines()
            if INTERESTING.search(line) and not SENSITIVE.search(line)
            and not re.match(r"^\s*[<>]", line)][:120]


def main() -> None:
    state, output = map(Path, sys.argv[1:])
    output.mkdir(parents=True, exist_ok=True)
    for log in sorted(state.glob("*.log")):
        selected = transport_lines(log.read_text(errors="replace"))
        if selected:
            report = "\n".join(selected) + "\n"
            (output / (log.stem + "-transport.txt")).write_text(report)
            print(f"--- {log.name}: transport diagnostics ---\n{report}", file=sys.stderr)


if __name__ == "__main__":
    main()

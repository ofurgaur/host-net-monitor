#!/usr/bin/env python3
"""Send JSONL files to the map API in 30-line chunks every second."""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen


def post(url: str, lines: list[str], timeout: float) -> None:
    body = "".join(lines).encode()
    request = Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-ndjson",
            "Content-Length": str(len(body)),
        },
    )
    with urlopen(request, timeout=timeout) as response:
        if response.status >= 300:
            raise RuntimeError(f"map API returned HTTP {response.status}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080/api/events")
    parser.add_argument("--file", action="append", dest="files", required=True, type=Path,
                        help="JSONL file to send; repeat for flow and IP logs")
    parser.add_argument("--chunk-lines", type=int, default=30,
                        help="lines per request (default: 30)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="seconds between requests (default: 1)")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    if args.chunk_lines <= 0 or args.interval <= 0:
        parser.error("chunk-lines and interval must be positive")

    lines = []
    for path in args.files:
        with path.open(encoding="utf-8", errors="replace") as handle:
            lines.extend(line for line in handle if line.strip())

    total = len(lines)
    sent = 0
    chunk_number = 0
    while sent < total:
        chunk = lines[sent:sent + args.chunk_lines]
        chunk_number += 1
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        print(f"{stamp} send chunk={chunk_number} lines={len(chunk)} remaining={total - sent - len(chunk)}", flush=True)
        try:
            post(args.url, chunk, args.timeout)
            sent += len(chunk)
            print(f"{stamp} sent chunk={chunk_number} lines={len(chunk)}", flush=True)
        except Exception as exc:
            print(f"{stamp} send failed chunk={chunk_number} lines={len(chunk)} error={exc}", flush=True)
            raise SystemExit(1) from exc
        if sent < total:
            time.sleep(args.interval)

    print(f"{datetime.now(timezone.utc).isoformat(timespec='seconds')} complete lines={sent} chunks={chunk_number}", flush=True)


if __name__ == "__main__":
    main()

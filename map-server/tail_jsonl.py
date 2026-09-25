#!/usr/bin/env python3
"""Experimental JSONL follower that sends timed chunks to the map API."""
from __future__ import annotations

import argparse
import time
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
                        help="JSONL file to follow; repeat for flow and IP logs")
    parser.add_argument("--start-at-end", action="store_true",
                        help="ignore existing records and only send new lines")
    parser.add_argument("--chunk-seconds", type=float, default=2.0,
                        help="flush buffered lines at this interval (default: 2 seconds)")
    parser.add_argument("--chunk-lines", type=int, default=500,
                        help="flush early after this many lines (default: 500)")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    if args.chunk_seconds <= 0 or args.chunk_lines <= 0:
        parser.error("chunk-seconds and chunk-lines must be positive")

    handles = []
    for path in args.files:
        handle = path.open(encoding="utf-8", errors="replace")
        if args.start_at_end:
            handle.seek(0, 2)
        handles.append(handle)

    pending: list[str] = []
    next_flush = time.monotonic() + args.chunk_seconds
    try:
        while True:
            found = False
            for handle in handles:
                while True:
                    line = handle.readline()
                    if not line:
                        break
                    found = True
                    if line.strip():
                        pending.append(line)
                    if len(pending) >= args.chunk_lines:
                        break
                if len(pending) >= args.chunk_lines:
                    break

            now = time.monotonic()
            if pending and (len(pending) >= args.chunk_lines or now >= next_flush):
                chunk, pending = pending, []
                try:
                    post(args.url, chunk, args.timeout)
                except Exception as exc:
                    print(f"post failed for {len(chunk)} lines: {exc}")
                next_flush = time.monotonic() + args.chunk_seconds
            elif not found:
                time.sleep(min(0.25, max(0.01, next_flush - now)))
    finally:
        for handle in handles:
            handle.close()


if __name__ == "__main__":
    main()

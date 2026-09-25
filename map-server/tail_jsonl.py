#!/usr/bin/env python3
"""Experimental JSONL follower that forwards monitor records to the map API."""
from __future__ import annotations
import argparse
import time
from pathlib import Path
from urllib.request import Request, urlopen


def post(url: str, lines: list[str], timeout: float) -> None:
    body = "".join(lines).encode()
    request = Request(url, data=body, method="POST", headers={"Content-Type": "application/x-ndjson", "Content-Length": str(len(body))})
    with urlopen(request, timeout=timeout) as response:
        if response.status >= 300:
            raise RuntimeError(f"map API returned HTTP {response.status}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://127.0.0.1:8080/api/events")
    parser.add_argument("--file", action="append", dest="files", required=True, type=Path, help="JSONL file to follow; repeat for flow and IP logs")
    parser.add_argument("--start-at-end", action="store_true", help="ignore existing records and only send new lines")
    parser.add_argument("--timeout", type=float, default=10)
    args = parser.parse_args()
    handles = []
    for path in args.files:
        handle = path.open(encoding="utf-8", errors="replace")
        if args.start_at_end:
            handle.seek(0, 2)
        handles.append(handle)
    try:
        while True:
            batch = []
            for handle in handles:
                while True:
                    line = handle.readline()
                    if not line:
                        break
                    if line.strip():
                        batch.append(line)
            if batch:
                try: post(args.url, batch, args.timeout)
                except Exception as exc: print(f"post failed: {exc}")
            else:
                time.sleep(0.5)
    finally:
        for handle in handles:
            handle.close()

if __name__ == "__main__": main()

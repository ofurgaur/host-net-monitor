#!/usr/bin/env python3
"""Minimal ntopng ZeroMQ flow exporter for host-net-monitor JSONL."""
from __future__ import annotations

import argparse
import json
import socket
import struct
import time
from datetime import datetime
from pathlib import Path

import zmq

HEADER = struct.Struct("<16sBBHI")


def timestamp(value) -> int:
    if not value:
        return int(time.time())
    try:
        return int(datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp())
    except ValueError:
        return int(time.time())


def read_rows(paths: list[Path]):
    for path in paths:
        with path.open(encoding="utf-8", errors="replace") as handle:
            for line in handle:
                try:
                    value = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(value, dict):
                    yield value


def protocol(value) -> int:
    if isinstance(value, int):
        return value
    return {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}.get(str(value).lower(), 0)


def flow(row: dict, local_ip: str) -> dict | None:
    external_ip = str(row.get("external_ip") or "")
    try:
        socket.inet_aton(external_ip)
    except OSError:
        return None  # this minimal format emits IPv4 records only
    now = timestamp(row.get("timestamp"))
    return {
        "IPV4_SRC_ADDR": local_ip,
        "IPV4_DST_ADDR": external_ip,
        "L4_SRC_PORT": int(row.get("local_port") or 0),
        "L4_DST_PORT": int(row.get("external_port") or 0),
        "PROTOCOL": protocol(row.get("protocol")),
        "IN_BYTES": 0,
        "IN_PKTS": 0,
        "OUT_BYTES": max(0, int(row.get("flow_byte_sum") or row.get("bytes_count") or 0)),
        "OUT_PKTS": max(0, int(row.get("flow_count") or row.get("flowcount") or 0)),
        "FIRST_SWITCHED": now,
        "LAST_SWITCHED": now,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--bind", default="tcp://*:5556", help="PUB bind endpoint")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between messages")
    parser.add_argument("--local-ip", required=True, help="IPv4 address used as flow source")
    parser.add_argument("--source-id", type=int, default=0)
    parser.add_argument("--startup-delay", type=float, default=1.0)
    args = parser.parse_args()
    if args.interval <= 0 or not 0 <= args.source_id <= 255:
        parser.error("interval must be positive and source-id must be 0..255")

    context = zmq.Context()
    sock = context.socket(zmq.PUB)
    sock.bind(args.bind)
    time.sleep(max(0, args.startup_delay))
    message_id = 0
    sent = skipped = 0
    try:
        for row in read_rows(args.input):
            value = flow(row, args.local_ip)
            if value is None:
                skipped += 1
                continue
            payload = json.dumps([value], separators=(",", ":")).encode()
            header = HEADER.pack(b"flow", 2, args.source_id, len(payload) & 0xFFFF, message_id)
            sock.send_multipart([header, payload])
            message_id = (message_id + 1) & 0xFFFFFFFF
            sent += 1
            print(f"sent flow={sent} message_id={message_id - 1} bytes={value['OUT_BYTES']} skipped={skipped}", flush=True)
            time.sleep(args.interval)
    finally:
        sock.close(linger=0)
        context.term()
    print(f"export complete sent={sent} skipped={skipped}", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Export host-net-monitor JSONL records as NetFlow v5 for ntopng/nProbe."""
from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import time
from datetime import datetime, timezone
from pathlib import Path

HEADER = struct.Struct("!HHIIIIHH")
RECORD = struct.Struct("!4s4s4sHHIIIIHHBBHHBBH")


def epoch(value: str | None) -> float:
    if not value:
        return time.time()
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def number(item: dict, *keys: str) -> int:
    for key in keys:
        value = item.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return max(0, int(value))
    return 0


def protocol(value) -> int:
    if isinstance(value, int):
        return value
    return {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58}.get(str(value).lower(), 0)


def load(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", action="append", required=True, type=Path,
                        help="JSONL file; repeat for endpoint and per-IP logs")
    parser.add_argument("--target", default="127.0.0.1:2055",
                        help="UDP target host:port (default: 127.0.0.1:2055)")
    parser.add_argument("--local-ip", required=True,
                        help="local IPv4 address used as the NetFlow source")
    parser.add_argument("--source-port", type=int, default=0)
    parser.add_argument("--chunk-size", type=int, default=30,
                        help="records per NetFlow packet (default: 30; max 30)")
    parser.add_argument("--interval", type=float, default=1.0,
                        help="seconds between packets (default: 1)")
    parser.add_argument("--speed", type=float, default=0,
                        help="replay timestamp speed; 0 sends at fixed interval")
    parser.add_argument("--observation-domain", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.chunk_size <= 30 or args.interval <= 0 or args.speed < 0:
        parser.error("chunk-size must be 1..30, interval must be positive, speed cannot be negative")
    try:
        local = ipaddress.IPv4Address(args.local_ip).packed
    except ipaddress.AddressValueError as exc:
        parser.error(f"--local-ip must be IPv4: {exc}")
    try:
        host, port_text = args.target.rsplit(":", 1)
        target = (host, int(port_text))
    except ValueError:
        parser.error("--target must be host:port")

    rows = [row for path in args.input for row in load(path)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.source_port:
        sock.bind(("0.0.0.0", args.source_port))
    start_mono = time.monotonic()
    start_wall = time.time()
    sequence = 0
    sent = skipped = 0
    previous_timestamp = None
    for offset in range(0, len(rows), args.chunk_size):
        packet_rows = []
        for row in rows[offset:offset + args.chunk_size]:
            try:
                external = ipaddress.ip_address(str(row.get("external_ip")))
            except ValueError:
                skipped += 1
                continue
            if external.version != 4:
                skipped += 1
                continue
            packet_rows.append((row, external.packed))
        if not packet_rows:
            continue
        now = time.time()
        uptime = int((time.monotonic() - start_mono) * 1000) & 0xFFFFFFFF
        rows_payload = []
        for row, destination in packet_rows:
            stamp = epoch(row.get("timestamp"))
            first = max(0, int((stamp - start_wall) * 1000)) & 0xFFFFFFFF
            last = first
            rows_payload.append(RECORD.pack(local, destination, b"\0\0\0\0", 0, 0, number(row, "flow_count", "flows"), number(row, "flow_byte_sum", "bytes_count", "bytes"), first, last, 0, int(row.get("external_port") or 0), 0, protocol(row.get("protocol")), 0, 0, 0, 0, 0))
            previous_timestamp = stamp
        header = HEADER.pack(5, len(rows_payload), uptime, int(now), int((now % 1) * 1_000_000_000), sequence, 0, args.observation_domain & 0xFFFF)
        sock.sendto(header + b"".join(rows_payload), target)
        sequence = (sequence + len(rows_payload)) & 0xFFFFFFFF
        sent += len(rows_payload)
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        print(f"{stamp} sent packet={sent // args.chunk_size + 1} records={len(rows_payload)} total={sent} skipped={skipped}", flush=True)
        if args.speed and previous_timestamp is not None:
            next_timestamp = epoch(rows[offset + args.chunk_size].get("timestamp")) if offset + args.chunk_size < len(rows) else previous_timestamp
            time.sleep(max(0, (next_timestamp - previous_timestamp) / args.speed))
        elif offset + args.chunk_size < len(rows):
            time.sleep(args.interval)
    print(f"export complete records={sent} skipped={skipped}", flush=True)


if __name__ == "__main__":
    main()

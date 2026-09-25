#!/usr/bin/env python3
"""Build a local reputation MMDB from Feodo JSON and FireHOL IP/CIDR lists.

Python 3.11+, Linux/macOS. Run --help for commands. No firewall changes.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import maxminddb
from mmdb_writer import MMDBWriter
from netaddr import IPSet

DATABASE_TYPE = "HostNetMonitor-Threat-Reputation"
DEFAULT_CONFIG = Path(__file__).resolve().parents[2] / "threat-reputation.config.json"


class UpdateError(Exception):
    pass


def utc(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def report(message, **fields):
    print(json.dumps({"timestamp": utc(time.time()), "message": message, **fields}), file=sys.stderr, flush=True)


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


@contextmanager
def lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise UpdateError("another updater is already running for this output") from error
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def load_config(path):
    config = json.loads(path.read_text())
    if not isinstance(config, dict):
        raise UpdateError("configuration must be a JSON object")
    allowed = {"output", "cache_directory", "timeout_seconds", "max_download_bytes", "sources"}
    if set(config) - allowed:
        raise UpdateError("unknown configuration fields")
    for key in ("output", "cache_directory"):
        if not isinstance(config.get(key), str) or not config[key]:
            raise UpdateError(f"{key} must be a nonempty path")
        config[key] = (path.resolve().parent / config[key]).resolve()
    for key, default, maximum in (("timeout_seconds", 30, 120), ("max_download_bytes", 20*1024*1024, 100*1024*1024)):
        value = config.setdefault(key, default)
        if type(value) is not int or not 1 <= value <= maximum:
            raise UpdateError(f"invalid {key}")
    if not isinstance(config.get("sources"), list) or not config["sources"]:
        raise UpdateError("sources must be a nonempty list")
    names = set()
    for source in config["sources"]:
        if not isinstance(source, dict):
            raise UpdateError("each source must be an object")
        if set(source) - {"name", "enabled", "url", "format", "category", "refresh_seconds", "max_age_seconds", "allow_empty"}:
            raise UpdateError("unknown source fields")
        name = source.get("name", "")
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_-]+", name) or name in names:
            raise UpdateError("source names must be unique lowercase identifiers")
        names.add(name)
        for flag, default in (("enabled", True), ("allow_empty", False)):
            if type(source.setdefault(flag, default)) is not bool:
                raise UpdateError(f"{name}: {flag} must be boolean")
        if source.get("format") not in ("feodo_json", "netset"):
            raise UpdateError(f"{name}: unsupported format")
        if not isinstance(source.get("url"), str) or urlparse(source["url"]).scheme != "https":
            raise UpdateError(f"{name}: feed URL must use HTTPS")
        if not isinstance(source.get("category"), str) or not source["category"]:
            raise UpdateError(f"{name}: category is required")
        for key in ("refresh_seconds", "max_age_seconds"):
            if type(source.get(key)) is not int or source[key] < 60:
                raise UpdateError(f"{name}: {key} must be an integer >= 60")
        if source["max_age_seconds"] < source["refresh_seconds"]:
            raise UpdateError(f"{name}: max_age_seconds must be >= refresh_seconds")
    if not any(s["enabled"] for s in config["sources"]):
        raise UpdateError("enable at least one source")
    return config


def network(value):
    if not isinstance(value, str):
        raise UpdateError("IP/CIDR must be a string")
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as error:
        raise UpdateError(f"invalid IP/CIDR: {value!r}") from error
    if net.prefixlen == 0:
        raise UpdateError("refusing an all-addresses /0 entry")
    if net.version == 6 and net.overlaps(ipaddress.ip_network("::/96")):
        raise UpdateError("IPv6 ::/96 is reserved for MMDB's IPv4 lookup subtree")
    return net


def parse_feed(body, source):
    """Return normalized (network, source-provided attributes), rejecting bad bodies."""
    text = body.decode("utf-8-sig")
    rows = []
    if source["format"] == "feodo_json":
        items = json.loads(text)
        if not isinstance(items, list):
            raise UpdateError("Feodo body must be a JSON array")
        for item in items:
            if not isinstance(item, dict) or "ip_address" not in item:
                raise UpdateError("invalid Feodo record")
            net = network(item["ip_address"])
            if net.prefixlen != net.max_prefixlen:
                raise UpdateError("Feodo entries must be individual IPs")
            details = {}
            if "port" in item:
                if type(item["port"]) is not int or not 1 <= item["port"] <= 65535:
                    raise UpdateError("invalid Feodo port")
                details["port"] = item["port"]
            for original, key in (("malware", "malware"), ("status", "reported_status"),
                                  ("first_seen", "reported_first_seen"), ("last_online", "reported_last_online")):
                if item.get(original) is not None:
                    if not isinstance(item[original], str):
                        raise UpdateError(f"invalid Feodo {original}")
                    details[key] = item[original]
            rows.append((net, details))
    else:
        for line in text.splitlines():
            value = line.split("#", 1)[0].strip()
            if value:
                rows.append((network(value), {}))
    unique = {(str(net), encode(details)): (net, details) for net, details in rows}
    if not unique and not source["allow_empty"]:
        raise UpdateError("unexpected empty feed")
    return list(unique.values())


def download(source, state, timeout, limit):
    headers = {"User-Agent": "host-net-monitor-reputation/1.0", "Accept-Encoding": "identity"}
    if state:
        if state.get("etag"):
            headers["If-None-Match"] = state["etag"]
        if state.get("last_modified"):
            headers["If-Modified-Since"] = state["last_modified"]
    for attempt in range(3):
        try:
            with urlopen(Request(source["url"], headers=headers), timeout=timeout) as response:
                if urlparse(response.url).scheme != "https":
                    raise UpdateError("refusing non-HTTPS redirect")
                if response.status != 200:
                    raise UpdateError(f"unexpected HTTP status {response.status}")
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise UpdateError("feed exceeds max_download_bytes")
                return body, {"etag": response.headers.get("ETag"), "last_modified": response.headers.get("Last-Modified")}
        except HTTPError as error:
            if error.code == 304 and state:
                return None, {}
            if error.code < 500 and error.code != 429:
                raise
            if attempt == 2:
                raise
        except (URLError, TimeoutError, OSError):
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)
    raise UpdateError("download failed")


def get_source(source, config, now, force=False, accept_large_change=False):
    """State and raw snapshot are committed only after the new feed validates."""
    cache = config["cache_directory"] / source["name"]
    state_path = cache / "state.json"
    state = None
    body = None
    if state_path.exists():
        try:
            candidate = json.loads(state_path.read_text())
            candidate_body = (cache / "snapshot.txt").read_bytes()
            valid = (isinstance(candidate, dict) and
                     all(type(candidate.get(k)) is int and candidate[k] >= 0
                         for k in ("entries", "confirmed_at", "content_changed_at")) and
                     "last_modified" in candidate)
            if valid and candidate["url"] == source["url"] and digest(candidate_body) == candidate["sha256"]:
                state, body = candidate, candidate_body
        except (OSError, ValueError, KeyError):
            report("ignoring damaged feed cache", source=source["name"])
    error_text = None
    health = "cached"
    due = not state or now - state["confirmed_at"] >= source["refresh_seconds"]
    try:
        if due or force:
            fresh, headers = download(source, state, config["timeout_seconds"], config["max_download_bytes"])
            candidate_body = body if fresh is None else fresh
            rows = parse_feed(candidate_body, source)
            count = len(rows)
            if state and state["entries"] >= 100 and not accept_large_change:
                ratio = count / state["entries"]
                # Explicitly allowed empty feeds can legitimately lose all listings.
                if not (count == 0 and source["allow_empty"]) and not 0.5 <= ratio <= 2:
                    raise UpdateError("feed size changed by >2x or dropped >50%; inspect and use --accept-large-change")
            changed = not state or digest(candidate_body) != state["sha256"]
            new_state = {
                "url": source["url"], "sha256": digest(candidate_body), "entries": count,
                "confirmed_at": now,
                "content_changed_at": now if changed else state["content_changed_at"],
                "etag": headers.get("etag", state.get("etag") if state else None),
                "last_modified": headers.get("last_modified", state.get("last_modified") if state else None),
            }
            atomic_write(cache / "snapshot.txt", candidate_body)
            atomic_write(state_path, encode(new_state))
            body, state = candidate_body, new_state
            health = "fresh" if fresh is not None else "not_modified"
    except (UpdateError, ValueError, UnicodeError, OSError, URLError) as error:
        error_text = str(error)
        health = "stale"
        report("feed refresh failed", source=source["name"], error=error_text)
    if state is None:
        raise UpdateError(f"{source['name']}: no validated snapshot available: {error_text}")
    expires = state["confirmed_at"] + source["max_age_seconds"]
    if now >= expires:
        health = "expired"
        rows = []
    else:
        rows = parse_feed(body, source)
    manifest = {
        "name": source["name"], "url": source["url"], "status": health,
        "sha256": state["sha256"], "entries": state["entries"], "included_entries": len(rows),
        "last_confirmed_at": utc(state["confirmed_at"]), "expires_at": utc(expires),
        "content_changed_at": utc(state["content_changed_at"]), "upstream_last_modified": state["last_modified"],
    }
    if error_text:
        manifest["error"] = error_text
    entries = []
    for net, details in rows:
        evidence = {
            "source": source["name"], "category": source["category"], "network": str(net),
            "last_confirmed_in_feed": utc(state["confirmed_at"]), "expires_at": utc(expires),
            "feed_status": health, **details,
        }
        entries.append((net, evidence))
    return entries, manifest


def merge_networks(entries):
    """Sweep interval boundaries: never enumerate IPs or overwrite overlapping evidence."""
    for version, address in ((4, ipaddress.IPv4Address), (6, ipaddress.IPv6Address)):
        changes = defaultdict(list)
        values = {}
        for net, evidence in entries:
            if net.version != version:
                continue
            key = encode(evidence)
            values[key] = evidence
            changes[int(net.network_address)].append((key, 1))
            changes[int(net.broadcast_address) + 1].append((key, -1))
        active = {}
        previous = None
        for position in sorted(changes):
            if active and previous is not None and previous < position:
                matches = [values[key] for key in sorted(active)]
                for net in ipaddress.summarize_address_range(address(previous), address(position - 1)):
                    yield net, matches
            for key, delta in changes[position]:
                active[key] = active.get(key, 0) + delta
                if active[key] == 0:
                    del active[key]
            previous = position


def publish(output, entries, manifest):
    version = manifest["database_version"]
    writer = MMDBWriter(ip_version=6, ipv4_compatible=True, database_type=DATABASE_TYPE,
                        description={"en": "Source-attributed IP reputation; listing is not proof of malicious traffic"},
                        int_type="u32")
    expected = []
    for net, matches in merge_networks(entries):
        value = {"schema_version": 1, "database_version": version, "matches": matches}
        writer.insert_network(IPSet([str(net)]), value)
        expected.append((net, value))
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".threat-reputation-", suffix=".mmdb", dir=output.parent)
    os.close(fd)
    temporary = Path(name)
    try:
        writer.to_db_file(str(temporary))
        # Verify with an independent reader, including every generated range boundary.
        with maxminddb.open_database(str(temporary)) as reader:
            if reader.metadata().database_type != DATABASE_TYPE:
                raise UpdateError("database type verification failed")
            for net, value in expected:
                for ip in (net.network_address, net.broadcast_address):
                    if reader.get(str(ip)) != value:
                        raise UpdateError(f"MMDB verification failed for {ip}")
        data = temporary.read_bytes()
        manifest.update({"sha256": digest(data), "bytes": len(data), "networks": len(expected)})
        manifest_path = output.with_name(output.name + ".manifest.json")
        if output.exists():
            atomic_write(output.with_name(output.name + ".previous"), output.read_bytes())
            if manifest_path.exists():
                atomic_write(manifest_path.with_name(manifest_path.name + ".previous"), manifest_path.read_bytes())
        # Manifest is versioned in records; readers must match its hash to the MMDB.
        with temporary.open("rb") as handle:
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output)
        atomic_write(manifest_path, json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
        directory = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
    return manifest


def update(config, force=False, accept_large_change=False):
    output = config["output"]
    with lock(output.with_name(output.name + ".lock")):
        now = int(time.time())
        entries, sources = [], []
        for source in config["sources"]:
            if not source["enabled"]:
                sources.append({"name": source["name"], "status": "disabled"})
                continue
            rows, status = get_source(source, config, now, force, accept_large_change)
            entries.extend(rows)
            sources.append(status)
            report("feed processed", **status)
        if all(s["status"] in ("expired", "disabled") for s in sources):
            raise UpdateError("all feeds expired; retaining previous database (check per-match expiry before use)")
        version = utc(now) + "-" + digest(encode(sources))[:12]
        manifest = {"schema_version": 1, "database_type": DATABASE_TYPE,
                    "database_version": version, "built_at": utc(now), "sources": sources}
        return publish(output, entries, manifest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--force", action="store_true", help="check sources now, ignoring refresh intervals")
    parser.add_argument("--accept-large-change", action="store_true", help="accept reviewed feed count anomalies")
    parser.add_argument("--lookup", metavar="IP", help="query the current database; performs no downloads")
    args = parser.parse_args()
    try:
        config = load_config(args.config)
        if args.lookup:
            ip = str(ipaddress.ip_address(args.lookup))
            with maxminddb.open_database(str(config["output"])) as reader:
                result = reader.get(ip)
            print(json.dumps({"ip": ip, "reputation": result}, indent=2))
        else:
            result = update(config, args.force, args.accept_large_change)
            print(json.dumps({"output": str(config["output"]), **result}, indent=2))
        return 0
    except (UpdateError, ValueError, OSError, maxminddb.InvalidDatabaseError) as error:
        report("reputation update failed", error=str(error))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

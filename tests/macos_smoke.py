"""macOS CI: actual BPF capture, local-traffic exclusion, idle timer, SIGTERM.

Run with sudo and pass the native release binary. No external traffic is sent.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def main():
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise SystemExit("Run on macOS with sudo")
    binary = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="host-net-monitor-") as directory:
        root = Path(directory)
        config = root / "config.yaml"
        config.write_text(
            "capture:\n  interfaces: [lo0]\n"
            "aggregation:\n  interval_seconds: 1\n"
            "output:\n  type: jsonl\n  path: flows.jsonl\n  ip_path: ips.jsonl\n"
        )
        diagnostics = root / "service.log"
        with diagnostics.open("w") as log:
            process = subprocess.Popen(
                [str(binary), "run", "--config", str(config)],
                cwd=root, stdout=log, stderr=log,
            )
            try:
                deadline = time.monotonic() + 10
                while 'monitor started' not in diagnostics.read_text():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise AssertionError(diagnostics.read_text())
                    time.sleep(0.1)
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
                    receiver.bind(("127.0.0.1", 0))
                    receiver.settimeout(2)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                        for _ in range(10):
                            sender.sendto(b"", receiver.getsockname())
                            receiver.recvfrom(1)
                time.sleep(2)  # Cross idle window boundaries after the local traffic.
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 0, diagnostics.read_text()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
        events = [json.loads(line) for line in diagnostics.read_text().splitlines()]
        assert any(e["fields"].get("message") == "capture stopped" and
                   e["fields"].get("parsed", 0) > 0 for e in events), events
        assert any(e["fields"].get("message") == "monitor stopped; final window flushed"
                   for e in events), events
        assert (root / "flows.jsonl").read_text() == ""
        assert (root / "ips.jsonl").read_text() == ""
        print("macOS BPF capture, local exclusion, and graceful shutdown passed")


if __name__ == "__main__":
    main()

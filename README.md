# Host network monitor — Linux, macOS, and Windows

A Rust/libpcap daemon that summarizes this host's external TCP/UDP traffic as JSONL.
There is no GUI, DNS enrichment, process attribution, or packet dump output.

For macOS build, installation, and LaunchDaemon instructions, see [MACOS.md](MACOS.md).

For Windows/Npcap builds and Windows Service installation, see [WINDOWS.md](WINDOWS.md).

Common build and maintenance commands are collected in the [Makefile](Makefile):
`make build`, `make test`, `make lint`, `make check-config CONFIG=config.yaml`,
and `make reputation`.

Pushing a tag matching `v*` starts the release workflow. It builds Linux x86_64,
macOS arm64 and x86_64, and Windows x86_64 artifacts, runs the platform checks,
packages the service files and updater source, creates SHA-256 checksums, and
publishes a GitHub Release. The workflow does not bundle Npcap, WinSW, or either
MMDB; those remain deployment/data dependencies with their own licenses and update
cadence.

To build and maintain a separate Feodo/FireHOL reputation MMDB, see the
[Python reputation updater](tools/reputation/README.md). Its output is separate
from geolocation. Reputation enrichment is configurable separately.

## Build and run on Linux

On Debian/Ubuntu, install Rust and the native build prerequisites:

```sh
sudo apt-get install build-essential pkg-config libpcap-dev
cd host-net-monitor
cargo build --release --locked
cargo test --locked
./target/release/host-net-monitor list-interfaces
```

Copy `config.example.yaml` to `config.yaml`, choose exactly one interface, and set
output paths whose parent directories exist. Physical and VPN interfaces represent
different views of traffic; select the one you want to account for.

```sh
./target/release/host-net-monitor check-config config.yaml
sudo setcap cap_net_raw=ep target/release/host-net-monitor
./target/release/host-net-monitor run --config config.yaml
```

The capability is attached to this binary and must be reapplied after rebuilding.
Use the systemd unit below for deployment with a dedicated account. `check-config`
validates configuration syntax and bounds, and opens the MMDB when enrichment is
enabled. It does not open capture or output files.
SIGINT and SIGTERM stop capture, drain queued metadata, and flush a partial window.

## Accounting and configuration

The default interval is 30 seconds. Windows align to UTC at startup and then advance
with a monotonic clock; wall-clock adjustments do not change their duration.
Packets belong to the window in which the capture worker reads them, rather than
their kernel capture timestamp. Backlog can therefore shift traffic into a later
window. Empty windows produce no records. The final partial window uses shutdown
time, and a backward wall-clock adjustment can make that final timestamp earlier
than a preceding interval label. Diagnostics and output are separate: diagnostics
are structured JSON on stderr; flow records append to two configured files.

```json
{"timestamp":"2026-09-24T12:00:30Z","external_ip":"1.1.1.1","external_port":443,"protocol":"tcp","flow_count":2,"flow_byte_sum":1200}
```

The second log, `output.ip_path` (`./network-ips.jsonl` in the example), aggregates
all ports and protocols for each external IP in the same window:

```json
{"timestamp":"2026-09-24T12:00:30Z","external_ip":"1.1.1.1","flow_count":2,"flow_byte_sum":1200}
```

`flow_count` still counts unique five-tuples, not packets or ports. Both logs use
identical filtering and interval timestamps, including the final partial window.
If `ip_path` is omitted, it defaults to the detailed filename with the extension
`.by-ip.jsonl` (for example, `network-flows.by-ip.jsonl`). The paths must differ.
Writes to the two files are sequential, not transactional: if one fails, the
monitor stops, and the files may contain different numbers of completed windows.

Exactly one IP endpoint must match an address on an active local interface.
Addresses refresh every 30 seconds. The remote endpoint is excluded if it matches
a built-in exclusion or any additional `ignored_networks` entry. Entries may be
private or public CIDRs. Defaults are
the ten ranges listed in the spec, including both multicast ranges; this is an
exclusion list, not a general test of Internet routability.

Both directions share the same flow identity. A flow is the protocol, local IP and
port, and remote IP and port. Reuse of the same five-tuple within a window counts
once, including successive TCP connections. Incoming connections are grouped by
the remote source port, even when the local host is the server. Byte totals use IP
header lengths (IPv6 base header plus payload length), include retransmissions,
and exclude link-layer framing. Checksums are not verified.

Memory is bounded by `max_flows`, `event_queue_capacity`, and
`output_queue_capacity`. At the flow limit, existing flows continue accumulating;
packets for new flows are dropped and diagnosed. Full metadata queues drop packets
and increment reported counters. Output queue saturation or write failure stops
the monitor with a nonzero exit rather than silently continuing without output.
Capture drop and parser skip totals are reported every 30 seconds and at normal
shutdown. Exact totals require these loss counters to stay zero for relevant traffic.

## Optional local IP enrichment

```yaml
enrichment:
  enabled: true
  database_path: mmdb/IP2LOCATION-LITE-DB11.MMDB
```

Enrichment is enabled in the local `config.yaml` and disabled in the example.
Omitting the section also disables it. Set `enabled: false` to stop loading or
querying the database. Restart the monitor after changing configuration or updating
the database. Relative database paths resolve from the configuration file's
folder; output paths retain their existing working-directory-relative behavior.

Both logs gain a `geo` object with available `country_code`, `country_name`,
`region_name`, `city_name`, `latitude`, `longitude`, `postal_code`, and `time_zone`
fields. Names use English. Missing fields are omitted, and an unmatched IP has no
`geo` object. When disabled, the original JSON schema is preserved. For example:

```json
{"timestamp":"2026-09-24T12:00:30Z","external_ip":"8.8.8.8","flow_count":1,"flow_byte_sum":100,"geo":{"country_code":"US","country_name":"United States of America","region_name":"California","city_name":"Mountain View","latitude":37.38605,"longitude":-122.08385,"postal_code":"94043","time_zone":"America/Los_Angeles"}}
```

The supplied IP2Location DB11 MMDB uses the City schema, supported through the
[maxminddb reader](https://docs.rs/maxminddb/0.32.0/maxminddb/). Compatible City MMDBs
can be selected via `database_path`. Lookups run locally in the output worker,
once per external IP per window, and do not change aggregation counts or keys.
No external lookup requests are made. The database is loaded once into memory
(approximately 85 MiB for the supplied file), with no persistent lookup cache.
Missing or invalid enabled databases fail startup and `check-config`; record
lookup/decode errors stop the monitor with a diagnostic. Missing IPs are normal.
Coordinates describe the database's approximate IP location.

For systemd, place the database somewhere the service can read, outside `/home`
(which the unit protects), for example:

```sh
sudo install -d -m 0755 /usr/local/share/host-net-monitor
sudo install -m 0644 mmdb/IP2LOCATION-LITE-DB11.MMDB /usr/local/share/host-net-monitor/
```

Set `database_path` to
`/usr/local/share/host-net-monitor/IP2LOCATION-LITE-DB11.MMDB` in the service config.
The database is supplied separately; retain its included license and attribution.
Host network monitor uses the IP2Location LITE database for
[IP geolocation](https://lite.ip2location.com).

## Optional threat reputation

The generated Feodo/FireHOL database can be added to both logs independently:

```yaml
reputation:
  enabled: true
  database_path: mmdb/threat-reputation.mmdb
```

The local `config.yaml` enables this; the example configurations disable it.
When enabled, a listed external IP gains a `reputation` object containing the
source-attributed matches from the custom database. An IP absent from the database
has no `reputation` field. Disabled mode does not open the file and preserves the
existing JSON schema. The monitor validates the database type at startup and fails
if the configured file is missing or is not produced by the reputation updater.

Reputation evidence is looked up once per external IP per output window in the
writer thread. It does not affect filtering, flow counts, byte totals, or the
aggregation key. Evidence expiry is retained in each match; a match is not a claim
that traffic was malicious. Refresh the database with
`tools/reputation/update.py` and restart the monitor to load a replacement.
See [the updater guide](tools/reputation/README.md) for scheduling and feed health.

## Privacy and capture limits

libpcap receives a snapshot of up to 512 bytes per frame. That snapshot can contain
payload bytes after the headers; a fixed snapshot size cannot promise that no
payload reaches memory. The application reads only headers, retains metadata only,
never sends raw buffers between threads, and never logs or persists payloads.
This implements the spec's no-retention requirement, **not** its stricter wording
that payload bytes must never be captured. Strict prevention requires a different
capture mechanism or kernel-side extraction before userspace delivery.

Supported framing: Ethernet (up to four VLAN tags), Linux cooked SLL/SLL2, raw IP,
and BSD loopback. IPv4 options and bounded IPv6 extension chains are supported.
All IPv4 fragments and IPv6 fragment headers (including atomic fragments) are
skipped; there is no reassembly or fragment-port cache. IPv6 jumbograms, unsupported
protocols, extension chains over eight headers, and headers beyond the snapshot
are skipped. No payload inspection or checksum repair is performed.

This release captures one named interface; `any` and multiple interfaces are
rejected to avoid promising deduplication. Local addresses come from the current
network namespace. Containers in other namespaces, forwarding/NAT, VPN layering,
and NIC segmentation/coalescing offloads can affect visibility and observed byte
totals. It is not a wire-accurate billing meter. There is no automatic interface
switching: disappearance/down status stops the process on capture failure or the
next address refresh, allowing systemd or launchd to restart it.

## Install as a systemd service

Build the release binary first, then:

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin host-net-monitor
sudo install -m 0755 target/release/host-net-monitor /usr/local/bin/host-net-monitor
sudo install -d -m 0755 /etc/host-net-monitor
sudo install -m 0644 config.example.yaml /etc/host-net-monitor/config.yaml
sudo install -m 0644 packaging/host-net-monitor.service /etc/systemd/system/
sudo install -m 0644 packaging/host-net-monitor.logrotate /etc/logrotate.d/host-net-monitor
```

Edit `/etc/host-net-monitor/config.yaml`: set your interface and change the output
paths to `/var/log/host-net-monitor/flows.jsonl` (`path`) and
`/var/log/host-net-monitor/ips.jsonl` (`ip_path`). Then:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now host-net-monitor
journalctl -u host-net-monitor -f
```

The unit grants only `CAP_NET_RAW`, disables privilege escalation, and lets systemd
create the writable log directory. `CAP_NET_ADMIN` is not granted by default. The
writer reopens the file each window to support rename/create log rotation; use the
included logrotate configuration. Writes flush userspace buffers each batch, but
do not call fsync. Power failure may lose recent data. A write failure can leave a
partial final line/window; there is no durable replay or transactional output.

## Implementation and verification

`capture.rs` isolates libpcap and interface discovery behind a metadata-only
`CaptureSource` trait. `packet.rs` parses headers, `flow.rs` owns accounting,
`runtime.rs` orders metadata and interval boundaries through a bounded FIFO,
and `output.rs` writes completed windows on a separate thread.

```sh
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

Tests use synthetic headers and metadata, require no capture permissions, and
cover both directions, unique tuples, exclusions, IPv4/IPv6, framing, truncation,
fragments, malformed inputs, capacity, timing, final flush, and output errors.
The workspace-level `.github/workflows/linux.yml` runs these checks on Linux;
`macos.yml` adds Apple Silicon and Intel builds and a BPF smoke test.
The supplied-database integration test is ignored by default so CI does not need
the 85 MiB database. To run it locally after placing the MMDB in `mmdb/`:

```sh
cargo test --locked supplied_mmdb -- --ignored
```

Linux systemd, macOS LaunchDaemon, and Windows Service packaging are provided.
Multiple-interface capture, automatic deduplication, and full cross-platform
acceptance remain future work. Native macOS and Windows capture validation is
tracked by their workflows; it has not been run from this Linux workspace.

Validation on the development host: release build, formatting, Clippy with warnings
denied, and all 30 tests passed (29 standard tests plus one local MMDB integration test), including native libpcap replay of synthetic
headers and 500,000 metadata events across five bounded aggregation windows.
The Apple Silicon macOS target passed `cargo check --all-targets`; the LaunchDaemon
plist structure and installer syntax were checked locally. Native macOS capture
and launchd behavior remain unverified until the macOS workflow or a local Mac
runs them. Interface discovery succeeded on Linux. The systemd unit validated with its executable
path substituted to the local release binary. Live capture and installed-service
operation remain unverified: the live smoke test could not start because sudo
requires an interactive password. Nothing has been installed or enabled as a service.

API references used: [pcap capture API](https://docs.rs/pcap/latest/pcap/struct.Capture.html),
[libpcap snapshot length](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap_set_snaplen.3pcap),
and [YAML deserialization](https://docs.rs/serde_yaml_ng/latest/serde_yaml_ng/).

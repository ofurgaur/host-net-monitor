# macOS network monitor

The macOS monitor uses the same Rust parser, host filtering, 30-second windows,
two JSONL logs, and optional MMDB enrichment as Linux. Capture uses libpcap/BPF.
Select one interface: usually `en0` for Wi-Fi, an Ethernet interface, or a specific
`utun` VPN interface. Confirm the name with `list-interfaces`.

## Build on your Mac

Install the Xcode Command Line Tools and a current stable Rust toolchain first:

```sh
xcode-select --install
```

From the project directory:

```sh
LIBPCAP_LIBDIR=/usr/lib cargo build --release --locked
LIBPCAP_LIBDIR=/usr/lib cargo test --locked
./target/release/host-net-monitor list-interfaces
cp config.macos.example.yaml config.macos.yaml
```

The explicit library directory selects Apple's system libpcap. The native build
matches your Mac: Apple Silicon or Intel. A Linux executable will not run on macOS.
CI builds each architecture separately and packages native binaries as artifacts
when the macOS workflow runs; binaries are not bundled with this source tree.

Edit `config.macos.yaml` to select your interface. For a foreground trial, change
`output.path` and `output.ip_path` to files in a writable directory, then:

```sh
./target/release/host-net-monitor check-config config.macos.yaml
sudo ./target/release/host-net-monitor run --config config.macos.yaml
```

Press Ctrl-C to stop and flush the final partial interval. Capture requires access
to `/dev/bpf*`; the provided daemon runs as root. It does not change device
permissions. See the upstream [macOS BPF permission guidance](https://github.com/the-tcpdump-group/libpcap/blob/master/doc/README.macos).

## Install the LaunchDaemon

After building locally:

```sh
sudo sh packaging/install-macos.sh
```

If using an extracted CI artifact instead, pass its binary explicitly:

```sh
sudo sh packaging/install-macos.sh ./host-net-monitor
```

The installer creates:

- `/usr/local/bin/host-net-monitor`
- `/Library/Application Support/HostNetMonitor/config.yaml`
- `/Library/LaunchDaemons/org.host-net-monitor.plist`
- `/var/log/host-net-monitor/`

It preserves an existing config and does not start the service. Edit the installed
config with `sudo`: choose the correct interface and ignored networks. The default
log paths are `flows.jsonl` (endpoint/port/protocol) and `ips.jsonl` (per-IP totals)
inside `/var/log/host-net-monitor`.

Validate and start:

```sh
sudo /usr/local/bin/host-net-monitor check-config '/Library/Application Support/HostNetMonitor/config.yaml'
sudo launchctl bootstrap system /Library/LaunchDaemons/org.host-net-monitor.plist
sudo launchctl print system/org.host-net-monitor
sudo tail -f /var/log/host-net-monitor/service.log
```

The LaunchDaemon starts at boot and retries failed exits with a throttle. It runs
the executable directly; the application stays in the foreground under launchd.
This follows Apple's [LaunchDaemon configuration model](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html).

Stop gracefully before editing configuration, upgrading, or replacing the MMDB:

```sh
sudo launchctl bootout system/org.host-net-monitor
```

After your changes, run `bootstrap` again. For an upgrade, stop the service, run
the installer with the new binary, and start it again. `bootout` unloads the job
for the current boot; to disable future starts, also run:

```sh
sudo launchctl disable system/org.host-net-monitor
```

To re-enable it later, run `sudo launchctl enable system/org.host-net-monitor`
before `bootstrap`. The files and logs remain available.

## Enable MMDB enrichment

Copy your separately supplied database and its license files on the Mac:

```sh
sudo install -d -o root -g wheel -m 0750 '/Library/Application Support/HostNetMonitor/mmdb'
sudo install -o root -g wheel -m 0640 mmdb/IP2LOCATION-LITE-DB11.MMDB mmdb/LICENSE_LITE.TXT mmdb/README_LITE.TXT '/Library/Application Support/HostNetMonitor/mmdb/'
```

In the installed config:

```yaml
enrichment:
  enabled: true
  database_path: mmdb/IP2LOCATION-LITE-DB11.MMDB
```

The database path resolves relative to the config directory. Set `enabled: false`
to disable enrichment. Restart after changes. Both logs use the same `geo` fields
and accounting as on Linux. The installer and CI archives do not include the MMDB.
Host network monitor uses the IP2Location LITE database for
[IP geolocation](https://lite.ip2location.com).

Threat reputation is configured independently:

```yaml
reputation:
  enabled: true
  database_path: mmdb/threat-reputation.mmdb
```

Set `enabled: false` to disable reputation lookups. Restart the LaunchDaemon after
the updater publishes a replacement database.

## Operation and validation

The single-interface, VPN, fragmentation, snapshot, and loss-counter limitations
in [README.md](README.md) also apply on macOS. Ethernet, raw IP and BSD loopback
framing are supported, including IPv4/IPv6 on VPN interfaces when exposed in these
formats. Unsupported link types fail at startup. No automatic Wi-Fi/VPN switching
or packet deduplication is performed. On sleep or interface changes, capture may
pause or fail; launchd retries failures, but a changed interface name needs a config
edit. Relative output paths resolve from the LaunchDaemon's working directory.

Plan log rotation for long-running deployments: flow files are reopened at every
window, so rename/create rotation works. Stop the daemon to rotate `service.log`,
which launchd holds open, then start it again. The package does not install a
rotation scheduler. Keep files readable only by the intended administrators.

The macOS CI workflow targets both Apple Silicon (`macos-15`) and Intel
(`macos-15-intel`). It builds, runs the Rust tests, lints the plist, validates the
example config, and runs a privileged BPF smoke test on `lo0`. That test generates
only local UDP traffic, verifies capture occurred and local traffic was excluded,
then checks graceful SIGTERM shutdown. Run it manually on a Mac with:

```sh
sudo python3 tests/macos_smoke.py target/release/host-net-monitor
```

Development took place on Linux. Native macOS execution, launchd installation,
and the new CI workflow still require validation on a Mac; a cross-target Rust
check is not a linked macOS executable or a live capture test.

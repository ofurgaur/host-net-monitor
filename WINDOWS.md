# Windows host monitor

The Windows build uses the shared Rust parser and aggregator with libpcap-compatible
capture through [Npcap](https://npcap.com/). Npcap is a required deployment
dependency; install it before starting the monitor. Choose WinPcap API-compatible
mode during Npcap installation. The monitor does not install or redistribute Npcap.

## Build

Install Rust with the MSVC toolchain and Visual Studio Build Tools with the Desktop
C++ workload. Install Npcap from its official installer, including the development
SDK if building locally. Then from PowerShell:

```powershell
cargo build --release --locked
.
target\release\host-net-monitor.exe list-interfaces
Copy-Item config.windows.example.yaml config.yaml
```

The `list-interfaces` output contains Npcap device names such as
`\Device\NPF_{GUID}`. Put one exact name in `config.yaml`. `any` and multiple
interfaces remain rejected in this first Windows version to avoid promising packet
deduplication. Run a foreground smoke test as Administrator:

```powershell
.\target\release\host-net-monitor.exe check-config .\config.yaml
.\target\release\host-net-monitor.exe run --config .\config.yaml
```

Stop with Ctrl-C. Npcap capture permissions, adapter selection, and VPN visibility
are deployment concerns; the process must be able to open the selected adapter.

## Windows Service installation

The supplied service wrapper is [WinSW](https://github.com/winsw/winsw), an external
Windows Service executable. Download a version compatible with your architecture,
rename it `host-net-monitor.exe`, and place it in `packaging/` beside
`host-net-monitor.winsw.xml`. The installer installs WinSW as
`host-net-monitor.exe` and the Rust binary as `host-net-monitor-rust.exe`. The
recommended layout is:

```text
packaging\host-net-monitor.winsw.xml
packaging\host-net-monitor.exe       # WinSW wrapper
target\release\host-net-monitor.exe  # Rust monitor binary
```

Run an elevated PowerShell:

```powershell
.\packaging\install-windows.ps1
```

The installer creates `%ProgramFiles%\HostNetMonitor`, preserves an existing
configuration, validates it, and registers/starts the `host-net-monitor` service.
Edit the installed config at `%ProgramFiles%\HostNetMonitor\config.yaml`, then:

```powershell
Restart-Service host-net-monitor
Get-Service host-net-monitor
```

WinSW captures stdout/stderr in its rolling service log. JSONL paths in the example
use `C:\ProgramData` so service writes are not placed under the protected program
directory. Create those directories and grant the service identity write access if
you change the defaults. The monitor reopens both JSONL files each interval, so
rename/create rotation works; coordinate service log rotation through WinSW.

## MMDB enrichment

Set `enrichment.enabled: true` and point `database_path` at a readable copy of the
IP2Location LITE DB11 MMDB. The Windows example uses
`C:\ProgramData\HostNetMonitor\mmdb\IP2LOCATION-LITE-DB11.MMDB`. Keep the supplied
license and attribution files with the database. Set the switch to false to disable
loading it. See the main README for the emitted `geo` fields.

Threat reputation is configured independently:

```yaml
reputation:
  enabled: true
  database_path: C:\ProgramData\HostNetMonitor\mmdb\threat-reputation.mmdb
```

Set `enabled: false` to disable reputation lookups. Restart the Windows Service
after the updater publishes a replacement database.

## Validation and limitations

The Windows CI workflow builds on `windows-latest`, runs formatting, Clippy, all
unit/synthetic tests, validates the example config, and packages the release binary
and service files. It cannot validate a real Npcap adapter without an installed
driver and a live Windows runner. A Windows host should additionally test
`list-interfaces`, selected adapter capture, inbound/outbound accounting, sleep or
adapter changes, and service stop/start behavior.

Npcap/libpcap supplies link-layer frames; unsupported link types fail at startup.
The one-interface, VPN double-observation, bounded queue, fragmentation, snapshot,
and no-payload-retention limits documented in README apply to Windows too.

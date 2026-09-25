#!/bin/sh
# Install a locally built binary and LaunchDaemon. Start the service separately.
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "This installer must run on macOS." >&2
    exit 1
fi
if [ "$(id -u)" != 0 ]; then
    echo "Run with sudo after building the release binary." >&2
    exit 1
fi
if [ "$#" -gt 1 ]; then
    echo "Usage: sudo sh packaging/install-macos.sh [path-to-macos-binary]" >&2
    exit 1
fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=${1:-"$project_dir/target/release/host-net-monitor"}
config_dir='/Library/Application Support/HostNetMonitor'
log_dir='/var/log/host-net-monitor'
plist='/Library/LaunchDaemons/org.host-net-monitor.plist'

if [ ! -x "$binary" ]; then
    echo "Missing executable: $binary. Run cargo build --release --locked first." >&2
    exit 1
fi
case "$(file -b "$binary")" in
    *Mach-O*) ;;
    *) echo "Expected a macOS Mach-O executable: $binary" >&2; exit 1 ;;
esac
if launchctl print system/org.host-net-monitor >/dev/null 2>&1; then
    echo "Stop the existing service with sudo launchctl bootout system/org.host-net-monitor before upgrading." >&2
    exit 1
fi
plutil -lint "$project_dir/packaging/org.host-net-monitor.plist"
"$binary" check-config "$project_dir/config.macos.example.yaml"

install -d -o root -g wheel -m 0755 /usr/local/bin
install -d -o root -g wheel -m 0750 "$config_dir" "$log_dir"
install -o root -g wheel -m 0755 "$binary" /usr/local/bin/host-net-monitor
if [ ! -e "$config_dir/config.yaml" ]; then
    install -o root -g wheel -m 0640 "$project_dir/config.macos.example.yaml" "$config_dir/config.yaml"
fi
install -o root -g wheel -m 0644 "$project_dir/packaging/org.host-net-monitor.plist" "$plist"

echo 'Installed. Existing configuration was preserved; the service has not been started.'
echo "Edit $config_dir/config.yaml to choose the interface and optional MMDB enrichment."
echo "Start: sudo launchctl bootstrap system $plist"

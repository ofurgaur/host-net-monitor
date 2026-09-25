[CmdletBinding()]
param(
    [string]$InstallDir = "$env:ProgramFiles\HostNetMonitor",
    [string]$Binary = "$(Join-Path $PSScriptRoot '..\target\release\host-net-monitor.exe')",
    [string]$WinSW = "$(Join-Path $PSScriptRoot 'host-net-monitor.exe')"
)

$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Run this installer on Windows PowerShell or PowerShell 7.' }
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$Binary = [IO.Path]::GetFullPath($Binary)
$WinSW = [IO.Path]::GetFullPath($WinSW)

if (-not (Test-Path -LiteralPath $Binary -PathType Leaf)) {
    throw "Missing release binary: $Binary. Build it with cargo build --release --locked."
}
if (-not (Test-Path -LiteralPath $WinSW -PathType Leaf)) {
    throw "Missing WinSW executable: $WinSW. Download the matching WinSW release and place it beside this script."
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator.'
}

$service = Get-Service -Name 'host-net-monitor' -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') { Stop-Service -Name 'host-net-monitor' -Force }
    & "$InstallDir\host-net-monitor.exe" uninstall | Out-Null
}

New-Item -ItemType Directory -Force -Path $InstallDir, "$InstallDir\mmdb" | Out-Null
Copy-Item -LiteralPath $Binary -Destination "$InstallDir\host-net-monitor-rust.exe" -Force
Copy-Item -LiteralPath $WinSW -Destination "$InstallDir\host-net-monitor.exe" -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'host-net-monitor.winsw.xml') -Destination "$InstallDir\host-net-monitor.xml" -Force

$example = Join-Path $PSScriptRoot '..\config.windows.example.yaml'
if (-not (Test-Path -LiteralPath "$InstallDir\config.yaml")) {
    Copy-Item -LiteralPath $example -Destination "$InstallDir\config.yaml"
}

& "$InstallDir\host-net-monitor.exe" check-config "$InstallDir\config.yaml"
& "$InstallDir\host-net-monitor.exe" install | Out-Host
& "$InstallDir\host-net-monitor.exe" start | Out-Host
Write-Host "Installed Host Network Monitor in $InstallDir. Edit config.yaml and restart the service after changes."

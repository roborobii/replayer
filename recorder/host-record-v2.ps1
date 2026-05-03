#Requires -RunAsAdministrator
# host-record-v2.ps1 — Phase 1 launcher for the v2 recorder.
#
# Brings up the "Elf" Hyper-V VM (1440x900, basic-session) if not already
# running, opens VMConnect, then spawns the python recorder, which itself
# manages BOTH tshark instances (one writing the raw pcap safety net, one
# feeding the in-process parser). No DXRender PID polling, no MemProcFS.
#
# On Ctrl+C only the recorder is stopped — the VM and VMConnect are left
# running so subsequent sessions can attach without re-booting the guest.
#
# Usage on the NVIDIA HOST (elevated PowerShell):
#   cd C:\Users\RC\recorder
#   powershell -ExecutionPolicy Bypass -File .\host-record-v2.ps1 <session_id>
#
# Output (in C:\Users\RC\sessions):
#   recording_<id>.pcap          raw all-VM-TCP capture
#   recording_<id>.jsonl         net + input events on a unified seq timeline
#   recording_<id>.manifest.json session metadata
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$SessionId
)

$ErrorActionPreference = "Stop"

$VmName      = "Elf"
$RecorderDir = "C:\Users\RC\recorder"
$OutDir      = "C:\Users\RC\sessions"
$Tshark      = "C:\Program Files\Wireshark\tshark.exe"
$Iface       = 4   # vEthernet (Default Switch); verify with `tshark -D` if traffic is missing
$VmResW      = 1440
$VmResH      = 900
$BootTimeoutSec = 180

if (-not (Test-Path $Tshark)) { Write-Error "tshark not found at $Tshark."; exit 1 }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# v2 must not run alongside MemProcFS — it holds the hvmm device handle and
# can stall Hyper-V control operations. Warn loudly but don't kill it; user
# said it should already be stopped.
$mpfs = Get-Process -Name "MemProcFS" -ErrorAction SilentlyContinue
if ($mpfs) {
    Write-Warning "MemProcFS is running (PID $($mpfs.Id)). v2 does not use it; stop it before recording if you hit VM control issues."
}

# Windows OpenSSH can leak file handles from SCP transfers, leaving orphaned
# sshd children that hold an exclusive lock on freshly-uploaded files. Probe
# the python entrypoint; if we can't open it shared-read, kill sshd children
# started in the last 10 min EXCEPT our own session's parent (so this stays
# safe whether the launcher runs from a local console or over SSH).
function Test-FileReadable {
    param([string]$Path)
    try {
        $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
        $fs.Close()
        return $true
    } catch { return $false }
}

$PyEntry = Join-Path $RecorderDir "host_recording_stream_v2.py"
if ((Test-Path $PyEntry) -and (-not (Test-FileReadable $PyEntry))) {
    Write-Warning "[host-record-v2] $PyEntry is locked (likely orphaned sshd child from SCP). Cleaning up..."
    $myParentPid = (Get-CimInstance Win32_Process -Filter "ProcessId=$PID").ParentProcessId
    $cutoff = (Get-Date).AddMinutes(-10)
    $stale = Get-Process sshd -ErrorAction SilentlyContinue | Where-Object {
        $_.StartTime -gt $cutoff -and $_.Id -ne $myParentPid
    }
    if ($stale) {
        Write-Host "[host-record-v2]   killing $($stale.Count) recent sshd child(ren): $($stale.Id -join ', ')"
        $stale | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
    if (-not (Test-FileReadable $PyEntry)) {
        Write-Error "$PyEntry is still locked after sshd cleanup. Reboot or investigate the holder manually."
        exit 1
    }
    Write-Host "[host-record-v2]   lock released."
}

$vm = Get-VM -Name $VmName -ErrorAction Stop

if ($vm.State -ne "Running") {
    Write-Host "[host-record-v2] $VmName is $($vm.State); bringing it up..."

    if ($vm.State -ne "Off") {
        Write-Host "[host-record-v2]   stopping $VmName..."
        Stop-VM -Name $VmName -Force
        Start-Sleep -Seconds 3
    }

    # Set-VMVideo only takes effect while the VM is off and only governs the
    # basic-session "Microsoft Hyper-V Video" adapter; enhanced session is
    # disabled host-wide below so the resolution actually sticks.
    Write-Host "[host-record-v2]   pinning resolution to ${VmResW}x${VmResH}..."
    Set-VMVideo -VMName $VmName -HorizontalResolution $VmResW -VerticalResolution $VmResH -ResolutionType Single

    Write-Host "[host-record-v2]   disabling enhanced session mode (host-wide)..."
    Set-VMHost -EnableEnhancedSessionMode $false

    Write-Host "[host-record-v2]   restarting vmms..."
    Restart-Service vmms -Force
    Start-Sleep -Seconds 5

    Write-Host "[host-record-v2]   closing any existing VMConnect sessions..."
    Get-Process vmconnect -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 1

    Write-Host "[host-record-v2]   starting $VmName..."
    Start-VM -Name $VmName
    Start-Process "vmconnect.exe" -ArgumentList "localhost",$VmName

    Write-Host "[host-record-v2]   waiting up to ${BootTimeoutSec}s for guest heartbeat..."
    $deadline = (Get-Date).AddSeconds($BootTimeoutSec)
    $hb = $null
    while ((Get-Date) -lt $deadline) {
        $hb = (Get-VMIntegrationService -VMName $VmName -Name Heartbeat -ErrorAction SilentlyContinue).PrimaryStatusDescription
        if ($hb -eq "OK") { break }
        Start-Sleep -Seconds 2
    }
    if ($hb -ne "OK") {
        Write-Warning "Guest heartbeat not OK after ${BootTimeoutSec}s (status: $hb). Proceeding anyway."
    } else {
        Write-Host "[host-record-v2]   guest heartbeat OK."
        Start-Sleep -Seconds 5
    }
} else {
    Write-Host "[host-record-v2] $VmName already running; leaving VM/resolution untouched."
    if (-not (Get-Process vmconnect -ErrorAction SilentlyContinue)) {
        Write-Host "[host-record-v2]   no VMConnect open; launching..."
        Start-Process "vmconnect.exe" -ArgumentList "localhost",$VmName
        Start-Sleep -Seconds 2
    }
}

$pcap     = Join-Path $OutDir "recording_${SessionId}.pcap"
$jsonl    = Join-Path $OutDir "recording_${SessionId}.jsonl"
$manifest = Join-Path $OutDir "recording_${SessionId}.manifest.json"

if (Test-Path $pcap)     { Write-Error "$pcap exists; pick a different id or delete it.";     exit 1 }
if (Test-Path $jsonl)    { Write-Error "$jsonl exists; pick a different id or delete it.";    exit 1 }
if (Test-Path $manifest) { Write-Error "$manifest exists; pick a different id or delete it."; exit 1 }

Write-Host "[host-record-v2] starting recorder; Ctrl+C to stop."
Write-Host "[host-record-v2]   id=$SessionId  iface=$Iface"
Write-Host "[host-record-v2]   pcap     = $pcap"
Write-Host "[host-record-v2]   jsonl    = $jsonl"
Write-Host "[host-record-v2]   manifest = $manifest"
Write-Host ""

Set-Location $RecorderDir

try {
    & python "$RecorderDir\host_recording_stream_v2.py" `
        --id       $SessionId `
        --iface    $Iface `
        --pcap     $pcap `
        --jsonl    $jsonl `
        --manifest $manifest `
        --tshark   "$Tshark"
} finally {
    Write-Host ""
    Write-Host "[host-record-v2] recorder exited; VM and VMConnect left running."
    Write-Host "[host-record-v2] reporting output sizes:"
    if (Test-Path $pcap) {
        $sz = (Get-Item $pcap).Length
        Write-Host "[host-record-v2]   pcap     : $pcap  ($sz bytes)"
    } else {
        Write-Host "[host-record-v2]   pcap     : MISSING"
    }
    if (Test-Path $jsonl) {
        $sz = (Get-Item $jsonl).Length
        $ln = (Get-Content $jsonl | Measure-Object -Line).Lines
        Write-Host "[host-record-v2]   jsonl    : $jsonl  ($sz bytes, $ln lines)"
    } else {
        Write-Host "[host-record-v2]   jsonl    : MISSING"
    }
    if (Test-Path $manifest) {
        $sz = (Get-Item $manifest).Length
        Write-Host "[host-record-v2]   manifest : $manifest  ($sz bytes)"
    } else {
        Write-Host "[host-record-v2]   manifest : MISSING"
    }
}

# Local Windows-host recorder launcher.
#
# Single-window flow that captures everything from t=0:
#   1. Start tshark immediately, writing recording_<id>.pcap (all VM TCP).
#   2. Wait for DXRender to appear in M:\pid (user logs in / launches game).
#   3. Start the python recorder for form-events + parsed net JSONL.
#   4. Ctrl+C cleanly stops both.
#
# Use this when you want master-server (port 1818) traffic captured,
# i.e. start the script BEFORE clicking Login in the game launcher.
#
# Usage on the Windows host:
#   cd C:\Users\RC\recorder
#   powershell -ExecutionPolicy Bypass -File .\host-record.ps1 <session_id>
#
# Output:
#   C:\Users\RC\sessions\recording_<id>.pcap   raw all-VM-TCP capture
#   C:\Users\RC\sessions\recording_<id>.jsonl  parsed form-events + game-port frames
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$SessionId,
    [int]$PollMs = 100,
    [int]$Iface = 8
)

$ErrorActionPreference = "Stop"
$RecorderDir = "C:\Users\RC\recorder"
$OutDir      = "C:\Users\RC\sessions"
$Tshark      = "C:\Program Files\Wireshark\tshark.exe"

if (-not (Test-Path "M:\pid")) { Write-Error "MemProcFS not mounted at M:\."; exit 1 }
if (-not (Test-Path $Tshark))  { Write-Error "tshark not found at $Tshark."; exit 1 }
if (-not (Test-Path $OutDir))  { New-Item -ItemType Directory -Path $OutDir | Out-Null }

$pcap  = Join-Path $OutDir "recording_${SessionId}.pcap"
$jsonl = Join-Path $OutDir "recording_${SessionId}.jsonl"
if (Test-Path $pcap)  { Write-Error "$pcap exists; pick a different id or delete it."; exit 1 }
if (Test-Path $jsonl) { Write-Error "$jsonl exists; pick a different id or delete it."; exit 1 }

function Find-DXRenderPid {
    Get-ChildItem "M:\pid" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $namePath = Join-Path $_.FullName "name.txt"
        $raw = Get-Content $namePath -Raw -ErrorAction SilentlyContinue
        if ($raw -and $raw.Trim() -match "DXRender") { [int]$_.Name }
    } | Select-Object -First 1
}

# 1) Start tshark immediately to capture all VM TCP from t=0.
Write-Host "[host-record] starting tshark -> $pcap"
$tshark = Start-Process -FilePath $Tshark `
    -ArgumentList @("-i", "$Iface", "-f", "tcp", "-w", "$pcap", "-q") `
    -PassThru -WindowStyle Hidden -RedirectStandardError "$pcap.err.log"
Start-Sleep -Milliseconds 800

if ($tshark.HasExited) {
    Write-Error "tshark died immediately (rc=$($tshark.ExitCode)). Check $pcap.err.log"
    exit 1
}
Write-Host "[host-record] tshark pid=$($tshark.Id)  capturing all VM TCP"

# 2) Wait for DXRender to appear.
$dxr = Find-DXRenderPid
if (-not $dxr) {
    Write-Host "[host-record] waiting for DXRender. Launch the game in the VM now..."
    $started = Get-Date
    while (-not $dxr -and ((Get-Date) - $started).TotalSeconds -lt 600) {
        Start-Sleep -Milliseconds 200
        $dxr = Find-DXRenderPid
    }
    if (-not $dxr) {
        Write-Error "DXRender did not appear within 600s; aborting"
        Stop-Process -Id $tshark.Id -Force -ErrorAction SilentlyContinue
        exit 1
    }
    $waitedMs = [int]((Get-Date) - $started).TotalMilliseconds
    Write-Host "[host-record] DXRender pid=$dxr appeared after ${waitedMs}ms"
} else {
    Write-Host "[host-record] DXRender pid=$dxr already running"
}

# 3) Start python recorder for form-poller + parsed JSONL.
Write-Host "[host-record] starting python recorder (form-poller + JSONL parser)"
Write-Host "[host-record] Ctrl+C to stop both."
Write-Host ""
Set-Location $RecorderDir

try {
    & python host_recording_stream.py --pid $dxr --id $SessionId --poll-ms $PollMs --iface $Iface --out-dir $OutDir
} finally {
    Write-Host ""
    Write-Host "[host-record] stopping tshark (pid=$($tshark.Id))"
    Stop-Process -Id $tshark.Id -Force -ErrorAction SilentlyContinue
    if (Test-Path $pcap) {
        $sz = (Get-Item $pcap).Length
        Write-Host "[host-record] pcap saved: $pcap  ($sz bytes)"
    }
    if (Test-Path $jsonl) {
        $ln = (Get-Content $jsonl | Measure-Object -Line).Lines
        Write-Host "[host-record] jsonl saved: $jsonl  ($ln lines)"
    }
}

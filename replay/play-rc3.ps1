# play-rc3.ps1 — Phase 2 RC3 orchestration.
# Pulls a recording from Mac via SCP, launches XenClient pointed at Mac,
# waits for the server-select handshake, then runs input_replayer.py.

param(
    [Parameter(Mandatory = $true)]
    [string]$RecordingId
)

$ErrorActionPreference = "Stop"

$MacIp        = "192.168.12.148"
$MacUser      = "robin"
$MacRecDir    = "/Users/robin/dev/github.com/roborobii/replayer/sessions"
$XenClientExe = "C:\work\solstice-client\XenRebirth_Xenepic\XenClient.exe"
$ReplayDir    = "C:\Users\RC3\replay"
$PythonExe    = "C:\Tools\python311\python.exe"
$GateDelaySec = 14

Write-Host "[play-rc3] RecordingId=$RecordingId Mac=$MacIp" -ForegroundColor Cyan

# 1. Ensure replay dir exists.
if (-not (Test-Path $ReplayDir)) {
    New-Item -ItemType Directory -Path $ReplayDir | Out-Null
}

# 2. SCP recording bundle from Mac (skip if already pushed locally).
$jsonl = Join-Path $ReplayDir "recording_$RecordingId.jsonl"
if (Test-Path $jsonl) {
    Write-Host "[play-rc3] using local copy: $jsonl"
} else {
    $src = "${MacUser}@${MacIp}:${MacRecDir}/recording_${RecordingId}.*"
    Write-Host "[play-rc3] scp $src -> $ReplayDir"
    & scp $src "$ReplayDir\"
    if ($LASTEXITCODE -ne 0) { throw "scp failed (exit $LASTEXITCODE) - push files manually from Mac side or set up RC3->Mac SSH key" }
    if (-not (Test-Path $jsonl)) { throw "missing $jsonl after scp" }
}

# 3. Verify python and XenClient exist.
foreach ($exe in @($PythonExe, $XenClientExe)) {
    if (-not (Test-Path $exe)) { throw "missing executable: $exe" }
}
Write-Host "[play-rc3] python: $PythonExe"
& $PythonExe --version
Write-Host "[play-rc3] xenclient: $XenClientExe"

# 4. Launch XenClient pointed at Mac emulator.
Write-Host "[play-rc3] launching XenClient -i $MacIp"
$xenProc = Start-Process -FilePath $XenClientExe `
    -ArgumentList @("-i", $MacIp) `
    -WorkingDirectory (Split-Path $XenClientExe) `
    -PassThru
Write-Host "[play-rc3] XenClient pid=$($xenProc.Id)"

# 5. Wait for the client to reach server-select (matches recorded gate delta).
Write-Host "[play-rc3] sleeping ${GateDelaySec}s for server-select handshake"
Start-Sleep -Seconds $GateDelaySec

# 6. Run input replayer.
$replayer = Join-Path $PSScriptRoot "input_replayer.py"
if (-not (Test-Path $replayer)) {
    # Fall back to ReplayDir copy (if user copied this whole folder).
    $replayer = Join-Path $ReplayDir "input_replayer.py"
}
if (-not (Test-Path $replayer)) { throw "input_replayer.py not found" }

Write-Host "[play-rc3] running input_replayer.py against $jsonl"
& $PythonExe $replayer $jsonl --window-title "XenClient" --start-from gate_opened
$rc = $LASTEXITCODE

Write-Host "[play-rc3] input_replayer exit=$rc; XenClient pid=$($xenProc.Id) left running"
exit $rc

# Stops every replay-side process and verifies the input_replayer
# python is actually gone before returning. Without this verification,
# the next step (neutralize) can race against a still-running replayer
# that re-presses keys we just released.

$ErrorActionPreference = "SilentlyContinue"

# 1. Stop + unregister scheduled tasks. Stop-ScheduledTask is async,
#    so it returns before the underlying process exits.
foreach ($t in @("xen-replay-input", "xen-launch", "xen-resize", "xen-neutralize")) {
    Stop-ScheduledTask -TaskName $t
    Unregister-ScheduledTask -TaskName $t -Confirm:$false
}

# 2. Force-stop the game and any stray python replayers.
Get-Process XenClient, DXRender, GLRender | Stop-Process -Force
function Get-Replayers {
    Get-CimInstance Win32_Process -Filter "Name = 'python.exe' OR Name = 'pythonw.exe'" |
        Where-Object { $_.CommandLine -match 'input_replayer' }
}
foreach ($p in Get-Replayers) {
    Stop-Process -Id $p.ProcessId -Force
}

# 3. Poll for the python replayer process to actually exit. Without this
#    we risk neutralize racing the still-dying replayer.
$deadline = (Get-Date).AddSeconds(5)
while ((Get-Date) -lt $deadline) {
    $remaining = @(Get-Replayers)
    if ($remaining.Count -eq 0) { break }
    Start-Sleep -Milliseconds 100
}

$remaining = @(Get-Replayers)
if ($remaining.Count -gt 0) {
    Write-Host "[kill_replayer] WARN: $($remaining.Count) replayer process(es) survived 5s; PIDs: $($remaining.ProcessId -join ',')"
    # Last-ditch: TerminateProcess via taskkill /F /T (kills tree).
    foreach ($p in $remaining) {
        & taskkill.exe /F /T /PID $p.ProcessId 2>$null | Out-Null
    }
    Start-Sleep -Milliseconds 500
}

$still = @(Get-Replayers)
if ($still.Count -gt 0) {
    Write-Host "[kill_replayer] FAIL: replayer still alive after taskkill; PIDs: $($still.ProcessId -join ',')"
    exit 1
}
Write-Host "[kill_replayer] all replayer processes confirmed dead"
exit 0

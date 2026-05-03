param(
    [Parameter(Mandatory=$true)] [string] $RecordingId,
    [Parameter(Mandatory=$true)] [int]    $Seq,
    [int]    $CursorMaskPx = 0,
    [string] $WindowTitle = "XenepicOnline Revo",
    [string] $PythonExe   = "C:\Tools\python311\python.exe"
)

# Schedule cv_calibrate.py in the interactive session so EnumWindows can
# actually see XenClient's window. Mirrors schedule_input.ps1.
#
# Trick: the scheduled action runs powershell.exe so the Python output
# can be redirected via `*>` into a log file. Running python.exe directly
# leaves stdout/stderr nowhere to go.

$replayDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$out       = Join-Path $replayDir "cv_calibrate_$Seq.png"
$logPath   = Join-Path $replayDir "cv_calibrate.log"
$pyScript  = Join-Path $replayDir "cv_calibrate.py"

if (Test-Path $logPath) { Remove-Item $logPath -Force }
if (Test-Path $out)     { Remove-Item $out -Force }

$maskArg = if ($CursorMaskPx -gt 0) { " --cursor-mask-px $CursorMaskPx" } else { "" }
$cmd = "& '$PythonExe' '$pyScript' --recording '$RecordingId' --seq $Seq --window-title '$WindowTitle' --out '$out'$maskArg *> '$logPath'"
$psArg = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"$cmd`""

$action    = New-ScheduledTaskAction    -Execute "powershell.exe" -Argument $psArg -WorkingDirectory $replayDir
$principal = New-ScheduledTaskPrincipal -UserId RC3 -RunLevel Highest -LogonType Interactive
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
$task      = New-ScheduledTask -Action $action -Principal $principal -Settings $settings

Register-ScheduledTask -TaskName xen-cv-calibrate -InputObject $task -Force | Out-Null
Start-ScheduledTask -TaskName xen-cv-calibrate

$deadline = (Get-Date).AddSeconds(25)
while ((Get-Date) -lt $deadline) {
    if (Test-Path $out) { break }
    Start-Sleep -Milliseconds 250
}
Start-Sleep -Milliseconds 500

if (Test-Path $logPath) {
    Write-Host "----- cv_calibrate.log -----"
    Get-Content $logPath
    Write-Host "----------------------------"
}
if (-not (Test-Path $out)) {
    Write-Host "[cv-calibrate.ps1] FAIL: $out not produced"
    exit 1
}

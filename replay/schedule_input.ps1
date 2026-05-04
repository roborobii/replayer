param(
    [Parameter(Mandatory = $true)] [string]$RecordingId,
    [string]$WindowTitle = "XenepicOnline Revo",
    [string]$StartFrom = "gate_opened",
    [int]$XCorrection = 0,
    [int]$YCorrection = 0,
    [int]$TopOffset = -1,
    [int]$LeftOffset = 0,
    [string]$CtrlHost = "",
    [int]$CtrlPort = 18999,
    [int]$StopAtSeq = -1,
    [ValidateSet("sendinput","postmessage")] [string]$ClickMode = "sendinput",
    [string]$CvDebugDir = "",
    [double]$Speed = 1.0
)
$ErrorActionPreference = "Stop"
$replayDir = "C:\Users\RC3\replay"
$pythonw = "C:\Tools\python311\pythonw.exe"
$replayer = "$replayDir\input_replayer.py"
$jsonl = "$replayDir\recording_${RecordingId}.jsonl"
if (-not (Test-Path $jsonl)) { throw "missing $jsonl" }
if (-not (Test-Path $pythonw)) { throw "missing $pythonw (embedded distro should ship pythonw.exe alongside python.exe)" }

# pythonw.exe runs without a console window, so SendInput clicks land on
# the foreground game instead of a stray cmd box. Logs come out via the
# in-script redirect in input_replayer.py.
$argLine = "`"$replayer`" `"$jsonl`" --window-title `"$WindowTitle`" --start-from $StartFrom --x-correction $XCorrection --y-correction $YCorrection --left-offset $LeftOffset --click-mode $ClickMode --speed $Speed"
if ($TopOffset -ge 0) { $argLine += " --top-offset $TopOffset" }
if ($CtrlHost -ne "") { $argLine += " --ctrl-host $CtrlHost --ctrl-port $CtrlPort" }
if ($CvDebugDir -ne "") { $argLine += " --cv-debug-dir `"$CvDebugDir`"" }

$action = New-ScheduledTaskAction -Execute $pythonw -Argument $argLine -WorkingDirectory $replayDir
$principal = New-ScheduledTaskPrincipal -UserId RC3 -RunLevel Highest -LogonType Interactive
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 1)
$task = New-ScheduledTask -Action $action -Principal $principal -Settings $settings
Register-ScheduledTask -TaskName xen-replay-input -InputObject $task -Force | Out-Null
Start-ScheduledTask -TaskName xen-replay-input
Write-Host "[schedule_input] started; arg='$argLine'"
Write-Host "[schedule_input] log: $replayDir\input_replayer.log"

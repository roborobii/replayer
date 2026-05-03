# Record-Session.ps1 -- VM memory snapshot recorder (Windows host).
#
# Wraps record_session.py. Reads VM DXRender memory via MemProcFS (M:\)
# and snapshots watched Delphi form instances + globals every time a click
# changes state. Read-only; invisible to guest and live server.
#
# Click-driven: takes one snapshot immediately, then one per mouse click
# anywhere on host (including clicks forwarded into the VM game window).
#
# Usage (from interactive PowerShell, not SSH):
#     cd C:\Users\RC\sessions
#     .\Record-Session.ps1 jureah_raito_run1
#     .\Record-Session.ps1 jureah_raito_run1 -AlsoKeys   # also snap on keypress
#
# Drive VM through one full flow (server pick → char pick → into world),
# press Ctrl+C when done. Output: C:\Users\RC\sessions\recordings\<label>\
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Label,

    [Parameter(Mandatory=$false)]
    [switch]$AlsoKeys,

    [Parameter(Mandatory=$false)]
    [int]$DelayMs = 500,

    [Parameter(Mandatory=$false)]
    [int]$IfaceIndex = 8,

    [Parameter(Mandatory=$false)]
    [switch]$NoNet
)

$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$py   = Join-Path $here "record_session.py"

if (-not (Test-Path $py)) {
    Write-Error "record_session.py not found next to this script ($py)"
    exit 1
}

if (-not (Test-Path "M:\name")) {
    Write-Error "MemProcFS not mounted at M:\ -- start it first."
    exit 1
}

# Recorder writes to C:\Users\RC\sessions\recordings\<label>\
$env:RECORD_OUT_BASE = (Join-Path $here "recordings")
$outDir = Join-Path $env:RECORD_OUT_BASE $Label
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host ("[Record-Session] label={0}  delay={1}ms  also-keys={2}  net={3}" -f $Label, $DelayMs, $AlsoKeys, (-not $NoNet))
Write-Host ("[Record-Session] output: {0}" -f $outDir)
Write-Host "[Record-Session] click-driven: 1 snap on start + 1 per button-up."
Write-Host "[Record-Session] drive VM through flow; Ctrl+C when done."

# Start tshark in background to capture all V2 traffic during the session.
$tshark = $null
$pcapPath = Join-Path $outDir "network.pcap"
if (-not $NoNet) {
    $tsharkExe = "C:\Program Files\Wireshark\tshark.exe"
    if (-not (Test-Path $tsharkExe)) {
        Write-Warning "tshark not found at $tsharkExe -- skipping pcap capture."
    } else {
        # Capture V2 ports + auth: 1818 (master), 1819 (svc), 18123 (world), 18124 (chat).
        $filter = "tcp port 1818 or tcp port 1819 or tcp port 18123 or tcp port 18124"
        $tsharkLog = Join-Path $outDir "tshark.log"
        # Start-Process splits ArgumentList on spaces unless each arg with
        # spaces is wrapped in embedded double quotes. Filter and pcap path
        # both need this.
        $tsharkArgs = @(
            "-i", "$IfaceIndex",
            "-f", ('"{0}"' -f $filter),
            "-w", ('"{0}"' -f $pcapPath)
        )
        Write-Host ("[Record-Session] starting tshark iface={0} -> {1}" -f $IfaceIndex, $pcapPath)
        # NoNewWindow keeps it in same console group; redirect stderr so we can
        # see capture errors. Don't use -WindowStyle Hidden (breaks tshark output).
        $tshark = Start-Process -FilePath $tsharkExe -ArgumentList $tsharkArgs `
            -PassThru -NoNewWindow `
            -RedirectStandardError $tsharkLog `
            -RedirectStandardOutput "$tsharkLog.out"
        Start-Sleep -Milliseconds 1500
        if ($tshark.HasExited) {
            Write-Warning ("tshark exited immediately (code={0}). See {1} for details." -f $tshark.ExitCode, $tsharkLog)
            if (Test-Path $tsharkLog) {
                Get-Content $tsharkLog | Select-Object -First 10 | ForEach-Object { Write-Warning "  $_" }
            }
            $tshark = $null
        } else {
            Write-Host ("[Record-Session] tshark pid={0} (log: {1})" -f $tshark.Id, $tsharkLog)
        }
    }
}

try {
    $pyArgs = @($Label, "--delay-ms", $DelayMs)
    if ($AlsoKeys) { $pyArgs += "--keys" }
    python $py @pyArgs
} finally {
    if ($tshark -and -not $tshark.HasExited) {
        Write-Host ("[Record-Session] stopping tshark pid={0}" -f $tshark.Id)
        Stop-Process -Id $tshark.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 200
        if (Test-Path $pcapPath) {
            $pcapSize = (Get-Item $pcapPath).Length
            Write-Host ("[Record-Session] pcap: {0} ({1:N0} bytes)" -f $pcapPath, $pcapSize)
        }
    }
}

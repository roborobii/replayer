param(
    [string]$Title = "XenepicOnline Revo",
    [int]$ClientW = 1440,
    [int]$ClientH = 900,
    [int]$X = 0,
    [int]$Y = 0,
    [int]$RetrySec = 30
)
"START $(Get-Date -Format 'HH:mm:ss.fff')" | Out-File -FilePath "$PSScriptRoot\resize.log" -Encoding UTF8
function Log { param($m); "$($m)" | Out-File -FilePath "$PSScriptRoot\resize.log" -Append -Encoding UTF8 }
trap { Log "TRAP: $_"; continue }
Log "params Title='$Title' ${ClientW}x${ClientH} retry=${RetrySec}s"
$src = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public class WR {
    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")]
    public static extern bool MoveWindow(IntPtr h, int x, int y, int w, int hh, bool repaint);
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")]
    public static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr h);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int L,T,R,B; }
    public static IntPtr FindBySubstring(string needle) {
        IntPtr found = IntPtr.Zero;
        EnumWindows((h, l) => {
            if (!IsWindowVisible(h)) return true;
            var sb = new StringBuilder(512);
            GetWindowTextW(h, sb, 512);
            if (sb.ToString().IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
                found = h;
                return false;
            }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
'@
try { Add-Type -TypeDefinition $src } catch { Log "Add-Type failed: $_"; exit 2 }
Log "Add-Type OK"

$h = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds($RetrySec)
$attempts = 0
while ((Get-Date) -lt $deadline) {
    $h = [WR]::FindBySubstring($Title)
    $attempts++
    if ($h -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 200
}
Log "FindWindow attempts=$attempts hwnd=$h"
if ($h -eq [IntPtr]::Zero) { Log "window '$Title' not found"; exit 1 }

# Measure current non-client overhead (borders + title bar) so we can
# compute the outer size that yields the desired client area.
$wr = New-Object WR+RECT
[WR]::GetWindowRect($h, [ref]$wr) | Out-Null
$cr = New-Object WR+RECT
[WR]::GetClientRect($h, [ref]$cr) | Out-Null
$ncW = ($wr.R - $wr.L) - ($cr.R - $cr.L)
$ncH = ($wr.B - $wr.T) - ($cr.B - $cr.T)

$outerW = $ClientW + $ncW
$outerH = $ClientH + $ncH

[WR]::MoveWindow($h, $X, $Y, $outerW, $outerH, $true) | Out-Null
[WR]::SetForegroundWindow($h) | Out-Null

[WR]::GetWindowRect($h, [ref]$wr) | Out-Null
[WR]::GetClientRect($h, [ref]$cr) | Out-Null
$gotW = $cr.R - $cr.L
$gotH = $cr.B - $cr.T
Log ("RESULT hwnd=0x{0:x} window=({1},{2}) outer={3}x{4} client={5}x{6}" -f `
    $h.ToInt64(), $wr.L, $wr.T, ($wr.R-$wr.L), ($wr.B-$wr.T), $gotW, $gotH)
if ($gotW -ne $ClientW -or $gotH -ne $ClientH) {
    Log "WARN: game ignored resize (locked render size $gotW x $gotH)"
}
Log "DONE $(Get-Date -Format 'HH:mm:ss.fff')"

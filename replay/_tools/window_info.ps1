param([string]$Title = "XenepicOnline Revo")
$src = @'
using System;
using System.Runtime.InteropServices;
public class WI {
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr FindWindow(string c, string n);
    [DllImport("user32.dll")]
    public static extern bool GetClientRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")]
    public static extern bool ClientToScreen(IntPtr h, ref POINT p);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int L,T,R,B; }
    [StructLayout(LayoutKind.Sequential)]
    public struct POINT { public int X,Y; }
}
'@
Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
$h = [WI]::FindWindow($null, $Title)
if ($h -eq [IntPtr]::Zero) {
    Write-Output "window '$Title' not found"
    exit 1
}
$cr = New-Object WI+RECT
[WI]::GetClientRect($h, [ref]$cr) | Out-Null
$wr = New-Object WI+RECT
[WI]::GetWindowRect($h, [ref]$wr) | Out-Null
$tl = New-Object WI+POINT
$tl.X = 0; $tl.Y = 0
[WI]::ClientToScreen($h, [ref]$tl) | Out-Null
Write-Output ("hwnd=0x{0:x}" -f $h.ToInt64())
Write-Output ("window_rect: ({0},{1}) {2}x{3}" -f $wr.L, $wr.T, ($wr.R-$wr.L), ($wr.B-$wr.T))
Write-Output ("client_rect: {0}x{1} client_top_left_screen=({2},{3})" -f ($cr.R-$cr.L), ($cr.B-$cr.T), $tl.X, $tl.Y)

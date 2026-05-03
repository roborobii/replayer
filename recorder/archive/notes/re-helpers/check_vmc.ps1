Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class W {
  [DllImport("user32.dll")] public static extern bool GetClientRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
}
"@
foreach ($p in (Get-Process vmconnect -ErrorAction SilentlyContinue)) {
  $h = $p.MainWindowHandle
  if ($h -eq [IntPtr]::Zero) { continue }
  $cr = New-Object W+RECT
  [W]::GetClientRect($h, [ref]$cr) | Out-Null
  $wr = New-Object W+RECT
  [W]::GetWindowRect($h, [ref]$wr) | Out-Null
  "vmconnect pid=$($p.Id) title='$($p.MainWindowTitle)' Client=$($cr.R-$cr.L)x$($cr.B-$cr.T) Window=$($wr.R-$wr.L)x$($wr.B-$wr.T)"
}

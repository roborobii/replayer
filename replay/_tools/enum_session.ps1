# Run via Task Scheduler so we enumerate windows in the user's interactive
# session (SSH-launched powershell can't see them).
$src = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Collections.Generic;
public class EnumS {
    [DllImport("user32.dll")]
    static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
    delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    static extern int GetWindowTextW(IntPtr hWnd, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)]
    static extern int GetClassNameW(IntPtr hWnd, StringBuilder s, int n);
    [DllImport("user32.dll")]
    static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")]
    static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll")]
    static extern bool GetWindowRect(IntPtr hWnd, out RECT r);
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT { public int L,T,R,B; }
    public static List<string> Run() {
        var rows = new List<string>();
        EnumWindows((h, l) => {
            if (!IsWindowVisible(h)) return true;
            uint pid; GetWindowThreadProcessId(h, out pid);
            var t = new StringBuilder(512); GetWindowTextW(h, t, 512);
            var c = new StringBuilder(512); GetClassNameW(h, c, 512);
            RECT r; GetWindowRect(h, out r);
            int w = r.R - r.L, ht = r.B - r.T;
            if (w < 100 || ht < 100) return true;
            rows.Add(string.Format("pid={0} hwnd=0x{1:x} pos=({2},{3}) size={4}x{5} title='{6}' class='{7}'",
                pid, h.ToInt64(), r.L, r.T, w, ht, t, c));
            return true;
        }, IntPtr.Zero);
        return rows;
    }
}
'@
Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
$rows = [EnumS]::Run()
$out = "C:\Users\RC3\replay\windows_dump.txt"
$rows | Out-File -FilePath $out -Encoding UTF8
"count=$($rows.Count) | output: $out" | Out-File -FilePath $out -Append -Encoding UTF8

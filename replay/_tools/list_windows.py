#!/usr/bin/env python3
"""List visible top-level windows. Writes to stdout AND a sibling file
in case ssh stdout buffering swallows it."""
import ctypes
import ctypes.wintypes as wt
import os
import sys

u = ctypes.WinDLL("user32", use_last_error=True)
u.IsWindowVisible.argtypes = [wt.HWND]
u.IsWindowVisible.restype = wt.BOOL
u.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
u.GetWindowTextW.restype = ctypes.c_int
u.GetClientRect.argtypes = [wt.HWND, ctypes.c_void_p]
u.GetClientRect.restype = wt.BOOL


class RECT(ctypes.Structure):
    _fields_ = [("l", wt.LONG), ("t", wt.LONG),
                ("r", wt.LONG), ("b", wt.LONG)]


CB = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
u.EnumWindows.argtypes = [CB, wt.LPARAM]
u.EnumWindows.restype = wt.BOOL

lines = []


def _cb(h, lp):
    try:
        if not u.IsWindowVisible(h):
            return True
        buf = ctypes.create_unicode_buffer(512)
        u.GetWindowTextW(h, buf, 512)
        title = buf.value
        rect = RECT()
        u.GetClientRect(h, ctypes.byref(rect))
        cw, ch = rect.r - rect.l, rect.b - rect.t
        lines.append(f"hwnd=0x{h:X}  client={cw}x{ch}  title={title!r}")
    except Exception as e:
        lines.append(f"err: {e}")
    return True


u.EnumWindows(CB(_cb), 0)
out = "\n".join(lines)
print(out, flush=True)
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "windows.txt"), "w", encoding="utf-8") as f:
    f.write(out)
sys.stdout.flush()

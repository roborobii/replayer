#!/usr/bin/env python3
"""
input_replayer.py — Phase 2 RC3-side input replayer.

Reads recording_<id>.jsonl, finds the XenClient window, and replays
recorded mouse/keyboard events via Win32 SendInput on the host. The
recorder captured input in vmconnect's client area (which has a 75px
toolbar at the top), so we compensate using vm_res from the manifest.

NOTE on SendInput coords (MOUSEEVENTF_ABSOLUTE):
    Absolute coords are normalized 0..65535 across the *virtual screen*
    (i.e. the union of all monitors), NOT a particular window. We map
    the in-game (game_x, game_y) -> screen pixel via the XenClient
    window's client rect, then normalize against virtual-screen bounds.
"""

import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import signal
import sys
import threading
import time
from typing import List, Optional

# spawn_parser is a sibling module in this directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from spawn_parser import parse_spawn_frame  # type: ignore
except Exception:
    parse_spawn_frame = None  # type: ignore

# When launched via pythonw.exe (no console window — needed so SendInput
# clicks aren't stolen by a stray cmd prompt), redirect stdout/stderr to
# a log file so the Task Scheduler launch path stays observable.
if os.path.basename(sys.executable).lower() == "pythonw.exe":
    _log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                             "input_replayer.log")
    _f = open(_log_path, "w", buffering=1, encoding="utf-8")
    sys.stdout = _f
    sys.stderr = _f


# ---------------------------------------------------------------------------
# Win32 plumbing

user32 = ctypes.WinDLL("user32", use_last_error=True)

INPUT_MOUSE = 0
INPUT_KEYBOARD = 1

MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800
MOUSEEVENTF_HWHEEL = 0x1000
MOUSEEVENTF_VIRTUALDESK = 0x4000
MOUSEEVENTF_ABSOLUTE = 0x8000

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_SCANCODE = 0x0008
KEYEVENTF_EXTENDEDKEY = 0x0001

# Map pynput key.name strings (recorder's payload) -> Windows VK codes.
# Recorder leaves vk=None for special keys, only setting vk for character
# keys; without this table f1/alt/etc. would silently no-op. Both lower-
# and Key.-prefixed forms are handled at lookup time.
NAME_TO_VK = {
    # function keys
    **{f"f{i}": 0x6F + i for i in range(1, 13)},  # f1=0x70 ... f12=0x7B
    # modifiers (left/right variants + generic)
    "alt": 0x12, "alt_l": 0xA4, "alt_r": 0xA5, "alt_gr": 0xA5,
    "ctrl": 0x11, "ctrl_l": 0xA2, "ctrl_r": 0xA3,
    "shift": 0x10, "shift_l": 0xA0, "shift_r": 0xA1,
    "cmd": 0x5B, "cmd_l": 0x5B, "cmd_r": 0x5C,  # left/right Win key
    # editing / navigation
    "backspace": 0x08, "tab": 0x09, "enter": 0x0D, "esc": 0x1B,
    "space": 0x20, "delete": 0x2E, "insert": 0x2D,
    "home": 0x24, "end": 0x23, "page_up": 0x21, "page_down": 0x22,
    "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
    # locks / misc
    "caps_lock": 0x14, "num_lock": 0x90, "scroll_lock": 0x91,
    "print_screen": 0x2C, "pause": 0x13,
}


def _resolve_vk(ev: dict) -> int:
    """Resolve a Windows VK code from a recorded input_key event.
    Prefers ev['vk'] (set for character keys), falls back to mapping
    ev['name'] via NAME_TO_VK, then uses VkKeyScanW on ev['char'] as a
    last resort. Returns 0 if unresolvable."""
    vk = ev.get("vk")
    if isinstance(vk, int) and vk > 0:
        return vk
    name = ev.get("name")
    if name:
        n = str(name).lower()
        if n.startswith("key."):
            n = n[4:]
        if n in NAME_TO_VK:
            return NAME_TO_VK[n]
    ch = ev.get("char")
    if isinstance(ch, str) and len(ch) == 1:
        # VkKeyScanW: low byte = VK, high byte = shift state. We only
        # need the VK; modifiers in the recording are separate events.
        rv = user32.VkKeyScanW(ord(ch))
        if rv != -1:
            return rv & 0xFF
    return 0

SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79
SM_CXSCREEN = 0
SM_CYSCREEN = 1


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wt.LONG), ("dy", wt.LONG),
        ("mouseData", wt.DWORD), ("dwFlags", wt.DWORD),
        ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_void_p),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD),
        ("time", wt.DWORD), ("dwExtraInfo", ctypes.c_void_p),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wt.DWORD), ("wParamL", wt.WORD), ("wParamH", wt.WORD)]


class _INPUTunion(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wt.DWORD), ("u", _INPUTunion)]


class RECT(ctypes.Structure):
    _fields_ = [("left", wt.LONG), ("top", wt.LONG),
                ("right", wt.LONG), ("bottom", wt.LONG)]


class POINT(ctypes.Structure):
    _fields_ = [("x", wt.LONG), ("y", wt.LONG)]


user32.SendInput.argtypes = [wt.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
user32.SendInput.restype = wt.UINT
user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, ctypes.c_void_p, ctypes.c_void_p]
user32.PostMessageW.restype = wt.BOOL
user32.FindWindowW.argtypes = [wt.LPCWSTR, wt.LPCWSTR]
user32.FindWindowW.restype = wt.HWND
user32.GetClientRect.argtypes = [wt.HWND, ctypes.POINTER(RECT)]
user32.GetClientRect.restype = wt.BOOL
user32.ClientToScreen.argtypes = [wt.HWND, ctypes.POINTER(POINT)]
user32.ClientToScreen.restype = wt.BOOL
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.GetSystemMetrics.restype = ctypes.c_int
user32.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM), wt.LPARAM]
user32.EnumWindows.restype = wt.BOOL
user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
user32.GetWindowTextW.restype = ctypes.c_int
user32.IsWindowVisible.argtypes = [wt.HWND]
user32.IsWindowVisible.restype = wt.BOOL
user32.IsIconic.argtypes = [wt.HWND]
user32.IsIconic.restype = wt.BOOL
user32.GetDoubleClickTime.argtypes = []
user32.GetDoubleClickTime.restype = wt.UINT
user32.VkKeyScanW.argtypes = [ctypes.c_wchar]
user32.VkKeyScanW.restype = ctypes.c_short

# GDI for window-screenshot (CV template match).
gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
SRCCOPY = 0x00CC0020


# ---------------------------------------------------------------------------
# CV template-matching (click accuracy via OpenCV)

CV_DEBUG_DIR = None  # set via --cv-debug-dir to dump per-click diagnostic PNGs
PATCH_SIZE = 96
# Match-confidence floor. Above => use CV result and learn its (dx, dy)
# shift. Below => fall back to recorded coord plus the median shift
# learned from prior successful matches. No halts. Real UI re-renders
# score 0.5–0.9; random world textures ~0.3. 0.5 cleanly separates.
CV_MATCH_THRESHOLD = 0.50
# When multiple cells lie within this margin of the global max
# (e.g. duplicate UI sprites rendered identically), break the tie by
# picking the one closest to (rec_cx, rec_cy).
CV_PEAK_TIE_MARGIN = 0.05
# Mask the cursor area at template center: 255 = use this pixel,
# 0 = ignore. The recorder centers the patch on the click, so the
# guest cursor sprite is always at template center; the live haystack's
# cursor is wherever SendInput last moved it. Mask out so the cursor
# doesn't dominate either the score or the match position.
CV_CURSOR_MASK_PX = 28
# Bounded buffer of (dx, dy) from CV-confident matches. The replayer's
# fallback path uses median(history) as the offset correction when CV
# can't find the patch in the live frame — self-calibrating per
# recording/machine, no hardcoded constants.
SHIFT_HISTORY_MAX = 20

_cv2 = None
_np = None


def _load_cv2():
    """Late-bind cv2 + numpy. Returns (cv2_module, np_module) or raises."""
    global _cv2, _np
    if _cv2 is not None:
        return _cv2, _np
    import cv2  # type: ignore
    import numpy as np  # type: ignore
    _cv2 = cv2
    _np = np
    return cv2, np


def screenshot_window(hwnd: int):
    """Return a BGR ndarray of the target window's CLIENT area via BitBlt."""
    cv2, np = _load_cv2()
    sx, sy, w, h = get_window_client_rect_screen(hwnd)
    if w <= 0 or h <= 0:
        raise OSError(f"screenshot_window: degenerate client rect {w}x{h}")
    user32.GetDC = ctypes.WinDLL("user32").GetDC
    user32.GetDC.argtypes = [wt.HWND]
    user32.GetDC.restype = ctypes.c_void_p
    user32.ReleaseDC.argtypes = [wt.HWND, ctypes.c_void_p]
    user32.ReleaseDC.restype = ctypes.c_int
    gdi32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]
    gdi32.CreateCompatibleDC.restype = ctypes.c_void_p
    gdi32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    gdi32.CreateCompatibleBitmap.restype = ctypes.c_void_p
    gdi32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    gdi32.SelectObject.restype = ctypes.c_void_p
    gdi32.BitBlt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
                             ctypes.c_int, ctypes.c_int, ctypes.c_void_p,
                             ctypes.c_int, ctypes.c_int, wt.DWORD]
    gdi32.BitBlt.restype = wt.BOOL
    gdi32.DeleteObject.argtypes = [ctypes.c_void_p]
    gdi32.DeleteObject.restype = wt.BOOL
    gdi32.DeleteDC.argtypes = [ctypes.c_void_p]
    gdi32.DeleteDC.restype = wt.BOOL
    gdi32.GetDIBits = ctypes.WinDLL("gdi32").GetDIBits
    # Use desktop-DC + screen coords so we capture exactly what's displayed.
    desk_dc = user32.GetDC(0)
    mem_dc = gdi32.CreateCompatibleDC(desk_dc)
    bmp = gdi32.CreateCompatibleBitmap(desk_dc, w, h)
    gdi32.SelectObject(mem_dc, bmp)
    gdi32.BitBlt(mem_dc, 0, 0, w, h, desk_dc, sx, sy, SRCCOPY)

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [
            ("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
            ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
            ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
            ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
            ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD),
        ]

    class BITMAPINFO(ctypes.Structure):
        _fields_ = [("bmiHeader", BITMAPINFOHEADER), ("bmiColors", wt.DWORD * 3)]

    bi = BITMAPINFO()
    bi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bi.bmiHeader.biWidth = w
    bi.bmiHeader.biHeight = -h  # top-down
    bi.bmiHeader.biPlanes = 1
    bi.bmiHeader.biBitCount = 32
    bi.bmiHeader.biCompression = 0
    buf = (ctypes.c_ubyte * (w * h * 4))()
    gdi32.GetDIBits.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.UINT,
                                wt.UINT, ctypes.c_void_p,
                                ctypes.POINTER(BITMAPINFO), wt.UINT]
    gdi32.GetDIBits.restype = ctypes.c_int
    gdi32.GetDIBits(mem_dc, bmp, 0, h, buf, ctypes.byref(bi), 0)
    gdi32.DeleteObject(bmp)
    gdi32.DeleteDC(mem_dc)
    user32.ReleaseDC(0, desk_dc)
    arr = np.frombuffer(buf, dtype=np.uint8).reshape((h, w, 4))
    return arr[:, :, :3].copy()  # BGRA -> BGR


def cv_match_patch(hwnd: int, patch_path: str, rec_cx: int, rec_cy: int,
                   threshold: float = CV_MATCH_THRESHOLD):
    """Single-shot CV match: screenshot the live window, run
    matchTemplate against the recorded 96x96 patch, return the global
    argmax (with proximity tiebreak among near-equal peaks).

    Returns (ok, score, client_x, client_y). `ok` indicates score >=
    threshold; the caller handles the below-threshold path (auto-learn
    fallback to recorded + median learned shift, no halt).
    """
    cv2, np = _load_cv2()
    template = cv2.imread(patch_path, cv2.IMREAD_COLOR)
    if template is None:
        return False, 0.0, 0, 0
    haystack = screenshot_window(hwnd)
    return cv_match_in_haystack(haystack, template, rec_cx, rec_cy, threshold)


def cv_match_in_haystack(haystack, template, rec_cx: int, rec_cy: int,
                         threshold: float = CV_MATCH_THRESHOLD):
    """Pure CV match (no Win32). Shared between the live replayer path
    (haystack from screenshot_window) and offline calibration tools.
    `template` is a BGR ndarray.
    """
    cv2, np = _load_cv2()
    hh, hw = haystack.shape[:2]
    th, tw = template.shape[:2]
    if hh < th or hw < tw:
        return False, 0.0, 0, 0
    half_tw, half_th = tw // 2, th // 2

    mask = np.full((th, tw), 255, dtype=np.uint8)
    m = CV_CURSOR_MASK_PX
    mask[half_th - m // 2:half_th + m // 2,
         half_tw - m // 2:half_tw + m // 2] = 0

    res = cv2.matchTemplate(haystack, template, cv2.TM_CCOEFF_NORMED, mask=mask)
    # TM_CCOEFF_NORMED with mask divides by per-cell variance; low-
    # variance regions can produce inf/nan. Clip so argmax doesn't pick
    # a bogus cell.
    res[~np.isfinite(res)] = -1.0

    _min_val, max_val, _min_loc, max_loc = cv2.minMaxLoc(res)
    if max_val < threshold:
        cx = int(max_loc[0] + half_tw)
        cy = int(max_loc[1] + half_th)
        return False, float(max_val), cx, cy

    # Tiebreak among cells within CV_PEAK_TIE_MARGIN of the global max:
    # pick the one closest to (rec_cx, rec_cy). For unambiguous matches
    # only the global max itself qualifies, so this collapses to argmax.
    tie_floor = float(max_val) - CV_PEAK_TIE_MARGIN
    ys, xs = np.where(res >= tie_floor)
    centers_x = xs + half_tw
    centers_y = ys + half_th
    dx = centers_x.astype(np.int32) - rec_cx
    dy = centers_y.astype(np.int32) - rec_cy
    i = int(np.argmin(dx * dx + dy * dy))
    return True, float(res[ys[i], xs[i]]), int(centers_x[i]), int(centers_y[i])


def _enumerate_title_matches(substr: str) -> List[int]:
    """Return ALL top-level HWNDs whose title contains substr (case-insensitive)."""
    found: List[int] = []
    target = substr.lower()

    @ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    def _cb(hwnd, lparam):
        buf = ctypes.create_unicode_buffer(512)
        n = user32.GetWindowTextW(hwnd, buf, 512)
        if n > 0 and target in buf.value.lower():
            found.append(hwnd)
        return True

    user32.EnumWindows(_cb, 0)
    return found


def _hwnd_client_size(hwnd: int):
    r = RECT()
    if not user32.GetClientRect(hwnd, ctypes.byref(r)):
        return (0, 0)
    return (r.right - r.left, r.bottom - r.top)


def find_window_by_substring(substr: str) -> Optional[int]:
    """Find first VISIBLE, non-iconic top-level window whose title contains substr,
    with non-zero client size. Skips hidden/minimized/zero-sized matches."""
    for hwnd in _enumerate_title_matches(substr):
        if not user32.IsWindowVisible(hwnd):
            continue
        if user32.IsIconic(hwnd):
            continue
        cw, ch = _hwnd_client_size(hwnd)
        if cw <= 0 or ch <= 0:
            continue
        return hwnd
    return None


def log_window_candidates(substr: str) -> None:
    """Log all title-matching candidates to aid diagnosis when find fails."""
    cands = _enumerate_title_matches(substr)
    if not cands:
        print(f"[diag] no windows match title substring '{substr}'", file=sys.stderr)
        return
    print(f"[diag] {len(cands)} candidate window(s) for '{substr}':", file=sys.stderr)
    for hwnd in cands:
        buf = ctypes.create_unicode_buffer(512)
        user32.GetWindowTextW(hwnd, buf, 512)
        vis = bool(user32.IsWindowVisible(hwnd))
        ico = bool(user32.IsIconic(hwnd))
        cw, ch = _hwnd_client_size(hwnd)
        print(f"[diag]   hwnd=0x{hwnd:X} visible={vis} iconic={ico} "
              f"client={cw}x{ch} title={buf.value!r}", file=sys.stderr)


def get_window_client_rect_screen(hwnd: int):
    """Return (sx, sy, w, h) — top-left in screen coords, plus client w/h."""
    r = RECT()
    if not user32.GetClientRect(hwnd, ctypes.byref(r)):
        raise OSError("GetClientRect failed")
    p = POINT(0, 0)
    if not user32.ClientToScreen(hwnd, ctypes.byref(p)):
        raise OSError("ClientToScreen failed")
    return p.x, p.y, r.right - r.left, r.bottom - r.top


def get_virtual_screen():
    return (
        user32.GetSystemMetrics(SM_XVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_YVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_CXVIRTUALSCREEN),
        user32.GetSystemMetrics(SM_CYVIRTUALSCREEN),
    )


def screen_to_abs(sx: int, sy: int, vs):
    vx, vy, vw, vh = vs
    if vw <= 0 or vh <= 0:
        return 0, 0
    nx = int(round((sx - vx) * 65535 / vw))
    ny = int(round((sy - vy) * 65535 / vh))
    return max(0, min(65535, nx)), max(0, min(65535, ny))


def send_mouse(flags: int, abs_x: int = 0, abs_y: int = 0, mouse_data: int = 0):
    inp = INPUT()
    inp.type = INPUT_MOUSE
    inp.mi = MOUSEINPUT(abs_x, abs_y, mouse_data,
                       flags | MOUSEEVENTF_VIRTUALDESK,
                       0, None)
    n = user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
    if n != 1:
        err = ctypes.get_last_error()
        print(f"[warn] SendInput(mouse) returned {n} err={err}", file=sys.stderr)


# VKs that require KEYEVENTF_EXTENDEDKEY for the OS to interpret them
# correctly (arrow keys, nav cluster, right-side modifiers, numpad div).
_EXTENDED_VKS = frozenset({
    0x21, 0x22, 0x23, 0x24,  # PgUp PgDn End Home
    0x25, 0x26, 0x27, 0x28,  # arrows
    0x2D, 0x2E,              # Insert Delete
    0x90,                    # NumLock
    0xA3, 0xA5,              # right Ctrl, right Alt
    0x6F,                    # numpad /
    0x0D,                    # numpad Enter (and regular Enter is fine without)
})


def neutralize_input():
    """Release any modifier keys and mouse buttons that may be stuck
    held from a previous run, manual typing on the host, or an
    interrupted drag/Alt-shortcut. SendInput KEY_UP / MOUSE_UP for
    not-currently-held keys is a no-op, so this is safe to call
    unconditionally before each replay session.
    """
    # Modifier keys (generic + left/right variants + Win keys).
    for vk in (0x10, 0xA0, 0xA1,  # Shift / LShift / RShift
               0x11, 0xA2, 0xA3,  # Ctrl / LCtrl / RCtrl
               0x12, 0xA4, 0xA5,  # Alt / LAlt / RAlt
               0x5B, 0x5C):       # LWin / RWin
        send_key(vk, up=True)
    # All mouse buttons.
    send_mouse(MOUSEEVENTF_LEFTUP)
    send_mouse(MOUSEEVENTF_RIGHTUP)
    send_mouse(MOUSEEVENTF_MIDDLEUP)


def send_key(vk: int, up: bool):
    inp = INPUT()
    inp.type = INPUT_KEYBOARD
    flags = KEYEVENTF_KEYUP if up else 0
    if vk in _EXTENDED_VKS:
        flags |= KEYEVENTF_EXTENDEDKEY
    inp.ki = KEYBDINPUT(vk, 0, flags, 0, None)
    n = user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(INPUT))
    if n != 1:
        err = ctypes.get_last_error()
        print(f"[warn] SendInput(key) returned {n} err={err}", file=sys.stderr)


# ---------------------------------------------------------------------------
# PostMessage-based click delivery (alternative path).
#
# Avoids cursor positioning / DPI / focus issues by posting WM_*BUTTON*
# messages directly to the target HWND using client-relative coords.

WM_MOUSEMOVE = 0x0200
WM_LBUTTONDOWN = 0x0201
WM_LBUTTONUP = 0x0202
WM_LBUTTONDBLCLK = 0x0203
WM_RBUTTONDOWN = 0x0204
WM_RBUTTONUP = 0x0205
WM_RBUTTONDBLCLK = 0x0206
WM_MBUTTONDOWN = 0x0207
WM_MBUTTONUP = 0x0208
WM_MBUTTONDBLCLK = 0x0209

_DBLCLK_MSG = {
    "L": WM_LBUTTONDBLCLK,
    "R": WM_RBUTTONDBLCLK,
    "M": WM_MBUTTONDBLCLK,
}

MK_LBUTTON = 0x0001
MK_RBUTTON = 0x0002
MK_MBUTTON = 0x0010

_BTN_MK_BY_BTN = {"L": MK_LBUTTON, "R": MK_RBUTTON, "M": MK_MBUTTON}

_PM_BTN_MSGS = {
    ("L", "down"): (WM_LBUTTONDOWN, MK_LBUTTON),
    ("L", "up"):   (WM_LBUTTONUP,   0),
    ("R", "down"): (WM_RBUTTONDOWN, MK_RBUTTON),
    ("R", "up"):   (WM_RBUTTONUP,   0),
    ("M", "down"): (WM_MBUTTONDOWN, MK_MBUTTON),
    ("M", "up"):   (WM_MBUTTONUP,   0),
}


def _post_message(hwnd: int, msg: int, wparam: int, lparam: int) -> None:
    ok = user32.PostMessageW(hwnd, msg, wparam, lparam)
    if not ok:
        err = ctypes.get_last_error()
        print(f"[warn] PostMessageW(hwnd=0x{hwnd:X}, msg=0x{msg:04X}) "
              f"failed err={err}", file=sys.stderr)


def post_click(hwnd: int, btn: str, state: str, cx: int, cy: int) -> None:
    """Post a mouse button event via PostMessageW using client-relative px.

    For "down" events, also posts a preceding WM_MOUSEMOVE so the target
    window's hover/hit-test state is current.
    """
    entry = _PM_BTN_MSGS.get((btn, state))
    if entry is None:
        return
    msg, mk = entry
    cx16 = cx & 0xFFFF
    cy16 = cy & 0xFFFF
    lparam = (cy16 << 16) | cx16
    if state == "down":
        _post_message(hwnd, WM_MOUSEMOVE, 0, lparam)
    _post_message(hwnd, msg, mk, lparam)


# ---------------------------------------------------------------------------
# Recording

def load_jsonl(path: str) -> List[dict]:
    out: List[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def load_manifest(jsonl_path: str) -> dict:
    base, _ = os.path.splitext(jsonl_path)
    mp = base + ".manifest.json"
    if os.path.isfile(mp):
        with open(mp, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


# ---------------------------------------------------------------------------
# Replay loop

INPUT_KINDS = {"input_mouse_move", "input_mouse_button", "input_mouse_wheel", "input_key"}


def find_start_index(events: List[dict], mode: str) -> int:
    if mode == "first_input":
        for i, ev in enumerate(events):
            if ev.get("kind") in INPUT_KINDS:
                return i
        return len(events)
    # default: gate_opened
    for i, ev in enumerate(events):
        if ev.get("kind") == "gate_opened":
            # start at first input AFTER gate_opened
            for j in range(i + 1, len(events)):
                if events[j].get("kind") in INPUT_KINDS:
                    return j
            return len(events)
    # fallback
    for i, ev in enumerate(events):
        if ev.get("kind") in INPUT_KINDS:
            return i
    return len(events)


def map_client(fx: float, fy: float, cw: int, ch: int,
               vm_w: int, vm_h: int, win_w: int, win_h: int,
               top_offset: int, left_offset: int):
    """Map recorded fractional vmconnect coords → CLIENT-area pixel of the
    target window. No Y_CORRECTION, no win_x/win_y offsets — pure
    geometry. Used for both screen-space click math and CV haystack
    indexing so they share the same reference frame."""
    game_x = fx * cw - left_offset
    game_y = fy * ch - top_offset
    game_x_norm = max(0.0, min(1.0, game_x / float(vm_w)))
    game_y_norm = max(0.0, min(1.0, game_y / float(vm_h)))
    cx = int(round(game_x_norm * win_w))
    cy = int(round(game_y_norm * win_h))
    return cx, cy


def map_coords(fx: float, fy: float, cw: int, ch: int,
               vm_w: int, vm_h: int,
               win_x: int, win_y: int, win_w: int, win_h: int,
               top_offset: int, left_offset: int,
               x_correction: int, y_correction: int):
    """Apply offsets and map fractional vmconnect coords → screen pixel."""
    cx, cy = map_client(fx, fy, cw, ch, vm_w, vm_h, win_w, win_h,
                        top_offset, left_offset)
    return win_x + cx + x_correction, win_y + cy + y_correction


_BTN_FLAGS = {
    ("L", "down"): MOUSEEVENTF_LEFTDOWN,
    ("L", "up"): MOUSEEVENTF_LEFTUP,
    ("R", "down"): MOUSEEVENTF_RIGHTDOWN,
    ("R", "up"): MOUSEEVENTF_RIGHTUP,
    ("M", "down"): MOUSEEVENTF_MIDDLEDOWN,
    ("M", "up"): MOUSEEVENTF_MIDDLEUP,
}


def _net_key(ev: dict):
    """Identity for matching emulator broadcasts to a recorded net event.
    The emulator broadcasts {seq, port, dir, opcode}; we key on seq."""
    return ev.get("seq")


def _ctrl_listener(ctrl_addr, ack_fn, stop_flag: List[bool]):
    """Background thread: connect to emulator's control bus and ack each
    {seq,port,dir,opcode} JSON line."""
    import socket as _s
    while not stop_flag[0]:
        try:
            s = _s.create_connection(ctrl_addr, timeout=5)
        except OSError as e:
            print(f"[ctrl] connect {ctrl_addr} failed: {e}", file=sys.stderr)
            time.sleep(1.0)
            continue
        print(f"[ctrl] connected {ctrl_addr}", file=sys.stderr)
        buf = b""
        s.settimeout(0.5)
        while not stop_flag[0]:
            try:
                chunk = s.recv(4096)
            except (TimeoutError, _s.timeout):
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                ack_fn(obj)
        try: s.close()
        except OSError: pass
        print("[ctrl] disconnected; retry", file=sys.stderr)
        time.sleep(0.5)


def replay(events: List[dict], start_idx: int, vm_w: int, vm_h: int,
           hwnd: int, speed: float, stop_flag: List[bool],
           top_offset: int, left_offset: int,
           x_correction: int, y_correction: int,
           ctrl_addr: Optional[tuple], net_timeout: float,
           stop_at_seq: Optional[int],
           click_mode: str = "sendinput",
           recorded_spawn: Optional[dict] = None,
           patches_dir: Optional[str] = None) -> None:
    if start_idx >= len(events):
        print("[replay] no input events to play", file=sys.stderr)
        return

    win_x, win_y, win_w, win_h = get_window_client_rect_screen(hwnd)
    vs = get_virtual_screen()
    print(f"[replay] window client_rect screen=({win_x},{win_y}) size=({win_w}x{win_h})",
          file=sys.stderr)
    # Release any modifier keys / mouse buttons stuck from a prior run
    # or manual host typing before injecting recorded events.
    neutralize_input()
    print("[replay] input neutralized (modifiers + mouse buttons released)",
          file=sys.stderr)
    if win_w <= 0 or win_h <= 0:
        print(f"[replay] HALT: window client_rect is degenerate ({win_w}x{win_h}); "
              f"hwnd=0x{hwnd:X} likely hidden/minimized/destroyed", file=sys.stderr)
        return
    _rect_refreshed = [False]
    print(f"[replay] virtual_screen={vs}", file=sys.stderr)
    print(f"[replay] vm_res=({vm_w}x{vm_h}) speed={speed} "
          f"top_off={top_offset} left_off={left_offset} "
          f"x_corr={x_correction} y_corr={y_correction}", file=sys.stderr)
    if click_mode == "postmessage":
        print(f"[replay] click-mode: postmessage, hwnd=0x{hwnd:X}", file=sys.stderr)

    # Walk ALL events (input + net) from start_idx onward in seq order.
    timeline = events[start_idx:]
    first_with_t = next((ev for ev in timeline if ev.get("t_wall_ns") is not None), None)
    if first_with_t is None:
        print("[replay] no timed events after start", file=sys.stderr)
        return

    print(f"[replay] {len(timeline)} timeline events; first seq={first_with_t.get('seq')}",
          file=sys.stderr)

    # Net-event sync: track which recorded seqs the emulator has confirmed.
    acked_seqs = set()
    ack_lock = threading.Lock()
    ack_event = threading.Event()
    desync_info = [None]  # one-shot

    # Spawn-assert state. We index world-port S2C payloads by seq so that
    # when the control bus acks a world-port frame we can parse the spawn
    # bytes and compare to recorded_spawn from the manifest. Asserts ONCE.
    world_payload_by_seq: dict = {}
    if recorded_spawn is not None and parse_spawn_frame is not None:
        for ev in events:
            if (ev.get("kind") == "net"
                    and ev.get("port") == 18123
                    and ev.get("dir") == "S2C"):
                seq_k = ev.get("seq")
                pay = ev.get("payload")
                if seq_k is not None and pay:
                    world_payload_by_seq[seq_k] = pay
    spawn_asserted = [False]

    def _on_ack(obj):
        if obj.get("event") == "desync":
            desync_info[0] = obj
            print(f"[ctrl] DESYNC seq={obj.get('seq')} port={obj.get('port')} "
                  f"got=0x{(obj.get('got_op') or 0):02x} "
                  f"want=0x{(obj.get('want_op') or 0):02x}", file=sys.stderr)
            stop_flag[0] = True
            ack_event.set()
            return
        seq = obj.get("seq")
        with ack_lock:
            acked_seqs.add(seq)
        ack_event.set()
        print(f"[ctrl] ack seq={seq} port={obj.get('port')} dir={obj.get('dir')} "
              f"op=0x{(obj.get('opcode') or 0):02x}", file=sys.stderr)

        # Spawn-assert: parse 18123 S2C payloads as they're observed,
        # compare first spawn-bearing frame to manifest's recorded_spawn.
        if (recorded_spawn is None or parse_spawn_frame is None
                or spawn_asserted[0]):
            return
        if obj.get("port") != 18123 or obj.get("dir") != "S2C":
            return
        pay_hex = world_payload_by_seq.get(seq)
        if not pay_hex:
            return
        try:
            spawn = parse_spawn_frame(bytes.fromhex(pay_hex))
        except Exception:
            spawn = None
        if spawn is None:
            return
        rec_map = recorded_spawn.get("map_id")
        rec_x = recorded_spawn.get("x")
        rec_y = recorded_spawn.get("y")
        live_map = spawn.get("map_id")
        live_x = spawn.get("x")
        live_y = spawn.get("y")
        # If live frame is self_spawn it has no map_id; allow rec map_id
        # to satisfy the comparison (we still match coordinates).
        cmp_map = live_map if live_map is not None else rec_map
        if cmp_map == rec_map and live_x == rec_x and live_y == rec_y:
            print(f"[spawn-assert] OK map={rec_map} spawn=({rec_x},{rec_y})",
                  file=sys.stderr)
            spawn_asserted[0] = True
        else:
            print(f"[spawn-assert] MISMATCH "
                  f"recorded=({rec_map},{rec_x},{rec_y}) "
                  f"live=({live_map},{live_x},{live_y})",
                  file=sys.stderr)
            spawn_asserted[0] = True
            stop_flag[0] = True
            ack_event.set()

    if ctrl_addr is not None:
        ctrl_thread = threading.Thread(
            target=_ctrl_listener, args=(ctrl_addr, _on_ack, stop_flag),
            daemon=True, name="ctrl-listener",
        )
        ctrl_thread.start()

    # Pace the timeline using delta-from-previous so that a slow net wait
    # doesn't cause a burst of input events whose recorded schedule has
    # already elapsed. We track the last recorded wall_ns and the local
    # monotonic_ns at which we last advanced, then sleep the recorded
    # delta between consecutive events.
    last_rec_ns = first_with_t["t_wall_ns"]
    last_local_ns = time.monotonic_ns()
    # Track CV-adjusted client coords per button from the last 'down' event
    # so the matching 'up' event clicks at the same screen position. Many
    # UIs require down/up at the same pixel for the click to register.
    last_cv_xy_by_btn: Dict[str, Tuple[int, int]] = {}
    # Bounded list of (dx, dy) shifts from CV-confident matches. Drives
    # the auto-fallback when a match scores below threshold: click at
    # recorded coord plus median(history). Self-calibrating, no halts.
    shift_history: List[Tuple[int, int]] = []
    # Last 'down' recorded client coord per button. Used on the matching
    # 'up' to distinguish a click (down ~= up) from a drag (down != up).
    # Drag releases use the up's own coord + learned shift so the drop
    # lands on the correct UI element instead of teleporting back to the
    # down position.
    last_down_rec_xy_by_btn: Dict[str, Tuple[int, int]] = {}
    # Last 'down' wall timestamp + client coords per button. If a second
    # 'down' arrives at the same coords within Windows' double-click time,
    # also post WM_*BUTTONDBLCLK to the HWND — SendInput alone doesn't
    # always generate the message games rely on for double-click handling.
    last_down_ns_by_btn: Dict[str, int] = {}
    last_down_xy_by_btn: Dict[str, Tuple[int, int]] = {}
    dblclk_ms = int(user32.GetDoubleClickTime()) or 500
    dblclk_ns = dblclk_ms * 1_000_000

    for ev in timeline:
        if stop_flag[0]:
            print("[replay] stop flag set", file=sys.stderr)
            return
        seq = ev.get("seq")
        if stop_at_seq is not None and seq is not None and seq > stop_at_seq:
            print(f"[replay] reached stop-at-seq={stop_at_seq}; handing off "
                  f"to human. Emulator stays up.", file=sys.stderr)
            return
        kind = ev["kind"]
        ev_rec = ev.get("t_wall_ns")
        if ev_rec is None:
            continue

        # Compute when this event should fire locally, advancing the play
        # clock by the recorded delta to the previous event.
        delta_rec_ns = max(0, ev_rec - last_rec_ns)
        delta_play_ns = int(delta_rec_ns / max(speed, 0.0001))
        target = last_local_ns + delta_play_ns
        # Sleep until target (no burst-catchup: if we're already past, just
        # advance the local clock to "now" so subsequent deltas pace correctly).
        now = time.monotonic_ns()
        if target > now:
            slack = (target - now) / 1e9
            if slack > 0.001:
                time.sleep(slack)
            now = time.monotonic_ns()
        last_rec_ns = ev_rec
        last_local_ns = max(target, now)

        if kind == "net":
            seq = ev.get("seq")
            if ctrl_addr is None:
                continue
            # Skip keepalives — emulator drops them from the recorded queue.
            if (ev.get("opcode") == 0x05
                    and ev.get("port") in (1818, 1819, 18124)
                    and ev.get("cipher", "none") == "none"):
                continue
            # World ports run fire-and-forget: emulator pushes recorded S2C
            # on connect and lets the live game send dynamic C2S. There's no
            # pair-match, so don't block the replayer here.
            if ev.get("port") in (18123, 18124):
                continue
            deadline = time.monotonic() + net_timeout
            while time.monotonic() < deadline and not stop_flag[0]:
                with ack_lock:
                    if seq in acked_seqs:
                        break
                ack_event.wait(timeout=0.1)
                ack_event.clear()
            with ack_lock:
                if seq not in acked_seqs:
                    print(f"[replay] HALT: net seq={seq} port={ev.get('port')} "
                          f"dir={ev.get('dir')} op=0x{(ev.get('opcode') or 0):02x} "
                          f"not acked within {net_timeout}s", file=sys.stderr)
                    return
            # Ack arrived; advance local clock to *now* so subsequent input
            # events pace from the moment the round-trip actually completed.
            last_local_ns = time.monotonic_ns()
            continue

        if kind not in INPUT_KINDS:
            continue

        if kind == "input_mouse_move":
            sx, sy = map_coords(ev["fx"], ev["fy"], ev["cw"], ev["ch"],
                                vm_w, vm_h, win_x, win_y, win_w, win_h,
                                top_offset, left_offset, x_correction, y_correction)
            ax, ay = screen_to_abs(sx, sy, vs)
            send_mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, ax, ay)
        elif kind == "input_mouse_button":
            if not _rect_refreshed[0]:
                try:
                    nx, ny, nw, nh = get_window_client_rect_screen(hwnd)
                except OSError as e:
                    print(f"[replay] HALT: rect refresh failed before first "
                          f"click: {e}", file=sys.stderr)
                    return
                if nw <= 0 or nh <= 0 or user32.IsIconic(hwnd):
                    print(f"[replay] HALT: window degenerate before first click "
                          f"(hwnd=0x{hwnd:X} client={nw}x{nh} "
                          f"iconic={bool(user32.IsIconic(hwnd))})",
                          file=sys.stderr)
                    return
                if (nx, ny, nw, nh) != (win_x, win_y, win_w, win_h):
                    print(f"[replay] rect changed before first click: "
                          f"({win_x},{win_y},{win_w}x{win_h}) -> "
                          f"({nx},{ny},{nw}x{nh})", file=sys.stderr)
                    win_x, win_y, win_w, win_h = nx, ny, nw, nh
                _rect_refreshed[0] = True
            # CV template-match: if recording bundled patches and this event
            # carries a cv_patch (down events only), match the patch against
            # the live window and use the match center for the click target.
            cv_client_xy = None  # (cx, cy) in client px, or None
            cv_patch_name = ev.get("cv_patch")
            btn = ev.get("btn")
            # 'up' events have no patch. Two cases:
            #   click — up's recorded coord ~= down's: reuse down's CV
            #     pixel so the click registers at a single pixel.
            #   drag — up's recorded coord differs from down's: this is
            #     a release at a NEW location. Use up's own recorded
            #     coord plus the learned median shift so the drop lands
            #     on the correct live-frame UI element instead of
            #     teleporting back to the drag origin.
            if ev.get("state") == "up":
                up_rec_cx, up_rec_cy = map_client(
                    ev["fx"], ev["fy"], ev["cw"], ev["ch"],
                    vm_w, vm_h, win_w, win_h, top_offset, left_offset)
                down_rec_xy = last_down_rec_xy_by_btn.get(btn)
                is_drag = (down_rec_xy is not None
                           and (abs(up_rec_cx - down_rec_xy[0]) > 4
                                or abs(up_rec_cy - down_rec_xy[1]) > 4))
                if is_drag:
                    if shift_history:
                        dxs = sorted(s[0] for s in shift_history)
                        dys = sorted(s[1] for s in shift_history)
                        mdx = dxs[len(dxs) // 2]
                        mdy = dys[len(dys) // 2]
                    else:
                        mdx = mdy = 0
                    cv_client_xy = (up_rec_cx + mdx, up_rec_cy + mdy)
                    print(f"[drag-up] seq={ev.get('seq')} btn={btn} "
                          f"down=({down_rec_xy[0]},{down_rec_xy[1]}) -> "
                          f"up=({up_rec_cx},{up_rec_cy})+shift({mdx},{mdy}) "
                          f"= drop=({cv_client_xy[0]},{cv_client_xy[1]})",
                          file=sys.stderr)
                else:
                    cv_client_xy = last_cv_xy_by_btn.get(btn)
            if patches_dir and cv_patch_name and ev.get("state") == "down":
                patch_path = os.path.join(patches_dir, cv_patch_name)
                if os.path.isfile(patch_path):
                    rec_cx, rec_cy = map_client(
                        ev["fx"], ev["fy"], ev["cw"], ev["ch"],
                        vm_w, vm_h, win_w, win_h, top_offset, left_offset)
                    last_down_rec_xy_by_btn[btn] = (rec_cx, rec_cy)
                    ok, score, mcx, mcy = cv_match_patch(hwnd, patch_path, rec_cx, rec_cy)
                    dx = mcx - rec_cx
                    dy = mcy - rec_cy
                    shift_px = (dx * dx + dy * dy) ** 0.5
                    if CV_DEBUG_DIR:
                        try:
                            cv2_dbg, np_dbg = _load_cv2()
                            os.makedirs(CV_DEBUG_DIR, exist_ok=True)
                            haystack = screenshot_window(hwnd)
                            seq = ev.get('seq')
                            # Raw haystack — for offline cv_calibrate.py
                            # iteration without re-running the replay.
                            cv2_dbg.imwrite(os.path.join(CV_DEBUG_DIR,
                                f"{seq}_haystack_raw.png"), haystack)
                            ann = haystack.copy()
                            cv2_dbg.circle(ann, (rec_cx, rec_cy), 6, (0, 0, 255), 2)
                            cv2_dbg.circle(ann, (mcx, mcy), 4, (0, 255, 0), 2)
                            label = (f"seq={seq} score={score:.2f} "
                                     f"shift=({dx},{dy}) ok={ok}")
                            cv2_dbg.putText(ann, label, (10, 24),
                                cv2_dbg.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 255), 2)
                            cv2_dbg.imwrite(os.path.join(CV_DEBUG_DIR,
                                f"{seq}_haystack.png"), ann)
                            patch_img = cv2_dbg.imread(patch_path)
                            if patch_img is not None:
                                cv2_dbg.imwrite(os.path.join(CV_DEBUG_DIR,
                                    f"{seq}_patch.png"), patch_img)
                        except Exception as _e:
                            print(f"[cv-debug] dump failed seq={ev.get('seq')}: {_e}",
                                  file=sys.stderr)
                    if ok:
                        # CV-confident match: click its center and learn
                        # the shift for future fallbacks.
                        print(f"[cv-match] OK seq={ev.get('seq')} "
                              f"score={score:.2f} shift=({dx},{dy})",
                              file=sys.stderr)
                        cv_client_xy = (mcx, mcy)
                        shift_history.append((dx, dy))
                        if len(shift_history) > SHIFT_HISTORY_MAX:
                            shift_history.pop(0)
                    else:
                        # Below threshold: don't halt, fall back to
                        # recorded coord plus the median shift learned
                        # from prior CV-confident matches. Self-
                        # calibrating, no hardcoded constants.
                        if shift_history:
                            dxs = sorted(s[0] for s in shift_history)
                            dys = sorted(s[1] for s in shift_history)
                            mdx = dxs[len(dxs) // 2]
                            mdy = dys[len(dys) // 2]
                            cv_client_xy = (rec_cx + mdx, rec_cy + mdy)
                            print(f"[cv-match] FALLBACK seq={ev.get('seq')} "
                                  f"score={score:.2f} (below "
                                  f"{CV_MATCH_THRESHOLD:.2f}); learned "
                                  f"shift=({mdx},{mdy}) -> click=("
                                  f"{cv_client_xy[0]},{cv_client_xy[1]})",
                                  file=sys.stderr)
                        else:
                            cv_client_xy = (rec_cx, rec_cy)
                            print(f"[cv-match] FALLBACK seq={ev.get('seq')} "
                                  f"score={score:.2f} (below "
                                  f"{CV_MATCH_THRESHOLD:.2f}); cold start, "
                                  f"using recorded coord ({rec_cx},{rec_cy})",
                                  file=sys.stderr)
                    last_cv_xy_by_btn[ev.get("btn")] = cv_client_xy
            if click_mode == "postmessage":
                btn = ev.get("btn")
                state = ev.get("state")
                if (btn, state) not in _PM_BTN_MSGS:
                    continue
                if cv_client_xy is not None:
                    # CV match center is the exact pixel — bypass coord corrections.
                    cx, cy = cv_client_xy
                else:
                    cx = int(round(ev["fx"] * win_w))
                    cy = int(round(ev["fy"] * win_h)) + y_correction
                    cx += x_correction
                print(f"[click] seq={ev.get('seq')} {btn}-{state} "
                      f"fx={ev['fx']:.4f} fy={ev['fy']:.4f} -> client=({cx},{cy})",
                      file=sys.stderr)
                post_click(hwnd, btn, state, cx, cy)
            else:
                if cv_client_xy is not None:
                    # CV match center is the exact pixel — bypass coord corrections.
                    cx, cy = cv_client_xy
                    sx = win_x + cx
                    sy = win_y + cy
                else:
                    sx, sy = map_coords(ev["fx"], ev["fy"], ev["cw"], ev["ch"],
                                        vm_w, vm_h, win_x, win_y, win_w, win_h,
                                        top_offset, left_offset, x_correction, y_correction)
                ax, ay = screen_to_abs(sx, sy, vs)
                flag = _BTN_FLAGS.get((ev.get("btn"), ev.get("state")))
                if flag is None:
                    continue
                print(f"[click] seq={ev.get('seq')} {ev.get('btn')}-{ev.get('state')} "
                      f"fx={ev['fx']:.4f} fy={ev['fy']:.4f} -> screen=({sx},{sy})",
                      file=sys.stderr)
                send_mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | flag, ax, ay)
                # Double-click bridge: if this is the second L/R/M down at
                # the same client coords within Windows' double-click time,
                # also post WM_*BUTTONDBLCLK to the HWND. SendInput alone
                # doesn't reliably synthesize this for games that watch
                # for it explicitly (e.g., character-select "enter world").
                btn = ev.get("btn")
                state = ev.get("state")
                if state == "down" and btn in _DBLCLK_MSG:
                    # client-coord click point for posting (px in window).
                    if cv_client_xy is not None:
                        ccx, ccy = cv_client_xy
                    else:
                        ccx, ccy = sx - win_x, sy - win_y
                    now_ns = ev.get("t_wall_ns") or time.monotonic_ns()
                    last_ns = last_down_ns_by_btn.get(btn, 0)
                    last_xy = last_down_xy_by_btn.get(btn)
                    is_dbl = (
                        last_xy is not None
                        and abs(ccx - last_xy[0]) <= 4
                        and abs(ccy - last_xy[1]) <= 4
                        and 0 < (now_ns - last_ns) <= dblclk_ns
                    )
                    if is_dbl:
                        lparam = ((ccy & 0xFFFF) << 16) | (ccx & 0xFFFF)
                        _post_message(hwnd, _DBLCLK_MSG[btn],
                                      _BTN_MK_BY_BTN[btn], lparam)
                        print(f"[dblclk] seq={ev.get('seq')} {btn} "
                              f"posted WM_BUTTONDBLCLK at client=({ccx},{ccy})",
                              file=sys.stderr)
                        # Reset so a third click doesn't re-trigger.
                        last_down_ns_by_btn.pop(btn, None)
                        last_down_xy_by_btn.pop(btn, None)
                    else:
                        last_down_ns_by_btn[btn] = now_ns
                        last_down_xy_by_btn[btn] = (ccx, ccy)
        elif kind == "input_mouse_wheel":
            sx, sy = map_coords(ev.get("fx", 0.5), ev.get("fy", 0.5),
                                ev.get("cw", vm_w), ev.get("ch", vm_h),
                                vm_w, vm_h, win_x, win_y, win_w, win_h,
                                top_offset, left_offset, x_correction, y_correction)
            ax, ay = screen_to_abs(sx, sy, vs)
            dx = int(ev.get("dx", 0))
            dy = int(ev.get("dy", 0))
            if dy:
                send_mouse(MOUSEEVENTF_WHEEL | MOUSEEVENTF_ABSOLUTE, ax, ay,
                           mouse_data=dy * 120)
            if dx:
                send_mouse(MOUSEEVENTF_HWHEEL | MOUSEEVENTF_ABSOLUTE, ax, ay,
                           mouse_data=dx * 120)
        elif kind == "input_key":
            vk = _resolve_vk(ev)
            if vk <= 0:
                print(f"[key] skip seq={ev.get('seq')} unresolved "
                      f"name={ev.get('name')!r} vk={ev.get('vk')!r} "
                      f"char={ev.get('char')!r}", file=sys.stderr)
                continue
            up = (ev.get("state") == "up")
            print(f"[key] seq={ev.get('seq')} {ev.get('name') or ev.get('char')} "
                  f"vk=0x{vk:02X} {'up' if up else 'down'}", file=sys.stderr)
            send_key(vk, up=up)

    print("[replay] done", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main

def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 2 input replayer (RC3 side)")
    ap.add_argument("recording", nargs="?", default=None,
                    help="path to recording_<id>.jsonl (omit when "
                         "--neutralize-only is set)")
    ap.add_argument("--neutralize-only", action="store_true",
                    help="release any held modifier keys + mouse buttons "
                         "and exit. Use to clean up after an interrupted "
                         "replay or before manual play on this machine.")
    ap.add_argument("--window-title", default="XenClient")
    ap.add_argument("--start-from", choices=["gate_opened", "first_input"],
                    default="gate_opened")
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--find-timeout", type=float, default=30.0)
    # Coordinate-mapping tunables (in pixels of the recording's vmconnect frame).
    # top-offset / left-offset describe where the in-VM render area starts inside
    # the vmconnect client rect. Default = (ch - vm_h) at top, 0 at left.
    ap.add_argument("--top-offset", type=int, default=None,
                    help="px of vmconnect toolbar at top (default: ch - vm_h)")
    ap.add_argument("--left-offset", type=int, default=0,
                    help="px of vmconnect chrome at left (default 0)")
    # Final post-mapping nudge in screen pixels — for empirical tuning.
    ap.add_argument("--x-correction", type=int, default=0)
    ap.add_argument("--y-correction", type=int, default=0)
    # Sync to emulator's pair-match control bus.
    ap.add_argument("--ctrl-host", default=None,
                    help="emulator control bus host (e.g. 192.168.12.148); "
                         "if unset, no net sync — replayer fires inputs by recorded timing only")
    ap.add_argument("--ctrl-port", type=int, default=18999)
    ap.add_argument("--net-timeout", type=float, default=8.0,
                    help="seconds to wait for each net seq ack before halting")
    ap.add_argument("--stop-at-seq", type=int, default=None,
                    help="stop dispatching once we pass this seq (hand off to "
                         "human for the rest). Replayer exits cleanly; emulator "
                         "keeps running so user clicks pair-match normally.")
    ap.add_argument("--click-mode", choices=["sendinput", "postmessage"],
                    default="sendinput",
                    help="how to deliver mouse-button events. 'sendinput' "
                         "(default) uses Win32 SendInput with absolute "
                         "virtual-screen coords. 'postmessage' posts WM_*BUTTON* "
                         "messages directly to the target HWND with "
                         "client-relative coords (no cursor movement).")
    ap.add_argument("--cv-debug-dir", default=None,
                    help="if set, dump per-click haystack+patch PNGs here for "
                         "visual diagnosis of CV matches/misses.")
    args = ap.parse_args()
    global CV_DEBUG_DIR
    CV_DEBUG_DIR = args.cv_debug_dir

    if args.neutralize_only:
        neutralize_input()
        print("[neutralize] modifiers + mouse buttons released",
              file=sys.stderr)
        return 0

    if args.recording is None or not os.path.isfile(args.recording):
        print(f"recording not found: {args.recording}", file=sys.stderr)
        return 2

    # CV template-match mode: derive patches dir from recording filename.
    # `recording_<id>.jsonl` -> `recording_<id>_patches/` in same dir.
    rec_base, _ = os.path.splitext(args.recording)
    patches_dir = rec_base + "_patches"
    if os.path.isdir(patches_dir):
        try:
            _load_cv2()
        except ImportError as e:
            print(f"[main] HALT: cv2 required for template-match (recording "
                  f"has patches dir {patches_dir}). pip install opencv-python "
                  f"on RC3. import error: {e}", file=sys.stderr)
            return 4
        print(f"[main] CV mode ON: patches dir {patches_dir}", file=sys.stderr)
    else:
        print(f"[main] CV mode OFF: no patches dir at {patches_dir} "
              f"(coordinate-only clicks)", file=sys.stderr)
        patches_dir = None

    events = load_jsonl(args.recording)
    manifest = load_manifest(args.recording)
    vm_res = manifest.get("vm_res") or {}
    vm_w = int(vm_res.get("w", 1440))
    vm_h = int(vm_res.get("h", 900))

    print(f"[main] loaded {len(events)} events; vm_res=({vm_w}x{vm_h})",
          file=sys.stderr)

    # Find target window with retry. We require visible + non-iconic +
    # non-zero client rect; the launcher/in-world transition can briefly
    # leave a same-titled hidden or 0x0 window in EnumWindows results.
    deadline = time.monotonic() + args.find_timeout
    hwnd: Optional[int] = None
    while time.monotonic() < deadline:
        hwnd = find_window_by_substring(args.window_title)
        if hwnd:
            cw, ch = _hwnd_client_size(hwnd)
            if cw > 0 and ch > 0 and not user32.IsIconic(hwnd):
                break
            print(f"[main] hwnd=0x{hwnd:X} not ready (client={cw}x{ch} "
                  f"iconic={bool(user32.IsIconic(hwnd))}); retrying",
                  file=sys.stderr)
            hwnd = None
        time.sleep(0.5)
    if not hwnd:
        print(f"[main] window '{args.window_title}' not usable within "
              f"{args.find_timeout}s", file=sys.stderr)
        log_window_candidates(args.window_title)
        return 3
    cw0, ch0 = _hwnd_client_size(hwnd)
    print(f"[main] target hwnd=0x{hwnd:X} client={cw0}x{ch0}", file=sys.stderr)

    start_idx = find_start_index(events, args.start_from)
    print(f"[main] start mode={args.start_from} idx={start_idx}", file=sys.stderr)

    # Derive top_offset from the first event's ch if not specified.
    if args.top_offset is None:
        first_evt_ch = next(
            (ev.get("ch") for ev in events[start_idx:]
             if ev.get("kind") in INPUT_KINDS and ev.get("ch")),
            None,
        )
        top_offset = max(0, (first_evt_ch or vm_h) - vm_h)
    else:
        top_offset = max(0, args.top_offset)

    stop_flag = [False]

    def _sigint(signum, frame):
        print("[main] SIGINT", file=sys.stderr)
        stop_flag[0] = True
    signal.signal(signal.SIGINT, _sigint)

    ctrl_addr = (args.ctrl_host, args.ctrl_port) if args.ctrl_host else None

    # Load recorded_spawn from manifest for the spawn-assert check.
    recorded_spawn = manifest.get("recorded_spawn")
    if recorded_spawn is None and parse_spawn_frame is not None:
        # Fallback: scan the JSONL for the first 18123 S2C spawn-bearing frame.
        first_map_load = None
        first_self_spawn = None
        for ev in events:
            if (ev.get("kind") != "net" or ev.get("port") != 18123
                    or ev.get("dir") != "S2C"):
                continue
            pay_hex = ev.get("payload")
            if not pay_hex:
                continue
            try:
                sp = parse_spawn_frame(bytes.fromhex(pay_hex))
            except Exception:
                sp = None
            if sp is None:
                continue
            kind = sp.get("kind")
            if kind == "map_load" and first_map_load is None:
                first_map_load = sp
            elif kind == "self_spawn" and first_self_spawn is None:
                first_self_spawn = sp
            if first_map_load is not None and first_self_spawn is not None:
                break
        if first_self_spawn is not None:
            recorded_spawn = dict(first_self_spawn)
            if (recorded_spawn.get("map_id") is None
                    and first_map_load is not None):
                recorded_spawn["map_id"] = first_map_load.get("map_id")
        elif first_map_load is not None:
            recorded_spawn = dict(first_map_load)
        if recorded_spawn is not None:
            print(f"[main] recorded_spawn auto-derived from JSONL: "
                  f"map={recorded_spawn.get('map_id')} "
                  f"spawn=({recorded_spawn.get('x')},{recorded_spawn.get('y')}) "
                  f"actor={recorded_spawn.get('actor_id')} "
                  f"name={recorded_spawn.get('name')}", file=sys.stderr)
    if recorded_spawn is None:
        print("[main] manifest has no recorded_spawn block and no spawn "
              "frames found in JSONL; spawn-assert disabled", file=sys.stderr)
    else:
        print(f"[main] recorded_spawn={recorded_spawn}", file=sys.stderr)

    replay(events, start_idx, vm_w, vm_h, hwnd, args.speed, stop_flag,
           top_offset, args.left_offset, args.x_correction, args.y_correction,
           ctrl_addr, args.net_timeout, args.stop_at_seq,
           click_mode=args.click_mode,
           recorded_spawn=recorded_spawn,
           patches_dir=patches_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())

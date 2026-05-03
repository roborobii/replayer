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


def send_key(vk: int, up: bool):
    inp = INPUT()
    inp.type = INPUT_KEYBOARD
    flags = KEYEVENTF_KEYUP if up else 0
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
WM_RBUTTONDOWN = 0x0204
WM_RBUTTONUP = 0x0205
WM_MBUTTONDOWN = 0x0207
WM_MBUTTONUP = 0x0208

MK_LBUTTON = 0x0001
MK_RBUTTON = 0x0002
MK_MBUTTON = 0x0010

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


def map_coords(fx: float, fy: float, cw: int, ch: int,
               vm_w: int, vm_h: int,
               win_x: int, win_y: int, win_w: int, win_h: int,
               top_offset: int, left_offset: int,
               x_correction: int, y_correction: int):
    """Apply offsets and map fractional vmconnect coords → screen pixel."""
    game_x = fx * cw - left_offset
    game_y = fy * ch - top_offset
    game_x_norm = game_x / float(vm_w)
    game_y_norm = game_y / float(vm_h)
    game_x_norm = max(0.0, min(1.0, game_x_norm))
    game_y_norm = max(0.0, min(1.0, game_y_norm))
    sx = win_x + int(round(game_x_norm * win_w)) + x_correction
    sy = win_y + int(round(game_y_norm * win_h)) + y_correction
    return sx, sy


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
           recorded_spawn: Optional[dict] = None) -> None:
    if start_idx >= len(events):
        print("[replay] no input events to play", file=sys.stderr)
        return

    win_x, win_y, win_w, win_h = get_window_client_rect_screen(hwnd)
    vs = get_virtual_screen()
    print(f"[replay] window client_rect screen=({win_x},{win_y}) size=({win_w}x{win_h})",
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
            if click_mode == "postmessage":
                btn = ev.get("btn")
                state = ev.get("state")
                if (btn, state) not in _PM_BTN_MSGS:
                    continue
                cx = int(round(ev["fx"] * win_w))
                cy = int(round(ev["fy"] * win_h))
                print(f"[click] seq={ev.get('seq')} {btn}-{state} "
                      f"fx={ev['fx']:.4f} fy={ev['fy']:.4f} -> client=({cx},{cy})",
                      file=sys.stderr)
                post_click(hwnd, btn, state, cx, cy)
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
            vk = int(ev.get("vk", 0))
            if vk <= 0:
                continue
            send_key(vk, up=(ev.get("state") == "up"))

    print("[replay] done", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main

def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 2 input replayer (RC3 side)")
    ap.add_argument("recording", help="path to recording_<id>.jsonl")
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
    args = ap.parse_args()

    if not os.path.isfile(args.recording):
        print(f"recording not found: {args.recording}", file=sys.stderr)
        return 2

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
           recorded_spawn=recorded_spawn)
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Host-side input capture agent (Windows).

Runs on the Hyper-V host (RC@192.168.12.196). Uses pynput's WH_MOUSE_LL /
WH_KEYBOARD_LL hooks to observe input system-wide, filters events to those
where the foreground window belongs to vmconnect.exe, and emits a JSONL
stream of normalized events to stdout.

The guest (DXRender.exe) cannot detect this: hooks live in the host's hook
chain, no guest-side process/module/driver is added, and the input the guest
receives is the user's real input — we only observe.

Coords are reported as fractions (0.0..1.0) of the vmconnect client area so
the Mac replayer can scale to whatever offline Wine window size it has.

Wire format (one JSON object per line, stdout, flushed):
    {"t": 1.234, "kind": "mouse_down|mouse_up|mouse_move|scroll", "btn": "L|R|M",
     "fx": 0.41, "fy": 0.28, "cw": 1024, "ch": 768}
    {"t": 1.235, "kind": "key_down|key_up", "vk": 65, "char": "a"}

Run from an interactive desktop session (RDP / console). LL hooks installed
from session-0 (e.g. SSH-launched as service) often won't fire.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import json
import os
import sys
import time

try:
    from pynput import mouse, keyboard
    import win32gui
    import win32process
    import psutil
except ImportError as e:
    sys.stderr.write(f"missing dep: {e}\n  pip install pynput pywin32 psutil\n")
    sys.exit(2)

VMCONNECT_NAMES = {"vmconnect.exe", "mstsc.exe"}  # mstsc covers Enhanced Session
START_TS = time.time()
OUT_PATH = None  # set by main() if --out passed


def emit(obj: dict) -> None:
    line = json.dumps(obj, separators=(",", ":")) + "\n"
    sys.stdout.write(line)
    sys.stdout.flush()
    if OUT_PATH is not None:
        # Open/write/close per event so Windows updates the directory entry
        # immediately — Get-Content -Wait readers (over SSH) need the close
        # event to detect new bytes.
        with open(OUT_PATH, "a", encoding="utf-8") as f:
            f.write(line)


def emit_status(msg: str) -> None:
    sys.stderr.write(f"[host_agent] {msg}\n")
    sys.stderr.flush()


def foreground_vmconnect_hwnd():
    """Return (hwnd, client_w, client_h, screen_x, screen_y) if foreground is
    vmconnect, else None."""
    hwnd = win32gui.GetForegroundWindow()
    if not hwnd:
        return None
    try:
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        proc = psutil.Process(pid)
        if proc.name().lower() not in VMCONNECT_NAMES:
            return None
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None
    # Client area in screen coords
    cl, ct, cr, cb = win32gui.GetClientRect(hwnd)
    cw, ch = cr - cl, cb - ct
    if cw <= 0 or ch <= 0:
        return None
    sx, sy = win32gui.ClientToScreen(hwnd, (0, 0))
    return hwnd, cw, ch, sx, sy


def normalize(x: int, y: int):
    """Map screen pixel (x, y) -> (frac_x, frac_y, client_w, client_h) inside
    foreground vmconnect, or None if foreground is not vmconnect."""
    info = foreground_vmconnect_hwnd()
    if info is None:
        return None
    _hwnd, cw, ch, sx, sy = info
    fx = (x - sx) / cw
    fy = (y - sy) / ch
    if not (0.0 <= fx <= 1.0 and 0.0 <= fy <= 1.0):
        return None
    return fx, fy, cw, ch


def t_now() -> float:
    return round(time.time() - START_TS, 4)


# ---- Mouse handlers ----------------------------------------------------

def on_move(x, y):
    n = normalize(x, y)
    if n is None:
        return
    fx, fy, cw, ch = n
    emit({"t": t_now(), "kind": "mouse_move", "fx": round(fx, 5),
          "fy": round(fy, 5), "cw": cw, "ch": ch})


def on_click(x, y, button, pressed):
    n = normalize(x, y)
    if n is None:
        return
    fx, fy, cw, ch = n
    btn = {"Button.left": "L", "Button.right": "R", "Button.middle": "M"}.get(
        str(button), str(button))
    emit({"t": t_now(),
          "kind": "mouse_down" if pressed else "mouse_up",
          "btn": btn, "fx": round(fx, 5), "fy": round(fy, 5),
          "cw": cw, "ch": ch})


def on_scroll(x, y, dx, dy):
    n = normalize(x, y)
    if n is None:
        return
    fx, fy, cw, ch = n
    emit({"t": t_now(), "kind": "scroll", "dx": dx, "dy": dy,
          "fx": round(fx, 5), "fy": round(fy, 5), "cw": cw, "ch": ch})


# ---- Keyboard handlers -------------------------------------------------

def _key_payload(key) -> dict:
    payload = {}
    try:
        if hasattr(key, "char") and key.char is not None:
            payload["char"] = key.char
    except AttributeError:
        pass
    if hasattr(key, "vk") and key.vk is not None:
        payload["vk"] = int(key.vk)
    name = getattr(key, "name", None)
    if name:
        payload["name"] = name
    return payload


def on_press(key):
    if foreground_vmconnect_hwnd() is None:
        return
    p = {"t": t_now(), "kind": "key_down", **_key_payload(key)}
    emit(p)


def on_release(key):
    if foreground_vmconnect_hwnd() is None:
        return
    p = {"t": t_now(), "kind": "key_up", **_key_payload(key)}
    emit(p)


def main():
    global OUT_PATH
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=None,
                    help="Optional path to write JSONL events directly "
                         "(per-line flush + fsync). stdout still emits.")
    args = ap.parse_args()
    if args.out:
        OUT_PATH = args.out
        # Touch the file so Get-Content -Wait can attach immediately.
        with open(OUT_PATH, "a", encoding="utf-8") as _f:
            pass
        emit_status(f"writing JSONL to {OUT_PATH} (per-event open/close)")
    emit_status("starting LL hooks; foreground filter: " +
                ", ".join(sorted(VMCONNECT_NAMES)))
    ml = mouse.Listener(on_move=on_move, on_click=on_click, on_scroll=on_scroll)
    kl = keyboard.Listener(on_press=on_press, on_release=on_release)
    ml.start()
    kl.start()
    emit_status("hooks installed. capturing vmconnect input only.")
    try:
        ml.join()
        kl.join()
    except KeyboardInterrupt:
        emit_status("bye")


if __name__ == "__main__":
    main()

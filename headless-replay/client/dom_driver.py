#!/usr/bin/env python3
"""
dom_driver.py — drive recorded input clicks into a wine'd XenClient.exe via
dom_replay.dll, with zero Mac-side input synthesis.

The driver only writes commands to $WINEPREFIX/dosdevices/c:/dom_cmd.txt at
recorded inter-event timing. dom_replay.dll (already injected) polls that
file every 200ms and dispatches the click by calling the game's own internal
mouse handler at known VAs — fully in-process, no SendInput, no cursor move.

JSONL events used:
  - viewport       : establishes recorded client width/height (cw, ch)
  - server_endpoint: phase transition markers (login → world)
  - input_mouse_button (state=down): the actual clicks to fire

Click delivery:
  Uses dom_replay.dll's `click_post X Y` command, which PostMessage's
  WM_LBUTTONDOWN/UP to the game's main HWND. The game's own message loop
  dispatches it to whatever form is on top, on the UI thread, with full
  child hit-testing — exactly as if a human had clicked. Works uniformly
  for login screens, char-select, in-world clicks, modals, etc. No form
  detection or VA-specific paths needed.

  Earlier iterations tried calling form mouse-handlers directly (click_xy)
  or DLL-semantic commands (pick_slot/start_game). Both crash on this
  build: VA_ACTIVE_WIDGET reads stale globals before forms are constructed,
  and direct handler calls execute on the poll thread instead of the UI
  thread.

Form VMTs (instance_vmt values, matching dom_replay.c g_form_vmts[]):
  TDncServerSelectForm 0x001524B4
  TDncCharSelectShow   0x000EE6C0
  TDncCharCreateForm   0x00149A00
  TDncGameMainMenu     0x000F3AE8
  TMainForm            0x0011A470

Coordinates: recorded fx/fy are fractions of the *recording* client area
(cw × ch). Multiplied by the live game window size (default 1440×975 to
match the recording; override with --window WxH if your wine'd client is
windowed at a different size).

Usage:
  python3 dom_driver.py --recording ../sessions/recording_become-lacey-v1.jsonl
  python3 dom_driver.py --recording ... --speed 2.0
  python3 dom_driver.py --recording ... --dry-run
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

FORM_VMTS: Dict[str, int] = {
    "TDncServerSelectForm": 0x001524B4,
    "TDncCharSelectShow":   0x000EE6C0,
    "TDncCharCreateForm":   0x00149A00,
    "TDncGameMainMenu":     0x000F3AE8,
    "TMainForm":            0x0011A470,
}

DEFAULT_DOM_CMD = os.path.expanduser("~/.wine/dosdevices/c:/dom_cmd.txt")
DEFAULT_DOM_LOG = os.path.expanduser("~/.wine/dosdevices/c:/dom_replay.log")
DEFAULT_SERVER_LOG = "/tmp/v2_server.log"
DLL_POLL_INTERVAL = 0.20  # dom_replay.dll polls every 200ms

# CV match config (mirrors replay/input_replayer.py).
CV_MATCH_THRESHOLD = 0.50
CV_PEAK_TIE_MARGIN = 0.05
CV_CURSOR_MASK_PX = 28


def load_events(path: Path) -> List[dict]:
    with path.open() as f:
        return [json.loads(line) for line in f if line.strip()]


def world_transition_t(events: List[dict]) -> Optional[int]:
    for e in events:
        if e.get("kind") == "server_endpoint" and e.get("role") == "world":
            return e["t_mono_ns"]
    return None


def select_clicks(events: List[dict]) -> List[dict]:
    return [
        e for e in events
        if e.get("kind") == "input_mouse_button"
        and e.get("state") == "down"
        and e.get("btn") == "L"
    ]


def candidate_forms(t_mono_ns: int, world_t: Optional[int]) -> List[str]:
    if world_t is None or t_mono_ns < world_t:
        return ["TDncCharSelectShow", "TDncServerSelectForm", "TDncGameMainMenu"]
    return ["TMainForm"]


def write_cmd(path: str, cmd: str) -> None:
    # The DLL dedupes on "same line as last seen" — append a serial token so
    # consecutive commands always look unique.
    salt = str(time.monotonic_ns())
    with open(path, "w") as f:
        f.write(f"{cmd} #{salt}")


def tail_log_for_marker(log_path: str, marker: str, timeout: float) -> Optional[str]:
    """Wait until a line containing `marker` appears in dom_replay.log.
    Returns the matching line, or None on timeout. Polls every 50ms."""
    if not os.path.exists(log_path):
        return None
    start_size = os.path.getsize(log_path)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(log_path, "rb") as f:
                f.seek(start_size)
                tail = f.read().decode("utf-8", errors="replace")
        except OSError:
            tail = ""
        for line in tail.splitlines():
            if marker in line:
                return line
        time.sleep(0.05)
    return None


def parse_window(s: str) -> Tuple[int, int]:
    w, h = s.lower().split("x", 1)
    return int(w), int(h)


def next_c2s_seq_after(events: List[dict], click_seq: int) -> Optional[int]:
    """For a click event at recording-seq=click_seq, find the seq of the
    next *meaningful* C2S net event. Skips keepalive opcode 0x05 (the
    server logs those as 'ignored' rather than 'matched seq=N', so they
    can't be used as sync markers)."""
    KEEPALIVE = 0x05
    for e in events:
        if e.get("seq", -1) <= click_seq:
            continue
        if e.get("kind") != "net":
            continue
        if (e.get("dir", "") or "").lower() != "c2s":
            continue
        if e.get("opcode") == KEEPALIVE:
            continue
        return e["seq"]
    return None


def wait_for_server_match(server_log: str, target_seq: int,
                          since_offset: int, timeout: float) -> bool:
    """Tail v2_server.log from since_offset and wait for a line containing
    `→ matched seq=<target_seq>`. Returns True on match, False on timeout."""
    marker = f"matched seq={target_seq}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with open(server_log, "rb") as f:
                f.seek(since_offset)
                tail = f.read().decode("utf-8", errors="replace")
        except OSError:
            tail = ""
        if marker in tail:
            return True
        time.sleep(0.05)
    return False


def server_log_offset(server_log: str) -> int:
    try:
        return os.path.getsize(server_log)
    except OSError:
        return 0


# CV-based click resolution
# ─────────────────────────
# Wine's UI may render the same recorded data with subtle position deltas
# (different font fall-back, sub-pixel DPI). Recorded fx*cw might land on
# a "Create Character" slot when the real target was the lv 66 portrait
# one row up. Each recorded click has a ~64-96px patch saved in
# sessions/<id>_patches/<seq>.png — the screen content the recorder saw at
# the click point. matchTemplate it in the live screenshot to get the
# *actual* current position and click that instead of the recorded coord.

_cv2 = None
def _load_cv():
    global _cv2
    if _cv2 is None:
        import cv2
        import numpy as np
        _cv2 = (cv2, np)
    return _cv2


def take_screenshot(script_path: str, out_path: str) -> Optional[str]:
    """Run the screenshot.sh helper. Returns the output path on success."""
    import subprocess
    r = subprocess.run([script_path, out_path], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    return out_path


def cv_match_in_haystack(haystack, template, rec_cx: int, rec_cy: int,
                         threshold: float = CV_MATCH_THRESHOLD):
    """Mirrors replay/input_replayer.py:cv_match_in_haystack.
    Returns (ok, score, client_x, client_y)."""
    cv2, np = _load_cv()
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
    res[~np.isfinite(res)] = -1.0

    _min_val, max_val, _min_loc, max_loc = cv2.minMaxLoc(res)
    if max_val < threshold:
        cx = int(max_loc[0] + half_tw)
        cy = int(max_loc[1] + half_th)
        return False, float(max_val), cx, cy

    tie_floor = float(max_val) - CV_PEAK_TIE_MARGIN
    ys, xs = np.where(res >= tie_floor)
    centers_x = xs + half_tw
    centers_y = ys + half_th
    dx = centers_x.astype(np.int32) - rec_cx
    dy = centers_y.astype(np.int32) - rec_cy
    i = int(np.argmin(dx * dx + dy * dy))
    return True, float(res[ys[i], xs[i]]), int(centers_x[i]), int(centers_y[i])


def cv_resolve_click(screenshot_script: str, patches_dir: Path,
                      patch_name: str, rec_cx: int, rec_cy: int,
                      ) -> Tuple[bool, int, int, float]:
    """Take screenshot, template-match patch, return (matched, x, y, score).
    Falls back to recorded coords on any failure (returning matched=False)."""
    cv2, np = _load_cv()
    patch_path = patches_dir / patch_name
    if not patch_path.exists():
        return False, rec_cx, rec_cy, 0.0
    template = cv2.imread(str(patch_path), cv2.IMREAD_COLOR)
    if template is None:
        return False, rec_cx, rec_cy, 0.0
    shot_path = take_screenshot(screenshot_script, "/tmp/dom_driver_shot.png")
    if not shot_path:
        return False, rec_cx, rec_cy, 0.0
    haystack = cv2.imread(shot_path, cv2.IMREAD_COLOR)
    if haystack is None:
        return False, rec_cx, rec_cy, 0.0
    ok, score, cx, cy = cv_match_in_haystack(
        haystack, template, rec_cx, rec_cy)
    return ok, cx, cy, score


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--recording", required=True, type=Path)
    ap.add_argument("--cmd-file", default=DEFAULT_DOM_CMD,
                    help=f"path to dom_cmd.txt under $WINEPREFIX (default: {DEFAULT_DOM_CMD})")
    ap.add_argument("--log-file", default=DEFAULT_DOM_LOG,
                    help=f"path to dom_replay.log to watch for ack (default: {DEFAULT_DOM_LOG})")
    ap.add_argument("--window", type=parse_window, default=None,
                    help="live game window pixel size as WxH (default: use recorded cw×ch)")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="time scale; 2.0 = twice as fast")
    ap.add_argument("--start-delay", type=float, default=2.0,
                    help="seconds to wait before first click (let game settle)")
    ap.add_argument("--ack-timeout", type=float, default=1.0,
                    help="how long to wait for DLL log ack per command")
    ap.add_argument("--dry-run", action="store_true",
                    help="print plan but don't write commands")
    ap.add_argument("--login-slot", type=int, default=0,
                    help="character slot to pick during login phase (default: 0)")
    ap.add_argument("--skip-login", action="store_true",
                    help="skip pre-world phase entirely (assume already in-world)")
    ap.add_argument("--charselect-timeout", type=float, default=60.0,
                    help="max seconds to wait for CharSelect form to become live")
    ap.add_argument("--settle-time", type=float, default=3.0,
                    help="seconds to wait after CharSelect appears (for layout/paint)")
    ap.add_argument("--server-log", default=DEFAULT_SERVER_LOG,
                    help=f"v2_server log path for packet-driven sync "
                         f"(default: {DEFAULT_SERVER_LOG})")
    ap.add_argument("--no-sync", action="store_true",
                    help="disable packet-driven sync (revert to time-based pacing)")
    ap.add_argument("--match-timeout", type=float, default=8.0,
                    help="seconds to wait for v2_server C2S match per click")
    ap.add_argument("--no-resize", action="store_true",
                    help="don't issue 'resize' to canvas at startup")
    ap.add_argument("--cv-match", action="store_true", default=True,
                    help="use CV template matching to resolve click coords "
                         "from sessions/<id>_patches/ (default: on)")
    ap.add_argument("--no-cv-match", dest="cv_match", action="store_false",
                    help="disable CV match — use recorded fx*cw coords as-is")
    ap.add_argument("--screenshot-script", default="./screenshot.sh",
                    help="path to wine-window screenshot helper")
    args = ap.parse_args()

    events = load_events(args.recording)
    viewport = next((e for e in events if e.get("kind") == "viewport"), None)
    if viewport is None:
        print("[dom_driver] no viewport event in recording", file=sys.stderr)
        return 2
    rec_w, rec_h = viewport["cw"], viewport["ch"]
    win_w, win_h = args.window if args.window else (rec_w, rec_h)

    world_t = world_transition_t(events)
    clicks = select_clicks(events)
    if not clicks:
        print("[dom_driver] recording has no L-button down clicks", file=sys.stderr)
        return 2

    print(f"[dom_driver] recording={args.recording.name} clicks={len(clicks)} "
          f"world_transition_t={world_t} rec={rec_w}x{rec_h} win={win_w}x{win_h} "
          f"speed={args.speed}")

    if not args.dry_run:
        if not os.path.isdir(os.path.dirname(args.cmd_file)):
            print(f"[dom_driver] WINEPREFIX path missing: {os.path.dirname(args.cmd_file)}",
                  file=sys.stderr)
            return 2

    if args.start_delay > 0:
        print(f"[dom_driver] start_delay {args.start_delay:.1f}s")
        time.sleep(args.start_delay)

    # Force the wine window to the recording's client size so fx*cw lands
    # on the same UI elements the recorder saw. Retry — the DLL polls for
    # cmd files at 200ms intervals and the canvas hwnd may not exist for
    # several seconds after game launch (DXRender's TMainForm appears
    # after splash dismisses). Each attempt retries via the DLL's
    # find_canvas_hwnd (largest visible TMainForm-class window).
    if not args.dry_run and not args.no_resize:
        attempts = 15  # ~30s total at 2s per attempt
        for n in range(1, attempts + 1):
            cmd = f"resize {win_w} {win_h}"
            print(f"[dom_driver] {cmd} (attempt {n}/{attempts})")
            write_cmd(args.cmd_file, cmd)
            ack = tail_log_for_marker(args.log_file, "resize: hwnd=", 2.0)
            if ack:
                print(f"        ack: {ack.strip()}")
                time.sleep(0.5)
                break
            no_canvas = tail_log_for_marker(args.log_file, "resize: no canvas window yet", 0.2)
            if no_canvas:
                print("        no canvas yet — retrying")
                time.sleep(1.5)
                continue
            print("        no resize log line — retrying")
            time.sleep(1.5)
        else:
            print("[dom_driver] resize never acked; clicks will land on un-resized canvas")

    # All clicks go through PostMessage: no form detection, no VA path.
    work = clicks if not args.skip_login else [c for c in clicks
                                                if world_t is not None
                                                and c["t_mono_ns"] >= world_t]
    if args.skip_login:
        print(f"[dom_driver] --skip-login: replaying {len(work)} post-world clicks only")

    if not work:
        print("[dom_driver] no clicks to replay; done")
        return 0

    base_t = work[0]["t_mono_ns"]
    base_real = time.monotonic()
    sync_enabled = not args.no_sync and not args.dry_run
    patches_dir = args.recording.parent / (args.recording.stem + "_patches")
    cv_enabled = args.cv_match and not args.dry_run and patches_dir.exists()
    if args.cv_match and not patches_dir.exists():
        print(f"[dom_driver] cv-match: patches dir missing ({patches_dir}); falling back to recorded coords")

    # Learned-shift history: (dx, dy) from CV-confident matches. When a
    # later patch falls below threshold, use recorded coord + median
    # learned shift instead of the raw recorded coord. Self-calibrating —
    # mirrors replay/input_replayer.py's shift_history mechanism.
    shift_history: List[Tuple[int, int]] = []
    SHIFT_HISTORY_MAX = 32
    DOUBLE_CLICK_NS = 500_000_000  # 500ms window

    def _learned_median():
        if not shift_history:
            return 0, 0
        dxs = sorted(s[0] for s in shift_history)
        dys = sorted(s[1] for s in shift_history)
        return dxs[len(dxs) // 2], dys[len(dys) // 2]

    # Pre-detect double-clicks: a click event whose immediately-prior
    # click is at the same coord within DOUBLE_CLICK_NS becomes a dbl.
    is_dbl: Dict[int, bool] = {}
    for idx in range(1, len(work)):
        cur = work[idx]
        prev = work[idx - 1]
        if (cur["fx"] == prev["fx"] and cur["fy"] == prev["fy"]
                and cur["t_mono_ns"] - prev["t_mono_ns"] <= DOUBLE_CLICK_NS):
            is_dbl[idx] = True
            # Skip the prior single click — its purpose is the dbl.
            is_dbl[idx - 1] = False  # explicitly mark as not separately fired

    for i, c in enumerate(work):
        if not args.dry_run:
            target_real = base_real + (c["t_mono_ns"] - base_t) / 1e9 / args.speed
            delay = target_real - time.monotonic()
            if delay > 0:
                time.sleep(delay)

        rec_x = int(round(c["fx"] * win_w))
        rec_y = int(round(c["fy"] * win_h))
        rec_x = max(0, min(win_w - 1, rec_x))
        rec_y = max(0, min(win_h - 1, rec_y))

        # CV-resolve: find recorded patch in live screen, use matched coord.
        # On below-threshold: use recorded coord + median learned shift.
        x, y = rec_x, rec_y
        cv_note = ""
        patch_name = c.get("cv_patch")
        if cv_enabled and patch_name:
            ok, mx, my, score = cv_resolve_click(
                args.screenshot_script, patches_dir, patch_name, rec_x, rec_y)
            if ok:
                x, y = mx, my
                dx, dy = mx - rec_x, my - rec_y
                shift_history.append((dx, dy))
                if len(shift_history) > SHIFT_HISTORY_MAX:
                    shift_history.pop(0)
                cv_note = f"  [cv:{score:.2f} Δ=({dx:+d},{dy:+d})]"
            else:
                mdx, mdy = _learned_median()
                x, y = rec_x + mdx, rec_y + mdy
                cv_note = (f"  [cv:miss {score:.2f}; "
                           f"recorded+learned({mdx:+d},{mdy:+d})]")
        elif cv_enabled and not patch_name:
            # No patch for this event — apply learned shift if we have one.
            mdx, mdy = _learned_median()
            x, y = rec_x + mdx, rec_y + mdy
            if mdx or mdy:
                cv_note = f"  [no-patch; learned({mdx:+d},{mdy:+d})]"

        # Pre-compute what server-side seq this click should produce.
        target_c2s_seq = next_c2s_seq_after(events, c["seq"]) if sync_enabled else None

        # If this click is the second half of a recorded double-click,
        # send dblclick instead. Skip the click marked as "absorbed" by
        # a later dblclick (so we don't fire the prior single click).
        if is_dbl.get(i) is False:
            print(f"[{i+1:>3}/{len(work)}] (absorbed into dblclick at next slot)")
            continue
        cmd = f"click_dbl {x} {y}" if is_dbl.get(i) else f"click_post {x} {y}"
        label = f"[{i+1:>3}/{len(work)}] t+{(c['t_mono_ns']-base_t)/1e9:6.2f}s " \
                f"fx={c['fx']:.3f} fy={c['fy']:.3f} -> {x},{y}{cv_note}" \
                f"{' DBL' if is_dbl.get(i) else ''}"
        if target_c2s_seq is not None:
            label += f"  (await c2s seq={target_c2s_seq})"
        print(label)
        if args.dry_run:
            continue

        # Snapshot server log size BEFORE click so we don't match an old line.
        log_offset = server_log_offset(args.server_log) if sync_enabled else 0

        write_cmd(args.cmd_file, cmd)
        marker = "click_dbl:" if is_dbl.get(i) else "click_post:"
        ack = tail_log_for_marker(args.log_file, marker, args.ack_timeout)
        if ack:
            print(f"        dll: {ack.strip()}")

        # Block until v2_server confirms it matched the expected C2S seq.
        if sync_enabled and target_c2s_seq is not None:
            ok = wait_for_server_match(args.server_log, target_c2s_seq,
                                        log_offset, args.match_timeout)
            if ok:
                print(f"        sync: server matched seq={target_c2s_seq}")
                # Re-base the time anchor on real time after a sync wait so
                # next click's recorded delta is measured from now.
                base_real = time.monotonic()
                base_t = c["t_mono_ns"]
            else:
                print(f"        sync: TIMEOUT waiting for seq={target_c2s_seq} "
                      f"after {args.match_timeout:.1f}s — click likely missed")

    print("[dom_driver] done")
    return 0


if __name__ == "__main__":
    sys.exit(main())

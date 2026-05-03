"""Mac-side input replay: read JSONL from host_agent.py via SSH stdin,
synthesize equivalent input on offline Wine client via click_game.exe.

Usage:
    python3 pipeline/input_capture/mac_replay.py
        # SSH-launches the host agent, pipes stdout, replays in real time

    ssh RC@host "python C:\\path\\host_agent.py" | python3 mac_replay.py -
        # alt: read from stdin

The host agent reports vmconnect-client-relative fractions (0..1). We scale
to the offline Wine client's client area by reading its window size at start
(default 1024x768; configurable via --wine-w / --wine-h).

Replay strategy (1:1):
- Mouse down→up at same position (no movement) → click / rclick
- Mouse down → moves → up                        → drag / rdrag
- Standalone mouse_move events                   → hover (rate-limited)
- Keyboard char keys                             → type single char
- Keyboard Return / Enter                        → enter
- Modifiers (alt/ctrl/shift) tracked for combos; alt+letter → altkey
- Other special keys: logged, not replayed (extend as needed)
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

CLICK_EXE = "/Users/robin/proj/server-emulator-python3/tools/click_game.exe"
HOST = "RC@192.168.12.196"
DEFAULT_REMOTE_AGENT = r"C:\Users\RC\Desktop\dev\proj\pipeline\input_capture\host_agent.py"
DEFAULT_REMOTE_JSONL = r"C:\Users\RC\sessions\input_events.jsonl"

# Throttle mouse_move replays — game uses hover for tooltip only; no need to
# replay every pixel.
MOVE_REPLAY_INTERVAL_S = 0.10


def click_game(*args: str) -> None:
    """Spawn click_game.exe under wine, fire-and-forget."""
    cmd = ["wine", CLICK_EXE, *args]
    subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Replayer:
    def __init__(self, wine_w: int, wine_h: int, vmc_rect=None):
        self.wine_w = wine_w
        self.wine_h = wine_h
        # vmc_rect: (rx_frac, ry_frac, rw_frac, rh_frac) — game render area
        # within the vmconnect client window, expressed as fractions. None
        # means "use the whole client area" (default).
        self.vmc_rect = vmc_rect
        # Per-button down state: key=btn, val=(x_px, y_px, t)
        self.down = {}
        # Drag tracking: was there meaningful movement after down?
        self.moved_since_down = {}
        # Modifier state
        self.mods = {"alt": False, "ctrl": False, "shift": False}
        self.last_move_replay = 0.0
        self.events = 0
        self.replays = 0

    def to_px(self, fx: float, fy: float):
        # If a vmc_rect calibration is set, remap (fx, fy) from vmconnect
        # client space into the game render sub-rect, then scale to Wine.
        if self.vmc_rect is not None:
            rx, ry, rw, rh = self.vmc_rect
            gfx = (fx - rx) / rw
            gfy = (fy - ry) / rh
            return int(gfx * self.wine_w), int(gfy * self.wine_h)
        return int(fx * self.wine_w), int(fy * self.wine_h)

    def handle(self, ev: dict) -> None:
        self.events += 1
        kind = ev.get("kind")
        if kind == "mouse_down":
            x, y = self.to_px(ev["fx"], ev["fy"])
            self.down[ev["btn"]] = (x, y, ev["t"])
            self.moved_since_down[ev["btn"]] = False
        elif kind == "mouse_up":
            x, y = self.to_px(ev["fx"], ev["fy"])
            d = self.down.pop(ev["btn"], None)
            self.moved_since_down.pop(ev["btn"], None)
            if d is None:
                return
            x0, y0, _t0 = d
            btn = ev["btn"]
            dist = abs(x - x0) + abs(y - y0)
            if dist <= 4:
                # click
                if btn == "L":
                    click_game("click", str(x0), str(y0))
                elif btn == "R":
                    click_game("rclick", str(x0), str(y0))
                # middle: ignored (game doesn't use it)
            else:
                # drag
                if btn == "L":
                    click_game("drag", str(x0), str(y0), str(x), str(y))
                elif btn == "R":
                    click_game("rdrag", str(x0), str(y0), str(x), str(y))
            self.replays += 1
        elif kind == "mouse_move":
            now = time.time()
            if any(self.down):
                # During a press: drag will be issued on mouse_up.
                self.moved_since_down = {k: True for k in self.moved_since_down}
                return
            if now - self.last_move_replay < MOVE_REPLAY_INTERVAL_S:
                return
            self.last_move_replay = now
            x, y = self.to_px(ev["fx"], ev["fy"])
            click_game("hover", str(x), str(y))
            self.replays += 1
        elif kind == "scroll":
            x, y = self.to_px(ev["fx"], ev["fy"])
            delta = int(ev.get("dy", 0))
            if delta == 0:
                return
            click_game("scroll", str(delta), str(x), str(y))
            self.replays += 1
        elif kind in ("key_down", "key_up"):
            self._handle_key(ev)

    def _handle_key(self, ev: dict) -> None:
        name = ev.get("name") or ""
        ch = ev.get("char")
        is_down = ev["kind"] == "key_down"
        # Track modifiers
        if name in ("alt", "alt_l", "alt_r", "alt_gr"):
            self.mods["alt"] = is_down
            return
        if name in ("ctrl", "ctrl_l", "ctrl_r"):
            self.mods["ctrl"] = is_down
            return
        if name in ("shift", "shift_l", "shift_r"):
            self.mods["shift"] = is_down
            return
        # Only act on key_down; key_up of typed keys is implicit in click_game.
        if not is_down:
            return
        if name == "enter":
            click_game("enter")
            self.replays += 1
            return
        # Alt+letter combo
        if self.mods["alt"] and ch and ch.isalpha():
            click_game("altkey", ch)
            self.replays += 1
            return
        # Plain character → type single char
        if ch and ch.isprintable():
            click_game("type", ch)
            self.replays += 1
            return
        # Other named keys (esc, tab, function keys, arrows) — log only.
        if name:
            sys.stderr.write(f"[replay] unhandled key: {name}\n")


def open_source(args) -> "subprocess.Popen | object":
    if args.source == "-":
        # stdin
        class _Stdin:
            stdout = sys.stdin

            def poll(self):
                return None

            def terminate(self):
                pass
        return _Stdin()
    if args.source == "tail":
        # Tail the JSONL via a tiny Python script on the host. Avoids
        # PowerShell Get-Content -Wait stdout buffering over SSH.
        remote_tail = r"C:\Users\RC\sessions\tail_jsonl.py"
        cmd = [
            "ssh",
            "-o", "ServerAliveInterval=5",
            "-o", "ServerAliveCountMax=12",
            "-o", "TCPKeepAlive=yes",
            HOST,
            f'python -u "{remote_tail}" "{args.remote_jsonl}"',
        ]
        sys.stderr.write(f"[replay] tailing {args.remote_jsonl} via python -u\n")
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                bufsize=1, text=True, encoding="utf-8",
                                errors="replace")
    cmd = [
        "ssh",
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=12",
        "-o", "TCPKeepAlive=yes",
        HOST,
        f'python "{args.remote_agent}"',
    ]
    sys.stderr.write(f"[replay] launching: {' '.join(cmd)}\n")
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            bufsize=1, text=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("source", nargs="?", default="tail",
                    help="'tail' (default) tails JSONL on host via SSH; "
                         "'ssh' launches host agent over SSH (won't work in "
                         "session-0); '-' reads JSONL from stdin")
    ap.add_argument("--remote-agent", default=DEFAULT_REMOTE_AGENT,
                    help=f"Path to host_agent.py on the Windows host "
                         f"(default: {DEFAULT_REMOTE_AGENT})")
    ap.add_argument("--remote-jsonl", default=DEFAULT_REMOTE_JSONL,
                    help=f"JSONL file to tail when source='tail' "
                         f"(default: {DEFAULT_REMOTE_JSONL})")
    ap.add_argument("--wine-w", type=int, default=1024)
    ap.add_argument("--wine-h", type=int, default=768)
    ap.add_argument("--vmc-rect", default=None,
                    help="Game render rect within vmconnect, as 4 fractions "
                         "rx,ry,rw,rh (e.g. 0.10,0.05,0.80,0.90). Without "
                         "this, full vmconnect client is assumed.")
    args = ap.parse_args()
    vmc_rect = None
    if args.vmc_rect:
        vmc_rect = tuple(float(x) for x in args.vmc_rect.split(","))
        if len(vmc_rect) != 4:
            sys.stderr.write("--vmc-rect needs 4 comma-separated floats\n")
            sys.exit(2)

    if not Path(CLICK_EXE).exists():
        sys.stderr.write(f"[replay] click_game.exe not found at {CLICK_EXE}\n")
        sys.exit(1)

    rep = Replayer(args.wine_w, args.wine_h, vmc_rect=vmc_rect)
    if vmc_rect:
        sys.stderr.write(f"[replay] vmconnect game-rect: {vmc_rect}\n")
    proc = open_source(args)
    src = proc.stdout
    sys.stderr.write(f"[replay] reading events; wine target {args.wine_w}x{args.wine_h}\n")
    last_stat = time.time()
    try:
        for line in src:
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                # status from agent stderr-mixed-in; ignore
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            rep.handle(ev)
            if time.time() - last_stat > 5.0:
                sys.stderr.write(f"[replay] events={rep.events} replays={rep.replays}\n")
                last_stat = time.time()
    except KeyboardInterrupt:
        sys.stderr.write("[replay] bye\n")
    finally:
        try:
            proc.terminate()
        except Exception:
            pass


if __name__ == "__main__":
    main()

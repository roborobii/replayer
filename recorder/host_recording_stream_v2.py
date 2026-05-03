#!/usr/bin/env python3
"""host_recording_stream_v2.py - Phase 1 host-side unified recorder (v2).

Runs on the NVIDIA HOST (Windows). Two threads, single mutex-protected
JSONL writer producing a v2-schema timeline:

  Thread A: net-sniffer. Spawns tshark on vEthernet (Default Switch),
            reassembles V2 frames [u16 LE len][u8 op][payload], decrypts
            world-port (18123) frames via v2cipher, emits one `net` event
            per frame to JSONL.

  Thread B: input-recorder. pynput LL mouse + keyboard listeners,
            foreground-filtered to vmconnect/mstsc. Emits
            input_mouse_move / _button / _wheel / _key / _focus and
            viewport-change events under the same JsonlWriter.

Universal fields on every event: kind, seq, t_mono_ns, t_wall_ns.
seq is allocated under the JsonlWriter mutex at emit time → total
ordering across threads.

NO MemProcFS. NO form-poller. NO DXRender PID polling.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

# v2cipher is imported as a sibling module (lives in recorder/ alongside us).
sys.path.insert(0, str(Path(__file__).parent))
# spawn_parser lives in ../replay (shared between recorder and replayer).
sys.path.insert(0, str(Path(__file__).parent.parent / "replay"))
try:
    import v2cipher  # type: ignore
    _V2_CIPHER_OK = True
    _V2_CIPHER_ERR = None
except Exception as _e:  # pragma: no cover
    v2cipher = None  # type: ignore
    _V2_CIPHER_OK = False
    _V2_CIPHER_ERR = f"{type(_e).__name__}: {_e}"

try:
    from spawn_parser import parse_spawn_frame  # type: ignore
except Exception:
    parse_spawn_frame = None  # type: ignore

# ---------------------------------------------------------------------------
# Hardcoded constants for the NVIDIA HOST.

TSHARK_DEFAULT = r"C:\Program Files\Wireshark\tshark.exe"
DEFAULT_IFACE  = "8"  # vEthernet (Default Switch)
GAME_PORTS     = {1818, 1819, 18123, 18124}
BPF            = "tcp and (port 1818 or port 1819 or port 18123 or port 18124)"
WORLD_PORT     = 18123
MAX_CIPHER_BUF = 8192

SCHEMA_VERSION = "v2.0"
DEFAULT_VM_RES = {"w": 1440, "h": 900}

VMCONNECT_NAMES = {"vmconnect.exe", "mstsc.exe"}

# Heuristic role classification for server endpoints.
WORLD_PORTS = {18123, 18124}
LOGIN_PORTS = {1818, 1819}


def _ts_pair() -> tuple[int, int]:
    """Sample (t_mono_ns, t_wall_ns) at this exact moment."""
    return time.monotonic_ns(), time.time_ns()


# ---------------------------------------------------------------------------
# Shared writer

class JsonlWriter:
    """Mutex-protected JSONL writer. Owns the seq counter.

    Caller fills the event dict — including kind and t_mono_ns/t_wall_ns
    sampled at observation time — then calls emit(). The writer injects
    a monotonically increasing seq under the lock so events from any
    thread share a single total order.
    """

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.fh = open(path, "a", buffering=1, encoding="utf-8")
        self._seq = 0

    def emit(self, event: dict) -> None:
        with self.lock:
            event["seq"] = self._seq
            self._seq += 1
            line = json.dumps(event, separators=(",", ":"))
            self.fh.write(line + "\n")

    def close(self) -> None:
        with self.lock:
            try:
                self.fh.flush()
                self.fh.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Manifest

def write_manifest(path: Path, manifest: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# Net sniffer (tshark -w - producing pcap on stdout)

class PcapStream:
    def __init__(self, src):
        self.src = src
        hdr = self._read_exact(24)
        if len(hdr) < 24:
            raise RuntimeError("pcap: short global header")
        magic = struct.unpack_from("<I", hdr, 0)[0]
        self.bo = "<" if magic == 0xA1B2C3D4 else ">" if magic == 0xD4C3B2A1 else None
        if self.bo is None:
            raise RuntimeError(f"pcap: bad magic {magic:#x}")
        self.linktype = struct.unpack_from(self.bo + "I", hdr, 20)[0]

    def _read_exact(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            chunk = self.src.read(n - len(out))
            if not chunk:
                return bytes(out)
            out.extend(chunk)
        return bytes(out)

    def packets(self):
        bo = self.bo
        while True:
            hdr = self._read_exact(16)
            if len(hdr) < 16:
                return
            ts_sec, ts_usec, incl, _ = struct.unpack(bo + "IIII", hdr)
            data = self._read_exact(incl)
            if len(data) < incl:
                return
            yield (ts_sec + ts_usec / 1_000_000.0), data


def parse_eth_ip_tcp(pkt: bytes, linktype: int):
    off = 0
    if linktype == 1:
        if len(pkt) < 14:
            return None
        et = struct.unpack_from(">H", pkt, 12)[0]
        off = 14
        if et == 0x8100 and len(pkt) >= 18:
            et = struct.unpack_from(">H", pkt, 16)[0]
            off = 18
        if et != 0x0800:
            return None
    elif linktype == 113:
        if len(pkt) < 16:
            return None
        et = struct.unpack_from(">H", pkt, 14)[0]
        off = 16
        if et != 0x0800:
            return None
    else:
        return None
    if len(pkt) < off + 20:
        return None
    ihl = (pkt[off] & 0x0F) * 4
    if ihl < 20 or len(pkt) < off + ihl:
        return None
    if pkt[off + 9] != 6:
        return None
    src_ip = ".".join(str(b) for b in pkt[off + 12:off + 16])
    dst_ip = ".".join(str(b) for b in pkt[off + 16:off + 20])
    total_len = struct.unpack_from(">H", pkt, off + 2)[0]
    ip_end = off + total_len
    tcp_off = off + ihl
    if len(pkt) < tcp_off + 20:
        return None
    sport, dport = struct.unpack_from(">HH", pkt, tcp_off)
    data_off = (pkt[tcp_off + 12] >> 4) * 4
    payload = pkt[tcp_off + data_off:min(ip_end, len(pkt))]
    return src_ip, dst_ip, sport, dport, payload


def _role_for_port(port: int) -> str:
    if port in WORLD_PORTS:
        return "world"
    if port in LOGIN_PORTS:
        return "login"
    return "unknown"


class NetSniffer(threading.Thread):
    def __init__(self, iface: str, tshark_path: str, writer: JsonlWriter,
                 stop_evt: threading.Event, gate_evt: threading.Event):
        super().__init__(name="net-sniffer", daemon=True)
        self.iface = iface
        self.tshark_path = tshark_path
        self.writer = writer
        self.stop = stop_evt
        self.gate_evt = gate_evt
        self.proc: subprocess.Popen | None = None
        # Most-recent spawn frames seen on world port (for manifest).
        self.last_map_load: dict | None = None
        self.last_self_spawn: dict | None = None

    def _spawn(self) -> subprocess.Popen:
        cmd = [self.tshark_path, "-i", self.iface, "-f", BPF,
               "-F", "pcap", "-w", "-", "-l"]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, bufsize=0)

    def terminate(self) -> None:
        try:
            if self.proc:
                self.proc.terminate()
        except Exception:
            pass

    def _emit_error(self, msg: str, **extra) -> None:
        m, w = _ts_pair()
        ev = {"kind": "net_error", "t_mono_ns": m, "t_wall_ns": w, "err": msg}
        ev.update(extra)
        self.writer.emit(ev)

    def _maybe_open_gate(self, direction: str, port: int, opcode: int) -> None:
        """Open the input-gate when the server-list response is observed.

        Trigger: S2C frame on login port 1818 with opcode 0xd1 (209). On
        first match this sets gate_evt AND emits a synthetic gate_opened
        event (with fresh t_mono_ns/t_wall_ns sampled at this moment).
        """
        if self.gate_evt.is_set():
            return
        if direction != "S2C" or port != 1818 or opcode != 209:
            return
        self.gate_evt.set()
        m, w = _ts_pair()
        self.writer.emit({
            "kind": "gate_opened",
            "t_mono_ns": m, "t_wall_ns": w,
            "trigger": "server_select_visible",
            "via": {"port": 1818, "opcode": 209},
        })

    def run(self) -> None:
        try:
            self.proc = self._spawn()
        except FileNotFoundError as e:
            self._emit_error(f"spawn: {e}")
            return

        try:
            pcap = PcapStream(self.proc.stdout)
        except Exception as e:
            err_tail = b""
            if self.proc.stderr:
                try:
                    err_tail = self.proc.stderr.read(1024)
                except Exception:
                    pass
            self._emit_error(f"pcap init: {e}",
                             stderr=err_tail.decode("utf-8", "replace"))
            return

        # Per-flow assembly state.
        streams: dict[tuple, bytearray] = defaultdict(bytearray)
        consumed: dict[tuple, int] = defaultdict(int)
        cipher_warned: dict[tuple, bool] = defaultdict(bool)
        seen_endpoints: set[tuple] = set()  # (ip, port) for server-bound flows

        if not _V2_CIPHER_OK:
            self._emit_error(
                f"v2cipher import failed: {_V2_CIPHER_ERR}; world frames will be raw")

        try:
            for _ts, raw in pcap.packets():
                if self.stop.is_set():
                    break
                # Sample timestamps at packet-observation time.
                t_mono, t_wall = _ts_pair()

                parsed = parse_eth_ip_tcp(raw, pcap.linktype)
                if parsed is None:
                    continue
                src_ip, dst_ip, sport, dport, payload = parsed
                if dport in GAME_PORTS:
                    port, direction = dport, "C2S"
                    server_ip = dst_ip
                elif sport in GAME_PORTS:
                    port, direction = sport, "S2C"
                    server_ip = src_ip
                else:
                    continue

                # First-time server endpoint emit (only on C2S — that's where
                # we know which (ip, port) the client is actually targeting).
                if direction == "C2S":
                    ep = (server_ip, port)
                    if ep not in seen_endpoints:
                        seen_endpoints.add(ep)
                        self.writer.emit({
                            "kind": "server_endpoint",
                            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
                            "ip": server_ip, "port": port,
                            "role": _role_for_port(port),
                        })

                key = (src_ip, sport, dst_ip, dport)
                if payload:
                    streams[key].extend(payload)

                buf = bytes(streams[key])
                start = consumed[key]
                seg = buf[start:]

                if port == WORLD_PORT and _V2_CIPHER_OK:
                    # World traffic is V2-encrypted post-handshake. Slice
                    # frames from the ciphertext via the encrypted-length
                    # decoder, then decrypt each one. Stateless across frames.
                    i = 0
                    while i + 4 <= len(seg):
                        plain_len = v2cipher.extract_length(seg[i:i + 4])
                        if plain_len < 6:
                            break
                        size = plain_len + 2
                        if i + size > len(seg):
                            break
                        cipher_frame = bytes(seg[i:i + size])
                        try:
                            plain = v2cipher.decrypt_frame(
                                cipher_frame, plaintext_len_known=plain_len)
                        except Exception as e:
                            self._emit_error(
                                f"v2 decrypt: {type(e).__name__}: {e}",
                                port=port, dir=direction,
                                frame_hex=cipher_frame[:32].hex())
                            i += size
                            continue
                        # plain[2] is the real semantic opcode.
                        body_off = 7
                        body_end = 7 + (plain_len - 5)
                        body = plain[body_off:body_end]
                        real_op = plain[2] if len(plain) >= 3 else 0
                        op_int = int(real_op)
                        self.writer.emit({
                            "kind": "net",
                            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
                            "dir": direction, "port": port,
                            "opcode": op_int,
                            "len": int(plain_len),
                            "payload": plain.hex(),
                            "cipher": "v2_world",
                        })
                        self._maybe_open_gate(direction, port, op_int)
                        # Spawn-frame capture (S2C only — only the server tells
                        # us where we ended up). Keep most-recent of each kind
                        # for the manifest's `recorded_spawn` block.
                        if direction == "S2C" and parse_spawn_frame is not None:
                            try:
                                spawn = parse_spawn_frame(plain)
                            except Exception:
                                spawn = None
                            if spawn is not None:
                                if spawn["kind"] == "map_load":
                                    self.last_map_load = spawn
                                elif spawn["kind"] == "self_spawn":
                                    self.last_self_spawn = spawn
                        i += size
                    consumed[key] += i
                    unconsumed = len(seg) - i
                    if unconsumed > MAX_CIPHER_BUF and not cipher_warned[key]:
                        self._emit_error(
                            f"v2 cipher buffer overflow ({unconsumed}B unconsumed); resetting flow",
                            port=port, dir=direction)
                        cipher_warned[key] = True
                        consumed[key] = len(buf)
                else:
                    # Plaintext V2 framing: [u16 LE len][u8 op][payload].
                    # 'len' counts bytes from opcode onward. Wire size = len + 2.
                    i = 0
                    while i + 3 <= len(seg):
                        plain_len = seg[i] | (seg[i + 1] << 8)
                        size = plain_len + 2
                        if plain_len < 1 or i + size > len(seg):
                            break
                        op = seg[i + 2]
                        body_hex = bytes(seg[i:i + size]).hex()
                        self.writer.emit({
                            "kind": "net",
                            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
                            "dir": direction, "port": port,
                            "opcode": int(op),
                            "len": int(size),
                            "payload": body_hex,
                            "cipher": "none",
                        })
                        self._maybe_open_gate(direction, port, int(op))
                        i += size
                    consumed[key] += i
        except Exception as e:
            self._emit_error(f"loop: {type(e).__name__}: {e}")
        finally:
            self.terminate()


# ---------------------------------------------------------------------------
# Input recorder (pynput LL hooks + vmconnect foreground filter)

class InputRecorder:
    """Owns pynput Listeners. Emits input_*, viewport, and input_focus events.

    Listeners run their own threads — start() simply launches them and
    returns. stop() unhooks them.
    """

    def __init__(self, writer: JsonlWriter, stop_evt: threading.Event,
                 gate_evt: threading.Event):
        self.writer = writer
        self.stop = stop_evt
        self.gate_evt = gate_evt
        # Lazy imports so the script can at least start to parse args even
        # if pynput/win32 aren't installed.
        from pynput import mouse, keyboard  # type: ignore
        import win32gui  # type: ignore
        import win32process  # type: ignore
        import psutil  # type: ignore
        self._mouse = mouse
        self._keyboard = keyboard
        self._win32gui = win32gui
        self._win32process = win32process
        self._psutil = psutil

        # Cached viewport state (last emitted) and focus state.
        self._lock = threading.Lock()
        self._last_viewport: tuple | None = None  # (cw, ch, sx, sy, hwnd)
        self._in_vmconnect = False  # last-known foreground-is-vmconnect

        self._mouse_listener = None
        self._keyboard_listener = None

    # -- gate --

    def _gated(self) -> bool:
        """True iff the input gate is open (i.e. emits are allowed).

        Lock-free; `threading.Event.is_set()` is safe to read concurrently.
        Pre-gate, internal cached state (last viewport, focus) is still
        UPDATED so that the first post-gate event triggers a fresh
        viewport/input_focus emit if state changed during the silence.
        """
        return self.gate_evt.is_set()

    # -- foreground / viewport helpers --

    def _foreground_info(self):
        """Return dict with keys hwnd, proc, in_vmc, cw, ch, sx, sy if
        foreground is a vmconnect/mstsc window with a valid client rect.
        Otherwise returns dict with in_vmc=False and best-effort hwnd/proc.
        """
        try:
            hwnd = self._win32gui.GetForegroundWindow()
        except Exception:
            return {"in_vmc": False, "hwnd": None, "proc": None}
        if not hwnd:
            return {"in_vmc": False, "hwnd": None, "proc": None}
        proc_name = None
        try:
            _, pid = self._win32process.GetWindowThreadProcessId(hwnd)
            proc_name = self._psutil.Process(pid).name()
        except Exception:
            proc_name = None
        if not proc_name or proc_name.lower() not in VMCONNECT_NAMES:
            return {"in_vmc": False, "hwnd": int(hwnd), "proc": proc_name}
        try:
            cl, ct, cr, cb = self._win32gui.GetClientRect(hwnd)
            cw, ch = cr - cl, cb - ct
            if cw <= 0 or ch <= 0:
                return {"in_vmc": False, "hwnd": int(hwnd), "proc": proc_name}
            sx, sy = self._win32gui.ClientToScreen(hwnd, (0, 0))
        except Exception:
            return {"in_vmc": False, "hwnd": int(hwnd), "proc": proc_name}
        return {
            "in_vmc": True, "hwnd": int(hwnd), "proc": proc_name,
            "cw": int(cw), "ch": int(ch), "sx": int(sx), "sy": int(sy),
        }

    def _check_focus_change(self, info: dict, t_mono: int, t_wall: int) -> None:
        """Emit input_focus if foreground vmconnect/mstsc state flipped.

        Pre-gate: do nothing. Cache stays at its initial value so the
        first post-gate check sees a state-flip vs. that baseline and
        fires a fresh input_focus emit.
        """
        if not self._gated():
            return
        in_vmc = bool(info.get("in_vmc"))
        with self._lock:
            prev = self._in_vmconnect
            if in_vmc == prev:
                return
            self._in_vmconnect = in_vmc
        self.writer.emit({
            "kind": "input_focus",
            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
            "gained": in_vmc,
            "hwnd": info.get("hwnd"),
            "proc": info.get("proc"),
        })

    def _maybe_emit_viewport(self, info: dict, t_mono: int, t_wall: int) -> None:
        """Emit a viewport event if the cached vmconnect rect changed.

        Pre-gate: do nothing. Cache stays None so the first post-gate
        input event observes a "change vs. baseline" and emits a fresh
        viewport before the input event itself.
        """
        if not self._gated():
            return
        if not info.get("in_vmc"):
            return
        cur = (info["cw"], info["ch"], info["sx"], info["sy"], info["hwnd"])
        with self._lock:
            prev = self._last_viewport
            if cur == prev:
                return
            self._last_viewport = cur
        self.writer.emit({
            "kind": "viewport",
            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
            "cw": cur[0], "ch": cur[1],
            "sx": cur[2], "sy": cur[3],
            "hwnd": cur[4],
        })

    # -- mouse handlers --

    def _normalize(self, x: int, y: int):
        """Return (fx, fy, cw, ch, info) if cursor is inside foreground
        vmconnect client area; else None."""
        t_mono, t_wall = _ts_pair()
        info = self._foreground_info()
        # Always run focus + viewport bookkeeping with each event.
        self._check_focus_change(info, t_mono, t_wall)
        if not info.get("in_vmc"):
            return None
        self._maybe_emit_viewport(info, t_mono, t_wall)
        cw, ch, sx, sy = info["cw"], info["ch"], info["sx"], info["sy"]
        fx = (x - sx) / cw
        fy = (y - sy) / ch
        if not (0.0 <= fx <= 1.0 and 0.0 <= fy <= 1.0):
            return None
        return fx, fy, cw, ch, t_mono, t_wall

    def _on_move(self, x, y):
        n = self._normalize(x, y)
        if n is None:
            return
        if not self._gated():
            return
        fx, fy, cw, ch, t_mono, t_wall = n
        self.writer.emit({
            "kind": "input_mouse_move",
            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
            "fx": round(fx, 5), "fy": round(fy, 5),
            "cw": cw, "ch": ch,
        })

    def _on_click(self, x, y, button, pressed):
        n = self._normalize(x, y)
        if n is None:
            return
        if not self._gated():
            return
        fx, fy, cw, ch, t_mono, t_wall = n
        btn = {"Button.left": "L", "Button.right": "R", "Button.middle": "M"}.get(
            str(button), str(button))
        self.writer.emit({
            "kind": "input_mouse_button",
            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
            "btn": btn,
            "state": "down" if pressed else "up",
            "fx": round(fx, 5), "fy": round(fy, 5),
            "cw": cw, "ch": ch,
        })

    def _on_scroll(self, x, y, dx, dy):
        n = self._normalize(x, y)
        if n is None:
            return
        if not self._gated():
            return
        fx, fy, cw, ch, t_mono, t_wall = n
        self.writer.emit({
            "kind": "input_mouse_wheel",
            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
            "dx": int(dx), "dy": int(dy),
            "fx": round(fx, 5), "fy": round(fy, 5),
            "cw": cw, "ch": ch,
        })

    # -- keyboard handlers --

    @staticmethod
    def _key_payload(key) -> dict:
        payload: dict = {"char": None, "vk": None, "name": None}
        try:
            if hasattr(key, "char") and key.char is not None:
                payload["char"] = key.char
        except AttributeError:
            pass
        if hasattr(key, "vk") and key.vk is not None:
            try:
                payload["vk"] = int(key.vk)
            except Exception:
                payload["vk"] = None
        name = getattr(key, "name", None)
        if name:
            payload["name"] = str(name)
        # Fallback name: stringified key without "Key." prefix.
        if payload["name"] is None:
            s = str(key)
            payload["name"] = s
        return payload

    def _on_press(self, key):
        t_mono, t_wall = _ts_pair()
        info = self._foreground_info()
        self._check_focus_change(info, t_mono, t_wall)
        if not info.get("in_vmc"):
            return
        self._maybe_emit_viewport(info, t_mono, t_wall)
        if not self._gated():
            return
        p = self._key_payload(key)
        self.writer.emit({
            "kind": "input_key",
            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
            "state": "down",
            "char": p["char"], "vk": p["vk"], "name": p["name"],
        })

    def _on_release(self, key):
        t_mono, t_wall = _ts_pair()
        info = self._foreground_info()
        self._check_focus_change(info, t_mono, t_wall)
        if not info.get("in_vmc"):
            return
        self._maybe_emit_viewport(info, t_mono, t_wall)
        if not self._gated():
            return
        p = self._key_payload(key)
        self.writer.emit({
            "kind": "input_key",
            "t_mono_ns": t_mono, "t_wall_ns": t_wall,
            "state": "up",
            "char": p["char"], "vk": p["vk"], "name": p["name"],
        })

    # -- lifecycle --

    def prime_initial_viewport(self) -> None:
        """If vmconnect is already foreground at session start, emit a
        starting viewport (and an input_focus gained=True)."""
        t_mono, t_wall = _ts_pair()
        info = self._foreground_info()
        self._check_focus_change(info, t_mono, t_wall)
        self._maybe_emit_viewport(info, t_mono, t_wall)

    def start(self) -> None:
        self._mouse_listener = self._mouse.Listener(
            on_move=self._on_move,
            on_click=self._on_click,
            on_scroll=self._on_scroll,
        )
        self._keyboard_listener = self._keyboard.Listener(
            on_press=self._on_press,
            on_release=self._on_release,
        )
        self._mouse_listener.start()
        self._keyboard_listener.start()

    def stop_listeners(self) -> None:
        for li in (self._mouse_listener, self._keyboard_listener):
            try:
                if li is not None:
                    li.stop()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Main

def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 1 host-side recorder (v2)")
    ap.add_argument("--id", required=True, help="recording id (filename suffix)")
    ap.add_argument("--iface", default=DEFAULT_IFACE, help="tshark interface index/name")
    ap.add_argument("--pcap", required=True, help="path to recording_<id>.pcap")
    ap.add_argument("--jsonl", required=True, help="path to recording_<id>.jsonl")
    ap.add_argument("--manifest", required=True, help="path to recording_<id>.manifest.json")
    ap.add_argument("--tshark", default=TSHARK_DEFAULT, help="path to tshark.exe")
    ap.add_argument("--force", action="store_true", help="overwrite existing recording files")
    args = ap.parse_args()

    pcap_path = Path(args.pcap)
    jsonl_path = Path(args.jsonl)
    manifest_path = Path(args.manifest)

    for p in (pcap_path, jsonl_path, manifest_path):
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and not args.force:
            sys.exit(f"FATAL: {p} exists; pass --force to overwrite")
        if p.exists():
            try:
                p.unlink()
            except Exception as e:
                sys.exit(f"FATAL: couldn't remove existing {p}: {e}")

    # Open JSONL writer.
    writer = JsonlWriter(jsonl_path)

    # Build initial manifest and write it before any threads spin up.
    started_mono, started_wall = _ts_pair()
    manifest = {
        "id": args.id,
        "schema": SCHEMA_VERSION,
        "iface": _coerce_iface(args.iface),
        "client_sha": None,
        "vm_res": dict(DEFAULT_VM_RES),
        "started_wall_ns": started_wall,
        "started_mono_ns": started_mono,
        "stopped_wall_ns": 0,
        "stopped_mono_ns": 0,
        "exit_reason": "clean",
        "files": {
            "pcap": pcap_path.name,
            "jsonl": jsonl_path.name,
        },
    }
    write_manifest(manifest_path, manifest)

    # Emit session_start.
    writer.emit({
        "kind": "session_start",
        "t_mono_ns": started_mono, "t_wall_ns": started_wall,
        "id": args.id,
        "iface": _coerce_iface(args.iface),
        "client_sha": None,
        "vm_res": dict(DEFAULT_VM_RES),
        "schema": SCHEMA_VERSION,
    })

    # State for shutdown bookkeeping.
    stop_evt = threading.Event()
    # Input gate: closed at session start. NetSniffer opens it on observing
    # an S2C frame on port 1818 with opcode 0xd1 (server-list response).
    # Until then, all input/viewport/focus emits are suppressed.
    gate_evt = threading.Event()
    exit_reason = {"value": "clean"}

    def _shutdown(signum, frame):
        exit_reason["value"] = "signal"
        stop_evt.set()

    try:
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
    except (ValueError, AttributeError):
        pass

    # ---- Spawn pcap-only mirror tshark process (raw all-VM TCP, safety net).
    pcap_proc: subprocess.Popen | None = None
    try:
        pcap_proc = subprocess.Popen(
            [args.tshark, "-i", str(args.iface), "-f", "tcp",
             "-w", str(pcap_path), "-q"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as e:
        m, w = _ts_pair()
        writer.emit({
            "kind": "net_error", "t_mono_ns": m, "t_wall_ns": w,
            "err": f"pcap tshark spawn failed: {e}",
        })
    # Give tshark a moment to attach so we don't miss the handshake.
    time.sleep(0.8)

    # ---- Net sniffer thread (parses game-port frames).
    sniffer = NetSniffer(str(args.iface), args.tshark, writer, stop_evt, gate_evt)
    sniffer.start()

    # ---- Input recorder (LL hooks). Lazy-fail if pynput/pywin32 missing.
    input_rec: InputRecorder | None = None
    try:
        input_rec = InputRecorder(writer, stop_evt, gate_evt)
        input_rec.prime_initial_viewport()
        input_rec.start()
    except Exception as e:
        m, w = _ts_pair()
        writer.emit({
            "kind": "input_error", "t_mono_ns": m, "t_wall_ns": w,
            "err": f"input recorder init: {type(e).__name__}: {e}",
        })
        input_rec = None

    # ---- Main wait loop.
    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
            # If the net sniffer thread dies on its own, treat as clean unless
            # we're already mid-signal handling.
            if not sniffer.is_alive():
                if exit_reason["value"] == "clean":
                    # Sniffer exited unexpectedly — record as crash.
                    exit_reason["value"] = "crash"
                stop_evt.set()
                break
    except KeyboardInterrupt:
        exit_reason["value"] = "signal"
        stop_evt.set()

    # ---- Shutdown.
    sniffer.terminate()
    if input_rec is not None:
        input_rec.stop_listeners()
    sniffer.join(timeout=5)

    # Stop the pcap mirror.
    if pcap_proc is not None:
        try:
            pcap_proc.terminate()
            try:
                pcap_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pcap_proc.kill()
        except Exception:
            pass

    # Emit session_stop and rewrite manifest.
    stopped_mono, stopped_wall = _ts_pair()
    writer.emit({
        "kind": "session_stop",
        "t_mono_ns": stopped_mono, "t_wall_ns": stopped_wall,
        "id": args.id,
        "reason": exit_reason["value"],
    })
    writer.close()

    manifest["stopped_wall_ns"] = stopped_wall
    manifest["stopped_mono_ns"] = stopped_mono
    manifest["exit_reason"] = exit_reason["value"]

    # Build recorded_spawn from sniffer state. Prefer self_spawn (richer);
    # merge map_id from map_load if both present. Omit if neither seen.
    spawn_self = sniffer.last_self_spawn
    spawn_map = sniffer.last_map_load
    if spawn_self is not None:
        rec = {
            "map_id": spawn_map["map_id"] if spawn_map is not None else None,
            "x": spawn_self["x"],
            "y": spawn_self["y"],
            "actor_id": spawn_self["actor_id"],
            "name": spawn_self["name"],
        }
        manifest["recorded_spawn"] = rec
    elif spawn_map is not None:
        manifest["recorded_spawn"] = {
            "map_id": spawn_map["map_id"],
            "x": spawn_map["x"],
            "y": spawn_map["y"],
        }

    write_manifest(manifest_path, manifest)

    return 0


def _coerce_iface(v):
    """Manifest stores iface as int when it parses cleanly, else string."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return str(v)


if __name__ == "__main__":
    sys.exit(main())

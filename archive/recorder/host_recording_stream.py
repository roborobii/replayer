#!/usr/bin/env python3
"""host_recording_stream.py - Phase 1 host-side unified recorder.

Runs on Windows host (RC@192.168.12.196). Two threads, single mutex-protected
JSONL writer.

  Thread A: form-poller. Heap-scans MemProcFS vmemd/*.vvmem for live Delphi
            instances of registered form classes (by VMT base), reads ONLY the
            registered offsets per onclick_catalog.json::form_watcher_fields,
            emits change events. Re-resolves heap addrs every ~2s.

  Thread B: net-sniffer. Spawns tshark on vEthernet (Default Switch),
            reassembles V2 frames [u16 LE len][u8 op][payload], emits per
            frame to JSONL.

Both threads append JSON-per-line under a mutex to:
  C:\\Users\\RC\\sessions\\recording_<id>.jsonl

CLI:
  python host_recording_stream.py --pid <pid> --id <str>
                                  [--poll-ms 100] [--iface 8]
                                  [--out-dir C:\\Users\\RC\\sessions]
                                  [--catalog onclick_catalog.json]
                                  [--forms forms_catalog.json]
                                  [--force]

READ-ONLY. No input synthesis. No writes to VM memory.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import struct
import subprocess
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

# v2_cipher is co-located via recording_session.sh scp manifest.
# NOTE: imported as `v2cipher` (no underscore) — the filename `v2_cipher.py`
# was getting persistently locked on the Windows host (Defender / scan hold).
# Renaming to `v2cipher.py` dodges the lock.
sys.path.insert(0, str(Path(__file__).parent))
try:
    import v2cipher as v2_cipher  # type: ignore
    _V2_CIPHER_OK = True
    _V2_CIPHER_ERR = None
except Exception as _e:  # pragma: no cover
    v2_cipher = None  # type: ignore
    _V2_CIPHER_OK = False
    _V2_CIPHER_ERR = f"{type(_e).__name__}: {_e}"

WORLD_PORT = 18123
MAX_CIPHER_BUF = 8192

# ---------------------------------------------------------------------------
# Config / constants

TSHARK         = r"C:\Program Files\Wireshark\tshark.exe"
DEFAULT_IFACE  = "8"  # vEthernet (Default Switch); shadow_stream.py-proven
GAME_PORTS     = {1818, 1819, 18123, 18124}
BPF            = "tcp and (port 1818 or port 1819 or port 18123 or port 18124)"

# ---------------------------------------------------------------------------
# Shared writer

class JsonlWriter:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.fh = open(path, "a", buffering=1, encoding="utf-8")

    def emit(self, obj: dict) -> None:
        line = json.dumps(obj, separators=(",", ":"))
        with self.lock:
            self.fh.write(line + "\n")

    def close(self) -> None:
        with self.lock:
            try:
                self.fh.flush()
                self.fh.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Form-poller

OFFSET_RE = re.compile(r"\+?0x([0-9a-fA-F]+)")

def _parse_offset(s: str) -> int:
    m = OFFSET_RE.search(s)
    if not m:
        raise ValueError(f"can't parse offset {s!r}")
    return int(m.group(1), 16)


def _width_of(type_str: str) -> int:
    t = type_str.lower()
    if "u32" in t or "ptr" in t:
        return 4
    if "u16" in t:
        return 2
    return 1  # default u8


def build_field_table(catalog_path: Path, forms_path: Path) -> list[dict]:
    """Return list of {form, vmt, instance_size, fields:[(offset,width,meaning)]}.

    vmt = forms_catalog[form].class_info_va + 0x2C
    fields come from onclick_catalog.form_watcher_fields[form].
    """
    cat = json.loads(catalog_path.read_text(encoding="utf-8"))
    forms_idx = json.loads(forms_path.read_text(encoding="utf-8"))
    fw = cat.get("form_watcher_fields", {})
    out = []
    for form, fields in fw.items():
        if form.startswith("_"):
            continue
        if form not in forms_idx:
            print(f"[forms] WARN: {form} not in forms_catalog; skipping", flush=True)
            continue
        info = forms_idx[form]
        ci_va = int(info["class_info_va"], 16) if isinstance(info["class_info_va"], str) else info["class_info_va"]
        vmt = ci_va + 0x2C
        inst_size = info.get("instance_size", 0x100)
        flds = []
        for f in fields:
            off_str = f.get("offset", "")
            # ranges like "+0x0C..+0x0F" -> single u32 read at low addr
            if ".." in off_str:
                low = _parse_offset(off_str.split("..")[0])
                width = 4
            else:
                low = _parse_offset(off_str)
                width = _width_of(f.get("type", "u8"))
            flds.append({"offset": low, "width": width, "meaning": f.get("meaning", "")})
        out.append({
            "form": form,
            "vmt": vmt,
            "instance_size": inst_size,
            "fields": flds,
        })
    return out


def scan_vmt_instances(pid: int, vmt: int) -> list[int]:
    """Heap-scan MemProcFS vmemd for u32-aligned occurrences of vmt. Returns
    list of *addresses where the u32 vmt was found* — i.e. candidate instance
    heads. Filtered to under 0x80000000."""
    vmemd = f"M:\\pid\\{pid}\\vmemd"
    try:
        files = os.listdir(vmemd)
    except OSError:
        return []
    skip = ("STACK", "TEB", ".dll", ".exe")
    needle = struct.pack("<I", vmt)
    hits: list[int] = []
    for fname in files:
        if not fname.endswith(".vvmem"):
            continue
        if any(s in fname for s in skip):
            continue
        m = re.match(r"0x([0-9a-fA-F]+)(?:-.*)?\.vvmem$", fname)
        if not m:
            continue
        base = int(m.group(1), 16)
        if base >= 0x80000000:
            continue
        path = os.path.join(vmemd, fname)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        idx = 0
        while True:
            idx = data.find(needle, idx)
            if idx < 0:
                break
            if idx % 4 == 0:
                addr = base + idx
                if addr < 0x80000000:
                    hits.append(addr)
            idx += 1
    return hits


def read_vmem(pid: int, addr: int, n: int) -> bytes | None:
    """Read n bytes from M:\\pid\\<pid>\\memory.vmem at virtual addr."""
    path = rf"M:\pid\{pid}\memory.vmem"
    try:
        with open(path, "rb") as f:
            f.seek(addr)
            return f.read(n)
    except OSError:
        return None


def is_live_instance(pid: int, addr: int, vmt: int) -> bool:
    """Confirm *(u32*)addr == vmt (filters scan false-positives)."""
    b = read_vmem(pid, addr, 4)
    if not b or len(b) < 4:
        return False
    return struct.unpack("<I", b)[0] == vmt


def has_nonempty_child_list(pid: int, addr: int) -> bool:
    """For TDnc widgets, FOwner@+0x08, child TList* @+0x28 (FCount @+0x08).
    Returns True if list ptr non-null and FCount > 0. Used to disambiguate
    multi-instance forms (e.g. TDncCharSelectShow has 2 instances; pick
    populated)."""
    b = read_vmem(pid, addr + 0x28, 4)
    if not b or len(b) < 4:
        return False
    list_ptr = struct.unpack("<I", b)[0]
    if list_ptr == 0 or list_ptr >= 0x80000000:
        return False
    cb = read_vmem(pid, list_ptr + 0x08, 4)
    if not cb or len(cb) < 4:
        return False
    return struct.unpack("<I", cb)[0] > 0


def read_field(pid: int, addr: int, off: int, width: int) -> int | None:
    b = read_vmem(pid, addr + off, width)
    if not b or len(b) < width:
        return None
    return int.from_bytes(b, "little")


def resolve_instances(pid: int, form: dict) -> list[int]:
    """Return live instance addrs for a form. If multiple, prefer those with
    non-empty child list at +0x28 (matches dom_click resolver)."""
    cands = scan_vmt_instances(pid, form["vmt"])
    live = [a for a in cands if is_live_instance(pid, a, form["vmt"])]
    if len(live) <= 1:
        return live
    populated = [a for a in live if has_nonempty_child_list(pid, a)]
    return populated if populated else live


class FormPoller(threading.Thread):
    def __init__(self, pid: int, fields_table: list[dict], writer: JsonlWriter,
                 poll_ms: int, stop_evt: threading.Event):
        super().__init__(name="form-poller", daemon=True)
        self.pid = pid
        self.table = fields_table
        self.writer = writer
        self.poll_s = poll_ms / 1000.0
        self.stop = stop_evt
        # per-form: addr -> {(off,width): last_value}
        self.state: dict[str, dict[int, dict[tuple, int]]] = {f["form"]: {} for f in fields_table}
        self.last_resolve = 0.0
        self.resolve_interval = 2.0

    def _resolve_all(self) -> None:
        for form in self.table:
            name = form["form"]
            cur_addrs = set(resolve_instances(self.pid, form))
            prev_addrs = set(self.state[name].keys())
            # destroyed instances
            for gone in prev_addrs - cur_addrs:
                self.writer.emit({
                    "t": time.time(), "kind": "form_destroy",
                    "form": name, "addr": f"0x{gone:08x}",
                })
                self.state[name].pop(gone, None)
            # newly-appeared instances
            for new in cur_addrs - prev_addrs:
                init_vals = {}
                for f in form["fields"]:
                    v = read_field(self.pid, new, f["offset"], f["width"])
                    if v is not None:
                        init_vals[(f["offset"], f["width"])] = v
                hex_init = " ".join(
                    f"+0x{o:x}={v:#x}" for (o, _w), v in init_vals.items()
                )
                self.writer.emit({
                    "t": time.time(), "kind": "form_appear",
                    "form": name, "addr": f"0x{new:08x}",
                    "instance_size": form["instance_size"],
                    "initial": hex_init,
                })
                self.state[name][new] = init_vals

    def run(self) -> None:
        self.writer.emit({"t": time.time(), "kind": "thread_start", "thread": "form-poller", "pid": self.pid})
        while not self.stop.is_set():
            now = time.time()
            if now - self.last_resolve >= self.resolve_interval:
                try:
                    self._resolve_all()
                except Exception as e:
                    self.writer.emit({"t": time.time(), "kind": "form_error", "err": f"resolve: {type(e).__name__}: {e}"})
                self.last_resolve = now

            for form in self.table:
                name = form["form"]
                for addr, last in list(self.state[name].items()):
                    for f in form["fields"]:
                        key = (f["offset"], f["width"])
                        v = read_field(self.pid, addr, f["offset"], f["width"])
                        if v is None:
                            continue
                        old = last.get(key)
                        if old is None:
                            last[key] = v
                            continue
                        if v != old:
                            self.writer.emit({
                                "t": time.time(), "kind": "form",
                                "form": name, "addr": f"0x{addr:08x}",
                                "off": f"0x{f['offset']:x}", "width": f["width"],
                                "old": old, "new": v,
                            })
                            last[key] = v
            self.stop.wait(self.poll_s)
        self.writer.emit({"t": time.time(), "kind": "thread_stop", "thread": "form-poller"})


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


class NetSniffer(threading.Thread):
    def __init__(self, iface: str, writer: JsonlWriter, stop_evt: threading.Event):
        super().__init__(name="net-sniffer", daemon=True)
        self.iface = iface
        self.writer = writer
        self.stop = stop_evt
        self.proc: subprocess.Popen | None = None

    def _spawn(self) -> subprocess.Popen:
        cmd = [TSHARK, "-i", self.iface, "-f", BPF, "-F", "pcap", "-w", "-", "-l"]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)

    def run(self) -> None:
        self.writer.emit({"t": time.time(), "kind": "thread_start", "thread": "net-sniffer", "iface": self.iface})
        try:
            self.proc = self._spawn()
        except FileNotFoundError as e:
            self.writer.emit({"t": time.time(), "kind": "net_error", "err": f"spawn: {e}"})
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
            self.writer.emit({"t": time.time(), "kind": "net_error",
                              "err": f"pcap init: {e}",
                              "stderr": err_tail.decode("utf-8", "replace")})
            return

        # Per-flow assembly
        streams: dict[tuple, bytearray] = defaultdict(bytearray)
        consumed: dict[tuple, int] = defaultdict(int)
        # Track whether we've warned about cipher buffer overflow per flow
        cipher_warned: dict[tuple, bool] = defaultdict(bool)

        if not _V2_CIPHER_OK:
            self.writer.emit({"t": time.time(), "kind": "net_error",
                              "err": f"v2_cipher import failed: {_V2_CIPHER_ERR}; world frames will be raw"})

        try:
            for ts, raw in pcap.packets():
                if self.stop.is_set():
                    break
                parsed = parse_eth_ip_tcp(raw, pcap.linktype)
                if parsed is None:
                    continue
                src_ip, dst_ip, sport, dport, payload = parsed
                if dport in GAME_PORTS:
                    port, direction = dport, "C2S"
                elif sport in GAME_PORTS:
                    port, direction = sport, "S2C"
                else:
                    continue

                key = (src_ip, sport, dst_ip, dport)
                if payload:
                    streams[key].extend(payload)

                buf = bytes(streams[key])
                start = consumed[key]
                seg = buf[start:]

                if port == WORLD_PORT and _V2_CIPHER_OK:
                    # World traffic is V2-encrypted post-handshake. Use
                    # v2_cipher.split_stream() to slice frames out of the
                    # ciphertext, then decrypt_frame() to get plaintext.
                    # Cipher is stateless across frames (per-frame seed/CRC).
                    i = 0
                    while i + 4 <= len(seg):
                        plain_len = v2_cipher.extract_length(seg[i:i + 4])
                        if plain_len < 6:
                            # Bad/short frame head — can't be a valid v2 frame.
                            # Likely mid-stream junk or partial. Wait for more.
                            break
                        size = plain_len + 2
                        if i + size > len(seg):
                            break
                        cipher_frame = bytes(seg[i:i + size])
                        try:
                            plain = v2_cipher.decrypt_frame(cipher_frame, plaintext_len_known=plain_len)
                        except Exception as e:
                            self.writer.emit({"t": ts, "kind": "net_error",
                                              "err": f"v2 decrypt: {type(e).__name__}: {e}",
                                              "port": port, "dir": direction,
                                              "frame_hex": cipher_frame[:32].hex()})
                            i += size
                            continue
                        opcode = plain[7] if len(plain) >= 8 else None
                        seq = plain[7] if len(plain) >= 8 else None  # frame[7] is seq counter / seed byte
                        # body[0] is the real semantic opcode per task spec
                        body_off = 7
                        body_end = 7 + (plain_len - 5)
                        body = plain[body_off:body_end]
                        real_op = body[0] if body else None
                        self.writer.emit({
                            "t": ts, "kind": "net", "dir": direction, "port": port,
                            "opcode": real_op, "len": plain_len,
                            "payload": plain.hex(),
                            "cipher": "v2_world",
                            "seq": seq,
                        })
                        i += size
                    consumed[key] += i
                    # Resilience: if the cipher buffer grows unboundedly,
                    # something's desynced. Warn + reset.
                    unconsumed = len(seg) - i
                    if unconsumed > MAX_CIPHER_BUF and not cipher_warned[key]:
                        self.writer.emit({"t": ts, "kind": "net_error",
                                          "err": f"v2 cipher buffer overflow ({unconsumed}B unconsumed); resetting flow",
                                          "port": port, "dir": direction})
                        cipher_warned[key] = True
                        consumed[key] = len(buf)  # drop unconsumed; resync on next valid frame
                else:
                    # V2 plaintext framing: [u16 LE len][u8 op][payload(len-1 bytes)]
                    # 'len' counts bytes from opcode onward. Frame total = len + 2.
                    i = 0
                    while i + 3 <= len(seg):
                        plain_len = seg[i] | (seg[i + 1] << 8)
                        size = plain_len + 2
                        if plain_len < 1 or i + size > len(seg):
                            break
                        op = seg[i + 2]
                        body_hex = bytes(seg[i:i + size]).hex()
                        self.writer.emit({
                            "t": ts, "kind": "net", "dir": direction, "port": port,
                            "opcode": op, "len": size, "payload": body_hex,
                        })
                        i += size
                    consumed[key] += i
        except Exception as e:
            self.writer.emit({"t": time.time(), "kind": "net_error",
                              "err": f"loop: {type(e).__name__}: {e}"})
        finally:
            try:
                if self.proc:
                    self.proc.terminate()
            except Exception:
                pass
            self.writer.emit({"t": time.time(), "kind": "thread_stop", "thread": "net-sniffer"})


# ---------------------------------------------------------------------------
# Main

def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 1 host-side recorder")
    ap.add_argument("--pid", type=int, required=True, help="DXRender PID inside the guest")
    ap.add_argument("--id", required=True, help="recording id (filename suffix)")
    ap.add_argument("--poll-ms", type=int, default=100)
    ap.add_argument("--iface", default=DEFAULT_IFACE)
    ap.add_argument("--out-dir", default=r"C:\Users\RC\sessions")
    ap.add_argument("--catalog", default=r"C:\Users\RC\recorder\onclick_catalog.json")
    ap.add_argument("--forms", default=r"C:\Users\RC\recorder\forms_catalog.json")
    ap.add_argument("--force", action="store_true", help="overwrite existing recording")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"recording_{args.id}.jsonl"
    if out_path.exists() and not args.force:
        sys.exit(f"FATAL: {out_path} exists; pass --force to overwrite")
    if out_path.exists():
        out_path.unlink()

    table = build_field_table(Path(args.catalog), Path(args.forms))
    writer = JsonlWriter(out_path)
    writer.emit({
        "t": time.time(), "kind": "session_start",
        "id": args.id, "pid": args.pid, "iface": args.iface,
        "poll_ms": args.poll_ms, "forms": [f["form"] for f in table],
    })

    stop_evt = threading.Event()
    poller = FormPoller(args.pid, table, writer, args.poll_ms, stop_evt)
    sniffer = NetSniffer(args.iface, writer, stop_evt)
    poller.start()
    sniffer.start()

    def _shutdown(signum, frame):
        stop_evt.set()
    try:
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
    except (ValueError, AttributeError):
        pass

    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_evt.set()

    poller.join(timeout=5)
    sniffer.join(timeout=5)
    writer.emit({"t": time.time(), "kind": "session_stop", "id": args.id})
    writer.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""record_session.py — Windows host-side click-driven memory recorder.

Snapshots the VM's DXRender process memory on every mouse click the user
makes anywhere on the Windows host (including clicks forwarded into the
guest's vmconnect window). Read-only on the guest — uses MemProcFS at M:\\.

Trigger model:
  - Initial snapshot fires immediately on start (so we have a baseline
    *before* the first click — run this script while at server-select).
  - Every left/right/middle mouse-button DOWN event triggers a new snapshot.
  - Optional: also snapshots on Enter/Space if --keys is passed.

Each snapshot dumps:
  - All heap VAD regions (M:\\pid\\<pid>\\vmemd\\*.vvmem, minus stack/TEB/DLL/EXE),
    gzip-compressed (level 1 — fast).
  - structured.json: parsed state of the watched Delphi forms + globals
    (same fields as Mac-side vm_form_emitter, useful as a quick index).

Output: C:\\Users\\RC\\sessions\\recordings\\<label>\\snap_NNNN\\

Usage (interactive PowerShell on host, NOT over SSH):
    python C:\\Users\\RC\\sessions\\record_session.py <label>
    (or via Record-Session.ps1)

Stealth: no in-guest agent, no OpenProcess/RPM, no network egress. Just
reading M:\\ and writing local files. Live server has no signal.
"""
import ctypes
from ctypes import wintypes
import gzip
import json
import os
import queue
import re
import shutil
import struct
import sys
import threading
import time
from pathlib import Path


# ---------------------------------------------------------------------------
# Watch table — used to build structured.json index per snapshot.
# ---------------------------------------------------------------------------
FORMS = {
    "TDncServerSelectForm":  (0x001524B4, 0x180),
    "TDncCharSelectShow":    (0x000EE6C0, 0x180),
    "TDncCharCreateForm":    (0x00149A00, 0x180),
    "TDncRootWidget":        (0x00154D00, 0x80),
    "TDncGameMainMenu":      (0x000F3AE8, 0x100),
    "TMainForm":             (0x0011A470, 0x100),
}
GLOBALS = [
    ("PTR_GLOBAL_ACTIVE_CHAR", 0x001C1678, 0x40),
    ("PTR_WORLD_CONNMGR",     0x001C0430, 0x100),
    ("PTR_ORCH_WIDGET",       0x001C0D64, 0x100),
]
FIELD_WATCHES = {
    "TDncCharSelectShow":   [(0x7D, 1, "char_slot"), (0x18, 1, "cs_active"),
                             (0x7C, 1, "cs_state7c")],
    "TDncServerSelectForm": [(0x39, 1, "row_dirty"), (0x18, 1, "form_active"),
                             (0x1A, 1, "form_advanced"), (0x0C, 4, "last_row_ptr")],
    "TDncRootWidget":       [(0x0C, 4, "current_widget_ptr"), (0x50, 1, "rw_flag50"),
                             (0x52, 1, "rw_flag52")],
}


# ---------------------------------------------------------------------------
# MemProcFS readers
# ---------------------------------------------------------------------------
def find_pid() -> int:
    base = "M:\\name"
    if not os.path.isdir(base):
        raise RuntimeError(f"{base} not mounted — start MemProcFS first.")
    for entry in os.listdir(base):
        if entry.lower().startswith("dxrender.exe"):
            m = re.search(r"-(\d+)$", entry)
            if m:
                return int(m.group(1))
    raise RuntimeError("DXRender not found in M:\\name")


_mem_handle = None  # opened lazily on M:\pid\<pid>\memory.vmem

def read_bytes(pid: int, addr: int, n: int) -> bytes:
    global _mem_handle
    if _mem_handle is None:
        _mem_handle = open(f"M:\\pid\\{pid}\\memory.vmem", "rb")
    try:
        _mem_handle.seek(addr)
        data = _mem_handle.read(n)
    except OSError:
        data = b""
    return data if data else b"\x00" * n


# Large VADs (> MAX_VAD_BYTES) are almost always asset/zlib/decode buffers,
# not Delphi state. Skipping them cuts initial snap time ~5-10x.
MAX_VAD_BYTES = 16 * 1024 * 1024


def list_heap_vads(pid: int, max_bytes: int = MAX_VAD_BYTES) -> list[tuple[str, str, int, int]]:
    """Return [(filename, full_path, base_addr_or_-1, size)] for heap VADs to dump."""
    vmemd = f"M:\\pid\\{pid}\\vmemd"
    if not os.path.isdir(vmemd):
        return []
    skip = ("STACK", "TEB", ".dll", ".exe")
    out = []
    for fname in os.listdir(vmemd):
        if not fname.endswith(".vvmem"):
            continue
        if any(s in fname for s in skip):
            continue
        path = os.path.join(vmemd, fname)
        try:
            sz = os.path.getsize(path)
        except OSError:
            continue
        if sz > max_bytes:
            continue
        m = re.match(r"0x([0-9a-fA-F]+)(?:-.*)?\.vvmem$", fname)
        base = int(m.group(1), 16) if m else -1
        out.append((fname, path, base, sz))
    return out


def find_instances(pid: int, vmt_base: int) -> list[int]:
    addrs: list[int] = []
    target = struct.pack("<I", vmt_base)
    for fname, path, base, _sz in list_heap_vads(pid):
        if base < 0:
            continue
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            continue
        idx = 0
        while True:
            idx = data.find(target, idx)
            if idx < 0:
                break
            if idx % 4 == 0:
                a = base + idx
                if a < 0x80000000:
                    addrs.append(a)
            idx += 1
    return addrs


# Cache of (form_name → [addrs]) used only by structured.json builder.
_addr_cache: dict[str, list[int]] = {}


def get_form_instances(pid: int, name: str, vmt: int) -> list[int]:
    cached = _addr_cache.get(name)
    if cached:
        ok = []
        for a in cached:
            head = read_bytes(pid, a, 4)
            if len(head) == 4 and struct.unpack("<I", head)[0] == vmt:
                ok.append(a)
        if ok:
            return ok
    fresh = find_instances(pid, vmt)
    valid = []
    for a in fresh:
        head = read_bytes(pid, a, 4)
        if len(head) == 4 and struct.unpack("<I", head)[0] == vmt:
            valid.append(a)
    _addr_cache[name] = valid
    return valid


def capture_structured(pid: int) -> dict:
    out = {"forms": {}, "globals": {}}
    for name, (vmt, _) in FORMS.items():
        addrs = get_form_instances(pid, name, vmt)
        entry = {"instance_count": len(addrs), "addrs": addrs, "fields": {}}
        if addrs:
            target = addrs[-1]
            for off, length, fname in FIELD_WATCHES.get(name, []):
                data = read_bytes(pid, target + off, length)
                entry["fields"][fname] = int.from_bytes(data, "little")
        out["forms"][name] = entry
    for label, addr, dlen in GLOBALS:
        ptr_bytes = read_bytes(pid, addr, 4)
        ptr = int.from_bytes(ptr_bytes, "little") if len(ptr_bytes) == 4 else 0
        entry = {"addr": addr, "ptr_value": ptr}
        if dlen > 0 and ptr and ptr < 0x80000000:
            entry["deref_hex"] = read_bytes(pid, ptr, dlen).hex()
        out["globals"][label] = entry
    return out


# ---------------------------------------------------------------------------
# Snapshot writer — full heap dump (gzipped) + structured index.
# ---------------------------------------------------------------------------
def write_snapshot(out_dir: Path, seq: int, pid: int, trigger: dict) -> dict:
    snap_dir = out_dir / f"snap_{seq:04d}"
    snap_dir.mkdir(parents=True, exist_ok=True)

    started = time.time()
    files_written = 0
    bytes_in = 0
    bytes_out = 0
    vads = list_heap_vads(pid)
    for fname, src, _base, sz in vads:
        bytes_in += sz
        dst = snap_dir / (fname + ".gz")
        try:
            with open(src, "rb") as f, gzip.open(dst, "wb", compresslevel=1) as g:
                shutil.copyfileobj(f, g, 1 << 20)
            bytes_out += dst.stat().st_size
            files_written += 1
        except OSError:
            try: dst.unlink()
            except OSError: pass

    try:
        structured = capture_structured(pid)
    except Exception as e:
        structured = {"error": repr(e)}
    (snap_dir / "structured.json").write_text(json.dumps(structured, indent=2))

    elapsed = time.time() - started
    info = {
        "seq": seq,
        "ts_ms": int(time.time() * 1000),
        "trigger": trigger,
        "vad_files": files_written,
        "raw_bytes": bytes_in,
        "gz_bytes": bytes_out,
        "elapsed_s": round(elapsed, 2),
    }
    (snap_dir / "info.json").write_text(json.dumps(info, indent=2))
    return info


# ---------------------------------------------------------------------------
# Win32 low-level mouse hook → fires snap requests on every click.
# ---------------------------------------------------------------------------
WH_MOUSE_LL = 14
WM_LBUTTONUP = 0x0202
WM_RBUTTONUP = 0x0205
WM_MBUTTONUP = 0x0208
CLICK_UPS = {WM_LBUTTONUP: "L", WM_RBUTTONUP: "R", WM_MBUTTONUP: "M"}

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104

LRESULT = ctypes.c_long
LowLevelHookProc = ctypes.WINFUNCTYPE(
    LRESULT, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM
)

user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

# Declare argtypes/restype explicitly so 64-bit Python doesn't truncate
# HMODULE/HHOOK pointers — that's what was causing SetWindowsHookEx err=126.
kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
kernel32.GetModuleHandleW.restype  = wintypes.HMODULE
kernel32.GetCurrentThreadId.restype = wintypes.DWORD
user32.SetWindowsHookExW.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                     wintypes.HMODULE, wintypes.DWORD]
user32.SetWindowsHookExW.restype  = wintypes.HHOOK
user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]
user32.UnhookWindowsHookEx.restype  = wintypes.BOOL
user32.CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int,
                                  wintypes.WPARAM, wintypes.LPARAM]
user32.CallNextHookEx.restype  = LRESULT
user32.PeekMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND,
                                ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
user32.PeekMessageW.restype  = wintypes.BOOL
user32.PostThreadMessageW.argtypes = [wintypes.DWORD, ctypes.c_uint,
                                      wintypes.WPARAM, wintypes.LPARAM]
user32.PostThreadMessageW.restype  = wintypes.BOOL


class HookThread(threading.Thread):
    def __init__(self, on_click, on_key=None, also_keys=False):
        super().__init__(daemon=True, name="HookThread")
        self.on_click = on_click
        self.on_key = on_key
        self.also_keys = also_keys
        self._stop = threading.Event()
        self._thread_id = None

    def stop(self):
        self._stop.set()
        # Post a quit message to break PeekMessage loop
        if self._thread_id is not None:
            try:
                user32.PostThreadMessageW(self._thread_id, 0x0012, 0, 0)  # WM_QUIT
            except Exception:
                pass

    def run(self):
        self._thread_id = kernel32.GetCurrentThreadId()

        def mouse_proc(nCode, wParam, lParam):
            if nCode == 0 and wParam in CLICK_UPS:
                try:
                    self.on_click(CLICK_UPS[wParam], int(time.time() * 1000))
                except Exception as e:
                    sys.stderr.write(f"[hook] on_click error: {e}\n")
            return user32.CallNextHookEx(0, nCode, wParam, lParam)

        def key_proc(nCode, wParam, lParam):
            if self.also_keys and nCode == 0 and wParam in (WM_KEYDOWN, WM_SYSKEYDOWN):
                # Read VK code from KBDLLHOOKSTRUCT (first DWORD)
                vk = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong))[0]
                if self.on_key:
                    try:
                        self.on_key(int(vk), int(time.time() * 1000))
                    except Exception as e:
                        sys.stderr.write(f"[hook] on_key error: {e}\n")
            return user32.CallNextHookEx(0, nCode, wParam, lParam)

        m_cb = LowLevelHookProc(mouse_proc)
        k_cb = LowLevelHookProc(key_proc)
        hmod = kernel32.GetModuleHandleW(None)
        m_h = user32.SetWindowsHookExW(WH_MOUSE_LL, m_cb, hmod, 0)
        if not m_h:
            sys.stderr.write(f"[hook] SetWindowsHookEx(MOUSE_LL) failed err={kernel32.GetLastError()}\n")
            return
        k_h = None
        if self.also_keys:
            k_h = user32.SetWindowsHookExW(WH_KEYBOARD_LL, k_cb, hmod, 0)

        msg = wintypes.MSG()
        # Pump messages until stop requested. PeekMessage so we can poll _stop.
        while not self._stop.is_set():
            r = user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1)  # PM_REMOVE
            if r:
                if msg.message == 0x0012:  # WM_QUIT
                    break
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            else:
                time.sleep(0.005)

        try: user32.UnhookWindowsHookEx(m_h)
        except Exception: pass
        if k_h:
            try: user32.UnhookWindowsHookEx(k_h)
            except Exception: pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    if len(sys.argv) < 2:
        print("usage: record_session.py <session_label> [--delay-ms N] [--keys]")
        sys.exit(2)
    label = sys.argv[1]
    also_keys = "--keys" in sys.argv
    delay_ms = 500
    for i, a in enumerate(sys.argv[2:], start=2):
        if a == "--delay-ms" and i + 1 < len(sys.argv):
            delay_ms = int(sys.argv[i + 1])

    base = os.environ.get("RECORD_OUT_BASE", "C:\\Users\\RC\\sessions\\recordings")
    out_dir = Path(base) / label
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[recorder] output: {out_dir}")

    pid = find_pid()
    print(f"[recorder] DXRender pid={pid}")

    meta = {
        "label": label,
        "pid": pid,
        "started_ms": int(time.time() * 1000),
        "mode": "click-driven (full heap dump per click)",
        "forms": {n: {"vmt": v, "size": s} for n, (v, s) in FORMS.items()},
        "globals": [{"name": n, "addr": a, "deref_len": dl} for n, a, dl in GLOBALS],
    }
    (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))

    events_path = out_dir / "events.jsonl"
    events_f = open(events_path, "a", buffering=1)

    snap_q: "queue.Queue[dict]" = queue.Queue()
    seq = [0]
    seq_lock = threading.Lock()

    def take_snap(trigger: dict):
        with seq_lock:
            n = seq[0]
            seq[0] += 1
        info = write_snapshot(out_dir, n, pid, trigger)
        events_f.write(json.dumps({"seq": n, "trigger": trigger, "info": info}) + "\n")
        kind = trigger.get("kind", "?")
        print(f"[recorder] snap {n:04d} ({kind}) — {info['gz_bytes']/1e6:.1f}MB gz "
              f"({info['vad_files']} files) in {info['elapsed_s']}s")

    # 1) Initial baseline NOW.
    take_snap({"kind": "initial", "ts_ms": int(time.time() * 1000)})

    # 2) Hook handlers — push onto queue (non-blocking; worker drains).
    pending = [0]
    def on_click(button: str, ts_ms: int):
        pending[0] += 1
        print(f"[recorder] click-up ({button}) queued (depth={pending[0]})")
        snap_q.put({"kind": "click", "button": button, "ts_ms": ts_ms})

    def on_key(vk: int, ts_ms: int):
        snap_q.put({"kind": "key", "vk": vk, "ts_ms": ts_ms})

    hook = HookThread(on_click=on_click, on_key=on_key, also_keys=also_keys)
    hook.start()

    # 3) Worker drains queue; one snapshot per request.
    stop_workers = threading.Event()
    def worker():
        while not stop_workers.is_set():
            try:
                req = snap_q.get(timeout=0.2)
            except queue.Empty:
                continue
            # Settling delay — let click effects propagate before reading memory.
            if req.get("kind") == "click" and delay_ms > 0:
                time.sleep(delay_ms / 1000.0)
                req["delay_ms"] = delay_ms
            try:
                take_snap(req)
            except Exception as e:
                sys.stderr.write(f"[recorder] snap error: {e}\n")
            finally:
                if req.get("kind") == "click":
                    pending[0] = max(0, pending[0] - 1)
    wt = threading.Thread(target=worker, daemon=True, name="SnapWorker")
    wt.start()

    print(f"[recorder] running. Click anywhere on host (incl. into VM window).")
    print(f"[recorder] trigger=button-UP, settle delay={delay_ms}ms.")
    print(f"[recorder] {'Keys also tracked. ' if also_keys else ''}Ctrl+C to stop.")
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[recorder] stopping…")
    finally:
        hook.stop()
        # Drain remaining queued requests (best-effort, with timeout).
        deadline = time.time() + 3
        while time.time() < deadline and not snap_q.empty():
            time.sleep(0.1)
        stop_workers.set()
        wt.join(2)
        events_f.close()
        meta["ended_ms"] = int(time.time() * 1000)
        meta["snapshot_count"] = seq[0]
        (out_dir / "meta.json").write_text(json.dumps(meta, indent=2))
        print(f"[recorder] done. {seq[0]} snapshots in {out_dir}")
        print(f"[recorder] pull to Mac:")
        print(f"  scp -r RC@192.168.12.196:{out_dir.as_posix()} recordings/")


if __name__ == "__main__":
    main()

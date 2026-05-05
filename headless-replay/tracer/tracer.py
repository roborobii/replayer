"""
Unicorn-based code-path tracer for DXRender.exe.

Loads the 32-bit PE into emulated memory at preferred image base (0x10000),
sets up minimal Win32 environment (TEB, FS segment, stack), stubs imported
APIs as no-ops returning sensible defaults, and executes a target function
identified by VA. Records every basic block executed.

Usage:
  python tracer.py --pe /game/DXRender.exe --fn-va 0x000EF6D8 \
    --self-ptr 0x00206784 --flags 0x08 --xy-packed 0x00640032 --btn 1 \
    --out /traces/mouse_handler_trace.jsonl

Calling convention for the mouse handler (Delphi register fastcall):
  EAX = Self, EDX = flags, ECX = xy_packed, [esp+4] = btn, callee `ret 4`.
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time
import traceback
from typing import Any

import pefile
from unicorn import (
    Uc,
    UcError,
    UC_ARCH_X86,
    UC_MODE_32,
    UC_PROT_ALL,
    UC_PROT_READ,
    UC_PROT_WRITE,
    UC_PROT_EXEC,
    UC_HOOK_BLOCK,
    UC_HOOK_CODE,
    UC_HOOK_MEM_INVALID,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
)
from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,
    UC_X86_REG_EBP,
    UC_X86_REG_ESP,
    UC_X86_REG_EIP,
    UC_X86_REG_EFLAGS,
    UC_X86_REG_FS,
    UC_X86_REG_GDTR,
)


# ---------------------------------------------------------------------------
# Memory layout constants.

PAGE = 0x1000
# DXRender.exe loads at 0x10000 with SizeOfImage 0x23E000 — extends to 0x24E000.
# Stack must sit above that to avoid mem_map overlap (UC_ERR_MAP).
STACK_BASE = 0x40000000          # 1 GiB — well above PE image
STACK_SIZE = 0x00100000          # 1 MiB
TEB_ADDR = 0x7FFD0000            # fake TEB
TEB_SIZE = PAGE
PEB_ADDR = 0x7FFD1000
PEB_SIZE = PAGE
STUB_BASE = 0x7B000000           # synthetic kernel stubs (one per import)
STUB_SIZE = 0x00100000           # 1 MiB of stubs (256k stubs at 4 bytes each)
GDT_ADDR = 0x7B200000            # 1 page for GDT
GDT_SIZE = PAGE
HEAP_BASE = 0x08000000           # synthetic heap for any allocs we fake
HEAP_SIZE = 0x00400000

FAKE_RET_ADDR = 0xCAFEFEED       # sentinel return address; tracer stops here
FAKE_HANDLE = 0xCAFEBABE
TICK_START = 0x12340000


# ---------------------------------------------------------------------------
# Unicorn permission helper.

def _prot_from_section(section) -> int:
    p = 0
    ch = section.Characteristics
    # PE characteristic flags
    IMAGE_SCN_MEM_READ    = 0x40000000
    IMAGE_SCN_MEM_WRITE   = 0x80000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    if ch & IMAGE_SCN_MEM_READ:
        p |= UC_PROT_READ
    if ch & IMAGE_SCN_MEM_WRITE:
        p |= UC_PROT_WRITE
    if ch & IMAGE_SCN_MEM_EXECUTE:
        p |= UC_PROT_EXEC
    if p == 0:
        p = UC_PROT_READ
    return p


def _align_down(x: int, a: int = PAGE) -> int:
    return x & ~(a - 1)


def _align_up(x: int, a: int = PAGE) -> int:
    return (x + a - 1) & ~(a - 1)


# ---------------------------------------------------------------------------
# GDT / FS segment setup.
#
# Unicorn x86 32-bit doesn't honor `mov eax, fs:[X]` purely from
# UC_X86_REG_FS — you also need a GDT entry whose base = TEB_ADDR. We write
# a single GDT entry at index 1 and load FS = (1<<3) | 0 (RPL=0).

def _make_gdt_entry(base: int, limit: int, access: int, flags: int) -> bytes:
    # Standard x86 GDT descriptor packing (8 bytes).
    if limit > 0xFFFFF:
        # Granularity bit: limit shifted by 12.
        limit >>= 12
        flags |= 0x8  # G bit
    desc = 0
    desc |= (limit & 0xFFFF)
    desc |= (base & 0xFFFFFF) << 16
    desc |= (access & 0xFF)   << 40
    desc |= ((limit >> 16) & 0xF) << 48
    desc |= (flags & 0xF)     << 52
    desc |= ((base >> 24) & 0xFF) << 56
    return desc.to_bytes(8, "little")


def setup_gdt(uc: Uc) -> None:
    uc.mem_map(GDT_ADDR, GDT_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    null_desc = b"\x00" * 8
    # Access byte: present(0x80) | ring0(0x00) | non-system(0x10) | RW(0x02)
    # = 0x92 for data segment.
    data_desc = _make_gdt_entry(base=TEB_ADDR, limit=0xFFFFFFFF, access=0x92, flags=0xC)
    code_desc = _make_gdt_entry(base=0, limit=0xFFFFFFFF, access=0x9A, flags=0xC)
    flat_data = _make_gdt_entry(base=0, limit=0xFFFFFFFF, access=0x92, flags=0xC)
    # entries: 0 null, 1 code(flat), 2 data(flat), 3 fs(base=TEB)
    gdt = null_desc + code_desc + flat_data + data_desc
    uc.mem_write(GDT_ADDR, gdt)
    # GDTR: limit (16) | base (32). reg_write for GDTR expects a tuple.
    try:
        uc.reg_write(UC_X86_REG_GDTR, (0, GDT_ADDR, len(gdt) - 1, 0))
        # FS selector = index 3, TI=0, RPL=3 -> (3<<3) | 3 = 0x1B
        uc.reg_write(UC_X86_REG_FS, (3 << 3) | 3)
    except Exception:
        # Unicorn 2.x sometimes rejects segment-selector writes with
        # UC_ERR_EXCEPTION. Fall back: skip proper segmentation, rely on
        # the FS-fetch memory hook installed elsewhere (or accept that
        # any code reading fs:[0x18] will get whatever happens to be
        # there). For functions that don't need TEB this is fine.
        pass


# ---------------------------------------------------------------------------
# TEB / PEB.

def setup_teb(uc: Uc) -> None:
    uc.mem_map(TEB_ADDR, TEB_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    uc.mem_map(PEB_ADDR, PEB_SIZE, UC_PROT_READ | UC_PROT_WRITE)
    # TEB.NtTib.Self is at offset 0x18 -> points to TEB.
    uc.mem_write(TEB_ADDR + 0x18, struct.pack("<I", TEB_ADDR))
    # TEB.NtTib.StackBase = offset 0x04, StackLimit = 0x08.
    uc.mem_write(TEB_ADDR + 0x04, struct.pack("<I", STACK_BASE + STACK_SIZE))
    uc.mem_write(TEB_ADDR + 0x08, struct.pack("<I", STACK_BASE))
    # TEB.ProcessEnvironmentBlock = offset 0x30.
    uc.mem_write(TEB_ADDR + 0x30, struct.pack("<I", PEB_ADDR))
    # TEB.LastErrorValue = offset 0x34.
    uc.mem_write(TEB_ADDR + 0x34, struct.pack("<I", 0))


# ---------------------------------------------------------------------------
# PE loading.

class LoadedPE:
    def __init__(self, path: str):
        self.pe = pefile.PE(path, fast_load=False)
        self.image_base = self.pe.OPTIONAL_HEADER.ImageBase
        self.image_size = self.pe.OPTIONAL_HEADER.SizeOfImage
        self.entry_va = self.image_base + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint

    def map_into(self, uc: Uc) -> None:
        # Map the entire image as RWX first (simpler — we don't enforce W^X
        # since some Delphi sections combine code + data oddly).
        base = self.image_base
        size = _align_up(self.image_size)
        uc.mem_map(base, size, UC_PROT_ALL)
        # Headers (first SizeOfHeaders bytes).
        headers = self.pe.__data__[: self.pe.OPTIONAL_HEADER.SizeOfHeaders]
        uc.mem_write(base, headers)
        # Each section's raw data -> base + VirtualAddress.
        for s in self.pe.sections:
            data = s.get_data()
            uc.mem_write(base + s.VirtualAddress, data)


# ---------------------------------------------------------------------------
# Import / IAT stubbing.

# Per-API behaviors. Each entry: (argc_for_stdcall_cleanup, handler_callable_or_None).
# argc is the number of stack slots to pop on return (stdcall). For cdecl APIs
# the caller cleans up so argc=0. We default to 0 (cdecl) for unknown APIs.
#
# Most Win32 APIs are stdcall; cdecl is the exception (msvcrt.* and a few).

# Stdcall arg counts for the small subset we know about. Anything not listed
# is treated as cdecl (argc=0) by default — that's wrong for most Win32 APIs
# but the worst case is stack imbalance which we'll detect via the trace.
STDCALL_ARGS: dict[str, int] = {
    "GetTickCount": 0,
    "GetCurrentThreadId": 0,
    "GetCurrentProcessId": 0,
    "GetLastError": 0,
    "SetLastError": 1,
    "GetVersion": 0,
    "GetCommandLineA": 0,
    "GetCommandLineW": 0,
    "GetModuleHandleA": 1,
    "GetModuleHandleW": 1,
    "GetProcAddress": 2,
    "LoadLibraryA": 1,
    "LoadLibraryW": 1,
    "FreeLibrary": 1,
    "ExitProcess": 1,
    "GetStartupInfoA": 1,
    "GetStartupInfoW": 1,
    "InitializeCriticalSection": 1,
    "EnterCriticalSection": 1,
    "LeaveCriticalSection": 1,
    "DeleteCriticalSection": 1,
    "TlsAlloc": 0,
    "TlsGetValue": 1,
    "TlsSetValue": 2,
    "TlsFree": 1,
    "VirtualAlloc": 4,
    "VirtualFree": 3,
    "VirtualProtect": 4,
    "VirtualQuery": 3,
    "HeapCreate": 3,
    "HeapAlloc": 3,
    "HeapFree": 3,
    "HeapDestroy": 1,
    "HeapReAlloc": 4,
    "GetProcessHeap": 0,
    "CreateFileA": 7,
    "CreateFileW": 7,
    "CloseHandle": 1,
    "ReadFile": 5,
    "WriteFile": 5,
    "GetMessageA": 4,
    "GetMessageW": 4,
    "PeekMessageA": 5,
    "PeekMessageW": 5,
    "PostMessageA": 4,
    "PostMessageW": 4,
    "SendMessageA": 4,
    "SendMessageW": 4,
    "DispatchMessageA": 1,
    "DispatchMessageW": 1,
    "TranslateMessage": 1,
    "QueryPerformanceCounter": 1,
    "QueryPerformanceFrequency": 1,
}


class ImportStubber:
    """Stub IAT entries to point at synthetic addresses; hook those addresses
    to fake out the API and `ret <argc*4>`."""

    def __init__(self, uc: Uc, pe: pefile.PE, image_base: int, log):
        self.uc = uc
        self.pe = pe
        self.image_base = image_base
        self.log = log
        self.next_stub = STUB_BASE
        # stub_addr -> (dll, fn_name)
        self.stubs: dict[int, tuple[str, str]] = {}
        self._tick = TICK_START
        self._heap_ptr = HEAP_BASE
        # Map the stub region as executable. We never actually execute real
        # bytes there — UC_HOOK_CODE on each stub_addr handles the call.
        uc.mem_map(STUB_BASE, STUB_SIZE, UC_PROT_READ | UC_PROT_EXEC)
        # Pre-fill with INT3 (0xCC) so any unhandled stub crashes loudly.
        uc.mem_write(STUB_BASE, b"\xCC" * STUB_SIZE)

    def install(self) -> None:
        if not hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            self.log({"event": "no_imports"})
            return
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("ascii", errors="replace")
            for imp in entry.imports:
                fn = imp.name.decode("ascii", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                stub_addr = self.next_stub
                self.next_stub += 4
                self.stubs[stub_addr] = (dll, fn)
                # Patch IAT entry (imp.address is RVA + image_base).
                iat_addr = imp.address  # already absolute.
                self.uc.mem_write(iat_addr, struct.pack("<I", stub_addr))

    def hook_code(self, uc: Uc, address: int, size: int, user_data: Any) -> None:
        # Called only when execution lands inside [STUB_BASE, STUB_BASE+STUB_SIZE).
        if not (STUB_BASE <= address < STUB_BASE + STUB_SIZE):
            return
        info = self.stubs.get(address)
        if info is None:
            self.log({"event": "stub_unknown", "addr": hex(address)})
            uc.emu_stop()
            return
        dll, fn = info
        self._dispatch(uc, dll, fn)

    def _dispatch(self, uc: Uc, dll: str, fn: str) -> None:
        # Read return address & args from current esp.
        esp = uc.reg_read(UC_X86_REG_ESP)
        ret_va = struct.unpack("<I", uc.mem_read(esp, 4))[0]
        # Pick a return value.
        eax = 0
        argc = STDCALL_ARGS.get(fn, 0)
        # Per-API behavior.
        if fn == "GetTickCount":
            self._tick += 16
            eax = self._tick
        elif fn in ("GetCurrentThreadId",):
            eax = 0x1000
        elif fn in ("GetCurrentProcessId",):
            eax = 0x1234
        elif fn in ("GetLastError",):
            eax = 0
        elif fn in ("GetVersion",):
            eax = 0x0A280106  # Windows 10.0 build 1
        elif fn in ("GetModuleHandleA", "GetModuleHandleW"):
            eax = self.image_base
        elif fn in ("GetProcessHeap",):
            eax = HEAP_BASE
        elif fn in ("HeapAlloc", "VirtualAlloc"):
            # crude bump allocator
            size_arg_off = 8 if fn == "HeapAlloc" else 4
            try:
                size = struct.unpack("<I", uc.mem_read(esp + 4 + size_arg_off, 4))[0]
            except Exception:
                size = 0x1000
            size = max(_align_up(size or 0x1000, 0x10), 0x10)
            ptr = self._heap_ptr
            self._heap_ptr += size
            if self._heap_ptr >= HEAP_BASE + HEAP_SIZE:
                eax = 0
            else:
                eax = ptr
        elif fn in ("HeapFree", "VirtualFree"):
            eax = 1
        elif fn in ("CreateFileA", "CreateFileW"):
            eax = FAKE_HANDLE
        elif fn in ("CloseHandle",):
            eax = 1
        elif fn in ("QueryPerformanceCounter",):
            # write counter to *arg1
            try:
                p = struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]
                uc.mem_write(p, struct.pack("<Q", self._tick * 1000))
            except Exception:
                pass
            eax = 1
        elif fn in ("QueryPerformanceFrequency",):
            try:
                p = struct.unpack("<I", uc.mem_read(esp + 4, 4))[0]
                uc.mem_write(p, struct.pack("<Q", 1_000_000))
            except Exception:
                pass
            eax = 1
        elif fn in ("GetMessageA", "GetMessageW", "PeekMessageA", "PeekMessageW"):
            # Return 0 to signal WM_QUIT / no-message — terminates message loops.
            eax = 0
        elif fn in ("PostMessageA", "PostMessageW", "SendMessageA", "SendMessageW",
                    "DispatchMessageA", "DispatchMessageW", "TranslateMessage"):
            eax = 1
        elif fn in ("InitializeCriticalSection", "EnterCriticalSection",
                    "LeaveCriticalSection", "DeleteCriticalSection"):
            eax = 0
        elif fn in ("TlsAlloc",):
            eax = 1
        elif fn in ("TlsGetValue",):
            eax = 0
        elif fn in ("TlsSetValue",):
            eax = 1
        elif fn in ("ExitProcess",):
            self.log({"event": "exit_process", "dll": dll, "fn": fn})
            uc.emu_stop()
            return
        else:
            # Unknown import. Log first occurrence per fn.
            self.log({"event": "stub_default", "dll": dll, "fn": fn,
                      "argc": argc, "eip_ret": hex(ret_va)})
            eax = 0

        uc.reg_write(UC_X86_REG_EAX, eax)
        # Pop ret addr + argc*4 args, jump to ret.
        new_esp = esp + 4 + (argc * 4)
        uc.reg_write(UC_X86_REG_ESP, new_esp)
        uc.reg_write(UC_X86_REG_EIP, ret_va)


# ---------------------------------------------------------------------------
# Tracer.

class Tracer:
    def __init__(self, args):
        self.args = args
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.loaded: LoadedPE | None = None
        self.stubber: ImportStubber | None = None
        self.out_f = open(args.out, "w")
        self.block_count = 0
        self.t0 = time.time()
        self.fake_ret = FAKE_RET_ADDR
        self.unique_blocks: set[int] = set()

    # ---- logging helpers ----
    def log(self, obj: dict) -> None:
        obj.setdefault("ts", round(time.time() - self.t0, 6))
        self.out_f.write(json.dumps(obj) + "\n")
        self.out_f.flush()

    # ---- setup ----
    def setup(self) -> None:
        # Stack
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        # Heap
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        # PE image
        self.loaded = LoadedPE(self.args.pe)
        self.log({"event": "pe_loaded",
                  "image_base": hex(self.loaded.image_base),
                  "image_size": hex(self.loaded.image_size),
                  "entry_va": hex(self.loaded.entry_va)})
        self.loaded.map_into(self.uc)

        # TEB / PEB / GDT / FS
        setup_teb(self.uc)
        setup_gdt(self.uc)

        # Imports
        self.stubber = ImportStubber(self.uc, self.loaded.pe, self.loaded.image_base, self.log)
        self.stubber.install()

        # Hooks
        self.uc.hook_add(UC_HOOK_BLOCK, self._on_block)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code,
                         begin=STUB_BASE, end=STUB_BASE + STUB_SIZE)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED |
                         UC_HOOK_MEM_WRITE_UNMAPPED |
                         UC_HOOK_MEM_FETCH_UNMAPPED, self._on_mem_invalid)

    # ---- hook callbacks ----
    def _on_block(self, uc, address, size, user):
        self.block_count += 1
        first_seen = address not in self.unique_blocks
        if first_seen:
            self.unique_blocks.add(address)
        # Always log first 4096 blocks, then sample.
        if self.block_count <= 4096 or first_seen:
            self.log({"event": "block",
                      "n": self.block_count,
                      "va": hex(address),
                      "size": size,
                      "first_seen": first_seen})
        # Stop when we hit our fake return address.
        if address == self.fake_ret:
            self.log({"event": "fake_ret_reached", "n": self.block_count})
            uc.emu_stop()

    def _on_code(self, uc, address, size, user):
        # Routed to import stubber.
        if self.stubber is not None:
            self.stubber.hook_code(uc, address, size, user)

    def _on_mem_invalid(self, uc, access, address, size, value, user):
        self.log({"event": "mem_invalid",
                  "access": access,
                  "addr": hex(address),
                  "size": size,
                  "value": hex(value),
                  "eip": hex(uc.reg_read(UC_X86_REG_EIP))})
        # Returning False stops emulation. Returning True after mapping the
        # page would let it continue. We choose to stop — the trace already
        # shows the path taken.
        return False

    # ---- run ----
    def run(self) -> None:
        assert self.loaded is not None
        fn_va = self.args.fn_va
        if fn_va < self.loaded.image_base:
            fn_va = self.loaded.image_base + fn_va  # treat as RVA
        # Set up call frame: push btn, push fake_ret. Delphi register fastcall.
        esp = STACK_BASE + STACK_SIZE - 0x100
        # push btn
        esp -= 4
        self.uc.mem_write(esp, struct.pack("<I", self.args.btn & 0xFFFFFFFF))
        # push fake return address
        esp -= 4
        self.uc.mem_write(esp, struct.pack("<I", self.fake_ret))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, esp)
        self.uc.reg_write(UC_X86_REG_EAX, self.args.self_ptr & 0xFFFFFFFF)
        self.uc.reg_write(UC_X86_REG_EDX, self.args.flags & 0xFFFFFFFF)
        self.uc.reg_write(UC_X86_REG_ECX, self.args.xy_packed & 0xFFFFFFFF)

        self.log({"event": "call_setup",
                  "fn_va": hex(fn_va),
                  "self_ptr": hex(self.args.self_ptr),
                  "flags": hex(self.args.flags),
                  "xy_packed": hex(self.args.xy_packed),
                  "btn": self.args.btn,
                  "esp": hex(esp),
                  "fake_ret": hex(self.fake_ret)})

        try:
            self.uc.emu_start(
                fn_va,
                until=0,  # we stop via UC_HOOK_BLOCK on FAKE_RET_ADDR
                timeout=self.args.timeout_s * 1_000_000,
                count=self.args.max_instrs,
            )
        except UcError as e:
            self.log({"event": "uc_error",
                      "err": str(e),
                      "eip": hex(self.uc.reg_read(UC_X86_REG_EIP))})
        except Exception as e:
            self.log({"event": "exception",
                      "err": repr(e),
                      "tb": traceback.format_exc()})

        self.log({"event": "done",
                  "blocks_total": self.block_count,
                  "blocks_unique": len(self.unique_blocks),
                  "eip_final": hex(self.uc.reg_read(UC_X86_REG_EIP)),
                  "eax_final": hex(self.uc.reg_read(UC_X86_REG_EAX))})


# ---------------------------------------------------------------------------
# CLI.

def _parse_int(s: str) -> int:
    s = s.strip()
    if not s:
        return 0
    return int(s, 0)


def main() -> int:
    p = argparse.ArgumentParser(description="Unicorn tracer for DXRender.exe")
    p.add_argument("--pe", required=True)
    p.add_argument("--fn-va", type=_parse_int, required=True,
                   help="VA (or RVA) of function to call")
    p.add_argument("--out", required=True)
    p.add_argument("--self-ptr", type=_parse_int, default=0)
    p.add_argument("--flags",    type=_parse_int, default=0)
    p.add_argument("--xy-packed", type=_parse_int, default=0)
    p.add_argument("--btn",      type=_parse_int, default=1)
    p.add_argument("--max-instrs", type=int, default=1_000_000)
    p.add_argument("--timeout-s", type=int, default=10)
    args = p.parse_args()

    if not os.path.isfile(args.pe):
        print(f"PE not found: {args.pe}", file=sys.stderr)
        return 2
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)

    t = Tracer(args)
    t.setup()
    t.run()
    t.out_f.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

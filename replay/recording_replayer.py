#!/usr/bin/env python3
"""recording_replayer.py -- Phase 3 replay driver.

Reads a Phase 1+ recording JSONL in time order and demultiplexes:
  - kind="form"  -> map via form_action_map.json -> DLL invoke (or skip).
  - kind="net"   -> push to emulator's pair-matcher (via PAIR_MATCH=<file>).

Gate 3 scope: --dry-run mode ONLY. No DLL invokes, no emulator/Wine
required. Validates that every recorded form-state transition either
maps to a documented action OR to a documented skip reason. Any
unmapped non-skip event is fail-loud (non-zero exit).

Hard rules (RECORDING_REPLAY_PLAN.md):
  - No jumping ahead. Events processed in recorded time order.
  - No skipping form events without a documented passive reason.
  - No VM input automation.

Usage:
  python3 pipeline/recording_replayer.py <recording.jsonl> --dry-run
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter, deque
from pathlib import Path
from typing import Any, Optional


HERE = Path(__file__).resolve().parent
DEFAULT_FORM_ACTION_MAP = HERE / "form_action_map.json"


def _form_event_key(ev: dict) -> str:
    """'TDncCharSelectShow+0x18:1->0' shape. Stable across recordings."""
    return f"{ev['form']}+{ev['off']}:{ev['old']}->{ev['new']}"


def _load_form_action_map(path: Path) -> dict[str, dict]:
    raw = json.loads(path.read_text())
    # Strip top-level _comment / _taxonomy etc.
    return {k: v for k, v in raw.items() if not k.startswith("_") and isinstance(v, dict)}


def _scan_net_queue_by_port(jsonl_path: Path) -> dict[int, deque]:
    """Build per-port C->S queue from the recording (mirrors pair_matcher's
    head-pairing model, but without the S->C attaching). Used for dry-run
    expected_net validation."""
    by_port: dict[int, deque] = {}
    with jsonl_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("kind") != "net":
                continue
            if ev.get("dir") != "C2S":
                continue
            port = int(ev["port"])
            opcode = int(ev["opcode"])
            cipher = ev.get("cipher")
            # Skip plaintext keepalives (op=5). Cipher frames carry seq, not opcode.
            if cipher is None and opcode == 5:
                continue
            by_port.setdefault(port, deque()).append({
                "port": port, "opcode": opcode, "cipher": cipher,
                "t": ev["t"],
            })
    return by_port


def _validate_expected_net(action: dict, c2s_by_port: dict[int, deque]) -> tuple[bool, str]:
    """For an invoke action with expected_net entries, confirm that each
    expected (port, opcode) is reachable somewhere in the remaining queue
    for that port. We don't pop here -- this is a structural feasibility
    check, not a strict head-match. The runtime pair-matcher does the
    strict head-match during real replay.

    Returns (ok, msg)."""
    expected = action.get("expected_net") or []
    if not expected:
        return True, "no expected_net"
    missing = []
    for want in expected:
        port = int(want["port"])
        op = int(want["opcode"])
        q = c2s_by_port.get(port) or deque()
        if not any(int(e["opcode"]) == op for e in q):
            missing.append(f"port={port} op=0x{op:02x}")
    if missing:
        return False, f"missing in net queue: {', '.join(missing)}"
    return True, f"all {len(expected)} expected_net reachable"


def dry_run(jsonl_path: Path, action_map_path: Path) -> int:
    print(f"[replayer] dry-run loading {jsonl_path}", flush=True)
    print(f"[replayer] action map: {action_map_path}", flush=True)
    action_map = _load_form_action_map(action_map_path)
    print(f"[replayer] action map keys: {len(action_map)}", flush=True)

    c2s_by_port = _scan_net_queue_by_port(jsonl_path)
    summary = ", ".join(f"port={p}:{len(q)}" for p, q in sorted(c2s_by_port.items()))
    print(f"[replayer] recording C->S queue (post keepalive-drop): {summary}", flush=True)

    n_form = 0
    n_form_appear = 0
    n_invoke = 0
    n_skip = 0
    n_unmapped = 0
    n_net = 0
    resolutions: list[dict[str, Any]] = []

    with jsonl_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = ev.get("kind")
            if kind == "net":
                n_net += 1
                continue
            if kind == "form_appear":
                n_form_appear += 1
                # form_appear is structural metadata (initial seed); not a
                # transition. The replayer takes no action on these.
                continue
            if kind != "form":
                continue
            n_form += 1
            key = _form_event_key(ev)
            entry = action_map.get(key)
            row: dict[str, Any] = {"t": ev["t"], "key": key, "addr": ev.get("addr")}
            if entry is None:
                n_unmapped += 1
                row["resolution"] = "UNMAPPED"
                row["detail"] = "no entry in form_action_map.json"
                print(f"  UNMAPPED: {key}  (addr={ev.get('addr')})", flush=True)
            elif entry.get("action") == "skip":
                n_skip += 1
                row["resolution"] = "SKIP"
                row["detail"] = entry.get("reason", "")
                print(f"  SKIP: {key}  reason={entry.get('reason')!r}", flush=True)
            elif entry.get("action") in ("pick_slot", "open_modal"):
                # Memory-only / client-only actions; no expected_net to validate.
                n_invoke += 1
                row["resolution"] = "MAP"
                row["detail"] = f"-> {entry.get('action')}"
                print(f"  MAP: {key} -> {entry.get('action')}", flush=True)
            elif entry.get("action") == "invoke":
                ok, msg = _validate_expected_net(entry, c2s_by_port)
                handler = entry.get("handler", "?")
                row["resolution"] = "MAP"
                row["detail"] = f"-> invoke {handler} ({msg})"
                if ok:
                    n_invoke += 1
                    print(f"  MAP: {key} -> invoke {handler}  [{msg}]", flush=True)
                else:
                    # expected_net unreachable is a hard fail in dry-run --
                    # means the recording's form events disagree with its
                    # net events, which would desync at Gate 4.
                    n_unmapped += 1
                    row["resolution"] = "INVALID"
                    print(
                        f"  INVALID: {key} -> invoke {handler}  [{msg}]",
                        flush=True,
                    )
            else:
                n_unmapped += 1
                row["resolution"] = "UNMAPPED"
                row["detail"] = f"unknown action type: {entry.get('action')!r}"
                print(
                    f"  UNMAPPED: {key}  unknown action type {entry.get('action')!r}",
                    flush=True,
                )
            resolutions.append(row)

    print("", flush=True)
    print(f"[replayer] form events: {n_form}  (form_appear: {n_form_appear})", flush=True)
    print(f"[replayer] net events:  {n_net}", flush=True)
    print(
        f"[replayer] resolutions: invoke={n_invoke} skip={n_skip} unmapped={n_unmapped}",
        flush=True,
    )

    # Per-key counts (useful when same key fires multiple times).
    keycounts = Counter(r["key"] for r in resolutions)
    if keycounts:
        print("[replayer] per-key counts:", flush=True)
        for k, c in keycounts.most_common():
            print(f"    {c}x  {k}", flush=True)

    if n_unmapped:
        print(f"[replayer] FAIL: {n_unmapped} unmapped/invalid form event(s)", flush=True)
        return 1
    print("[replayer] OK: all form events resolved (skip or valid invoke)", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("recording", type=Path, help="Path to recording JSONL")
    ap.add_argument("--dry-run", action="store_true",
                    help="Validate mapping only; no DLL/emulator side effects.")
    ap.add_argument("--form-action-map", type=Path, default=DEFAULT_FORM_ACTION_MAP)
    # Phase C handoff flags
    ap.add_argument("--save-as", type=str, default=None,
                    help="Override the auto-derived save name (max 12 chars).")
    ap.add_argument("--no-save", action="store_true",
                    help="Skip DB write; handoff is in-memory only.")
    ap.add_argument("--server", type=str, default="Solstice 1",
                    help="Server name for the new replay character row.")
    ap.add_argument("--owner", type=str, default="bob",
                    help="Owner username for the new replay character row.")
    args = ap.parse_args(argv)

    if not args.recording.exists():
        print(f"recording not found: {args.recording}", file=sys.stderr)
        return 2
    if not args.form_action_map.exists():
        print(f"form_action_map not found: {args.form_action_map}", file=sys.stderr)
        return 2

    if args.dry_run:
        return dry_run(args.recording, args.form_action_map)

    return live_run(args.recording, args.form_action_map,
                    save_as=args.save_as, no_save=args.no_save,
                    server=args.server, owner=args.owner)


# ---------------------------------------------------------------------------
# Gate 4 — live replay path
# ---------------------------------------------------------------------------

import os                # noqa: E402
import re                # noqa: E402
import subprocess        # noqa: E402
import time              # noqa: E402

ROOT = HERE.parent
WINE_C = Path(os.path.expanduser("~/.wine/dosdevices/c:"))
CMD_FILE = WINE_C / "dom_cmd.txt"
DOM_LOG = WINE_C / "dom_replay.log"
DOCKER_GAME = "solstice-game-1"
# pair_matcher persists the offline session token here at PAIR_MATCH eager
# init (Phase 3 token-substitution infra). The host-side replayer should
# read this and pass it to `wine -t` rather than re-authing (auth-service
# kicks prior sessions for the same user).
OFFLINE_TOKEN_PATH = ROOT / "server-emulator-python3" / "recorded_sessions" / ".offline_token"


def _step(msg: str) -> None:
    print(f"[replayer {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _docker_logs(tail: int = 4000) -> str:
    out = subprocess.run(
        ["docker", "logs", "--tail", str(tail), DOCKER_GAME],
        capture_output=True, text=True, timeout=10,
    )
    return out.stdout + out.stderr


def _docker_logs_since(iso: str) -> str:
    out = subprocess.run(
        ["docker", "logs", "--since", iso, DOCKER_GAME],
        capture_output=True, text=True, timeout=10,
    )
    return out.stdout + out.stderr


def _resolve_handle(name: str) -> int | None:
    out = subprocess.run(
        [sys.executable, str(HERE / "resolve_addrs.py"), "--refresh", name],
        capture_output=True, text=True, timeout=120,
    )
    if out.returncode != 0:
        _step(f"resolve_addrs failed: {out.stderr.strip()[:300]}")
        return None
    m = re.search(rf"{re.escape(name)}=0x([0-9a-fA-F]+)", out.stdout)
    if not m:
        return None
    addr = int(m.group(1), 16)
    if addr == 0:
        return None
    return addr


def _resolve_stable_path(stable_path: str) -> int | None:
    """Resolve an arbitrary stable_path (not in dom_handles.json) to a live
    heap addr by invoking dom_click._resolve_path_to_addr in a child
    interpreter. Returns int addr or None."""
    code = (
        "import sys, runpy, importlib.util as ilu;"
        f"sys.path=[{str(HERE.parent)!r}]+[p for p in sys.path if 'site-packages' not in p];"
        f"spec=ilu.spec_from_file_location('dc',{str(HERE / 'dom_click.py')!r});"
        "m=ilu.module_from_spec(spec); spec.loader.exec_module(m);"
        f"a=m._resolve_path_to_addr({stable_path!r});"
        "print(f'ADDR=0x{a:08x}' if a else 'ADDR=0x00000000')"
    )
    env = dict(os.environ)
    env["PYTHONNOUSERSITE"] = "1"
    out = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, timeout=60, env=env,
    )
    if out.returncode != 0:
        _step(f"resolve_stable_path failed: {out.stderr.strip()[:300]}")
        return None
    m = re.search(r"ADDR=0x([0-9a-fA-F]+)", out.stdout)
    if not m:
        return None
    addr = int(m.group(1), 16)
    return addr if addr else None


_seq = [0]


def _fire_invoke(addr: int) -> None:
    _seq[0] += 1
    cmd = f"invoke 0x{addr:08x} #{_seq[0]}"
    _step(f"DLL <- {cmd}")
    CMD_FILE.write_text(cmd)


def _wait_pair_match(needle: str, since_marker_count: int, timeout: float = 10.0) -> str | None:
    """Wait for a NEW emulator [PairMatch] log line containing needle.

    `since_marker_count` is the # of [PairMatch] lines that existed before
    we started watching; we only return matches at a higher index. This
    avoids docker --since timezone foot-guns.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = _docker_logs(tail=8000)
        pm_lines = [ln for ln in logs.splitlines() if "[PairMatch]" in ln]
        for i, ln in enumerate(pm_lines):
            if i < since_marker_count:
                continue
            if needle in ln:
                return ln.strip()
        time.sleep(0.4)
    return None


def _count_pm_lines() -> int:
    return sum(1 for ln in _docker_logs(tail=8000).splitlines() if "[PairMatch]" in ln)


def _emulator_pair_match_loaded() -> bool:
    """Check whether emulator container has PAIR_MATCH active.

    The PairMatcher singleton is lazy-initialized on first packet, so the
    "[PairMatch] loaded" banner won't appear until after the first client
    connects. As a preflight, accept either:
      (a) the banner present, OR
      (b) PAIR_MATCH env var visible in the container (lazy ready).
    """
    if "[PairMatch] loaded" in _docker_logs(tail=3000):
        return True
    try:
        out = subprocess.run(
            ["docker", "exec", DOCKER_GAME, "printenv", "PAIR_MATCH"],
            capture_output=True, text=True, timeout=5,
        )
        val = out.stdout.strip()
        if val:
            _step(f"PAIR_MATCH env in container: {val} (lazy-init pending)")
            return True
    except Exception as e:
        _step(f"could not probe container env: {e}")
    return False


def _ensure_dll_attached() -> bool:
    """Attach DLL to current DXRender if not already."""
    spec = importlib.util.spec_from_file_location(
        "_replay_smoke_local", HERE / "replay_smoke.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    if not mod.verify_dxrender_running():
        _step("DXRender not running")
        return False
    return mod.ensure_dll_attached_to_current_dxrender()


def _read_offline_token() -> Optional[str]:  # type: ignore[name-defined]
    """Read the emulator-side offline session token (persisted by pair_matcher
    on PAIR_MATCH startup). Returns None if missing/invalid."""
    try:
        tok = OFFLINE_TOKEN_PATH.read_text().strip()
    except OSError:
        return None
    if len(tok) == 20 and all(c in "0123456789abcdef" for c in tok.lower()):
        return tok
    _step(f"offline token file present but invalid (len={len(tok)})")
    return None


def _build_handoff_directive(jsonl_path: Path, save_as: Optional[str],
                              no_save: bool, server: str, owner: str
                              ) -> Optional[dict]:
    """Parse the recording into a V2Character and assemble the JSON
    directive consumed by pair_matcher's handoff. Returns None on parse
    failure (logged); caller decides whether to abort or proceed without
    handoff.

    For DB write paths this also queries the DB to derive a fresh
    `save_name` of the form `<base>_<NNNN...>` (12 chars total). The
    base is taken from the V2Character's name (e.g. 'Raito')."""
    try:
        # Lazy import to avoid forcing v2_character_parse into the dry-run
        # codepath.
        sys.path.insert(0, str(HERE))
        from v2_character_parse import parse_recording  # type: ignore
    except Exception as e:
        _step(f"handoff: cannot import v2_character_parse: {e}")
        return None

    try:
        d4_chars, active = parse_recording(str(jsonl_path))
    except Exception as e:
        _step(f"handoff: parse_recording failed: {e}")
        return None

    base_name = (active.name or (d4_chars[0].name if d4_chars else "")) or "Replay"
    base_name = base_name.strip()

    save_name = save_as
    if not save_name and not no_save:
        try:
            from v2_character_to_db import derive_save_name  # type: ignore
            save_name = derive_save_name(base_name, server, owner)
        except Exception as e:
            _step(f"handoff: derive_save_name failed (DB not reachable from "
                  f"host?): {e} — using fallback")
            # Fallback: deterministic synthetic name. Pair_matcher will run
            # this inside the container with DB access; it'll re-derive
            # there if save_name looks unsuitable.
            digits = max(1, 12 - len(base_name) - 1)
            save_name = f"{base_name}_{1:0{digits}d}"
    if save_name is None:
        save_name = base_name[:12]

    # Serialize V2Character to plain dict (drop bytes fields — not JSON-able
    # and not needed by insert_replay_character).
    def _to_dict(c) -> dict:
        return {
            "slot": int(c.slot),
            "name": c.name,
            "acct_id": int(c.acct_id),
            "level": int(c.level),
            "sex": int(c.sex),
            "player_class": int(c.player_class),
            "visual_outfit": int(c.visual_outfit),
            "visual_hair": int(c.visual_hair),
            "visual_head": int(c.visual_head),
            "visual_face": int(c.visual_face),
            "visual_arm_l": int(c.visual_arm_l),
            "visual_arm_r": int(c.visual_arm_r),
            "visual_back": int(c.visual_back),
            "visual_acc1": int(c.visual_acc1),
            "visual_acc2": int(c.visual_acc2),
            "entity_id": int(c.entity_id),
            "hp": int(c.hp),
            "hp_max": int(c.hp_max),
            "mp": int(c.mp),
            "mp_max": int(c.mp_max),
            "map_id": int(c.map_id or 84),
            "pos_x": int(c.pos_x),
            "pos_y": int(c.pos_y),
            "direction": int(c.direction),
        }

    return {
        "no_save": bool(no_save),
        "owner": owner,
        "server": server,
        "save_name": save_name,
        "v2_character": _to_dict(active),
    }


def live_run(jsonl_path: Path, action_map_path: Path,
             save_as: Optional[str] = None, no_save: bool = False,
             server: str = "Solstice 1", owner: str = "bob") -> int:
    _step(f"live-run loading {jsonl_path}")
    action_map = _load_form_action_map(action_map_path)
    _step(f"action map keys: {len(action_map)}")

    # Preflight: read offline token persisted by pair_matcher.
    offline_tok = _read_offline_token()
    if offline_tok is None:
        _step(
            "WARN: emulator-side offline token not found at "
            f"{OFFLINE_TOKEN_PATH}. Token-substitution will not engage. "
            "Bring up emulator with PAIR_MATCH=... and ensure auth-service "
            "is reachable from the container."
        )
    else:
        _step(f"offline token: {offline_tok} (use this for wine -t <token>)")

    # Preflight: emulator + DLL
    if not _emulator_pair_match_loaded():
        print("FAIL: emulator not running with PAIR_MATCH active. "
              "Start with PAIR_MATCH=/app/recordings/<file> docker compose up.",
              file=sys.stderr)
        return 1
    _step("preflight: PAIR_MATCH banner present")

    # Clear any stale invoke command sitting in dom_cmd.txt before DLL injects.
    # Otherwise the freshly-attached DLL immediately processes the leftover from
    # a previous run, firing an invoke before the replayer's pm_marker capture.
    try:
        CMD_FILE.write_text("")
        _step(f"preflight: cleared {CMD_FILE}")
    except Exception as e:
        _step(f"preflight: WARN could not clear {CMD_FILE}: {e}")

    # Clear any stale .replayer_done sentinel from prior runs. Otherwise
    # pair_matcher would immediately drain queues + freeze on the very first
    # offline C2S, before our replayer has a chance to pair-match anything.
    sessions_root = Path("/Users/robin/proj/server-emulator-python3/recorded_sessions")
    for stale_name in (".replayer_done", ".handoff_directive"):
        stale = sessions_root / stale_name
        if stale.exists():
            try:
                stale.unlink()
                _step(f"preflight: removed stale {stale}")
            except OSError as e:
                _step(f"preflight: WARN could not remove {stale}: {e}")

    if not _ensure_dll_attached():
        print("FAIL: dom_replay.dll not attached to DXRender", file=sys.stderr)
        return 1
    _step("preflight: DLL attached")

    # Iterate form events in time order
    invokes_done: list[dict] = []
    skips_done: list[dict] = []
    desync_lines: list[str] = []

    # Read all form events, then sort by (timestamp, off-priority) so that within
    # a single poll cycle, slot-pick (+0x7D) is processed before form-active clears
    # (+0x18). The recorder polls at 100ms; a double-click that hovers a slot and
    # clicks Start Game in the same tick will emit both events with identical
    # timestamps, but the replayer needs slot-pick first so the Start Game
    # handler reads the correct slot.
    form_events: list[dict] = []
    with jsonl_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("kind") != "form":
                continue
            form_events.append(ev)

    def _sort_key(e: dict) -> tuple:
        off = e.get("off", "")
        # Lower priority value = process earlier within same timestamp.
        # 0x7D (slot pick) must precede 0x18 (form-active clear) so the slot
        # global is set before the Start Game OnClick reads it.
        priority = {"0x7d": 0, "0x18": 1}.get(off, 2)
        return (e.get("t", 0.0), priority)
    form_events.sort(key=_sort_key)

    for ev in form_events:
        if True:  # preserve indentation for the existing block below
            key = _form_event_key(ev)
            entry = action_map.get(key)
            if entry is None:
                _step(f"UNMAPPED form event {key} — aborting (Phase 3 Gate 3 prereq violated)")
                return 1
            action = entry.get("action")
            if action == "skip":
                skips_done.append({"key": key, "reason": entry.get("reason", "")})
                _step(f"SKIP {key} ({entry.get('reason','')[:60]})")
                continue
            if action == "open_modal":
                # Client-side modal open: write the form-active byte and
                # invoke the form's VMT Show slot. No coord clicks, no
                # network expectations.
                sp = entry.get("stable_path")
                set_off = int(entry.get("set_byte_offset", "0x18"), 16)
                set_val = int(entry.get("set_byte_value", "0x01"), 16)
                slot = int(entry.get("vmt_show_slot", "0x30"), 16)
                if not sp:
                    _step(f"FAIL: open_modal missing stable_path for {key}")
                    return 1
                _step(f"OPEN_MODAL {key} -> path={sp} +0x{set_off:x}=0x{set_val:02x} vmt_slot=0x{slot:x}")
                addr = _resolve_stable_path(sp)
                if addr is None:
                    _step(f"FAIL: could not resolve stable_path {sp}")
                    return 1
                _seq[0] += 1
                cmd1 = f"set_byte 0x{addr + set_off:08x} 0x{set_val:02x}"
                _step(f"DLL <- {cmd1}")
                CMD_FILE.write_text(cmd1)
                time.sleep(0.3)
                _seq[0] += 1
                cmd2 = f"call_vmt 0x{addr:08x} 0x{slot:x}"
                _step(f"DLL <- {cmd2}")
                CMD_FILE.write_text(cmd2)
                time.sleep(0.5)
                invokes_done.append({
                    "key": key, "handle": "(open_modal)",
                    "handler": f"set_byte+call_vmt(0x{slot:x})",
                    "addr": f"0x{addr:08x}", "last_match": None,
                })
                continue
            if action == "pick_slot":
                # Slot index from the form event (new value of +0x7d).
                slot = int(ev.get("new", 0))
                cmd = f"pick_slot {slot}"
                _step(f"PICK_SLOT {key} -> slot={slot}")
                CMD_FILE.write_text(cmd)
                # pick_slot is a memory-only write; no network frame, no
                # pair-match expected. Brief pause to let DLL process.
                time.sleep(0.5)
                continue
            if action != "invoke":
                _step(f"UNKNOWN action {action!r} for {key}")
                return 1

            handle = entry.get("dom_handle")
            handler = entry.get("handler", "?")
            _step(f"INVOKE {key} -> handle={handle} handler={handler}")
            addr = _resolve_handle(handle) if handle else None
            if addr is None:
                _step(f"FAIL: could not resolve heap addr for handle={handle}")
                return 1
            pm_marker = _count_pm_lines()
            _fire_invoke(addr)

            # Wait for the LAST expected pair-match line associated with this invoke.
            expected = entry.get("expected_net") or []
            last_match_line: str | None = None
            for want in expected:
                port = int(want["port"])
                op = int(want["opcode"])
                needle = f"port={port} op=0x{op:02x}"
                _step(f"  awaiting pair-match {needle} (after marker={pm_marker})")
                ln = _wait_pair_match(needle + " OK", pm_marker, timeout=15.0)
                if ln is None:
                    logs = _docker_logs(tail=8000)
                    for d in logs.splitlines():
                        if "DESYNC" in d or "desync" in d.lower():
                            desync_lines.append(d.strip())
                    _step(f"FAIL: timeout waiting for {needle} after invoke {handle}")
                    return 1
                _step(f"  matched: {ln[-180:]}")
                last_match_line = ln
            invokes_done.append({
                "key": key, "handle": handle, "handler": handler,
                "addr": f"0x{addr:08x}", "last_match": last_match_line,
            })

    # Drain grace
    _step("invokes complete — grace pause 6s for cipher S->C drain")
    time.sleep(6.0)

    # Signal pair_matcher to drain remaining queues + enter echo mode AND
    # hand off to the v2 World handler (Phase C). The directive is written
    # FIRST so it's visible the moment pair_matcher observes .replayer_done.
    sessions_dir = Path("/Users/robin/proj/server-emulator-python3/recorded_sessions")
    try:
        sessions_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        _step(f"WARN: could not create {sessions_dir}: {e}")

    directive = _build_handoff_directive(jsonl_path, save_as, no_save, server, owner)
    directive_path = sessions_dir / ".handoff_directive"
    if directive is not None:
        try:
            directive_path.write_text(json.dumps(directive, indent=2))
            _step(f"handoff directive written: {directive_path} "
                  f"(save_name={directive['save_name']!r}, "
                  f"no_save={directive['no_save']}, owner={directive['owner']})")
        except OSError as e:
            _step(f"WARN: could not write handoff directive: {e}")
    else:
        _step("handoff directive skipped (parse failed) — replay will freeze "
              "without handoff to v2")
        # Clean up any stale directive from a previous run so pair_matcher
        # doesn't pick it up.
        try:
            directive_path.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            _step(f"WARN: could not remove stale directive: {e}")

    sentinel = sessions_dir / ".replayer_done"
    try:
        sentinel.write_text(str(time.time()))
        _step(f"freeze signal written: {sentinel}")
    except OSError as e:
        _step(f"WARN: could not write freeze signal {sentinel}: {e}")

    # Final state checks
    summary_logs = _docker_logs(tail=5000)
    pm_lines = [ln for ln in summary_logs.splitlines() if "[PairMatch]" in ln]
    cnt_1819 = sum(1 for ln in pm_lines if "port=1819" in ln and "OK" in ln)
    cnt_18124 = sum(1 for ln in pm_lines if "port=18124" in ln and "OK" in ln)
    cnt_18123 = sum(1 for ln in pm_lines if "port=18123" in ln and "OK" in ln)
    ex_1819 = next((ln for ln in pm_lines if "port=1819" in ln and "OK" in ln), "")
    ex_18124 = next((ln for ln in pm_lines if "port=18124" in ln and "OK" in ln), "")
    ex_18123 = next((ln for ln in pm_lines if "port=18123" in ln and "OK" in ln), "")
    desync_seen = [ln for ln in pm_lines if "DESYNC" in ln]

    # Optional: read TDncGameMainMenu +0x4C via form_watcher one-shot
    in_world_val = "n/a"
    try:
        fw = subprocess.run(
            [sys.executable, str(HERE / "form_watcher.py"), "snap",
             "TDncGameMainMenu", "post_replay"],
            capture_output=True, text=True, timeout=60,
        )
        # form_watcher writes to /tmp/form_snaps/...; output may include addr
        snap_path = Path("/tmp/form_snaps/TDncGameMainMenu.post_replay.json")
        if snap_path.exists():
            data = json.loads(snap_path.read_text())
            instances = data.get("instances", []) or data.get("snaps", [])
            for inst in instances:
                bytes_hex = inst.get("bytes") or inst.get("hex") or ""
                # +0x4c byte
                if isinstance(bytes_hex, str) and len(bytes_hex) >= (0x4c + 1) * 2:
                    val = int(bytes_hex[0x4c * 2:0x4c * 2 + 2], 16)
                    in_world_val = f"0x{val:02x}"
                    break
        else:
            in_world_val = f"snap missing (rc={fw.returncode})"
    except Exception as e:
        in_world_val = f"error: {e}"

    print("\n" + "=" * 70)
    print("recording_replayer live-run summary")
    print("=" * 70)
    print(f"invokes fired: {len(invokes_done)}")
    for r in invokes_done:
        print(f"  + {r['key']}  handle={r['handle']}  addr={r['addr']}")
        if r.get("last_match"):
            print(f"      last pair-match: {r['last_match'][-160:]}")
    print(f"skips: {len(skips_done)}")
    print(f"\npair-match OK counts: 1819={cnt_1819} 18124={cnt_18124} 18123={cnt_18123}")
    if ex_1819:
        print(f"  ex 1819:  {ex_1819[-180:]}")
    if ex_18124:
        print(f"  ex 18124: {ex_18124[-180:]}")
    if ex_18123:
        print(f"  ex 18123: {ex_18123[-180:]}")
    print(f"\nTDncGameMainMenu +0x4c = {in_world_val}")
    if desync_seen:
        print("\nDESYNC lines observed:")
        for ln in desync_seen[-5:]:
            print(f"  {ln}")

    passed = (
        len(invokes_done) >= 2
        and cnt_1819 >= 1
        and cnt_18124 >= 1
        and cnt_18123 >= 1
        and not desync_seen
    )
    print("\n" + ("PASS" if passed else "FAIL"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

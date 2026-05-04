#!/usr/bin/env python3
"""
v2_server.py — Phase 2 Mac-side server emulator.

Listens on the recorded game ports, accepts a connection from XenClient
running on RC3, and replays recorded server-bound (S2C) frames in lockstep
with the client's C2S frames using a dumb cursor-based pair-matcher.

MVP scope: ports 1818 (login) and 1819 (login aux) only — replay until
server-select is visible. World ports 18123/18124 are listened-to but
connections are closed (recorded payloads are decrypted plaintext, we
have no encryption path back to wire bytes here).

Recording schema (per Phase 1 host_recording_stream.py):
- net.payload is the FULL on-wire frame: [u16 LE total_len][u8 op][body]
- net.len = total wire byte count = 2 + total_len
- Replay just sends bytes.fromhex(payload) verbatim.
"""

import argparse
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from typing import Dict, List, Optional

# Phase 7 cipher port — encrypt/decrypt for ports 18123 / 18124.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cipher as _world_cipher

try:
    from spawn_parser import parse_spawn_frame
except ImportError:
    parse_spawn_frame = None  # swap disabled if parser missing


# ---------------------------------------------------------------------------
# Recording load

PLAINTEXT_PORTS = {1818, 1819, 18124}
KEEPALIVE_OP = 0x05  # 3-byte "010005" heartbeat — noise on plaintext ports.

# Replay-time config; populated in main() before any handler runs.
CFG: Dict[str, object] = {"pace": True, "speed": 1.0}


def _paced_sleep(target_ns: int, stop: Optional[threading.Event]) -> bool:
    """Sleep until time.monotonic_ns() >= target_ns, in <=100ms chunks so a
    stop signal isn't stuck behind a long sleep. Returns False if stopped."""
    while True:
        now = time.monotonic_ns()
        dt = target_ns - now
        if dt <= 0:
            return True
        if stop is not None and stop.is_set():
            return False
        time.sleep(min(dt, 100_000_000) / 1e9)


def _byte_swap_actor_ids(payload: bytes, own_le: bytes, target_le: bytes) -> bytes:
    # Single-pass bidirectional swap of two 2-byte values. Walks
    # payload looking for either own_le or target_le at any offset and
    # substitutes the opposite. Skips past the modified bytes so we
    # don't double-swap.
    if own_le == target_le:
        return payload
    out = bytearray(payload)
    i = 0
    n = len(out) - 1
    while i < n:
        pair = bytes(out[i:i + 2])
        if pair == own_le:
            out[i:i + 2] = target_le
            i += 2
        elif pair == target_le:
            out[i:i + 2] = own_le
            i += 2
        else:
            i += 1
    return bytes(out)


def swap_self_with_character(by_port: Dict[int, List[dict]], swap_name: str) -> None:
    # Make the live client render `swap_name` as the player by
    # rewriting the recorded session in three places:
    #   1. World self_spawn payload — bytes replaced with target's
    #      spawn frame so appearance / name / coords / actor_id all
    #      flip on the world entry frame.
    #   2. Lobby char-list (op=0xd4 on 1819) — the player's slot is
    #      renamed to the target's FULL spawn name (e.g. "Lacey_",
    #      "chikuro..."). Critical: must match the spawn-frame name
    #      exactly so the client's "I selected X" sent in C2S matches
    #      the spawn name X' the world server sends back.
    #   3. Byte-level actor_id swap across all world S2C frames —
    #      subsequent packets reference the player by 2-byte LE id;
    #      without flipping these, the client treats them as targeting
    #      "old self" (now another actor) and re-renders the original
    #      avatar as the player.
    if not swap_name or parse_spawn_frame is None:
        return
    world_q = by_port.get(18123, [])
    own_idx = target_idx = None
    own_name = target_name = None
    own_actor_id = target_actor_id = None
    swap_lower = swap_name.lower()
    for idx, rec in enumerate(world_q):
        if rec.get("dir") != "S2C":
            continue
        try:
            payload = bytes.fromhex(rec["payload_hex"])
        except (KeyError, ValueError):
            continue
        parsed = parse_spawn_frame(payload)
        if parsed is None or parsed.get("kind") != "self_spawn":
            continue
        name = parsed.get("name")
        actor_id = parsed.get("actor_id")
        if not name or actor_id is None:
            continue
        if own_idx is None:
            own_idx, own_name, own_actor_id = idx, name, actor_id
            continue
        if target_idx is None and name.lower().startswith(swap_lower):
            target_idx, target_name, target_actor_id = idx, name, actor_id
            break
    if own_idx is None:
        print(f"[swap] no self_spawn with a name found; cannot swap",
              file=sys.stderr, flush=True)
        return
    if own_name and own_name.lower().startswith(swap_lower):
        print(f"[swap] {own_name!r} is already 'self'; no-op",
              file=sys.stderr, flush=True)
        return
    if target_idx is None:
        print(f"[swap] no spawn matching '{swap_name}' found in port-18123 S2C",
              file=sys.stderr, flush=True)
        return

    own_rec = world_q[own_idx]
    target_rec = world_q[target_idx]
    print(f"[swap] world_spawn: {own_name!r}#{own_actor_id} (seq={own_rec['seq']}) "
          f"-> {target_name!r}#{target_actor_id} (seq={target_rec['seq']})",
          file=sys.stderr, flush=True)
    own_rec["payload_hex"] = target_rec["payload_hex"]
    own_rec["len"] = target_rec["len"]
    own_rec["opcode"] = target_rec["opcode"]

    # 2. Rename own's slot in lobby char-list (op=0xd4) using the
    # target's FULL spawn-frame name so client-selected name matches
    # what the world spawn sends back.
    NAME_LEN = 12
    own_padded = own_name.encode("utf-8")[:NAME_LEN].ljust(NAME_LEN, b"\x00")
    new_padded = target_name.encode("utf-8")[:NAME_LEN].ljust(NAME_LEN, b"\x00")
    renames = 0
    for port in (1818, 1819):
        for rec in by_port.get(port, []):
            if rec.get("dir") != "S2C" or rec.get("opcode") != 0xd4:
                continue
            try:
                payload = bytes.fromhex(rec["payload_hex"])
            except (KeyError, ValueError):
                continue
            if own_padded not in payload:
                continue
            rec["payload_hex"] = payload.replace(own_padded, new_padded, 1).hex()
            renames += 1
            print(f"[swap] charlist 0xd4 seq={rec['seq']} port={port}: "
                  f"slot {own_name!r} -> {target_name!r}",
                  file=sys.stderr, flush=True)
    if renames == 0:
        print(f"[swap] WARN: no 0xd4 char-list frames contained "
              f"{own_name!r} — char-select will not show {target_name!r}",
              file=sys.stderr, flush=True)

    # 3. Byte-level actor_id swap across all world S2C frames. Skip
    # the spawn frame we already replaced to avoid double-rewriting.
    own_le = own_actor_id.to_bytes(2, "little")
    target_le = target_actor_id.to_bytes(2, "little")
    swapped = 0
    for port in (18123, 18124):
        for rec in by_port.get(port, []):
            if rec.get("dir") != "S2C":
                continue
            if rec is own_rec:
                continue
            try:
                payload = bytes.fromhex(rec["payload_hex"])
            except (KeyError, ValueError):
                continue
            if own_le not in payload and target_le not in payload:
                continue
            new_payload = _byte_swap_actor_ids(payload, own_le, target_le)
            if new_payload != payload:
                rec["payload_hex"] = new_payload.hex()
                swapped += 1
    print(f"[swap] actor_id byte-swap {own_actor_id} <-> {target_actor_id} "
          f"applied to {swapped} world S2C frame(s)",
          file=sys.stderr, flush=True)


def load_net_events_by_port(jsonl_path: str) -> Dict[int, List[dict]]:
    by_port: Dict[int, List[dict]] = {}
    with open(jsonl_path, "r", encoding="utf-8") as f:
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
            port = int(ev["port"])
            opcode = int(ev.get("opcode", -1))
            cipher = ev.get("cipher", "none")
            # Drop plaintext keepalives from the queue: live client emits
            # them on its own timer and we'd false-desync trying to match
            # them in lockstep.
            if (cipher == "none" and port in PLAINTEXT_PORTS
                    and opcode == KEEPALIVE_OP):
                continue
            by_port.setdefault(port, []).append({
                "seq": ev.get("seq"),
                "dir": ev["dir"],
                "port": port,
                "opcode": opcode,
                "len": int(ev.get("len", 0)),
                "payload_hex": ev.get("payload", ""),
                "cipher": cipher,
                "t_ns": ev.get("t_mono_ns"),
            })
    return by_port


def collect_prod_ips(jsonl_path: str) -> List[bytes]:
    """Collect every IP seen in server_endpoint events. These are the prod
    addresses recorded in S2C payloads that DXRender will try to dial when
    we replay. We rewrite all of them to our Mac IP so the offline client
    keeps coming back to us."""
    ips: List[bytes] = []
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("kind") != "server_endpoint":
                continue
            ip = ev.get("ip")
            if not ip:
                continue
            try:
                b = ipv4_to_be_bytes(ip)
            except ValueError:
                continue
            if b not in ips:
                ips.append(b)
    return ips


# ---------------------------------------------------------------------------
# Frame I/O

def read_frame(sock: socket.socket) -> Optional[bytes]:
    """Read one V2 plaintext frame: [u16 LE total_len][u8 op][body].
    Returns the full on-wire bytes or None on EOF/short read."""
    hdr = _recv_exact(sock, 2)
    if hdr is None:
        return None
    total_len = struct.unpack("<H", hdr)[0]
    if total_len < 1:
        return None
    body = _recv_exact(sock, total_len)
    if body is None:
        return None
    return hdr + body


def _recv_exact(sock: socket.socket, n: int) -> Optional[bytes]:
    out = bytearray()
    while len(out) < n:
        try:
            chunk = sock.recv(n - len(out))
        except (ConnectionError, OSError):
            return None
        if not chunk:
            return None
        out.extend(chunk)
    return bytes(out)


def parse_frame(frame: bytes) -> Optional[dict]:
    if len(frame) < 3:
        return None
    total_len = struct.unpack_from("<H", frame, 0)[0]
    if total_len + 2 != len(frame):
        return None
    return {
        "opcode": frame[2],
        "len": len(frame),
        "wire": frame,
    }


def rewrite_payload(frame: bytes, prod_ips: List[bytes],
                    mac_ip_bytes: bytes) -> tuple:
    """Replace every occurrence of any known prod IP (4-B BE) in the frame
    with our Mac IP, so the offline client keeps connecting back to us.

    Covers: 0xd1 server-list entries on 1818, 0xd4 char-list world-host on
    1819, and any other recorded payload that embeds a server address.
    Returns (new_bytes, n_rewrites)."""
    if not prod_ips:
        return frame, 0
    out = bytearray(frame)
    n = 0
    for prod in prod_ips:
        i = 0
        while True:
            j = out.find(prod, i)
            if j < 0:
                break
            out[j:j + 4] = mac_ip_bytes
            n += 1
            i = j + 4
    return bytes(out), n


def ipv4_to_be_bytes(ip: str) -> bytes:
    parts = ip.split(".")
    if len(parts) != 4:
        raise ValueError(f"bad IPv4: {ip}")
    return bytes(int(p) for p in parts)


# ---------------------------------------------------------------------------
# Connection handler — login ports (1818/1819)

def handle_login_conn(sock: socket.socket, addr, port: int, queue: List[dict],
                      ctrl: "ControlBus", rewrite_ip: Optional[bytes],
                      prod_ips: List[bytes]) -> None:
    log = lambda s: print(f"[port={port} {addr[0]}:{addr[1]}] {s}", file=sys.stderr, flush=True)
    cursor = 0
    log(f"connected; recorded queue has {len(queue)} entries")

    # On connect, flush any leading S2C frames before the first C2S (rare for
    # login but cheap to handle).
    cursor = _flush_s2c(sock, queue, cursor, port, log, ctrl, rewrite_ip, prod_ips)

    while True:
        frame = read_frame(sock)
        if frame is None:
            log("client closed")
            return
        parsed = parse_frame(frame)
        if parsed is None:
            log(f"bad frame ({len(frame)}B), closing")
            return

        # Live keepalives are noise; the recorded queue has them stripped,
        # so skip pair-match and just keep reading.
        if parsed["opcode"] == KEEPALIVE_OP and port in PLAINTEXT_PORTS:
            log(f"keepalive 0x{parsed['opcode']:02x} (ignored)")
            continue

        # Advance cursor over the next recorded C2S (warn on opcode mismatch).
        nxt = _next_c2s(queue, cursor)
        if nxt is None:
            log(f"C2S op=0x{parsed['opcode']:02x} len={parsed['len']} → no more recorded C2S; closing")
            return
        idx, rec = nxt
        if rec["opcode"] != parsed["opcode"]:
            log(f"DESYNC C2S op=0x{parsed['opcode']:02x} != recorded op=0x{rec['opcode']:02x} "
                f"at seq={rec['seq']} — closing connection (broadcast suppressed)")
            ctrl.broadcast_desync(rec["seq"], port, parsed["opcode"], rec["opcode"])
            return
        log(f"C2S op=0x{parsed['opcode']:02x} len={parsed['len']} → matched seq={rec['seq']}")
        ctrl.broadcast(rec["seq"], port, "C2S", parsed["opcode"])
        cursor = idx + 1

        # Flush all S2C entries up to next C2S.
        cursor = _flush_s2c(sock, queue, cursor, port, log, ctrl, rewrite_ip, prod_ips)


def _next_c2s(queue: List[dict], cursor: int):
    for i in range(cursor, len(queue)):
        if queue[i]["dir"] == "C2S":
            return i, queue[i]
    return None


def _flush_s2c(sock: socket.socket, queue: List[dict], cursor: int, port: int, log,
               ctrl: "ControlBus", rewrite_ip: Optional[bytes],
               prod_ips: List[bytes]) -> int:
    pace = bool(CFG.get("pace", True))
    speed = float(CFG.get("speed", 1.0)) or 1.0
    rec_t0: Optional[int] = None
    play_t0 = time.monotonic_ns()
    while cursor < len(queue) and queue[cursor]["dir"] == "S2C":
        rec = queue[cursor]
        if pace and rec.get("t_ns") is not None:
            if rec_t0 is None:
                rec_t0 = rec["t_ns"]
            target = play_t0 + int((rec["t_ns"] - rec_t0) / speed)
            if not _paced_sleep(target, None):
                return cursor
        try:
            payload = bytes.fromhex(rec["payload_hex"])
        except ValueError:
            log(f"WARN bad hex at seq={rec['seq']}, skipping")
            cursor += 1
            continue
        # Replace every embedded prod IP with our Mac IP so DXRender's next
        # TCP connect (server-pick, world entry, etc.) lands on our emulator.
        if rewrite_ip is not None and prod_ips:
            new_payload, n_rewrites = rewrite_payload(payload, prod_ips, rewrite_ip)
            if n_rewrites:
                log(f"rewrote {n_rewrites} prod-IP(s) in seq={rec['seq']} op=0x{rec['opcode']:02x}")
                payload = new_payload
        try:
            sock.sendall(payload)
        except (ConnectionError, OSError) as e:
            log(f"send failed: {e}")
            return cursor
        log(f"S2C op=0x{rec['opcode']:02x} len={rec['len']} sent (seq={rec['seq']})")
        ctrl.broadcast(rec["seq"], port, "S2C", rec["opcode"])
        cursor += 1
    return cursor


# ---------------------------------------------------------------------------
# Control bus: broadcasts {seq,port,dir,opcode} JSON lines to all connected
# replayer/observer clients so they can pair-match in lockstep.

class ControlBus:
    def __init__(self, bind: str, port: int, stop_evt: threading.Event):
        self.bind = bind
        self.port = port
        self.stop_evt = stop_evt
        self.lock = threading.Lock()
        self.clients: List[socket.socket] = []
        self.sock: Optional[socket.socket] = None
        self._pending_s2c_ports: set = set()
        self._pending_lock = threading.Lock()
        self._progress_lock = threading.Lock()
        self._progress_cond = threading.Condition(self._progress_lock)
        self._input_progress_seq = 0
        self._input_done_received = False

    def register_pending_s2c_port(self, port: int) -> None:
        with self._pending_lock:
            self._pending_s2c_ports.add(port)

    def mark_s2c_port_done(self, port: int) -> bool:
        with self._pending_lock:
            self._pending_s2c_ports.discard(port)
            return len(self._pending_s2c_ports) == 0

    def wait_for_input_progress(self, target_seq: int, timeout_s: float = 30.0) -> bool:
        # Block until input_replayer has reported progress past target_seq,
        # input_done has been signaled (input drained → no more gating
        # needed), or stop_evt fires. Returns True if progress reached or
        # input_done; False on timeout.
        deadline = time.monotonic() + timeout_s
        with self._progress_cond:
            while True:
                if (self._input_done_received
                        or self._input_progress_seq >= target_seq
                        or self.stop_evt.is_set()):
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._progress_cond.wait(timeout=min(remaining, 0.5))

    def serve(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.bind, self.port))
        except OSError as e:
            print(f"[ctrl] bind failed: {e}", file=sys.stderr, flush=True)
            return
        s.listen(4)
        s.settimeout(0.5)
        self.sock = s
        print(f"[ctrl] listening on {self.bind}:{self.port}", file=sys.stderr, flush=True)
        while not self.stop_evt.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            print(f"[ctrl] client connected from {addr[0]}:{addr[1]}",
                  file=sys.stderr, flush=True)
            with self.lock:
                self.clients.append(conn)
            t = threading.Thread(target=self._reader, args=(conn, addr),
                                 daemon=True)
            t.start()
        try:
            s.close()
        except OSError:
            pass

    def _reader(self, conn: socket.socket, addr) -> None:
        conn.settimeout(0.5)
        buf = b""
        while not self.stop_evt.is_set():
            try:
                chunk = conn.recv(4096)
            except (TimeoutError, socket.timeout):
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
                if obj.get("event") == "input_progress":
                    seq = obj.get("seq", 0)
                    with self._progress_cond:
                        if seq > self._input_progress_seq:
                            self._input_progress_seq = seq
                            self._progress_cond.notify_all()
                    continue
                if obj.get("event") == "input_done":
                    print(f"[ctrl] input_done from {addr[0]}:{addr[1]}; "
                          f"emulator stays up for live play (use 'make kill' to stop)",
                          file=sys.stderr, flush=True)
                    with self._progress_cond:
                        self._input_done_received = True
                        self._progress_cond.notify_all()
        with self.lock:
            if conn in self.clients:
                self.clients.remove(conn)
        try: conn.close()
        except OSError: pass

    def broadcast(self, seq, port, direction, opcode) -> None:
        self._send({"seq": seq, "port": port, "dir": direction,
                    "opcode": opcode})

    def broadcast_desync(self, seq, port, got_op, want_op) -> None:
        self._send({"event": "desync", "seq": seq, "port": port,
                    "got_op": got_op, "want_op": want_op})

    def broadcast_event(self, event: str, **kwargs) -> None:
        payload = {"event": event}
        payload.update(kwargs)
        self._send(payload)

    def _send(self, obj) -> None:
        data = (json.dumps(obj) + "\n").encode("utf-8")
        with self.lock:
            dead = []
            for c in self.clients:
                try:
                    c.sendall(data)
                except (ConnectionError, OSError):
                    dead.append(c)
            for c in dead:
                self.clients.remove(c)
                try: c.close()
                except OSError: pass


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Stateful in-world handlers (Phase 9 port).
#
# After the recorded S2C burst exhausts, the connection stays alive and we
# respond to live C2S movement / heartbeats from in-memory state. This
# turns a v1 "play recording then exit" session into a "play recording
# then stay in-world freely" session — clicks past the recording's end
# generate movement, server echoes back, character keeps walking around
# the recorded map without needing further packets.

def _build_b3_position_echo(actor_id: int, x: int, y: int,
                             seq: int = 0) -> bytes:
    """Build plaintext 0xb3/0x01 actor-position echo frame.
    Layout (cracked from PHASES/009/proto_18123.py):
      [u16 LE total_len][u8 op=0xb3][u8 seq][u8 sub=0x01]
      [u16 LE actor_id][u16 LE x][u16 LE y]
    """
    body = struct.pack("<BBHHH", seq & 0xFF, 0x01, actor_id, x, y)
    op = 0xB3
    plain_len = 1 + len(body)  # op + body
    total_len = 2 + plain_len
    return struct.pack("<H", plain_len) + bytes([op]) + body


def _parse_bc_move(plain: bytes):
    """Recover (x,y) from a 0xbc/0x16 C2S frame's plaintext bytes.
    plain[7:] = [seq][sub=0x16][x_LE][y_LE] (6 B)."""
    if len(plain) < 13:
        return None
    body = plain[7:]
    if len(body) != 6 or body[1] != 0x16:
        return None
    x = struct.unpack_from("<H", body, 2)[0]
    y = struct.unpack_from("<H", body, 4)[0]
    return (x, y)


def _extract_actor_id_from_spawn(world_q: List[dict]) -> Optional[int]:
    """Scan recorded S2C 18123 frames for the self-spawn 0xb1/0x01 and
    return its actor_id. The actor_id is needed to echo movement frames
    in-character (client validates the actor_id in echo equals the spawn).
    """
    for rec in world_q:
        if rec.get("dir") != "S2C":
            continue
        if rec.get("opcode") != 0xB1:
            continue
        try:
            plain = bytes.fromhex(rec["payload_hex"])
        except (ValueError, KeyError):
            continue
        # 0xb1 layout: [len][op][seq][sub][actor_id_LE]...
        if len(plain) < 6 or plain[3] != 0x01:
            continue
        return struct.unpack_from("<H", plain, 4)[0]
    return None


# Recorded "exit world" frames that v1 sessions end with. We strip these
# so the connection doesn't tear down at burst end.
EXIT_WORLD_FRAMES = {
    (0xB0, 0x13),  # leave-map probe
    (0x03, 0x00),  # session-end disconnect
}


def _is_exit_world_frame(rec: dict) -> bool:
    op = rec.get("opcode")
    if op is None:
        return False
    try:
        plain = bytes.fromhex(rec.get("payload_hex", ""))
    except ValueError:
        return False
    if len(plain) < 4:
        return False
    sub = plain[3]
    return (op, sub) in EXIT_WORLD_FRAMES


# Connection handler — world ports (18123/18124) — full cipher replay.

def _pack_world_frame(plain: bytes) -> bytes:
    """Encrypt + length-encode a recorded plaintext world frame for the wire."""
    if len(plain) < 4:
        return plain
    decoded_len = struct.unpack_from("<H", plain, 0)[0]
    enc = _world_cipher.encrypt_frame(plain)
    raw_len = _world_cipher.length_encode(decoded_len, enc[2], enc[3])
    out = bytearray(enc)
    struct.pack_into("<H", out, 0, raw_len & 0xFFFF)
    return bytes(out)


def _read_world_frame(sock: socket.socket) -> Optional[bytes]:
    """Read one wire-encrypted world frame and return its plaintext bytes."""
    head = _recv_exact(sock, 4)
    if head is None:
        return None
    decoded_len = _world_cipher.length_decode(head)
    if decoded_len < 6 or decoded_len > 0x10000:
        return None
    body = _recv_exact(sock, decoded_len - 2)
    if body is None:
        return None
    full = bytearray(4 + len(body))
    struct.pack_into("<H", full, 0, decoded_len)
    full[2:] = head[2:] + body
    ok, plain = _world_cipher.decrypt_frame(bytes(full))
    if not ok:
        return None
    return plain


def handle_world_conn(sock: socket.socket, addr, port: int, queue: List[dict],
                      ctrl: "ControlBus") -> None:
    log = lambda s: print(f"[port={port} {addr[0]}:{addr[1]}] {s}", file=sys.stderr, flush=True)
    log(f"world connected; recorded queue has {len(queue)} entries")

    # Filter out "exit world" S2C frames so the connection doesn't close
    # at recording's end; the stateful loop below keeps the world alive.
    keep_world_alive = bool(CFG.get("keep_world_alive", True))
    raw_s2c_recs = [r for r in queue if r["dir"] == "S2C"]
    if keep_world_alive and port == 18123:
        s2c_recs = [r for r in raw_s2c_recs if not _is_exit_world_frame(r)]
        skipped = len(raw_s2c_recs) - len(s2c_recs)
        if skipped:
            log(f"keep-alive: stripped {skipped} exit-world S2C frame(s)")
    else:
        s2c_recs = raw_s2c_recs
    c2s_recs = [r for r in queue if r["dir"] == "C2S"]
    log(f"world S2C={len(s2c_recs)} C2S={len(c2s_recs)}")

    # Cache actor_id from recorded self-spawn so live move-echoes carry it.
    actor_id = _extract_actor_id_from_spawn(queue) if port == 18123 else None
    if port == 18123:
        log(f"keep-alive: actor_id={actor_id}")
    player_x = player_y = 0  # last reported position

    stop = threading.Event()

    def _push_s2c():
        # Push all recorded S2C frames in seq order. Cipher is stateless
        # per-frame, so we can re-encrypt each plaintext payload and send.
        pace = bool(CFG.get("pace", True))
        paced_recs = [r for r in s2c_recs if r.get("t_ns") is not None]
        rec_t0 = paced_recs[0]["t_ns"] if (pace and paced_recs) else None
        play_t0 = time.monotonic_ns()
        rec_span_s = ((s2c_recs[-1]["t_ns"] - s2c_recs[0]["t_ns"]) / 1e9
                      if (pace and rec_t0 is not None and s2c_recs[-1].get("t_ns")) else 0.0)
        if pace and rec_t0 is not None:
            log(f"[pace] world S2C: {len(s2c_recs)} frames spanning {rec_span_s:.1f}s (rec) starting playback")
        sent = 0
        speed = float(CFG.get("speed", 1.0)) or 1.0
        lookahead = int(CFG.get("world_lookahead_seq", 100))
        gate_timeout = float(CFG.get("world_gate_timeout_s", 30.0))
        for rec in s2c_recs:
            if stop.is_set():
                return
            if pace and rec_t0 is not None and rec.get("t_ns") is not None:
                target = play_t0 + int((rec["t_ns"] - rec_t0) / speed)
                if not _paced_sleep(target, stop):
                    return
            rec_seq = rec.get("seq")
            if rec_seq is not None:
                target_seq = rec_seq - lookahead
                if not ctrl.wait_for_input_progress(target_seq, gate_timeout):
                    log(f"[gate] timeout waiting for input progress >= {target_seq} "
                        f"(current S2C seq={rec_seq}); pushing anyway")
            try:
                plain = bytes.fromhex(rec["payload_hex"])
            except ValueError:
                continue
            wire = _pack_world_frame(plain)
            try:
                sock.sendall(wire)
            except (ConnectionError, OSError) as e:
                log(f"world S2C send failed seq={rec['seq']}: {e}")
                return
            ctrl.broadcast(rec["seq"], port, "S2C", rec["opcode"])
            sent += 1
        elapsed_s = (time.monotonic_ns() - play_t0) / 1e9
        if pace and rec_t0 is not None:
            log(f"[pace] world S2C: pushed {sent} frames in {elapsed_s:.1f}s (rec was {rec_span_s:.1f}s)")
        else:
            log(f"world: pushed {sent} S2C frames")
        if sent > 0 and ctrl.mark_s2c_port_done(port):
            ctrl.broadcast_event("recording_done", port=port, sent=sent)

    pusher = threading.Thread(target=_push_s2c, daemon=True, name=f"world-push-{port}")
    pusher.start()

    # Drain incoming C2S; decrypt + handle. After the recorded S2C burst
    # exhausts (S2C pusher exits), this loop is what keeps the connection
    # alive: 0xbc/0x16 movement gets a synthetic position-echo reply, and
    # heartbeats are silently absorbed. The client thinks it's still in a
    # live world session — clicks generate movement, character walks, no
    # disconnect.
    while not stop.is_set():
        plain = _read_world_frame(sock)
        if plain is None:
            log("world client closed")
            stop.set()
            return
        if len(plain) < 8:
            continue
        # plain layout: [u16 len][u8 op][u8 ?][u32 ?][u8 seq][u8 sub][...body]
        # Opcode is byte 2; sub is at byte 8.
        op = plain[2]
        sub = plain[8] if len(plain) > 8 else 0xFF
        if port == 18123 and keep_world_alive and op == 0xBC and sub == 0x16:
            # Movement: echo position back so client's local entity stays
            # synced and other clients (none here) would see the move.
            move = _parse_bc_move(plain)
            if move is not None and actor_id is not None:
                player_x, player_y = move
                echo_plain = _build_b3_position_echo(
                    actor_id, player_x, player_y)
                try:
                    sock.sendall(_pack_world_frame(echo_plain))
                    log(f"keep-alive: 0xbc/0x16 move ({player_x},{player_y}) "
                        f"-> 0xb3/0x01 echo")
                except (ConnectionError, OSError) as e:
                    log(f"keep-alive: echo send failed: {e}")
                    return
            continue
        if op == 0x05:
            # Heartbeat — drop silently (connection-alive is enough).
            continue
        # Diagnostic for everything else.
        log(f"world C2S op=0x{op:02x} sub=0x{sub:02x} len={len(plain)}")


# ---------------------------------------------------------------------------
# Listeners

class Listener(threading.Thread):
    def __init__(self, bind: str, port: int, queue: Optional[List[dict]], world: bool,
                 stop_evt: threading.Event, ctrl: ControlBus,
                 rewrite_ip: Optional[bytes], prod_ips: List[bytes]):
        super().__init__(daemon=True, name=f"listen-{port}")
        self.bind = bind
        self.port = port
        self.queue = queue
        self.world = world
        self.stop_evt = stop_evt
        self.ctrl = ctrl
        self.rewrite_ip = rewrite_ip
        self.prod_ips = prod_ips
        self.sock: Optional[socket.socket] = None

    def run(self) -> None:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.bind, self.port))
        except OSError as e:
            print(f"[port={self.port}] bind failed: {e}", file=sys.stderr, flush=True)
            return
        s.listen(4)
        s.settimeout(0.5)
        self.sock = s
        kind = "world" if self.world else "login"
        n = len(self.queue) if self.queue else 0
        print(f"[port={self.port}] listening on {self.bind}:{self.port} "
              f"({kind}, {n} recorded entries)",
              file=sys.stderr, flush=True)

        while not self.stop_evt.is_set():
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            t = threading.Thread(
                target=self._handle, args=(conn, addr), daemon=True,
                name=f"conn-{self.port}-{addr[1]}",
            )
            t.start()

        try:
            s.close()
        except OSError:
            pass

    def _handle(self, conn: socket.socket, addr) -> None:
        try:
            if self.world:
                handle_world_conn(conn, addr, self.port, self.queue or [], self.ctrl)
            else:
                handle_login_conn(conn, addr, self.port, self.queue or [],
                                  self.ctrl, self.rewrite_ip, self.prod_ips)
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Main

def main() -> int:
    ap = argparse.ArgumentParser(description="Phase 2 server emulator (Mac side)")
    ap.add_argument("recording", help="path to recording_<id>.jsonl")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--ports", default="1818,1819,18123,18124")
    ap.add_argument("--ctrl-port", type=int, default=18999,
                    help="control bus port (broadcasts match events to replayer)")
    ap.add_argument("--rewrite-host", default=None,
                    help="rewrite 0xd1 server-list entries to this IPv4 (e.g. 192.168.12.148) "
                         "so client picks our emulator instead of recorded prod IPs")
    ap.add_argument("--no-pace", action="store_true",
                    help="disable wall-clock S2C pacing; burst all frames at line rate "
                         "(faster iteration; default is pacing on)")
    ap.add_argument("--speed", type=float, default=1.0,
                    help="playback speed multiplier for S2C pacing. 2.0 = "
                         "deliver server packets twice as fast; pair with "
                         "the replayer's --speed so input + network stay "
                         "synchronized.")
    ap.add_argument("--world-lookahead-seq", type=int, default=100,
                    help="how many recorded events the world S2C pusher may "
                         "lead the input replayer by. S2C with seq=N waits "
                         "until input_progress reaches N-lookahead.")
    ap.add_argument("--world-gate-timeout-s", type=float, default=30.0,
                    help="if input progress stalls this long, push the next "
                         "S2C anyway (prevents deadlock if replayer dies).")
    ap.add_argument("--no-keep-world-alive", action="store_true",
                    help="disable post-burst stateful handoff (default: stay "
                         "in-world after recording exhausts; movement gets a "
                         "synthetic 0xb3/0x01 echo, heartbeats absorbed).")
    ap.add_argument("--swap-with-character", default=None,
                    help="replace the recorded self_spawn payload with the "
                         "spawn frame of NAME (case-insensitive prefix match) "
                         "found later in the recording's port-18123 S2C "
                         "queue. Live client renders that character as self.")
    args = ap.parse_args()
    CFG["pace"] = not args.no_pace
    CFG["speed"] = float(args.speed) or 1.0
    CFG["world_lookahead_seq"] = int(args.world_lookahead_seq)
    CFG["world_gate_timeout_s"] = float(args.world_gate_timeout_s)
    CFG["keep_world_alive"] = not args.no_keep_world_alive

    if not os.path.isfile(args.recording):
        print(f"recording not found: {args.recording}", file=sys.stderr)
        return 2

    by_port = load_net_events_by_port(args.recording)
    print(f"loaded {sum(len(v) for v in by_port.values())} net events "
          f"across ports {sorted(by_port.keys())}", file=sys.stderr, flush=True)

    if args.swap_with_character:
        swap_self_with_character(by_port, args.swap_with_character)

    all_t = [r["t_ns"] for q in by_port.values() for r in q
             if r.get("t_ns") is not None]
    rec_dur_s = (max(all_t) - min(all_t)) / 1e9 if all_t else 0.0
    expected_s = rec_dur_s / max(CFG["speed"], 0.001)
    print(f"[timer] recording={rec_dur_s:.1f}s; at speed={CFG['speed']} "
          f"expected={expected_s:.1f}s", file=sys.stderr, flush=True)
    t_start = time.monotonic()

    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
    stop_evt = threading.Event()

    ctrl = ControlBus(args.bind, args.ctrl_port, stop_evt)
    for p, q in by_port.items():
        if p in (18123, 18124) and any(r["dir"] == "S2C" for r in q):
            ctrl.register_pending_s2c_port(p)
    ctrl_thread = threading.Thread(target=ctrl.serve, daemon=True, name="ctrl")
    ctrl_thread.start()

    rewrite_ip: Optional[bytes] = None
    prod_ips: List[bytes] = []
    if args.rewrite_host:
        rewrite_ip = ipv4_to_be_bytes(args.rewrite_host)
        prod_ips = collect_prod_ips(args.recording)
        # Also catch the *non-server-endpoint* IPs that only show up in
        # 0xd1 server-list payloads (e.g. the second server's address that
        # may not appear in any actual TCP flow). Easier to scan once and
        # union them in.
        for queue in by_port.values():
            for rec in queue:
                if rec["dir"] != "S2C":
                    continue
                try:
                    payload = bytes.fromhex(rec["payload_hex"])
                except ValueError:
                    continue
                # Look for `[4-B host][1b 07]` (port 1819 LE) signature.
                i = 4
                while i + 1 < len(payload):
                    if payload[i] == 0x1b and payload[i + 1] == 0x07:
                        host = bytes(payload[i - 4:i])
                        if (host not in prod_ips
                                and host[0] not in (0, 127)
                                and host != rewrite_ip):
                            prod_ips.append(host)
                    i += 1
        ip_strs = ['.'.join(str(b) for b in ip) for ip in prod_ips]
        print(f"[main] rewriting prod IPs -> {args.rewrite_host}: "
              f"{ip_strs}", file=sys.stderr, flush=True)

    listeners: List[Listener] = []
    for p in ports:
        world = p in (18123, 18124)
        listeners.append(Listener(args.bind, p, by_port.get(p, []), world,
                                  stop_evt, ctrl, rewrite_ip, prod_ips))

    for lis in listeners:
        lis.start()

    def _sigint(signum, frame):
        print("\n[main] SIGINT; shutting down", file=sys.stderr, flush=True)
        stop_evt.set()
    signal.signal(signal.SIGINT, _sigint)
    signal.signal(signal.SIGTERM, _sigint)

    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_evt.set()

    for lis in listeners:
        lis.join(timeout=2.0)
    elapsed = time.monotonic() - t_start
    diff = elapsed - expected_s
    print(f"[timer] elapsed={elapsed:.1f}s (expected={expected_s:.1f}s, "
          f"diff={diff:+.1f}s)", file=sys.stderr, flush=True)
    print("[main] done", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

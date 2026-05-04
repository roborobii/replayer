"""spawn_parser.py - Shared parser for spawn-bearing 18123 frames.

Plaintext frame layout (post-decrypt):
    [u16 LE length][u8 op][u32 LE crc][u8 seq][u8 sub][body...]
    payload[0:2]  = length (counts bytes from op onward; wire size = length+2)
    payload[2]    = real opcode
    payload[3:7]  = crc
    payload[7]    = sub-batch seq counter
    payload[8]    = sub-opcode

Two spawn-bearing frame variants (verified against
sessions/recording_smoke5.jsonl seq 2725 and 2753):

  op=0xB0, sub=0x11  map-load:
      payload[9:13]  u32 LE = map_id
      payload[13:15] u16 LE = spawn_x
      payload[15:17] u16 LE = spawn_y
      total len >= 17

  op=0xB1, sub=0x01  self-spawn:
      payload[10:12] u16 LE = actor_id
      payload[32:34] u16 LE = x
      payload[34:36] u16 LE = y
      payload[56:58] u16 LE = name_len
      payload[58:58+name_len] UTF-8 = name
"""
from __future__ import annotations

import struct


def parse_spawn_frame(payload_bytes: bytes) -> dict | None:
    """Return spawn dict or None if frame is not spawn-bearing.

    Reads op from payload_bytes[2] and sub from payload_bytes[8].
    """
    if len(payload_bytes) < 9:
        return None
    op = payload_bytes[2]
    sub = payload_bytes[8]

    if op == 0xB0 and sub == 0x11:
        if len(payload_bytes) < 17:
            return None
        map_id = struct.unpack_from("<I", payload_bytes, 9)[0]
        x = struct.unpack_from("<H", payload_bytes, 13)[0]
        y = struct.unpack_from("<H", payload_bytes, 15)[0]
        return {
            "kind": "map_load",
            "map_id": int(map_id),
            "x": int(x),
            "y": int(y),
            "actor_id": None,
            "name": None,
        }

    if op == 0xB1 and sub == 0x01:
        if len(payload_bytes) < 36:
            return None
        actor_id = struct.unpack_from("<H", payload_bytes, 10)[0]
        x = struct.unpack_from("<H", payload_bytes, 32)[0]
        y = struct.unpack_from("<H", payload_bytes, 34)[0]
        name = None
        if len(payload_bytes) >= 58:
            name_len = struct.unpack_from("<H", payload_bytes, 56)[0]
            end = min(58 + name_len, len(payload_bytes))
            if name_len > 0 and end > 58:
                try:
                    name = payload_bytes[58:end].decode("utf-8")
                except UnicodeDecodeError:
                    name = None
        return {
            "kind": "self_spawn",
            "map_id": None,
            "x": int(x),
            "y": int(y),
            "actor_id": int(actor_id),
            "name": name,
        }

    return None

"""Phase 7 — 18123 cipher (encrypt + decrypt).

Direct port of `FUN_00152cd4` (per-frame decrypt) and `FUN_00152be4`
(length decode) from `solstice-client/XenRebirth_Xenepic/DXRender.exe`,
plus the inverse `encrypt_frame` so the server can synthesize world
frames from scratch. Decrypt validated end-to-end against the 292
(ciphertext, plaintext) pairs captured via Frida at
`PHASES/006/captures/cipher/iter6_eax_register_fix.jsonl`
(sha256 74d3a4b09b62af96c0b4254e45db293d5c54de414f5a2937b85f933dea92e0bd).
Encrypt validated by round-tripping the same captured plaintexts back
to their original ciphertexts byte-for-byte.

================================================================
Wire layout (post length-decode)
================================================================

    [u16 LE length-excluding-self][u8 op][u32 LE CRC][payload...]
        bytes 0-1                  byte 2  bytes 3-6  bytes 7..length+1

  - bytes 0-1: length (encrypted on wire; decoded by `length_decode`).
  - byte 2: opcode (encrypted by Stage 1+2).
  - bytes 3-6: 32-bit CRC of the decrypted payload, computed via
    FUN_00068a20's multiplicative hash. Plaintext on the wire — used
    by the decryptor to verify the keying material.
  - bytes 7+: payload (encrypted by Stage 1+4).

================================================================
Algorithm (Ghidra `FUN_00152cd4`)
================================================================

Stage 1 — bit-rotation pass keyed by byte 3 / CRC:
  byte 2 = ROR8(byte_2, byte_3)
  iVar7 = (CRC_u32 % 7) + 1
  for each u32 word in payload (whole words from bytes 7..):
      word = ROR32(word, iVar7)
  for each remaining byte (length-5 mod 4):
      byte = ROR8(byte, iVar7)

Stage 1 sanity check — CRC equality:
  if FUN_00068a20(post-Stage-1 payload) != CRC_u32: bail.

Stage 2 — byte 2 / byte 7 cross-XOR:
  m = (length & 0xff) ^ byte_1 ^ 0x1e
  byte 7 ^= m
  m ^= byte_7   # m is now the *pre-Stage-2* byte 7 (post-Stage-1)
  byte 2 ^= m

Stage 4 — payload keystream XOR (length > 6 only):
  local_c = bytes(m, m, m, m) interpreted as u32 LE
  local_c ^= 0xb244c01e
  for each u32 word in payload starting at byte 8:
      word ^= local_c
      local_c = ROL32(local_c, 1)
  for each remaining trailing byte:
      byte ^= ((local_c >> (i*8)) & 0xff)

================================================================
Encrypt direction (inverse of `FUN_00152cd4`)
================================================================

`encrypt_frame` undoes the four stages in reverse: Stage 4 -> Stage 2
-> CRC field synthesis -> Stage 1. The Stage 4 XOR is involutive so
the same keystream applies in either direction; Stage 2 byte 7 is
restored to its post-Stage-1 form before we can recompute the CRC of
that payload window; Stage 1 ROR8/ROR32 become ROL8/ROL32.

================================================================
Length codec (FUN_00152be4 / FUN_00152c6c)
================================================================

Length decode runs first on the recv ring before each frame is
dispatched (`FUN_00152c6c` is the buffer-mutating wrapper around
`FUN_00152be4`, which is the value-returning core):

  raw = u16_le(bytes_0_1)
  k1  = (byte_2 % 7) + 1
  k2  = (byte_3 % 7) + 1
  decoded = ROL16( ROR16(raw, k1) ^ 0xC01E , k2 )

The encode (server-side; inverse of the above):

  raw = ROL16( ROR16(decoded, k2) ^ 0xC01E , k1 )

`FUN_000685d8` and `FUN_00068624` are both straight 16-bit rotations
by `(n & 7)` — `FUN_000685d8` is ROR16, `FUN_00068624` is ROL16.
The Phase 6 port mis-translated `FUN_000685d8`'s OR-into-high-byte
reassembly as OR-into-low-byte, which scrambled bits and produced
garbage decoded lengths; this is the bug Phase 7 fixes. Validated
292/292 against `PHASES/004/real_pcap/18123_s2c.bin` (both decode
and encode directions).
"""

from __future__ import annotations

import struct
from typing import Tuple


# ----------------------------------------------------------------------
# Primitives — direct ports of the Borland helpers
# ----------------------------------------------------------------------


def ror8(b: int, n: int) -> int:
    """FUN_00068664 — byte ROR by (n & 7). n=0 returns b unchanged."""
    n &= 7
    if n == 0:
        return b & 0xFF
    return ((b << (8 - n)) | (b >> n)) & 0xFF


def rol8(b: int, n: int) -> int:
    """Byte ROL by (n & 7). n=0 returns b unchanged. Inverse of ror8."""
    n &= 7
    if n == 0:
        return b & 0xFF
    return ((b << n) | (b >> (8 - n))) & 0xFF


def ror32(x: int, n: int) -> int:
    """FUN_00068554 — u32 ROR by (n & 7). n=0 returns x unchanged."""
    n &= 7
    if n == 0:
        return x & 0xFFFFFFFF
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def rol32(x: int, n: int) -> int:
    """FUN_0006859c — u32 ROL by (n & 7). n=0 returns x unchanged."""
    n &= 7
    if n == 0:
        return x & 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def rol16(x: int, n: int) -> int:
    """FUN_00068624 — u16 ROL by (n & 7). n=0 returns x unchanged."""
    n &= 7
    if n == 0:
        return x & 0xFFFF
    return ((x << n) | (x >> (16 - n))) & 0xFFFF


def ror16(x: int, n: int) -> int:
    """FUN_000685d8 — u16 ROR by (n & 7). n=0 returns x unchanged.

    The Ghidra C for FUN_000685d8 looked exotic (it stack-allocates a
    u16, does `shr` on the upper 16 bits via a 32-bit register, then
    OR-merges the dropped low bits into the high byte of the result),
    but the bit permutation it computes is exactly a 16-bit ROR by n
    — verified bit-by-bit from the raw asm at 0x685d8 and confirmed
    against all 292 pcap frames.
    """
    n &= 7
    if n == 0:
        return x & 0xFFFF
    return ((x >> n) | (x << (16 - n))) & 0xFFFF


def crc_hash(data: bytes) -> int:
    """FUN_00068a20 — multiplicative hash, returned as int32.

    iVar1 = 0
    for byte in data:
        iVar1 = byte + iVar1 * 0x1003f
    return iVar1
    """
    h = 0
    for b in data:
        h = (b + h * 0x1003F) & 0xFFFFFFFF
    return h


# ----------------------------------------------------------------------
# Length decode / encode (FUN_00152be4 + inverse)
# ----------------------------------------------------------------------


def length_decode(buf: bytes) -> int:
    """Decode the encrypted u16 length field at buf[0:2].

    Direct port of `FUN_00152be4`:
        raw = u16_le(buf[0:2])
        k1  = (buf[2] % 7) + 1
        k2  = (buf[3] % 7) + 1
        return ROL16( ROR16(raw, k1) ^ 0xC01E , k2 )
    """
    if len(buf) < 4:
        return -1
    raw = struct.unpack_from("<H", buf, 0)[0]
    k1 = (buf[2] % 7) + 1
    k2 = (buf[3] % 7) + 1
    return rol16(ror16(raw, k1) ^ 0xC01E, k2)


def length_encode(decoded: int, byte_2: int, byte_3: int) -> int:
    """Encode a u16 frame length for the wire — inverse of `length_decode`.

    Given the post-decode length and the (plaintext) bytes that will be
    stored at wire offsets 2 and 3, produce the encrypted u16 that goes
    at offsets 0..1.

        k1  = (byte_2 % 7) + 1
        k2  = (byte_3 % 7) + 1
        return ROL16( ROR16(decoded, k2) ^ 0xC01E , k1 )
    """
    k1 = (byte_2 % 7) + 1
    k2 = (byte_3 % 7) + 1
    return rol16(ror16(decoded & 0xFFFF, k2) ^ 0xC01E, k1)


# ----------------------------------------------------------------------
# Per-frame decrypt — FUN_00152cd4 port
# ----------------------------------------------------------------------


def decrypt_frame(buf: bytes) -> Tuple[bool, bytes]:
    """Decrypt a single 18123 frame in-place semantics, return (ok, plain).

    `buf` is the frame including the (already-decoded) length prefix:
    bytes 0-1 = length, byte 2 = opcode (encrypted), bytes 3-6 = CRC,
    bytes 7+ = payload (encrypted). Total frame size = length + 2.

    Returns (False, original_buf) if CRC verify fails.
    """
    if len(buf) < 4:
        return False, bytes(buf)
    length = struct.unpack_from("<H", buf, 0)[0]
    if length < 6:
        return False, bytes(buf)
    if len(buf) < length + 2:
        return False, bytes(buf)

    out = bytearray(buf)

    # --- Stage 1: byte 2 + payload rotations ---
    byte_3_raw = out[3]
    out[2] = ror8(out[2], byte_3_raw)

    crc_field = struct.unpack_from("<I", out, 3)[0]
    rot = (crc_field % 7) + 1

    payload_len = length - 5  # bytes 7..(7+payload_len)
    n_words = payload_len // 4 if payload_len >= 0 else (length - 2) // 4

    for i in range(n_words):
        off = 7 + i * 4
        word = struct.unpack_from("<I", out, off)[0]
        word = ror32(word, rot)
        struct.pack_into("<I", out, off, word)

    remaining = payload_len - n_words * 4
    for i in range(remaining):
        idx = 7 + n_words * 4 + i
        out[idx] = ror8(out[idx], rot)

    # --- Stage 1 sanity: CRC of post-rotation payload ---
    computed = crc_hash(bytes(out[7 : 7 + payload_len]))
    if computed != crc_field:
        return False, bytes(buf)

    # --- Stage 2: byte 2 / byte 7 cross-XOR ---
    m = (length & 0xFF) ^ out[1] ^ 0x1E
    out[7] ^= m
    m ^= out[7]  # m now equals the *pre-Stage-2* byte 7 (post-Stage-1)
    out[2] ^= m

    # --- Stage 4: payload keystream XOR (length > 6 only) ---
    if length > 6:
        local_c = (m << 24) | (m << 16) | (m << 8) | m
        local_c ^= 0xB244C01E

        ks_payload_len = length - 6  # bytes 8..(8+ks_payload_len)
        n_words2 = ks_payload_len // 4 if ks_payload_len >= 0 else (length - 3) // 4
        for i in range(n_words2):
            off = 8 + i * 4
            word = struct.unpack_from("<I", out, off)[0]
            word ^= local_c
            struct.pack_into("<I", out, off, word & 0xFFFFFFFF)
            local_c = rol32(local_c, 1)

        remaining2 = ks_payload_len - n_words2 * 4
        for i in range(remaining2):
            idx = 8 + n_words2 * 4 + i
            out[idx] ^= (local_c >> ((i & 3) * 8)) & 0xFF

    return True, bytes(out)


# ----------------------------------------------------------------------
# Per-frame encrypt — inverse of FUN_00152cd4
# ----------------------------------------------------------------------


def encrypt_frame(plain: bytes) -> bytes:
    """Encrypt a plaintext 18123 frame; inverse of decrypt_frame.

    Input layout matches decrypt_frame's output: bytes 0-1 = length,
    byte 2 = plaintext opcode, bytes 3-6 = CRC slot (ignored — recomputed),
    bytes 7+ = plaintext payload. Inverse-stage order:

      1. Undo Stage 4 (XOR is involutive) using the same keystream as
         decrypt; this requires recovering m from `length`/byte 1 and the
         post-Stage-1 byte 7 = m_init XOR plain[7].
      2. Undo Stage 2 by writing post_s1_b7 into byte 7 and
         (plain[2] XOR post_s1_b7) into byte 2.
      3. Recompute the CRC field over the post-Stage-1 payload window
         (bytes 7..7+payload_len) and write it into bytes 3-6 LE.
      4. Undo Stage 1: ROL32 each payload word and ROL8 each tail byte
         by (CRC % 7)+1, then ROL8 byte 2 by the freshly written CRC LSB.
    """
    if len(plain) < 4:
        return bytes(plain)
    length = struct.unpack_from("<H", plain, 0)[0]
    if length < 6 or len(plain) < length + 2:
        return bytes(plain)

    out = bytearray(plain)
    payload_len = length - 5

    m_init = (length & 0xFF) ^ out[1] ^ 0x1E
    post_s1_b7 = m_init ^ out[7]

    if length > 6:
        local_c = (post_s1_b7 << 24) | (post_s1_b7 << 16) | (post_s1_b7 << 8) | post_s1_b7
        local_c ^= 0xB244C01E

        ks_payload_len = length - 6
        n_words2 = ks_payload_len // 4 if ks_payload_len >= 0 else (length - 3) // 4
        for i in range(n_words2):
            off = 8 + i * 4
            word = struct.unpack_from("<I", out, off)[0]
            word ^= local_c
            struct.pack_into("<I", out, off, word & 0xFFFFFFFF)
            local_c = rol32(local_c, 1)

        remaining2 = ks_payload_len - n_words2 * 4
        for i in range(remaining2):
            idx = 8 + n_words2 * 4 + i
            out[idx] ^= (local_c >> ((i & 3) * 8)) & 0xFF

    out[2] = (out[2] ^ post_s1_b7) & 0xFF
    out[7] = post_s1_b7

    crc_field = crc_hash(bytes(out[7 : 7 + payload_len]))
    struct.pack_into("<I", out, 3, crc_field)

    rot = (crc_field % 7) + 1
    n_words = payload_len // 4 if payload_len >= 0 else (length - 2) // 4
    for i in range(n_words):
        off = 7 + i * 4
        word = struct.unpack_from("<I", out, off)[0]
        word = rol32(word, rot)
        struct.pack_into("<I", out, off, word)

    remaining = payload_len - n_words * 4
    for i in range(remaining):
        idx = 7 + n_words * 4 + i
        out[idx] = rol8(out[idx], rot)

    out[2] = rol8(out[2], out[3])

    return bytes(out)


# ----------------------------------------------------------------------
# Self-tests against captured Frida pairs
# ----------------------------------------------------------------------


def _load_pairs(jsonl_path: str):
    import json

    pairs = []
    cur_in = None
    with open(jsonl_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            e = json.loads(line)
            if e.get("evt") == "decrypt_enter":
                cur_in = e
            elif e.get("evt") == "decrypt_leave" and cur_in is not None:
                pairs.append((cur_in, e))
                cur_in = None
    return pairs


def _validate_against_capture(jsonl_path: str) -> Tuple[int, int, list]:
    """Run decrypt_frame against every (ciphertext, plaintext) pair from
    a Frida capture jsonl and report the pass/fail counts.
    """
    pairs = _load_pairs(jsonl_path)
    ok = 0
    fail_examples = []
    for ci, co in pairs:
        c_hex = ci.get("ciphertext", {}).get("hex", "")
        p_hex = co.get("plaintext", {}).get("hex", "")
        if not c_hex or not p_hex:
            continue
        c = bytes.fromhex(c_hex)
        p = bytes.fromhex(p_hex)
        success, decoded = decrypt_frame(c)
        if success and decoded[: len(p)] == p[: len(decoded)]:
            ok += 1
        else:
            if len(fail_examples) < 5:
                fail_examples.append((c, p, decoded, success))
    return ok, len(pairs), fail_examples


def _validate_roundtrip(jsonl_path: str) -> Tuple[int, int, list]:
    """Run encrypt_frame on each captured plaintext and compare against
    the captured ciphertext byte-for-byte.
    """
    pairs = _load_pairs(jsonl_path)
    ok = 0
    fail_examples = []
    for ci, co in pairs:
        c_hex = ci.get("ciphertext", {}).get("hex", "")
        p_hex = co.get("plaintext", {}).get("hex", "")
        if not c_hex or not p_hex:
            continue
        c = bytes.fromhex(c_hex)
        p = bytes.fromhex(p_hex)
        encoded = encrypt_frame(p)
        if encoded == c:
            ok += 1
        else:
            if len(fail_examples) < 5:
                fail_examples.append((c, p, encoded))
    return ok, len(pairs), fail_examples


def _validate_length_codec(pairs_path: str) -> Tuple[int, int, int, list, list]:
    """Validate length_decode + length_encode against the (raw, b2, b3, L)
    tuples extracted from PHASES/004/real_pcap/18123_s2c.bin (one entry
    per frame; 292 total).
    """
    import json

    with open(pairs_path) as f:
        pairs = json.load(f)

    ok_d = 0
    ok_e = 0
    fails_d = []
    fails_e = []
    for p in pairs:
        raw = p["raw"] & 0xFFFF
        b2 = p["b2"] & 0xFF
        b3 = p["b3"] & 0xFF
        L = p["L"] & 0xFFFF

        # Build a 4-byte synthetic prefix [raw_lo, raw_hi, b2, b3] for length_decode.
        prefix = bytes([raw & 0xFF, (raw >> 8) & 0xFF, b2, b3])
        decoded = length_decode(prefix)
        if decoded == L:
            ok_d += 1
        elif len(fails_d) < 5:
            fails_d.append((p, decoded))

        encoded = length_encode(L, b2, b3)
        if encoded == raw:
            ok_e += 1
        elif len(fails_e) < 5:
            fails_e.append((p, encoded))

    return ok_d, ok_e, len(pairs), fails_d, fails_e


if __name__ == "__main__":
    import os
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else \
        "../006/captures/cipher/iter6_eax_register_fix.jsonl"

    ok_d, total_d, fails_d = _validate_against_capture(path)
    print(f"Decrypt validation: {ok_d}/{total_d} pairs match")
    if fails_d:
        print("\nFirst decrypt failures:")
        for c, p, d, s in fails_d:
            print(f"  C: {c.hex()}")
            print(f"  P: {p.hex()}")
            print(f"  D: {d.hex()}  (success={s})")
            print()

    ok_e, total_e, fails_e = _validate_roundtrip(path)
    print(f"Encrypt round-trip: {ok_e}/{total_e} pairs match")
    if fails_e:
        print("\nFirst encrypt failures:")
        for c, p, e in fails_e:
            print(f"  C: {c.hex()}")
            print(f"  P: {p.hex()}")
            print(f"  E: {e.hex()}")
            print()

    here = os.path.dirname(os.path.abspath(__file__))
    pairs_path = os.path.join(here, "captures", "length_pairs.json")
    if os.path.exists(pairs_path):
        ok_ld, ok_le, total_l, lfd, lfe = _validate_length_codec(pairs_path)
        print(f"Length codec: {ok_ld}/{total_l} matches (decode), "
              f"{ok_le}/{total_l} matches (encode)")
        if lfd:
            print("\nFirst length decode failures:")
            for p, d in lfd:
                print(f"  raw=0x{p['raw']:04x} b2=0x{p['b2']:02x} "
                      f"b3=0x{p['b3']:02x} expected_L={p['L']} got_L={d}")
        if lfe:
            print("\nFirst length encode failures:")
            for p, e in lfe:
                print(f"  L={p['L']} b2=0x{p['b2']:02x} b3=0x{p['b3']:02x} "
                      f"expected_raw=0x{p['raw']:04x} got_raw=0x{e:04x}")
    else:
        print(f"Length codec: SKIPPED (run _extract_length_pairs.py first to "
              f"populate {pairs_path})")

"""V2 stream cipher for XenClient/DXRender world server (port 18123).

Reverse-engineered from /Users/robin/proj/v2_re/dxr.bin:
  decrypt routine at VA 0x152cd4 (RVA 0x142cd4)
  encrypt routine at VA 0x152a1c (RVA 0x142a1c)
  PRNG step ROL32 helper at VA 0x6859c
  ROR32 helper at VA 0x68554
  ROL8/ROR8 helpers at VA 0x68690/0x68664
  CRC helper at VA 0x68a20: crc = crc * 0x1003F + byte (running u32)
  PRNG seed  : 0xB244C01E  (V1 was 0xC08AEF25)
  Header XOR : 0x1E        (V1 was 0x25)
  Length XOR : 0xC01E      (V1 was 0xEF25)

Length decoding (function VA 0x152be4) is NOT a flat XOR — it's:
    n1   = (cipher_buf[2] % 7) + 1     # rotation by encrypted byte 2
    ax   = ROR16(u16(cipher_buf[0:2]), n1)
    ax  ^= 0xC01E
    n2   = (cipher_buf[3] % 7) + 1     # rotation by encrypted byte 3
    plain_len = ROL16(ax, n2)
This means both bytes 2 and 3 must remain in their original (ciphertext) form
when we extract the length. Body length on wire = plain_len + 2.

Frame layout (plaintext):
  +0 : u16 len            -- length field (semantics: number of bytes after offset 5)
  +2 : u8  byte2          -- second-key derived byte
  +3 : u32 crc            -- crc32-like hash of body bytes (computed over buf[7..7+len-5])
  +7 : body[len-5]        -- payload (opcode is body[0])
Total frame size on the wire = len + 2 bytes.
"""

import struct


# ---- 32-bit rotate helpers (matching VA 0x6859c / 0x68554) ----
def _rol32(v: int, n: int) -> int:
    n &= 31
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF if n else v & 0xFFFFFFFF


def _ror32(v: int, n: int) -> int:
    n &= 31
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF if n else v & 0xFFFFFFFF


def _rol8(b: int, n: int) -> int:
    n &= 7
    return ((b << n) | (b >> (8 - n))) & 0xFF if n else b & 0xFF


def _ror8(b: int, n: int) -> int:
    n &= 7
    return ((b >> n) | (b << (8 - n))) & 0xFF if n else b & 0xFF


def _rol16(v: int, n: int) -> int:
    n &= 15
    return ((v << n) | (v >> (16 - n))) & 0xFFFF if n else v & 0xFFFF


def _ror16(v: int, n: int) -> int:
    n &= 15
    return ((v >> n) | (v << (16 - n))) & 0xFFFF if n else v & 0xFFFF


def extract_length(cipher_buf: bytes) -> int:
    """Decode plaintext length from the still-encrypted frame head (>=4 bytes).

    Mirrors VA 0x152be4. Returns the plaintext length field; total wire
    bytes for the frame is `plain_len + 2`.
    """
    if len(cipher_buf) < 4:
        return -1
    u = cipher_buf[0] | (cipher_buf[1] << 8)
    n1 = (cipher_buf[2] % 7) + 1
    ax = _ror16(u, n1)
    ax ^= LEN_MASK
    n2 = (cipher_buf[3] % 7) + 1
    return _rol16(ax, n2)


def _crc(buf: bytes) -> int:
    """Mirror VA 0x68a20: crc = byte + (crc<<6) + (crc<<16) - crc, all u32."""
    crc = 0
    for b in buf:
        crc = (b + (crc << 6) + (crc << 16) - crc) & 0xFFFFFFFF
    return crc


SEED_CONST = 0xB244C01E
HEAD_MASK  = 0x1E
LEN_MASK   = 0xC01E


def _decrypt_inplace(b: bytearray) -> bool:
    """Decrypt one frame in-place; b[0:2] must already hold plaintext length."""
    if len(b) < 7:
        return False
    plain_len = b[0] | (b[1] << 8)
    if plain_len < 6:
        return False

    # Frame body covers buf[7..7+(plain_len-5)) i.e. plain_len-5 bytes after byte 6.
    body_total = plain_len - 5
    if 7 + body_total > len(b):
        # plaintext length disagrees with received frame length; bail.
        return False

    # ----- Phase 1: undo per-byte ROR8 of buf[2] (n = b[3] & 7, +1 inside helper) -----
    # decrypt does: al = ROR8(buf[2], buf[3]); buf[2] = al  (encrypt did ROL8 with same key)
    n2 = (b[3] & 7)
    if n2 == 0: n2 = 8  # actually: helper does (n & 7) and falls through if 0; but
    # the asm: "and edx, 7; jg ...; if edx<=0 return value unchanged"
    # so a count of 0 means no rotation. Don't add +1 here.
    n2 = b[3] & 7
    if n2:
        b[2] = _ror8(b[2], n2)

    # ----- Phase 2: ROR32 each u32 word in body by rot_count = (crc%7)+1 -----
    crc_field = struct.unpack_from('<I', b, 3)[0]
    rot = (crc_field % 7) + 1
    word_count = body_total // 4
    for i in range(word_count):
        off = 7 + i * 4
        w = struct.unpack_from('<I', b, off)[0]
        struct.pack_into('<I', b, off, _ror32(w, rot))

    # ----- Phase 3: ROR8 the trailing remainder bytes by same rot -----
    rem = body_total - word_count * 4
    base = 7 + word_count * 4
    for i in range(rem):
        b[base + i] = _ror8(b[base + i], rot)

    # ----- Phase 4: verify CRC matches stored field -----
    computed = _crc(bytes(b[7:7 + body_total]))
    if computed != crc_field:
        # Don't hard-fail: still surface the data for inspection.
        pass

    # ----- Phase 5: header XOR -----
    al = b[0] ^ b[1] ^ HEAD_MASK
    b[7] ^= al            # b[7] now holds plaintext seed byte
    al ^= b[7]            # al = original al ^ plain_seed  (this is the PRNG seed byte)
    b[2] ^= al
    prng_seed = al

    # ----- Phase 6: PRNG body XOR over buf[8..] -----
    if plain_len > 6:
        state = int.from_bytes(bytes([prng_seed]) * 4, 'little') ^ SEED_CONST
        body_xor_total = plain_len - 6  # bytes from offset 8 onward
        wcount = body_xor_total // 4
        for i in range(wcount):
            off = 8 + i * 4
            w = struct.unpack_from('<I', b, off)[0]
            struct.pack_into('<I', b, off, w ^ state)
            state = _rol32(state, 1)
        # remainder
        rem = body_xor_total - wcount * 4
        base = 8 + wcount * 4
        sb = state.to_bytes(4, 'little')
        for i in range(rem):
            b[base + i] ^= sb[i]
    return True


def _encrypt_inplace(b: bytearray) -> bool:
    """Encrypt one plaintext frame in-place. b[0:2] holds plaintext length."""
    if len(b) < 7:
        return False
    plain_len = b[0] | (b[1] << 8)
    if plain_len < 6:
        return False
    body_total = plain_len - 5
    if 7 + body_total > len(b):
        return False

    # ----- Inverse Phase 6: PRNG body XOR -----
    seed_byte = b[7]  # plaintext byte
    if plain_len > 6:
        state = int.from_bytes(bytes([seed_byte]) * 4, 'little') ^ SEED_CONST
        body_xor_total = plain_len - 6
        wcount = body_xor_total // 4
        for i in range(wcount):
            off = 8 + i * 4
            w = struct.unpack_from('<I', b, off)[0]
            struct.pack_into('<I', b, off, w ^ state)
            state = _rol32(state, 1)
        rem = body_xor_total - wcount * 4
        base = 8 + wcount * 4
        sb = state.to_bytes(4, 'little')
        for i in range(rem):
            b[base + i] ^= sb[i]

    # ----- Inverse Phase 5: header XOR -----
    al0 = b[0] ^ b[1] ^ HEAD_MASK    # this equals plaintext seed_byte
    # encrypt order:  buf[2] ^= al ; buf[7] ^= al ^ buf[2] ?
    # decrypt did: al^seed_byte; b[7]^=al; al^=b[7]; b[2]^=al
    # We need the inverse. Currently b[7] is plaintext (== seed_byte), b[2] is plaintext byte2.
    # Apply: b[2] ^= al0  (since decrypt's last step was b[2]^=al where al=buf[7]_plain)
    b[2] ^= al0  # because decrypt sets al=buf[7]_plain at this point; al = al0
    # Now b[2] is "encrypted" wrt phase 5. Then b[7] ^= al0 to get encrypted byte7.
    b[7] ^= al0

    # ----- Inverse Phase 2/3: ROL32 over body words, ROL8 over remainder, by (crc%7)+1 -----
    # First need CRC of plaintext body (compute BEFORE phase 5 broke b[7]/b[2]).
    # Wait — encrypt actually computes CRC over current body (after phase 5/6 only modify head bytes [0..7]).
    # In decrypt, CRC verify happens AFTER ROR-undo and BEFORE header-undo. So CRC was computed
    # over (post-rotate) body == plaintext body. So in encrypt: compute CRC of plaintext body first,
    # store in b[3..6], then apply ROL.
    # We've already mutated b[2] and b[7]; but body is bytes 7..end. b[7] is now ENCRYPTED,
    # so we must undo our header step before CRC computation, or compute CRC earlier.
    # Easier: redo this function in the proper order.
    raise NotImplementedError("encrypt: see ordered helper below")


def encrypt_frame(plaintext: bytes, encode_length: bool = False) -> bytes:
    """Encrypt a plaintext frame (with plaintext u16 length at offset 0).

    Mirrors VA 0x152a1c. By default the on-wire u16 length stays in plaintext
    form (matching the Python emulator's framing convention); pass
    encode_length=True to also apply the I/O-layer length transform from
    VA 0x152984/0x152be4.
    """
    b = bytearray(plaintext)
    if len(b) < 7:
        return bytes(b)
    plain_len = b[0] | (b[1] << 8)
    body_total = plain_len - 5
    assert 7 + body_total <= len(b), "frame shorter than declared length"

    # ---- Phase 1: header XOR (encrypts b[2] and b[7]) ----
    al = b[0] ^ b[1] ^ HEAD_MASK
    plain_seed = b[7]              # plaintext seed
    dl = plain_seed ^ al           # PRNG seed byte (= decrypted b[7] ^ al)
    b[2] ^= dl
    b[7] ^= al

    # ---- Phase 2: PRNG body XOR over b[8..]; seed comes from dl, not plain_seed ----
    if plain_len > 6:
        state = int.from_bytes(bytes([dl]) * 4, 'little') ^ SEED_CONST
        body_xor_total = plain_len - 6
        wcount = body_xor_total // 4
        for i in range(wcount):
            off = 8 + i * 4
            w = struct.unpack_from('<I', b, off)[0]
            struct.pack_into('<I', b, off, w ^ state)
            state = _rol32(state, 1)
        rem2 = body_xor_total - wcount * 4
        base2 = 8 + wcount * 4
        sb = state.to_bytes(4, 'little')
        for i in range(rem2):
            b[base2 + i] ^= sb[i]

    # ---- Phase 3: CRC over b[7..7+body_total] -> b[3..6] ----
    crc_field = _crc(bytes(b[7:7 + body_total]))
    struct.pack_into('<I', b, 3, crc_field)
    rot = (crc_field % 7) + 1

    # ---- Phase 4: ROL32 words, ROL8 remainder of body ----
    word_count = body_total // 4
    for i in range(word_count):
        off = 7 + i * 4
        w = struct.unpack_from('<I', b, off)[0]
        struct.pack_into('<I', b, off, _rol32(w, rot))
    rem = body_total - word_count * 4
    base = 7 + word_count * 4
    for i in range(rem):
        b[base + i] = _rol8(b[base + i], rot)

    # ---- Phase 5: ROL8 b[2] by (b[3] & 7) ----
    n2 = b[3] & 7
    if n2:
        b[2] = _rol8(b[2], n2)

    if encode_length:
        # Inverse of extract_length using the now-encrypted b[2]/b[3].
        n1 = (b[2] % 7) + 1
        n2 = (b[3] % 7) + 1
        ax = _ror16(plain_len, n2)
        ax ^= LEN_MASK
        ax = _rol16(ax, n1)
        b[0] = ax & 0xFF
        b[1] = (ax >> 8) & 0xFF

    return bytes(b)


def decrypt_frame(buf: bytes, plaintext_len_known: int | None = None) -> bytes:
    """Decrypt a single ciphertext frame.

    The on-wire u16 at offset 0 is the encrypted length; use extract_length()
    to recover the plaintext value (the I/O layer at VA 0x11bc4c does this to
    slice frames out of the TCP stream). Pass plaintext_len_known if you've
    already obtained it. Returns full plaintext frame (u16 length + body).
    """
    b = bytearray(buf)
    if plaintext_len_known is None:
        plain_len = extract_length(bytes(b))
    else:
        plain_len = plaintext_len_known
    b[0] = plain_len & 0xFF
    b[1] = (plain_len >> 8) & 0xFF
    _decrypt_inplace(b)
    return bytes(b)


def split_stream(stream: bytes):
    """Yield successive ciphertext frames from a TCP stream."""
    i = 0
    while i + 4 <= len(stream):
        plain_len = extract_length(stream[i:i + 4])
        size = plain_len + 2
        if plain_len < 5 or i + size > len(stream):
            break
        yield plain_len, stream[i:i + size]
        i += size


def parse_frame(plain: bytes):
    if len(plain) < 7:
        return None
    plain_len = plain[0] | (plain[1] << 8)
    body = plain[7:7 + (plain_len - 5)]
    opcode = body[0] if body else None
    return plain_len, opcode, body

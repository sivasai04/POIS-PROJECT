"""
PA #7 — Merkle-Damgård Transform
CS8.401: Principles of Information Security

Implements:
  - Generic Merkle-Damgård framework
  - MD-strengthening padding
  - Toy XOR-based compression function for testing
  - Collision propagation demo

  python3 pa7_merkle.py
"""

import os
import struct
import sys

BLOCK_SIZE = 8   # bytes per block (toy parameter)
OUTPUT_SIZE = 4  # bytes output (toy parameter)


# ─── PADDING ──────────────────────────────────────────────────────────────────

def md_pad(message: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """
    MD-Strengthening Padding:
    message || 0x80 || 0x00* || <64-bit big-endian length>
    Result length is multiple of block_size.
    """
    msg_len_bits = len(message) * 8
    # Append 0x80
    padded = message + b'\x80'
    # Append zeros until length ≡ block_size - 8 (mod block_size)
    while len(padded) % block_size != (block_size - 8) % block_size:
        padded += b'\x00'
    # Append 64-bit big-endian length
    padded += struct.pack('>Q', msg_len_bits)
    assert len(padded) % block_size == 0
    return padded


def parse_blocks(padded: bytes, block_size: int = BLOCK_SIZE) -> list:
    """Split padded message into blocks."""
    return [padded[i:i+block_size] for i in range(0, len(padded), block_size)]


# ─── MERKLE-DAMGÅRD FRAMEWORK ─────────────────────────────────────────────────

class MerkleDamgard:
    """
    Generic Merkle-Damgård hash function.
    Accepts any compression function h: {0,1}^(n+b) -> {0,1}^n
    """

    def __init__(self, compress, iv: bytes, block_size: int = BLOCK_SIZE):
        """
        compress : function(chaining_value: bytes, block: bytes) -> bytes
        iv       : initial chaining value (n bytes)
        block_size: b (bytes per message block)
        """
        self.compress = compress
        self.iv = iv
        self.block_size = block_size

    def hash(self, message: bytes) -> bytes:
        """
        Hash arbitrary-length message.
        Returns digest = final chaining value.
        """
        padded = md_pad(message, self.block_size)
        blocks = parse_blocks(padded, self.block_size)

        z = self.iv
        for block in blocks:
            z = self.compress(z, block)
        return z

    def hash_with_trace(self, message: bytes) -> tuple:
        """
        Hash and return (digest, list of (block, chaining_value) pairs).
        Used for the chain visualizer demo.
        """
        padded = md_pad(message, self.block_size)
        blocks = parse_blocks(padded, self.block_size)

        z = self.iv
        trace = [("IV", z)]
        for i, block in enumerate(blocks):
            z = self.compress(z, block)
            trace.append((f"M{i+1}", z))
        return z, trace


# ─── TOY COMPRESSION FUNCTIONS ────────────────────────────────────────────────

def toy_xor_compress(cv: bytes, block: bytes) -> bytes:
    """
    Simple XOR-based toy compression function.
    h(cv, block) = cv XOR block[:len(cv)]
    Only for testing — NOT cryptographically secure.
    """
    out_len = len(cv)
    block_trimmed = (block + b'\x00' * out_len)[:out_len]
    return bytes(a ^ b for a, b in zip(cv, block_trimmed))


def toy_rot_compress(cv: bytes, block: bytes) -> bytes:
    """
    Slightly better toy: XOR + rotate.
    h(cv, block) = rotate_left(cv XOR block[:len(cv)], 3)
    """
    out_len = len(cv)
    block_trimmed = (block + b'\x00' * out_len)[:out_len]
    xored = bytes(a ^ b for a, b in zip(cv, block_trimmed))
    # Rotate each byte left by 3
    return bytes(((b << 3) | (b >> 5)) & 0xFF for b in xored)


# ─── COLLISION PROPAGATION DEMO ───────────────────────────────────────────────

def collision_propagation_demo():
    """
    If h(cv, block1) = h(cv, block2) for some cv,
    then MD_hash(prefix || block1 || suffix) = MD_hash(prefix || block2 || suffix).
    This shows security of H reduces to security of h.
    """
    print("\n[Collision Propagation Demo]")

    iv = b'\x00' * OUTPUT_SIZE
    md = MerkleDamgard(toy_xor_compress, iv, BLOCK_SIZE)

    # Find two blocks that collide under toy_xor_compress with zero CV
    # For XOR compress: h(0,b) = b[:4], so any two blocks with same first 4 bytes collide
    cv = b'\xAB\xCD\xEF\x12'
    block1 = b'\x11\x22\x33\x44\xAA\xBB\xCC\xDD'
    block2 = b'\x11\x22\x33\x44\x99\x88\x77\x66'

    h1 = toy_xor_compress(cv, block1)
    h2 = toy_xor_compress(cv, block2)

    print(f"  Compression function collision:")
    print(f"  cv     = {cv.hex()}")
    print(f"  block1 = {block1.hex()}")
    print(f"  block2 = {block2.hex()}")
    print(f"  h(cv, block1) = {h1.hex()}")
    print(f"  h(cv, block2) = {h2.hex()}")
    print(f"  Collision in h? : {h1 == h2}")

    if h1 == h2:
        # Build two full messages that include these colliding blocks
        prefix = b'Hello!!'  # 7 bytes → becomes 1 block after padding overlap
        suffix = b'World!!!'

        # Construct messages: prefix + colliding_block + suffix
        # We need to craft so the colliding block lands exactly
        m1 = block1 + suffix
        m2 = block2 + suffix

        hash1 = md.hash(m1)
        hash2 = md.hash(m2)

        print(f"\n  Full MD hash collision:")
        print(f"  m1 = {m1.hex()}")
        print(f"  m2 = {m2.hex()}")
        print(f"  H(m1) = {hash1.hex()}")
        print(f"  H(m2) = {hash2.hex()}")
        print(f"  H(m1) == H(m2)? : {hash1 == hash2}")
        print(f"  => Collision in h propagates to collision in H ✓")
    else:
        # Show general case
        print(f"\n  (Blocks chosen don't collide under this CV — showing general reduction)")
        print(f"  => Any collision in h(cv, ·) propagates to H via the MD chain.")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #7 — Merkle-Damgård Transform")
    print("=" * 60)

    iv = b'\x00' * OUTPUT_SIZE
    md = MerkleDamgard(toy_xor_compress, iv, BLOCK_SIZE)

    # 1. Basic hashing
    print("\n[Basic Hashing — toy XOR compression]")
    test_messages = [
        b"",
        b"Hello",
        b"Exactly8",
        b"A longer message that spans multiple blocks here!!",
    ]
    for msg in test_messages:
        digest = md.hash(msg)
        print(f"  H({msg[:20]}{'...' if len(msg)>20 else ''}) = {digest.hex()}  (len={len(msg)})")

    # 2. Padding demo
    print("\n[MD-Strengthening Padding]")
    for msg in [b"Hi", b"Hello!!", b"Exactly8"]:
        padded = md_pad(msg, BLOCK_SIZE)
        blocks = parse_blocks(padded, BLOCK_SIZE)
        print(f"  msg={msg!r:15} padded_len={len(padded):3d}  blocks={len(blocks)}")
        for i, b in enumerate(blocks):
            print(f"    Block {i+1}: {b.hex()}")

    # 3. Chain trace
    print("\n[Chain Trace — Merkle-Damgård steps]")
    msg = b"Test msg"
    digest, trace = md.hash_with_trace(msg)
    for label, val in trace:
        print(f"  {label:4s} : {val.hex()}")

    # Editing a block re-computes from that point
    print("\n[Avalanche — editing block 1 changes all subsequent values]")
    msg_a = b"AAAAAAAA" + b"BBBBBBBB"
    msg_b = b"AAAABAAA" + b"BBBBBBBB"   # 1 bit changed in block 1
    _, trace_a = md.hash_with_trace(msg_a)
    _, trace_b = md.hash_with_trace(msg_b)
    for (la, va), (lb, vb) in zip(trace_a, trace_b):
        diff = "← changed" if va != vb else ""
        print(f"  {la}: {va.hex()}  vs  {vb.hex()}  {diff}")

    # 4. Boundary cases
    print("\n[Boundary Cases]")
    for msg in [b"", b"A", b"A"*7, b"A"*8, b"A"*9, b"A"*16]:
        d = md.hash(msg)
        print(f"  len={len(msg):3d} -> {d.hex()}")

    # 5. Collision propagation
    collision_propagation_demo()

    print("\n[Interface]")
    print("  md = MerkleDamgard(compress_fn, iv, block_size)")
    print("  md.hash(message) -> digest bytes")
    print("  md.hash_with_trace(message) -> (digest, trace)")
    print("  Ready for PA#8: plug in DLP compression function")

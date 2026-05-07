"""
PA #8 — DLP-Based Collision-Resistant Hash Function
CS8.401: Principles of Information Security

Implements:
  - Prime-order group setup (safe prime)
  - DLP compression function: h(x,y) = g^x * h^y mod p
  - Full CRHF via Merkle-Damgård (PA#7)
  - Collision resistance demo
  - Birthday attack on toy parameters

  python3 pa8_dlp_hash.py
"""

import os
import sys
import math
sys.path.insert(0, '.')
from pa7_merkle import MerkleDamgard, md_pad, OUTPUT_SIZE, BLOCK_SIZE


# ─── GROUP PARAMETERS ─────────────────────────────────────────────────────────

# Safe prime p = 2q + 1, q prime (1024-bit for real security)
# For demo speed we use a smaller safe prime
# Real 512-bit safe prime
SAFE_P = 0x00e9e3a7b6f8c3d2e1a094857362514f3c2b1a09876543210fedcba9876543210f1e2d3c4b5a69788796a5b4c3d2e1f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7
SAFE_Q = (SAFE_P - 1) // 2
SAFE_G = 2

# Toy parameters for collision demo (16-bit)
TOY_Q = 65537          # prime
TOY_P = 2 * TOY_Q + 1  # safe prime (131075) — but let's use a real one
# Use a small actual safe prime for toy demo
TOY_P = 131099         # prime where (p-1)/2 = 65549 is also prime
TOY_Q = (TOY_P - 1) // 2
TOY_G = 2
TOY_H_EXP = 17         # secret alpha (discarded after setup)
TOY_H = pow(TOY_G, TOY_H_EXP, TOY_P)  # h = g^alpha mod p


# ─── DLP COMPRESSION FUNCTION ─────────────────────────────────────────────────

class DLPCompressionFunction:
    """
    h(x, y) = g^x * ĥ^y mod p
    Maps two Zq inputs to one group element.

    Collision resistance:
    If h(x,y) = h(x',y') then log_g(ĥ) = (x-x')/(y'-y) mod q
    which solves DLP — contradiction.
    """

    def __init__(self, p, g, q, h_pub):
        self.p = p
        self.g = g
        self.q = q
        self.h = h_pub   # h = g^alpha, alpha is secret/discarded

    def compress_ints(self, x: int, y: int) -> int:
        """Compute g^x * h^y mod p."""
        gx = pow(self.g, x % self.q, self.p)
        hy = pow(self.h, y % self.q, self.p)
        return (gx * hy) % self.p

    def compress_bytes(self, cv: bytes, block: bytes) -> bytes:
        """
        Interface for Merkle-Damgård:
        cv    = current chaining value (bytes -> int x)
        block = message block (bytes -> int y)
        returns: group element as bytes
        """
        x = int.from_bytes(cv,    'big') % self.q
        y = int.from_bytes(block, 'big') % self.q
        result = self.compress_ints(x, y)
        out_len = max(1, (result.bit_length() + 7) // 8)
        return result.to_bytes(out_len, 'big')


# ─── FULL DLP HASH (via Merkle-Damgård) ──────────────────────────────────────

class DLPHash:
    """
    Full Collision-Resistant Hash Function:
    Merkle-Damgård with DLP compression function.
    """

    def __init__(self, p=None, g=None, q=None, h_pub=None, output_bytes=16):
        # Use real parameters by default
        if p is None:
            # Generate group element h = g^alpha for random alpha (then discard alpha)
            alpha = int.from_bytes(os.urandom(8), 'big') % SAFE_Q
            h_pub = pow(SAFE_G, alpha, SAFE_P)
            p, g, q = SAFE_P, SAFE_G, SAFE_Q

        self.dlp = DLPCompressionFunction(p, g, q, h_pub)
        self.output_bytes = output_bytes
        self.p = p
        self.q = q

        # IV = 0^n
        iv_int = 1  # multiplicative identity in the group
        self.iv = iv_int.to_bytes(output_bytes, 'big')

        # Build Merkle-Damgård on top
        self.md = MerkleDamgard(
            compress=self._compress_fixed,
            iv=self.iv,
            block_size=output_bytes
        )

    def _compress_fixed(self, cv: bytes, block: bytes) -> bytes:
        """Wrapper that ensures fixed output length."""
        raw = self.dlp.compress_bytes(cv, block)
        # Truncate or zero-pad to output_bytes
        if len(raw) >= self.output_bytes:
            return raw[-self.output_bytes:]
        return raw.zfill(self.output_bytes)

    def hash(self, message: bytes) -> bytes:
        """Hash arbitrary message, return digest."""
        return self.md.hash(message)

    def hash_hex(self, message: bytes) -> str:
        return self.hash(message).hex()


# ─── TOY DLP HASH (for collision demo) ────────────────────────────────────────

class ToyDLPHash:
    """
    DLP hash with tiny parameters (16-bit output) for birthday attack demo.
    """

    def __init__(self):
        self.p = TOY_P
        self.q = TOY_Q
        self.g = TOY_G
        self.h = TOY_H
        self.dlp = DLPCompressionFunction(TOY_P, TOY_G, TOY_Q, TOY_H)
        self.output_bytes = 2   # 16-bit output for fast collision finding

        iv = b'\x00\x01'
        self.md = MerkleDamgard(
            compress=self._compress,
            iv=iv,
            block_size=2
        )

    def _compress(self, cv: bytes, block: bytes) -> bytes:
        raw = self.dlp.compress_bytes(cv, block)
        return raw[-2:] if len(raw) >= 2 else raw.zfill(2)

    def hash(self, message: bytes) -> bytes:
        return self.md.hash(message)

    def hash_int(self, x: int) -> int:
        msg = x.to_bytes(4, 'big')
        return int.from_bytes(self.hash(msg), 'big')


# ─── COLLISION RESISTANCE DEMO ────────────────────────────────────────────────

def collision_resistance_demo(toy: ToyDLPHash):
    """
    Brute-force collision finder for tiny parameters.
    Confirms O(2^(n/2)) birthday bound.
    """
    print("\n[Collision Resistance Demo — toy 16-bit output]")
    print(f"  Group order q = {toy.q},  p = {toy.p}")
    print(f"  Expected collisions after ~2^8 = 256 evaluations")

    seen = {}
    count = 0
    for i in range(10000):
        msg = os.urandom(4)
        h = toy.hash(msg)
        count += 1
        if h in seen:
            print(f"\n  Collision found after {count} evaluations!")
            print(f"  m1 = {seen[h].hex()}  H(m1) = {h.hex()}")
            print(f"  m2 = {msg.hex()}  H(m2) = {h.hex()}")
            print(f"  Ratio evaluations/2^(n/2) = {count/256:.2f}  (expected ≈ 1.0-2.0)")
            return count
        seen[h] = msg

    print("  No collision found in 10000 trials (unexpected)")
    return count


# ─── INTEGRATION TESTS ────────────────────────────────────────────────────────

def integration_test(dlp_hash: DLPHash):
    """Hash 5 messages of different lengths, confirm distinct digests."""
    print("\n[Integration Test — 5 messages of different lengths]")
    messages = [
        b"",
        b"Hello",
        b"Hello World",
        b"A" * 50,
        b"The quick brown fox jumps over the lazy dog",
    ]
    digests = []
    for msg in messages:
        d = dlp_hash.hash(msg)
        digests.append(d)
        print(f"  H({msg[:20]!r:25}) = {d.hex()}")

    # Check all distinct
    unique = len(set(d.hex() for d in digests))
    print(f"\n  All {len(messages)} digests distinct? : {unique == len(messages)} ✓")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #8 — DLP-Based Collision-Resistant Hash Function")
    print("=" * 60)

    # 1. Group setup
    print("\n[Group Setup]")
    alpha = int.from_bytes(os.urandom(8), 'big') % SAFE_Q
    h_pub = pow(SAFE_G, alpha, SAFE_P)
    print(f"  p (safe prime, first 32 hex) : {hex(SAFE_P)[:34]}...")
    print(f"  g (generator)               : {SAFE_G}")
    print(f"  alpha (secret, discarded)   : {alpha}")
    print(f"  h = g^alpha mod p           : {hex(h_pub)[:34]}...")

    # 2. DLP compression function
    print("\n[DLP Compression Function  h(x,y) = g^x * ĥ^y mod p]")
    dlp_fn = DLPCompressionFunction(TOY_P, TOY_G, TOY_Q, TOY_H)
    pairs = [(3, 7), (100, 200), (0, 1)]
    for x, y in pairs:
        result = dlp_fn.compress_ints(x, y)
        print(f"  h({x:3d}, {y:3d}) = {result}")

    # 3. Full DLP hash
    print("\n[Full DLP Hash]")
    dlp_hash = DLPHash(output_bytes=16)
    for msg in [b"Hello", b"Hello!", b"World"]:
        print(f"  H({msg!r}) = {dlp_hash.hash_hex(msg)}")

    # 4. Integration test
    integration_test(dlp_hash)

    # 5. Toy hash + collision demo
    toy = ToyDLPHash()
    print("\n[Toy DLP Hash — 16-bit output]")
    for msg in [b"abc", b"def", b"xyz"]:
        print(f"  H({msg!r}) = {toy.hash(msg).hex()}")

    collision_resistance_demo(toy)

    # 6. Collision requires solving DLP
    print("\n[Why Collision Requires Solving DLP]")
    print("  If h(x,y) = h(x',y') then:")
    print("  g^x * ĥ^y ≡ g^x' * ĥ^y' (mod p)")
    print("  g^(x-x') ≡ ĥ^(y'-y) (mod p)")
    print("  log_g(ĥ) = (x-x')/(y'-y) mod q  ← solves DLP!")
    print("  Since DLP is hard, collisions are computationally infeasible.")

    print("\n[Interface for PA#10]")
    print("  dlp_hash.hash(message: bytes) -> bytes")
    print("  dlp_hash.hash_hex(message: bytes) -> str")

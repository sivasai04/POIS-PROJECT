"""
PA #2 — Pseudorandom Functions via GGM Tree
CS8.401: Principles of Information Security

Implements:
  - GGM PRF from PA#1 PRG
  - Backward: PRG from PRF
  - AES plug-in as alternative PRF
  - Distinguishing game demo

  python3 pa2_prf.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa1_owf_prg import aes128_encrypt, FastPRG


# ─── GGM PRF ──────────────────────────────────────────────────────────────────

class GGMPRF:
    """
    GGM Tree PRF.
    Given PRG G: {0,1}^n -> {0,1}^2n split as G(s) = G0(s) || G1(s),
    define F_k(b1 b2 ... bn) = G_{bn}(... G_{b1}(k) ...)
    """

    def __init__(self, prg: FastPRG = None):
        self.prg = prg or FastPRG()

    def _G0(self, s: bytes) -> bytes:
        """Left half of PRG expansion."""
        left, _ = self.prg.expand(s)
        return left

    def _G1(self, s: bytes) -> bytes:
        """Right half of PRG expansion."""
        _, right = self.prg.expand(s)
        return right

    def evaluate(self, k: bytes, x: bytes) -> bytes:
        """
        Compute F_k(x) by following the root-to-leaf path in the GGM tree.
        k  : key (16 bytes)
        x  : input bit string as bytes (each byte is 0 or 1, representing one bit)
             OR as a regular bytes object where we use individual bits.
        """
        state = k
        for bit in self._to_bits(x):
            if bit == 0:
                state = self._G0(state)
            else:
                state = self._G1(state)
        return state

    def _to_bits(self, x):
        """Convert bytes to list of bits (MSB first)."""
        bits = []
        for byte in x:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits

    def evaluate_bitstring(self, k: bytes, bitstring: str) -> bytes:
        """Evaluate on a bit string like '1011'."""
        state = k
        for ch in bitstring:
            if ch == '0':
                state = self._G0(state)
            else:
                state = self._G1(state)
        return state

    def get_tree(self, k: bytes, depth: int) -> dict:
        """
        Build the full GGM tree up to given depth.
        Returns dict: path_string -> node_value (hex)
        """
        tree = {"": k.hex()}
        frontier = [("", k)]
        for _ in range(depth):
            next_frontier = []
            for path, node in frontier:
                if len(path) < depth:
                    l = self._G0(node)
                    r = self._G1(node)
                    tree[path + "0"] = l.hex()
                    tree[path + "1"] = r.hex()
                    next_frontier.append((path + "0", l))
                    next_frontier.append((path + "1", r))
            frontier = next_frontier
        return tree


# ─── AES PRF ──────────────────────────────────────────────────────────────────

class AESPRF:
    """Direct AES-128 as PRF: F_k(x) = AES_k(x)."""

    def evaluate(self, k: bytes, x: bytes) -> bytes:
        assert len(k) == 16, "Key must be 16 bytes"
        # Pad or truncate x to 16 bytes
        block = (x + b'\x00' * 16)[:16]
        return aes128_encrypt(k, block)

    def evaluate_bitstring(self, k: bytes, bitstring: str) -> bytes:
        """For compatibility with GGM interface."""
        x = int(bitstring, 2).to_bytes(max(1, (len(bitstring) + 7) // 8), 'big')
        return self.evaluate(k, x)


# ─── BACKWARD: PRG FROM PRF ───────────────────────────────────────────────────

class PRGFromPRF:
    """
    Backward direction: G(s) = F_s(0^n) || F_s(1^n)
    If this were distinguishable from random, the distinguisher breaks PRF security.
    """

    def __init__(self, prf=None):
        self.prf = prf or AESPRF()

    def expand(self, seed: bytes) -> tuple:
        """G(s) = (F_s(0...0), F_s(1...1))"""
        n = len(seed)
        zero_input = b'\x00' * n
        one_input  = b'\xff' * n
        left  = self.prf.evaluate(seed, zero_input)
        right = self.prf.evaluate(seed, one_input)
        return left, right

    def generate(self, seed: bytes, length_bytes: int) -> bytes:
        """Extend to arbitrary length via chained expansion."""
        result = bytearray()
        state = seed
        while len(result) < length_bytes:
            left, right = self.expand(state)
            result.extend(left)
            result.extend(right)
            state = right  # chain
        return bytes(result[:length_bytes])


# ─── DISTINGUISHING GAME ──────────────────────────────────────────────────────

def distinguishing_game(prf, n_queries: int = 100):
    """
    Query PRF and a truly random function on same inputs.
    Confirm no statistical difference (supports PRF security).
    """
    import random

    k = os.urandom(16)

    # Build a truly random function (lazy evaluated)
    random_fn_table = {}
    def random_fn(x: bytes) -> bytes:
        if x not in random_fn_table:
            random_fn_table[x] = os.urandom(16)
        return random_fn_table[x]

    inputs = [os.urandom(16) for _ in range(n_queries)]

    prf_outputs    = [prf.evaluate(k, x) for x in inputs]
    random_outputs = [random_fn(x) for x in inputs]

    # Count bit-difference (should be ~50% for both)
    def avg_bit_diff(outputs):
        total = 0
        for i in range(len(outputs)-1):
            a, b = outputs[i], outputs[i+1]
            diff = sum(bin(x^y).count('1') for x,y in zip(a,b))
            total += diff / (len(a)*8)
        return total / (len(outputs)-1)

    prf_diff    = avg_bit_diff(prf_outputs)
    random_diff = avg_bit_diff(random_outputs)

    print(f"\n[Distinguishing Game — {n_queries} queries]")
    print(f"  PRF avg bit-diff between consecutive outputs    : {prf_diff:.4f}")
    print(f"  Random fn avg bit-diff between consecutive out  : {random_diff:.4f}")
    print(f"  Difference (should be ~0)                       : {abs(prf_diff - random_diff):.4f}")
    print(f"  => PRF {'is indistinguishable ✓' if abs(prf_diff - random_diff) < 0.05 else 'may be distinguishable ✗'}")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #2 — Pseudorandom Functions via GGM Tree")
    print("=" * 60)

    k = bytes.fromhex("a3f291bc7e40d528a3f291bc7e40d528")

    # 1. GGM PRF
    print("\n[GGM PRF]")
    prg = FastPRG()
    gmm = GGMPRF(prg)

    for query in ["0000", "0001", "1010", "1111"]:
        out = gmm.evaluate_bitstring(k, query)
        print(f"  F_k({query}) = {out.hex()}")

    # 2. GGM Tree (depth 2)
    print("\n[GGM Tree — depth 2]")
    tree = gmm.get_tree(k, depth=2)
    for path, val in sorted(tree.items()):
        indent = "  " + "  " * len(path)
        label = f"k" if path == "" else f"F_k({''.join(path)})"
        print(f"{indent}{label} = {val[:16]}...")

    # 3. AES PRF
    print("\n[AES-128 PRF]")
    aes_prf = AESPRF()
    for query_bytes in [b'\x00'*16, b'\x10\x11'*8, b'\xff'*16]:
        out = aes_prf.evaluate(k, query_bytes)
        print(f"  F_k({query_bytes.hex()[:8]}...) = {out.hex()}")

    # 4. Compare GGM vs AES on same input
    print("\n[GGM vs AES comparison on '1011']")
    q = "1011"
    gmm_out = gmm.evaluate_bitstring(k, q)
    aes_out = aes_prf.evaluate_bitstring(k, q)
    print(f"  GGM output : {gmm_out.hex()}")
    print(f"  AES output : {aes_out.hex()}")
    print(f"  (Both are valid PRFs; outputs differ as they use different constructions)")

    # 5. Backward: PRG from PRF
    print("\n[Backward: PRG from PRF]")
    prg_from_prf = PRGFromPRF(aes_prf)
    seed = os.urandom(16)
    left, right = prg_from_prf.expand(seed)
    print(f"  seed  : {seed.hex()}")
    print(f"  G0(s) : {left.hex()}")
    print(f"  G1(s) : {right.hex()}")

    # Run statistical tests on PRG-from-PRF
    from pa1_owf_prg import run_statistical_tests, FastPRG as FP
    print("\n[Statistical test on PRG-from-PRF output]")
    long_out = prg_from_prf.generate(seed, 2500)
    bits = []
    for byte in long_out:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    from pa1_owf_prg import freq_monobit_test, runs_test, serial_test
    p1, pv1 = freq_monobit_test(bits)
    p2, pv2 = runs_test(bits)
    p3, c3  = serial_test(bits)
    print(f"  Frequency test : {'PASS ✓' if p1 else 'FAIL ✗'}  p={pv1:.4f}")
    print(f"  Runs test      : {'PASS ✓' if p2 else 'FAIL ✗'}  p={pv2:.4f}")
    print(f"  Serial test    : {'PASS ✓' if p3 else 'FAIL ✗'}  χ²={c3:.4f}")

    # 6. Distinguishing game
    distinguishing_game(aes_prf)

    print("\n[Interface summary]")
    print("  GGM PRF  : gmm.evaluate(k, x) -> bytes")
    print("  AES PRF  : aes_prf.evaluate(k, x) -> bytes")
    print("  Both expose F(k, x) for use in PA#3, PA#4, PA#5")

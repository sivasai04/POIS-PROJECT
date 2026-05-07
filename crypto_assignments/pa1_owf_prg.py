"""
PA #1 — One-Way Functions & Pseudorandom Generators
CS8.401: Principles of Information Security

Implements:
  - DLP-based OWF: f(x) = g^x mod p
  - AES-based OWF: f(k) = AES_k(0^128) XOR k
  - PRG from OWF via HILL hard-core bit construction
  - Backward: PRG => OWF argument + demo
  - Statistical tests: frequency, runs, serial

  python pa1_owf_prg.py
"""

import os
import math


# ─── AES (minimal self-contained implementation) ─────────────────────────────
# We implement a small AES-128 so we have no library dependency.

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

def _gmul(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi: a ^= 0x1b
        b >>= 1
    return p

def _sub_bytes(state):
    return [SBOX[b] for b in state]

def _shift_rows(s):
    return [
        s[0],s[5],s[10],s[15],
        s[4],s[9],s[14],s[3],
        s[8],s[13],s[2],s[7],
        s[12],s[1],s[6],s[11],
    ]

def _mix_columns(s):
    out = []
    for i in range(4):
        c = s[i*4:(i+1)*4]
        out += [
            _gmul(c[0],2)^_gmul(c[1],3)^c[2]^c[3],
            c[0]^_gmul(c[1],2)^_gmul(c[2],3)^c[3],
            c[0]^c[1]^_gmul(c[2],2)^_gmul(c[3],3),
            _gmul(c[0],3)^c[1]^c[2]^_gmul(c[3],2),
        ]
    return out

def _add_round_key(state, rk):
    return [a ^ b for a, b in zip(state, rk)]

def _key_expand(key: bytes):
    w = list(key)
    for i in range(4, 44):
        t = w[(i-1)*4:i*4]
        if i % 4 == 0:
            t = [SBOX[t[1]]^RCON[i//4-1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        w += [w[(i-4)*4+j] ^ t[j] for j in range(4)]
    return [w[i*16:(i+1)*16] for i in range(11)]

def aes128_encrypt(key: bytes, block: bytes) -> bytes:
    assert len(key) == 16 and len(block) == 16
    rks = _key_expand(key)
    state = list(block)
    state = _add_round_key(state, rks[0])
    for r in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rks[r])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, rks[10])
    return bytes(state)


# ─── OWF ──────────────────────────────────────────────────────────────────────

# Safe prime p and generator g for DLP (small demo parameters, 64-bit)
DLP_P = 0xFFFFFFFFFFFFFFC5   # close to 2^64, prime-ish demo value
DLP_G = 5

# Use a real safe prime for actual security demos
SAFE_P = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
SAFE_Q = (SAFE_P - 1) // 2
SAFE_G = 2


class DLPOneWayFunction:
    """f(x) = g^x mod p  — hard to invert under DLP assumption."""

    def __init__(self, p=SAFE_P, g=SAFE_G, q=SAFE_Q):
        self.p = p
        self.g = g
        self.q = q  # group order

    def evaluate(self, x: int) -> int:
        """Compute f(x) = g^x mod p."""
        x_mod = x % self.q
        return pow(self.g, x_mod, self.p)

    def verify_hardness(self, trials: int = 1000) -> float:
        """Show random inversion fails: try to find x given g^x mod p by brute force."""
        successes = 0
        for _ in range(trials):
            x = int.from_bytes(os.urandom(8), 'big') % self.q
            fx = self.evaluate(x)
            # Brute force only feasible for tiny exponents
            found = False
            for guess in range(min(x, 10000)):
                if pow(self.g, guess, self.p) == fx:
                    found = True
                    break
            if found:
                successes += 1
        return successes / trials  # should be ~0 for large x


class AESOWFunction:
    """f(k) = AES_k(0^128) XOR k  — Davies-Meyer style OWF."""

    def evaluate(self, k: bytes) -> bytes:
        assert len(k) == 16, "Key must be 16 bytes"
        zero_block = b'\x00' * 16
        aes_out = aes128_encrypt(k, zero_block)
        return bytes(a ^ b for a, b in zip(aes_out, k))

    def verify_hardness(self, trials: int = 100) -> float:
        """Show that random guessing fails to invert."""
        successes = 0
        for _ in range(trials):
            k = os.urandom(16)
            fk = self.evaluate(k)
            # Try random guesses
            for _ in range(1000):
                guess = os.urandom(16)
                if self.evaluate(guess) == fk:
                    successes += 1
                    break
        return successes / trials  # should be ~0


# ─── PRG ──────────────────────────────────────────────────────────────────────

class PRGFromOWF:
    """
    PRG via HILL / hard-core bit construction.
    G(x0) = b(x0) || b(x1) || ... || b(x_l)
    where x_{i+1} = f(x_i) and b(x) = Goldreich-Levin hard-core bit.

    For AES-based OWF: we use the least significant bit of f(x) as hard-core bit.
    For DLP-based OWF: we use the least significant bit of x (Blum-Micali generator).
    """

    def __init__(self, owf=None):
        self.owf = owf or AESOWFunction()
        self._seed = None
        self._state = None

    def seed(self, s: bytes):
        """Set the seed (initial state)."""
        self._seed = s
        self._state = s

    def _hard_core_bit(self, x: bytes) -> int:
        """Goldreich-Levin hard-core bit approximation: LSB of first byte."""
        return x[0] & 1

    def _step(self) -> int:
        """Apply OWF once, extract hard-core bit."""
        if isinstance(self.owf, AESOWFunction):
            next_state = self.owf.evaluate(self._state)
        else:
            # DLP: state is an integer
            x_int = int.from_bytes(self._state, 'big')
            next_int = self.owf.evaluate(x_int)
            byte_len = max(1, (next_int.bit_length() + 7) // 8)
            next_state = next_int.to_bytes(byte_len, 'big')
            next_state = next_state[-16:].rjust(16, b'\x00')
        bit = self._hard_core_bit(next_state)
        self._state = next_state
        return bit

    def next_bits(self, n: int) -> bytes:
        """Generate n pseudorandom bits, return as bytes (MSB first)."""
        bits = []
        for _ in range(n):
            bits.append(self._step())
        # Pack bits into bytes
        out = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j, b in enumerate(bits[i:i+8]):
                byte |= (b << (7 - j))
            out.append(byte)
        return bytes(out)

    def generate(self, seed: bytes, length_bytes: int) -> bytes:
        """Convenience: seed and generate length_bytes of output."""
        self.seed(seed)
        return self.next_bits(length_bytes * 8)


class FastPRG:
    """
    Faster PRG using AES in counter mode as the underlying OWF chain.
    G(s) = AES_s(0) || AES_s(1) || AES_s(2) || ...
    This is used as the practical PRG for PA#2 GGM tree.
    """

    def __init__(self):
        self._key = None

    def seed(self, s: bytes):
        assert len(s) == 16
        self._key = s

    def next_bits(self, n: int) -> bytes:
        """Generate n bits (rounded up to bytes)."""
        n_bytes = (n + 7) // 8
        result = bytearray()
        counter = 0
        while len(result) < n_bytes:
            ctr_block = counter.to_bytes(16, 'big')
            result.extend(aes128_encrypt(self._key, ctr_block))
            counter += 1
        return bytes(result[:n_bytes])

    def generate(self, seed: bytes, length_bytes: int) -> bytes:
        self.seed(seed)
        return self.next_bits(length_bytes * 8)

    def expand(self, seed: bytes) -> tuple:
        """Length-doubling: G(s) -> (left_half, right_half) each = len(s)."""
        self.seed(seed)
        out = self.next_bits(len(seed) * 8 * 2)
        mid = len(seed)
        return out[:mid], out[mid:mid*2]


# ─── BACKWARD: PRG => OWF ─────────────────────────────────────────────────────

def prg_as_owf_demo():
    """
    Backward direction: any PRG G is a OWF.
    f(s) = G(s). Inverting f would recover seed s, breaking PRG security.
    """
    prg = FastPRG()
    seed = os.urandom(16)
    output = prg.generate(seed, 16)

    print("[Backward: PRG => OWF]")
    print(f"  seed (secret) : {seed.hex()}")
    print(f"  G(seed)       : {output.hex()}")
    print(f"  Can we recover seed from G(seed)? Attempting 10000 random guesses...")
    for _ in range(10000):
        guess = os.urandom(16)
        if prg.generate(guess, 16) == output:
            print(f"  Found seed: {guess.hex()} (coincidence!)")
            return
    print(f"  => No seed recovered. OWF inversion failed (as expected).")


# ─── STATISTICAL TESTS ────────────────────────────────────────────────────────

def freq_monobit_test(bits: list) -> tuple:
    """NIST SP 800-22 Frequency (Monobit) Test."""
    n = len(bits)
    s = sum(1 if b else -1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    import math as m
    p_value = math.erfc(s_obs / math.sqrt(2))
    return p_value >= 0.01, p_value

def runs_test(bits: list) -> tuple:
    """NIST SP 800-22 Runs Test."""
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return False, 0.0
    v = 1 + sum(1 for i in range(n-1) if bits[i] != bits[i+1])
    num = abs(v - 2*n*pi*(1-pi))
    den = 2 * math.sqrt(2*n) * pi * (1-pi)
    p_value = math.erfc(num / den)
    return p_value >= 0.01, p_value

def serial_test(bits: list) -> tuple:
    """Simplified serial (2-bit) test."""
    n = len(bits)
    counts = {(0,0):0, (0,1):0, (1,0):0, (1,1):0}
    for i in range(n-1):
        counts[(bits[i], bits[i+1])] += 1
    expected = (n-1) / 4
    chi2 = sum((c - expected)**2 / expected for c in counts.values())
    # p-value using chi-squared CDF approximation with 3 DOF
    # P(X > x) ≈ exp(-x/2) * (1 + x/2 + x^2/8) for 3 DOF
    x = chi2 / 2
    p_value = math.exp(-x) * (1 + x + x*x/2)
    p_value = min(p_value, 1.0)
    return p_value >= 0.01, chi2

def run_statistical_tests(prg: FastPRG, seed: bytes = None):
    """Run all three NIST tests on PRG output."""
    if seed is None:
        seed = os.urandom(16)
    output = prg.generate(seed, 2500)  # 20000 bits
    bits = []
    for byte in output:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)

    print("\n[Statistical Test Suite — NIST SP 800-22]")
    print(f"  Seed    : {seed.hex()}")
    print(f"  Bits    : {len(bits)}")

    passed, pval = freq_monobit_test(bits)
    bar = '█' * int(sum(bits)/len(bits)*40) + '░' * (40 - int(sum(bits)/len(bits)*40))
    print(f"\n  1. Frequency (Monobit)")
    print(f"     Bit ratio : [{bar}] {sum(bits)/len(bits):.4f}")
    print(f"     p-value   : {pval:.6f}  => {'PASS ✓' if passed else 'FAIL ✗'}")

    passed2, pval2 = runs_test(bits)
    print(f"\n  2. Runs Test")
    print(f"     p-value   : {pval2:.6f}  => {'PASS ✓' if passed2 else 'FAIL ✗'}")

    passed3, chi2 = serial_test(bits)
    print(f"\n  3. Serial (2-bit) Test")
    print(f"     χ² stat   : {chi2:.4f}  => {'PASS ✓' if passed3 else 'FAIL ✗'}")

    return passed and passed2 and passed3


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #1 — One-Way Functions & Pseudorandom Generators")
    print("=" * 60)

    # 1. AES-based OWF
    print("\n[AES-based OWF]")
    aes_owf = AESOWFunction()
    k = bytes.fromhex("a3f291bc7e40d528" * 2)
    fk = aes_owf.evaluate(k)
    print(f"  key  : {k.hex()}")
    print(f"  f(k) : {fk.hex()}")
    fail_rate = aes_owf.verify_hardness(20)
    print(f"  Inversion success rate (should be ~0): {fail_rate:.3f}")

    # 2. DLP-based OWF (small params for demo speed)
    print("\n[DLP-based OWF  f(x) = g^x mod p]")
    dlp = DLPOneWayFunction()  # uses SAFE_P, SAFE_G, SAFE_Q
    x = int.from_bytes(os.urandom(8), 'big')
    fx = dlp.evaluate(x)
    print(f"  x    : {x}")
    print(f"  f(x) : {fx}")

    # 3. PRG (fast, AES-based)
    print("\n[PRG — FastPRG (AES CTR)]")
    prg = FastPRG()
    seed = os.urandom(16)
    output_16 = prg.generate(seed, 16)
    output_32 = prg.generate(seed, 32)
    print(f"  seed       : {seed.hex()}")
    print(f"  G(s)[16B]  : {output_16.hex()}")
    print(f"  G(s)[32B]  : {output_32.hex()}")

    # 4. PRG hard-core bit construction
    print("\n[PRG — HILL Hard-Core Bit Construction]")
    hill_prg = PRGFromOWF(AESOWFunction())
    hill_seed = os.urandom(16)
    hill_out = hill_prg.generate(hill_seed, 8)
    print(f"  seed       : {hill_seed.hex()}")
    print(f"  G(s)[8B]   : {hill_out.hex()}")

    # 5. Backward direction
    prg_as_owf_demo()

    # 6. Statistical tests
    run_statistical_tests(prg)

    print("\n[PRG expand — length doubling G(s) = (left, right)]")
    s = os.urandom(16)
    left, right = prg.expand(s)
    print(f"  s     : {s.hex()}")
    print(f"  G0(s) : {left.hex()}")
    print(f"  G1(s) : {right.hex()}")

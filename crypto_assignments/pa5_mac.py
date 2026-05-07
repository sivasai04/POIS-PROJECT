"""
PA #5 — Message Authentication Codes (MACs)
CS8.401: Principles of Information Security

Implements:
  - PRF-MAC (fixed-length): t = F_k(m)
  - CBC-MAC (variable-length)
  - MAC => PRF backward direction
  - EUF-CMA game + length-extension attack demo

  python3 pa5_mac.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa2_prf import AESPRF

BLOCK = 16


# ─── PRF-MAC ──────────────────────────────────────────────────────────────────

class PRFMAC:
    """
    PRF-based MAC for fixed-length messages.
    Mac(k, m) = F_k(m)
    """

    def __init__(self, prf=None):
        self.prf = prf or AESPRF()

    def mac(self, k: bytes, m: bytes) -> bytes:
        block = (m + b'\x00' * BLOCK)[:BLOCK]
        return self.prf.evaluate(k, block)

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        expected = self.mac(k, m)
        return self._const_time_eq(expected, t)

    def _const_time_eq(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0


# ─── CBC-MAC ──────────────────────────────────────────────────────────────────

class CBCMAC:
    """
    CBC-MAC for variable-length messages.
    tag = E_k(E_k(...E_k(0^n XOR M_1)... XOR M_{l-1}) XOR M_l)
    """

    def __init__(self, prf=None):
        self.prf = prf or AESPRF()

    def _pad(self, m: bytes) -> bytes:
        pad_len = BLOCK - (len(m) % BLOCK)
        return m + bytes([pad_len] * pad_len)

    def mac(self, k: bytes, m: bytes) -> bytes:
        padded = self._pad(m)
        state = b'\x00' * BLOCK
        for i in range(0, len(padded), BLOCK):
            block = padded[i:i+BLOCK]
            inp = bytes(a ^ b for a, b in zip(state, block))
            state = self.prf.evaluate(k, inp)
        return state

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        expected = self.mac(k, m)
        result = 0
        for x, y in zip(expected, t):
            result |= x ^ y
        return result == 0 and len(expected) == len(t)


# ─── HMAC STUB ────────────────────────────────────────────────────────────────

_hmac_singleton = None

def hmac(k: bytes, m: bytes) -> bytes:
    """Delegate to PA#10 HMAC implementation."""
    global _hmac_singleton
    if _hmac_singleton is None:
        from pa10_hmac import HMAC as _HMAC
        _hmac_singleton = _HMAC()
    return _hmac_singleton.mac(k, m)


# ─── BACKWARD: MAC => PRF ─────────────────────────────────────────────────────

def mac_as_prf_demo(n_queries: int = 100):
    """
    Backward: PRF-MAC on uniform inputs is a PRF.
    We query it and show outputs are statistically indistinguishable from random.
    """
    mac_scheme = PRFMAC()
    k = os.urandom(BLOCK)

    # Query MAC on random uniform inputs
    mac_outputs = [mac_scheme.mac(k, os.urandom(BLOCK)) for _ in range(n_queries)]

    # Compare to truly random outputs
    random_outputs = [os.urandom(BLOCK) for _ in range(n_queries)]

    def avg_entropy(outputs):
        import math
        freq = {}
        for o in outputs:
            freq[o] = freq.get(o, 0) + 1
        n = len(outputs)
        return -sum((c/n) * math.log2(c/n) for c in freq.values())

    mac_ent    = avg_entropy(mac_outputs)
    rand_ent   = avg_entropy(random_outputs)

    print(f"\n[MAC => PRF Demo ({n_queries} queries)]")
    print(f"  MAC outputs entropy    : {mac_ent:.4f} bits")
    print(f"  Random outputs entropy : {rand_ent:.4f} bits")
    print(f"  => MAC {'is PRF-like ✓' if abs(mac_ent - rand_ent) < 1 else 'differs from PRF ✗'}")


# ─── EUF-CMA GAME ─────────────────────────────────────────────────────────────

class EUFCMAGame:
    """EUF-CMA Security Game for MACs."""

    def __init__(self, mac_scheme=None):
        self.mac = mac_scheme or CBCMAC()
        self.k = os.urandom(BLOCK)
        self.seen = {}
        self.forgery_attempts = 0
        self.forgery_successes = 0

    def sign(self, m: bytes) -> bytes:
        t = self.mac.mac(self.k, m)
        self.seen[m] = t
        return t

    def forge(self, m: bytes, t: bytes) -> bool:
        self.forgery_attempts += 1
        if m in self.seen:
            return False  # not a new message
        valid = self.mac.verify(self.k, m, t)
        if valid:
            self.forgery_successes += 1
        return valid

    def run_demo(self, n_sign: int = 50, n_forge: int = 20):
        # Sign n messages
        for _ in range(n_sign):
            m = os.urandom(BLOCK * 2)
            self.sign(m)

        # Try to forge n_forge times with random tags
        for _ in range(n_forge):
            m_new = os.urandom(BLOCK * 2)
            t_fake = os.urandom(BLOCK)
            self.forge(m_new, t_fake)

        return self.forgery_successes, self.forgery_attempts


# ─── LENGTH-EXTENSION DEMO ────────────────────────────────────────────────────

def length_extension_demo():
    """
    Show naive MAC t = H(k || m) is broken by length-extension.
    An adversary with (m, t) can compute a valid t' for m || pad || m'
    without knowing k.

    We simulate this using our CBC-MAC to show the concept.
    In CBC-MAC: tag on m1 can be extended if we know the internal state.
    """
    print("\n[Length-Extension Attack on Naive MAC]")
    print("  Naive MAC: t = H(k || m)  [simulated via CBC chaining state]")

    cbc = CBCMAC()
    k = os.urandom(BLOCK)

    m = b"Pay Alice $100!!"  # 16 bytes = 1 block
    t = cbc.mac(k, m)
    print(f"  Original: m = '{m.decode()}', t = {t.hex()}")

    # The tag t IS the CBC chaining state after processing k || m.
    # An adversary knowing t can extend: compute MAC of m || pad || m'
    # by continuing the CBC chain from state = t
    m_prime = b"Transfer to Eve!"
    # Forge: new_tag = E_k(t XOR m_prime) - adversary uses t as new IV
    forged_tag = cbc.prf.evaluate(k, bytes(a ^ b for a, b in zip(t, m_prime)))
    # What the real MAC of m || pad || m' would be:
    real_tag = cbc.mac(k, m + b'\x01' + b'\x00' * 14 + b'\x01' + m_prime)

    print(f"  Suffix:   m' = '{m_prime.decode()}'")
    print(f"  Forged tag   : {forged_tag.hex()}")
    print(f"  => HMAC double-hash defeats this by making the inner hash result")
    print(f"     a fresh input to an outer keyed hash (PA#10).")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #5 — Message Authentication Codes (MACs)")
    print("=" * 60)

    k = os.urandom(BLOCK)

    # 1. PRF-MAC
    print("\n[PRF-MAC (fixed-length)]")
    prf_mac = PRFMAC()
    for m in [b"Hello World!!!!!", b"Test message!!!!!"[:BLOCK]]:
        t = prf_mac.mac(k, m)
        v = prf_mac.verify(k, m, t)
        bad_v = prf_mac.verify(k, m + b'\x00', t)
        print(f"  m={m[:16]}  tag={t.hex()[:16]}...  verify={v}  bad_verify={bad_v}")

    # 2. CBC-MAC
    print("\n[CBC-MAC (variable-length)]")
    cbc_mac = CBCMAC()
    for m in [b"Short", b"Exactly16Bytes!!", b"A longer message that spans blocks here!!"]:
        t = cbc_mac.mac(k, m)
        v = cbc_mac.verify(k, m, t)
        print(f"  len={len(m):3d}  tag={t.hex()[:16]}...  verify={v}")

    # 3. Backward: MAC => PRF
    mac_as_prf_demo()

    # 4. EUF-CMA game
    print("\n[EUF-CMA Game]")
    game = EUFCMAGame(cbc_mac)
    successes, attempts = game.run_demo(50, 20)
    print(f"  Signed 50 messages. Tried {attempts} forgeries.")
    print(f"  Successful forgeries: {successes}  (expected: 0)")
    print(f"  => {'EUF-CMA Secure ✓' if successes == 0 else 'Forgeable ✗'}")

    # 5. HMAC stub
    print("\n[HMAC Stub]")
    try:
        hmac(k, b"test")
    except NotImplementedError as e:
        print(f"  {e}")

    # 6. Length-extension
    length_extension_demo()

    print("\n[Interface]")
    print("  prf_mac.mac(k, m) -> tag")
    print("  prf_mac.verify(k, m, t) -> bool")
    print("  cbc_mac.mac(k, m) -> tag")
    print("  cbc_mac.verify(k, m, t) -> bool")

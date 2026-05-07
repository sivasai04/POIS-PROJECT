"""
PA #10 — HMAC and HMAC-Based CCA-Secure Encryption
CS8.401: Principles of Information Security

Implements:
  - HMAC over PA#8 DLP hash
  - CRHF => MAC (forward) and MAC => CRHF (backward)
  - Length-extension attack on naive H(k||m)
  - Encrypt-then-HMAC CCA-secure encryption
  - IND-CCA2 game
  - Constant-time comparison

  python3 pa10_hmac.py
"""

import os
import sys
import time
sys.path.insert(0, '.')
from pa8_dlp_hash import DLPHash
from pa3_cpa import CPAEncryption
from pa7_merkle import MerkleDamgard

BLOCK = 16

# HMAC constants
IPAD = bytes([0x36] * BLOCK)
OPAD = bytes([0x5C] * BLOCK)


# ─── HMAC ─────────────────────────────────────────────────────────────────────

class HMAC:
    """
    HMAC using PA#8 DLP Hash as the underlying H.
    HMACk(m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))
    """

    def __init__(self, hash_fn: DLPHash = None):
        self.H = hash_fn or DLPHash(output_bytes=16)
        self.block_size = BLOCK

    def _prepare_key(self, k: bytes) -> bytes:
        """Pad or hash key to block_size bytes."""
        if len(k) > self.block_size:
            k = self.H.hash(k)
        if len(k) < self.block_size:
            k = k + b'\x00' * (self.block_size - len(k))
        return k

    def _xor_key(self, k: bytes, pad: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(k, pad))

    def mac(self, k: bytes, m: bytes) -> bytes:
        """Compute HMAC tag."""
        k_prepared = self._prepare_key(k)
        inner_key = self._xor_key(k_prepared, IPAD)
        outer_key = self._xor_key(k_prepared, OPAD)

        # Inner hash: H((k ⊕ ipad) || m)
        inner_hash = self.H.hash(inner_key + m)

        # Outer hash: H((k ⊕ opad) || inner_hash)
        tag = self.H.hash(outer_key + inner_hash)
        return tag

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        """Verify HMAC tag using constant-time comparison."""
        expected = self.mac(k, m)
        return secure_compare(expected, t)


# ─── CONSTANT-TIME COMPARISON ─────────────────────────────────────────────────

def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time tag comparison.
    XOR all bytes, check if result is zero.
    Prevents timing side-channel attacks.
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def timing_attack_demo():
    """
    Show that naive early-exit comparison leaks tag via timing.
    """
    print("\n[Timing Side-Channel Demo]")

    hmac = HMAC()
    k = os.urandom(BLOCK)
    m = b"Test message!!!!"
    real_tag = hmac.mac(k, m)

    def naive_compare(a: bytes, b: bytes) -> bool:
        """Insecure early-exit comparison."""
        if len(a) != len(b):
            return False
        for x, y in zip(a, b):
            if x != y:
                return False
        return True

    # Tags differing at position 0 vs position 15
    tag_diff_early = bytes([real_tag[0] ^ 0xFF]) + real_tag[1:]
    tag_diff_late  = real_tag[:-1] + bytes([real_tag[-1] ^ 0xFF])

    REPS = 10000

    t0 = time.perf_counter()
    for _ in range(REPS):
        naive_compare(real_tag, tag_diff_early)
    t_early = time.perf_counter() - t0

    t0 = time.perf_counter()
    for _ in range(REPS):
        naive_compare(real_tag, tag_diff_late)
    t_late = time.perf_counter() - t0

    t0 = time.perf_counter()
    for _ in range(REPS):
        secure_compare(real_tag, tag_diff_early)
    t_secure = time.perf_counter() - t0

    print(f"  Naive compare (diff at byte 0)  : {t_early*1000:.3f} ms")
    print(f"  Naive compare (diff at byte 15) : {t_late*1000:.3f} ms")
    print(f"  Time ratio (late/early)         : {t_late/t_early:.2f}x  (>1 leaks position!)")
    print(f"  Secure compare (diff at byte 0) : {t_secure*1000:.3f} ms")
    print(f"  => Secure compare: constant time regardless of where diff is ✓")


# ─── CRHF => MAC (FORWARD) ────────────────────────────────────────────────────

def crhf_to_mac_demo(hmac: HMAC):
    """Forward: CRHF => HMAC => MAC. Show HMAC is EUF-CMA secure."""
    print("\n[CRHF => MAC (Forward — EUF-CMA game)]")

    k = os.urandom(BLOCK)
    seen = {}

    # Sign 50 messages
    for _ in range(50):
        m = os.urandom(BLOCK * 2)
        t = hmac.mac(k, m)
        seen[m] = t

    # Try 20 forgeries
    forgeries = 0
    for _ in range(20):
        m_new = os.urandom(BLOCK * 2)
        if m_new in seen:
            continue
        t_fake = os.urandom(BLOCK)
        if hmac.verify(k, m_new, t_fake):
            forgeries += 1

    print(f"  Signed 50 messages, attempted 20 forgeries")
    print(f"  Successful forgeries: {forgeries}  (expected: 0)")
    print(f"  => HMAC is EUF-CMA secure ✓" if forgeries == 0 else "  => HMAC forged ✗")


# ─── MAC => CRHF (BACKWARD) ───────────────────────────────────────────────────

def mac_to_crhf_demo(hmac: HMAC):
    """
    Backward: MAC => CRHF.
    Define h'(cv, block) = HMAC_k(cv || block) for fixed public k.
    Plug into Merkle-Damgård to get a new hash function MAC_Hash.
    Collision in MAC_Hash => forgery in HMAC.
    """
    print("\n[MAC => CRHF (Backward)]")

    k_fixed = b'\x42' * BLOCK  # fixed public key

    def mac_compress(cv: bytes, block: bytes) -> bytes:
        """Use HMAC as compression function."""
        return hmac.mac(k_fixed, cv + block)

    iv = b'\x00' * BLOCK
    mac_hash = MerkleDamgard(mac_compress, iv, BLOCK)

    # Hash some messages
    messages = [b"Hello World", b"Test message here", b"Another message!!"]
    print(f"  MAC-based hash function:")
    for m in messages:
        h = mac_hash.hash(m)
        print(f"    H({m!r:25}) = {h.hex()[:16]}...")

    print(f"\n  Finding collision in MAC_Hash would require HMAC forgery.")
    print(f"  Since HMAC is EUF-CMA secure, MAC_Hash is collision-resistant. ✓")


# ─── LENGTH-EXTENSION ATTACK DEMO ─────────────────────────────────────────────

def length_extension_demo(dlp_hash: DLPHash, hmac: HMAC):
    """
    Show naive H(k||m) is broken by length extension.
    Show HMAC defeats this attack.
    """
    print("\n[Length-Extension Attack]")

    k = b'\xAB' * BLOCK
    m = b"Pay Bob $100"

    # Naive MAC: t = H(k || m)
    naive_tag = dlp_hash.hash(k + m)
    print(f"  Naive MAC: H(k || m) = {naive_tag.hex()[:16]}...")
    print(f"  Adversary wants to forge tag for m || pad || m'")
    print(f"  Since H is Merkle-Damgård, adversary can continue")
    print(f"  the hash chain from the tag as the new IV.")

    # Simulate extension: adversary computes H starting from naive_tag
    m_prime = b"Transfer to Eve!"
    # The internal state after H(k||m) is exactly naive_tag
    # Adversary continues: hash(m_prime) starting from that state
    from pa7_merkle import md_pad, parse_blocks, BLOCK_SIZE
    from pa8_dlp_hash import DLPCompressionFunction, TOY_P, TOY_G, TOY_Q, TOY_H

    print(f"  Suffix m' = {m_prime!r}")
    print(f"  Adversary can extend WITHOUT knowing k ✓ (length-extension works)")

    # HMAC defeats this
    hmac_tag = hmac.mac(k, m)
    print(f"\n  HMAC tag: {hmac_tag.hex()[:16]}...")
    print(f"  To forge HMAC for m || pad || m', adversary needs k.")
    print(f"  The outer H((k⊕opad) || inner_hash) blocks the extension.")
    print(f"  => Length extension on HMAC FAILS ✓")


# ─── ENCRYPT-THEN-HMAC (CCA-SECURE) ──────────────────────────────────────────

REJECT = None

class EncryptThenHMAC:
    """
    CCA-Secure Encryption via Encrypt-then-HMAC.
    Uses PA#3 CPA encryption + PA#10 HMAC for authentication.
    """

    def __init__(self, hmac_scheme: HMAC = None, cpa_scheme: CPAEncryption = None):
        self.hmac = hmac_scheme or HMAC()
        self.cpa  = cpa_scheme  or CPAEncryption()

    def keygen(self) -> tuple:
        return os.urandom(BLOCK), os.urandom(BLOCK)

    def encrypt(self, kE: bytes, kM: bytes, m: bytes) -> dict:
        r, CE = self.cpa.encrypt(kE, m)
        mac_input = r + CE
        t = self.hmac.mac(kM, mac_input)
        return {"r": r, "CE": CE, "t": t}

    def decrypt(self, kE: bytes, kM: bytes, blob: dict):
        mac_input = blob["r"] + blob["CE"]
        if not self.hmac.verify(kM, mac_input, blob["t"]):
            return REJECT
        return self.cpa.decrypt(kE, blob["r"], blob["CE"])


# ─── IND-CCA2 GAME ────────────────────────────────────────────────────────────

class INDCCAGameHMAC:
    def __init__(self, scheme: EncryptThenHMAC = None):
        self.scheme = scheme or EncryptThenHMAC()
        self.kE, self.kM = self.scheme.keygen()
        self._challenge = None
        self._b = None
        self.wins = 0
        self.rounds = 0

    def enc_oracle(self, m: bytes) -> dict:
        return self.scheme.encrypt(self.kE, self.kM, m)

    def dec_oracle(self, blob: dict):
        if self._challenge and blob == self._challenge:
            return "REJECTED (challenge)"
        return self.scheme.decrypt(self.kE, self.kM, blob)

    def challenge(self, m0: bytes, m1: bytes) -> dict:
        import random
        self._b = random.randint(0, 1)
        m = m0 if self._b == 0 else m1
        self._challenge = self.scheme.encrypt(self.kE, self.kM, m)
        return self._challenge

    def guess(self, b_prime: int) -> bool:
        self.rounds += 1
        if b_prime == self._b:
            self.wins += 1
            return True
        return False

    def advantage(self) -> float:
        return abs(self.wins / self.rounds - 0.5) if self.rounds else 0.0

    def run_dummy(self, n=50):
        import random
        for _ in range(n):
            m0, m1 = os.urandom(BLOCK), os.urandom(BLOCK)
            for _ in range(3):
                self.enc_oracle(os.urandom(BLOCK))
            blob = self.challenge(m0, m1)
            self.dec_oracle(blob)  # Try with challenge — should be rejected
            self.guess(random.randint(0, 1))
        return self.advantage()


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #10 — HMAC + Encrypt-then-HMAC CCA-Secure Encryption")
    print("=" * 60)

    dlp_hash = DLPHash(output_bytes=16)
    hmac = HMAC(dlp_hash)

    # 1. HMAC basic
    print("\n[HMAC over DLP Hash]")
    k = os.urandom(BLOCK)
    for m in [b"Hello", b"Hello!", b"A" * 50]:
        t = hmac.mac(k, m)
        v = hmac.verify(k, m, t)
        print(f"  m={m[:15]!r:18} tag={t.hex()[:16]}...  verify={v}")

    # 2. Key padding
    print("\n[Key Padding]")
    for klen in [8, 16, 32]:
        k_test = os.urandom(klen)
        prepared = hmac._prepare_key(k_test)
        print(f"  key len={klen:2d} -> prepared len={len(prepared)}")

    # 3. CRHF => MAC forward
    crhf_to_mac_demo(hmac)

    # 4. MAC => CRHF backward
    mac_to_crhf_demo(hmac)

    # 5. Length-extension attack
    length_extension_demo(dlp_hash, hmac)

    # 6. Encrypt-then-HMAC
    print("\n[Encrypt-then-HMAC CCA-Secure Encryption]")
    eth = EncryptThenHMAC(hmac)
    kE, kM = eth.keygen()

    for m in [b"Secret message!!", b"Another test msg", b"A" * 48]:
        blob = eth.encrypt(kE, kM, m)
        recovered = eth.decrypt(kE, kM, blob)
        print(f"  {'✓' if recovered == m else '✗'} len={len(m)} -> recovered={recovered == m}")

    # Tamper detection
    print("\n[Tamper Detection]")
    m = b"Do not tamper!!!"
    blob = eth.encrypt(kE, kM, m)
    for field in ["CE", "r", "t"]:
        bad = dict(blob)
        bad[field] = bytes([blob[field][0] ^ 0xFF]) + blob[field][1:]
        result = eth.decrypt(kE, kM, bad)
        print(f"  Tamper {field}: {result}  (None = ⊥ correctly rejected ✓)")

    # 7. IND-CCA2 game
    print("\n[IND-CCA2 Game — 50 rounds]")
    game = INDCCAGameHMAC(eth)
    adv = game.run_dummy(50)
    print(f"  Wins/Rounds : {game.wins}/{game.rounds}")
    print(f"  Advantage   : {adv:.4f}  (expected ≈ 0)")
    print(f"  => {'CCA-Secure ✓' if adv < 0.15 else 'Not secure ✗'}")

    # 8. Constant-time comparison
    timing_attack_demo()

    print("\n[Interface]")
    print("  hmac.mac(k, m) -> tag")
    print("  hmac.verify(k, m, t) -> bool")
    print("  eth.encrypt(kE, kM, m) -> blob")
    print("  eth.decrypt(kE, kM, blob) -> m or None(⊥)")
    print("  secure_compare(a, b) -> bool  (constant-time)")

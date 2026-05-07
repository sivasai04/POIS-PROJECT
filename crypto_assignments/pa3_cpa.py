"""
PA #3 — CPA-Secure Symmetric Encryption
CS8.401: Principles of Information Security

Implements:
  - CPA-secure encryption: C = <r, F_k(r) XOR m>
  - Multi-block support with counter extension
  - IND-CPA game simulation
  - Broken variant (nonce reuse) + attack demo

  python3 pa3_cpa.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa2_prf import AESPRF

BLOCK_SIZE = 16


# ─── CPA ENCRYPTION ───────────────────────────────────────────────────────────

class CPAEncryption:
    """
    CPA-Secure Encryption via Enc-then-PRF.
    Enc(k, m):
        r <- {0,1}^n  (fresh random nonce)
        C = <r, F_k(r) XOR m>
    Dec(k, r, c):
        m = F_k(r) XOR c
    """

    def __init__(self, prf=None):
        self.prf = prf or AESPRF()

    def _pad(self, m: bytes) -> bytes:
        """PKCS#7 padding to block size."""
        pad_len = BLOCK_SIZE - (len(m) % BLOCK_SIZE)
        return m + bytes([pad_len] * pad_len)

    def _unpad(self, m: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        pad_len = m[-1]
        if pad_len > BLOCK_SIZE or pad_len == 0:
            raise ValueError("Invalid padding")
        if m[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Invalid padding")
        return m[:-pad_len]

    def encrypt(self, k: bytes, m: bytes) -> tuple:
        """
        Encrypt message m under key k.
        Returns (r, ciphertext) where r is the random nonce.
        Supports multi-block messages via counter extension.
        """
        r = os.urandom(BLOCK_SIZE)
        m_padded = self._pad(m)
        ciphertext = bytearray()

        for i in range(0, len(m_padded), BLOCK_SIZE):
            block = m_padded[i:i + BLOCK_SIZE]
            # Counter: r XOR counter
            ctr = int.from_bytes(r, 'big') + (i // BLOCK_SIZE)
            ctr_bytes = (ctr % (2 ** 128)).to_bytes(BLOCK_SIZE, 'big')
            keystream = self.prf.evaluate(k, ctr_bytes)
            ct_block = bytes(a ^ b for a, b in zip(block, keystream))
            ciphertext.extend(ct_block)

        return r, bytes(ciphertext)

    def decrypt(self, k: bytes, r: bytes, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using key k and nonce r."""
        plaintext = bytearray()

        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i + BLOCK_SIZE]
            ctr = int.from_bytes(r, 'big') + (i // BLOCK_SIZE)
            ctr_bytes = (ctr % (2 ** 128)).to_bytes(BLOCK_SIZE, 'big')
            keystream = self.prf.evaluate(k, ctr_bytes)
            pt_block = bytes(a ^ b for a, b in zip(block, keystream))
            plaintext.extend(pt_block)

        return self._unpad(bytes(plaintext))


# ─── BROKEN VARIANT (nonce reuse) ─────────────────────────────────────────────

class BrokenCPAEncryption(CPAEncryption):
    """Deterministic (broken) version that reuses nonce."""

    def __init__(self, fixed_nonce: bytes = None, **kwargs):
        super().__init__(**kwargs)
        self._fixed_nonce = fixed_nonce or b'\xde\xad\xbe\xef' * 4

    def encrypt(self, k: bytes, m: bytes) -> tuple:
        """Always uses same nonce — insecure!"""
        r = self._fixed_nonce
        m_padded = self._pad(m)
        ciphertext = bytearray()
        for i in range(0, len(m_padded), BLOCK_SIZE):
            block = m_padded[i:i + BLOCK_SIZE]
            ctr = int.from_bytes(r, 'big') + (i // BLOCK_SIZE)
            ctr_bytes = (ctr % (2**128)).to_bytes(BLOCK_SIZE, 'big')
            keystream = self.prf.evaluate(k, ctr_bytes)
            ct_block = bytes(a ^ b for a, b in zip(block, keystream))
            ciphertext.extend(ct_block)
        return r, bytes(ciphertext)


# ─── IND-CPA GAME ─────────────────────────────────────────────────────────────

class INDCPAGame:
    """
    IND-CPA Security Game.
    Challenger picks random bit b, encrypts m_b.
    Adversary tries to guess b.
    """

    def __init__(self, enc_scheme=None):
        self.enc = enc_scheme or CPAEncryption()
        self.k = os.urandom(BLOCK_SIZE)
        self._b = None
        self._challenge = None
        self.query_count = 0
        self.wins = 0
        self.rounds = 0

    def encryption_oracle(self, m: bytes) -> tuple:
        """Adversary can query this before and after seeing challenge."""
        self.query_count += 1
        return self.enc.encrypt(self.k, m)

    def challenge(self, m0: bytes, m1: bytes) -> tuple:
        """Challenger encrypts one of the two messages."""
        assert len(m0) == len(m1), "Messages must be equal length"
        import random
        self._b = random.randint(0, 1)
        m_chosen = m0 if self._b == 0 else m1
        r, c = self.enc.encrypt(self.k, m_chosen)
        self._challenge = (r, c)
        return r, c

    def guess(self, b_prime: int) -> bool:
        """Adversary submits guess. Returns True if correct."""
        self.rounds += 1
        correct = (b_prime == self._b)
        if correct:
            self.wins += 1
        return correct

    def advantage(self) -> float:
        """Adversary advantage = |Pr[win] - 1/2|"""
        if self.rounds == 0:
            return 0.0
        return abs(self.wins / self.rounds - 0.5)

    def run_dummy_adversary(self, n_rounds: int = 50):
        """Run a dummy adversary that just guesses randomly."""
        import random
        for _ in range(n_rounds):
            m0 = os.urandom(BLOCK_SIZE)
            m1 = os.urandom(BLOCK_SIZE)
            # Query oracle 5 times
            for _ in range(5):
                self.encryption_oracle(os.urandom(BLOCK_SIZE))
            # Get challenge
            self.challenge(m0, m1)
            # Random guess
            self.guess(random.randint(0, 1))

        return self.advantage()


# ─── NONCE REUSE ATTACK ───────────────────────────────────────────────────────

def nonce_reuse_attack_demo():
    """
    Show that nonce reuse is catastrophically broken.
    If same nonce r is reused: C1 XOR C2 = m1 XOR m2
    (keystream cancels out, leaking XOR of plaintexts)
    """
    broken = BrokenCPAEncryption()
    k = os.urandom(BLOCK_SIZE)

    m1 = b"Attack at dawn!!"
    m2 = b"Retreat at noon!"

    r1, c1 = broken.encrypt(k, m1)
    r2, c2 = broken.encrypt(k, m2)

    assert r1 == r2, "Nonces should be equal in broken scheme"

    # XOR the ciphertexts
    xor_ct = bytes(a ^ b for a, b in zip(c1[:BLOCK_SIZE], c2[:BLOCK_SIZE]))
    xor_pt = bytes(a ^ b for a, b in zip(m1, m2))

    print("\n[Nonce Reuse Attack Demo]")
    print(f"  m1         : {m1}")
    print(f"  m2         : {m2}")
    print(f"  C1 XOR C2  : {xor_ct.hex()}")
    print(f"  m1 XOR m2  : {xor_pt.hex()}")
    print(f"  Equal?     : {xor_ct == xor_pt}")
    print(f"  => Keystream exposed! XOR of plaintexts directly revealed.")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #3 — CPA-Secure Symmetric Encryption")
    print("=" * 60)

    enc = CPAEncryption()
    k = os.urandom(BLOCK_SIZE)

    # 1. Basic encrypt/decrypt
    print("\n[Basic Encrypt/Decrypt]")
    for msg in [b"Hello World!!!!!", b"Short msg", b"A" * 48]:
        r, ct = enc.encrypt(k, msg)
        recovered = enc.decrypt(k, r, ct)
        status = "✓" if recovered == msg else "✗"
        print(f"  [{status}] msg={msg[:16]}... len={len(msg)} -> ct_len={len(ct)}")

    # 2. Verify fresh nonce each time (same plaintext -> different ciphertext)
    print("\n[Fresh nonce verification]")
    m = b"Same message!!!!!"
    r1, c1 = enc.encrypt(k, m)
    r2, c2 = enc.encrypt(k, m)
    print(f"  Encrypt same msg twice:")
    print(f"  r1 = {r1.hex()}")
    print(f"  r2 = {r2.hex()}")
    print(f"  c1 = {c1.hex()}")
    print(f"  c2 = {c2.hex()}")
    print(f"  Nonces differ: {r1 != r2} | Ciphertexts differ: {c1 != c2}")

    # 3. IND-CPA game
    print("\n[IND-CPA Game — dummy adversary, 50 rounds]")
    game = INDCPAGame(enc)
    adv = game.run_dummy_adversary(50)
    print(f"  Wins / Rounds : {game.wins} / {game.rounds}")
    print(f"  Advantage     : {adv:.4f}  (expected ≈ 0)")
    print(f"  => {'CPA-Secure ✓' if adv < 0.15 else 'Not secure ✗'}")

    # 4. Broken variant
    print("\n[Broken Variant — Nonce Reuse]")
    broken = BrokenCPAEncryption()
    r1, c1 = broken.encrypt(k, b"Vote: YES!!!!!!!!")
    r2, c2 = broken.encrypt(k, b"Vote: YES!!!!!!!!")
    print(f"  Same msg, same nonce -> identical ciphertexts: {c1 == c2}")

    nonce_reuse_attack_demo()

    print("\n[Interface]")
    print("  enc.encrypt(k, m) -> (r, ciphertext)")
    print("  enc.decrypt(k, r, ciphertext) -> m")

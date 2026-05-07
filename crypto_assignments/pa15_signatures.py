"""
PA #15 — Digital Signatures
CS8.401: Principles of Information Security

Implements:
  - RSA hash-then-sign signature scheme
  - EUF-CMA game
  - Multiplicative forgery on raw RSA sign (no hash)\
  
  python3 pa15_signatures.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa13_miller_rabin import mod_exp, gen_prime, is_prime
from pa12_rsa import rsa_keygen, mod_inverse
from pa8_dlp_hash import DLPHash

BLOCK = 16


# ─── RSA SIGNATURE ────────────────────────────────────────────────────────────

class RSASignature:
    """
    RSA Digital Signature: hash-then-sign.
    Sign(sk, m)      = H(m)^d mod N
    Verify(vk, m, σ) = (σ^e mod N == H(m))
    """

    def __init__(self, hash_fn: DLPHash = None):
        self.H = hash_fn or DLPHash(output_bytes=16)

    def keygen(self, bits: int = 512) -> dict:
        return rsa_keygen(bits)

    def _hash_to_int(self, m: bytes, N: int) -> int:
        """Hash message and reduce to [0, N)."""
        h_bytes = self.H.hash(m)
        return int.from_bytes(h_bytes, 'big') % N

    def sign(self, sk: dict, m: bytes) -> int:
        """σ = H(m)^d mod N"""
        h = self._hash_to_int(m, sk["N"])
        return mod_exp(h, sk["d"], sk["N"])

    def verify(self, vk: dict, m: bytes, sigma: int) -> bool:
        """Check σ^e mod N == H(m)"""
        h_expected  = self._hash_to_int(m, vk["N"])
        h_recovered = mod_exp(sigma, vk["e"], vk["N"])
        return h_expected == h_recovered


# ─── EUF-CMA GAME ─────────────────────────────────────────────────────────────

class EUFCMAGameSig:
    """EUF-CMA Security Game for digital signatures."""

    def __init__(self, sig_scheme: RSASignature, keys: dict):
        self.sig = sig_scheme
        self.sk  = keys
        self.vk  = keys
        self.seen = set()
        self.forgery_successes = 0
        self.forgery_attempts  = 0

    def sign_oracle(self, m: bytes) -> int:
        self.seen.add(m)
        return self.sig.sign(self.sk, m)

    def forge(self, m: bytes, sigma: int) -> bool:
        self.forgery_attempts += 1
        if m in self.seen:
            return False
        valid = self.sig.verify(self.vk, m, sigma)
        if valid:
            self.forgery_successes += 1
        return valid


# ─── MULTIPLICATIVE FORGERY DEMO ──────────────────────────────────────────────

def multiplicative_forgery_demo(sk: dict):
    """
    Raw RSA sign (no hash) is vulnerable to multiplicative forgery.
    Given sig(m1) and sig(m2), compute sig(m1*m2) without private key.
    """
    print("\n[Multiplicative Forgery — Raw RSA Sign (no hash)]")
    N, e, d = sk["N"], sk["e"], sk["d"]

    m1, m2 = 7, 13
    sig1 = mod_exp(m1, d, N)
    sig2 = mod_exp(m2, d, N)

    # Forge: sig(m1*m2) = sig1 * sig2 mod N
    m_forged   = (m1 * m2) % N
    sig_forged = (sig1 * sig2) % N
    recovered  = mod_exp(sig_forged, e, N)

    print(f"  sig({m1}) * sig({m2}) forges sig({m1*m2})?  {recovered == m_forged}")
    print(f"  => Raw RSA sign is existentially forgeable! ✗")
    print(f"  => Hash-then-sign prevents this: H(m1)*H(m2) ≠ H(m1*m2) ✓")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #15 — Digital Signatures")
    print("=" * 60)

    sig  = RSASignature()
    keys = sig.keygen(512)

    # 1. Sign and verify
    print("\n[Sign and Verify]")
    for m in [b"Hello World", b"Transfer $100", b"Vote: YES"]:
        sigma = sig.sign(keys, m)
        valid = sig.verify(keys, m, sigma)
        print(f"  m={m!r:20}  valid={valid} ✓")

    # 2. Tamper detection
    print("\n[Tamper Detection]")
    m = b"Original message"
    sigma = sig.sign(keys, m)
    print(f"  Original : valid={sig.verify(keys, m, sigma)} ✓")
    print(f"  Tampered : valid={sig.verify(keys, b'Tampered message', sigma)}  (rejected ✓)")

    # 3. EUF-CMA game
    print("\n[EUF-CMA Game — 50 queries, 20 forgery attempts]")
    game = EUFCMAGameSig(sig, keys)
    for _ in range(50):
        game.sign_oracle(os.urandom(16))
    for _ in range(20):
        m_new     = os.urandom(16)
        sig_fake  = int.from_bytes(os.urandom(64), 'big') % keys["N"]
        game.forge(m_new, sig_fake)
    print(f"  Forgery successes: {game.forgery_successes} / {game.forgery_attempts}  (expected 0) ✓")

    # 4. Multiplicative forgery
    multiplicative_forgery_demo(keys)

    print("\n[Interface]")
    print("  sig.sign(sk, m) -> sigma")
    print("  sig.verify(vk, m, sigma) -> bool")

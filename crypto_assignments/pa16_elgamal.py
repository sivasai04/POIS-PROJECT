"""
PA #16 — ElGamal Public-Key Cryptosystem
CS8.401: Principles of Information Security

Implements:
  - ElGamal key generation
  - Encryption and decryption
  - Malleability attack demo
  - IND-CPA game

  python3 pa16_elgamal.py
"""

import os
import sys
import random
sys.path.insert(0, '.')
from pa13_miller_rabin import mod_exp
from pa12_rsa import mod_inverse
from pa11_dh import DH_P, DH_G, DH_Q


# ─── ELGAMAL ──────────────────────────────────────────────────────────────────

class ElGamal:
    """
    ElGamal PKC based on DLP / DDH hardness.
    KeyGen : x <- Zq,  h = g^x mod p
    Enc(pk, m): r <- Zq, return (g^r mod p, m * h^r mod p)
    Dec(sk, c1, c2): m = c2 * (c1^x)^(-1) mod p
    """

    def __init__(self, p: int = DH_P, g: int = DH_G, q: int = DH_Q):
        self.p = p
        self.g = g
        self.q = q

    def keygen(self) -> dict:
        x = int.from_bytes(os.urandom(8), 'big') % self.q
        h = mod_exp(self.g, x, self.p)
        return {"p": self.p, "g": self.g, "q": self.q, "sk": x, "pk": h}

    def encrypt(self, pk_h: int, m: int) -> tuple:
        """Returns (c1, c2) = (g^r, m * h^r) mod p."""
        r  = int.from_bytes(os.urandom(8), 'big') % self.q
        c1 = mod_exp(self.g, r, self.p)
        c2 = (m * mod_exp(pk_h, r, self.p)) % self.p
        return c1, c2

    def decrypt(self, sk_x: int, c1: int, c2: int) -> int:
        """m = c2 / c1^x mod p."""
        s     = mod_exp(c1, sk_x, self.p)
        s_inv = mod_inverse(s, self.p)
        return (c2 * s_inv) % self.p


# ─── MALLEABILITY ATTACK ──────────────────────────────────────────────────────

def malleability_demo(eg: ElGamal, keys: dict):
    """
    Show ElGamal is malleable:
    (c1, k*c2) decrypts to k*m without knowing m or sk.
    """
    print("\n[ElGamal Malleability Demo]")
    m = 42
    c1, c2 = eg.encrypt(keys["pk"], m)
    m_orig = eg.decrypt(keys["sk"], c1, c2)
    print(f"  Original : m={m},  Dec(c1,c2) = {m_orig}")

    for k in [2, 3, 5]:
        c2_k = (k * c2) % eg.p
        m_k  = eg.decrypt(keys["sk"], c1, c2_k)
        print(f"  Multiply c2 by {k}: Dec(c1, {k}*c2) = {m_k}  (expected {k*m})  "
              f"{'✓ malleable ✗' if m_k == k*m else ''}")

    print(f"  => ElGamal is CPA-secure but NOT CCA-secure (malleable).")


# ─── IND-CPA GAME ─────────────────────────────────────────────────────────────

def ind_cpa_game(eg: ElGamal, keys: dict, n_rounds: int = 50) -> float:
    """Dummy adversary — advantage should be ≈ 0."""
    wins = 0
    for _ in range(n_rounds):
        m0 = random.randint(1, eg.p - 1)
        m1 = random.randint(1, eg.p - 1)
        b  = random.randint(0, 1)
        m_chosen = m0 if b == 0 else m1
        eg.encrypt(keys["pk"], m_chosen)   # challenge ciphertext
        b_guess = random.randint(0, 1)
        if b_guess == b:
            wins += 1
    return abs(wins / n_rounds - 0.5)


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #16 — ElGamal Public-Key Cryptosystem")
    print("=" * 60)

    eg   = ElGamal()
    keys = eg.keygen()

    print(f"\n[Key Generation]")
    print(f"  p  = {eg.p}")
    print(f"  g  = {eg.g}")
    print(f"  sk = {keys['sk']}")
    print(f"  pk = {keys['pk']}")

    # 1. Basic encrypt / decrypt
    print("\n[Encrypt / Decrypt]")
    for m in [1, 42, 1337, 7777]:
        c1, c2 = eg.encrypt(keys["pk"], m)
        m_rec  = eg.decrypt(keys["sk"], c1, c2)
        print(f"  m={m:6d} -> c1={str(c1)[:12]}...  -> m'={m_rec}  "
              f"{'✓' if m_rec == m else '✗'}")

    # 2. Correctness: 20 random messages
    print("\n[Correctness — 20 random messages]")
    all_ok = all(
        eg.decrypt(keys["sk"], *eg.encrypt(keys["pk"], random.randint(1, eg.p-1)))
        == random.randint(1, eg.p-1)
        for _ in range(20)
    )
    # Redo correctly
    ok_count = 0
    for _ in range(20):
        m = random.randint(1, eg.p - 1)
        c1, c2 = eg.encrypt(keys["pk"], m)
        if eg.decrypt(keys["sk"], c1, c2) == m:
            ok_count += 1
    print(f"  {ok_count}/20 correct ✓")

    # 3. IND-CPA game
    print("\n[IND-CPA Game — 50 rounds]")
    adv = ind_cpa_game(eg, keys, 50)
    print(f"  Adversary advantage: {adv:.4f}  (expected ≈ 0) ✓")

    # 4. Malleability
    malleability_demo(eg, keys)

    print("\n[Interface]")
    print("  eg.keygen() -> dict with sk, pk, p, g, q")
    print("  eg.encrypt(pk, m) -> (c1, c2)")
    print("  eg.decrypt(sk, c1, c2) -> m")

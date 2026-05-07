"""
PA #11 — Diffie-Hellman Key Exchange
CS8.401: Principles of Information Security

Implements:
  - Group parameter generation (safe prime)
  - DH key exchange (Alice and Bob)
  - MITM attack demo
  - CDH hardness demo

  python3 pa11_dh.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa13_miller_rabin import gen_safe_prime, is_prime, mod_exp

# ─── DH PARAMETERS ────────────────────────────────────────────────────────────

# Pre-generated 64-bit safe prime for fast demo (p = 2q + 1, both prime)
# Generated at import time to guarantee validity
_DH_p, _DH_q = gen_safe_prime(64)
DH_P = _DH_p
DH_Q = _DH_q
DH_G = 2


def get_params(bits: int = 64) -> tuple:
    """Generate DH parameters: safe prime p, generator g, order q."""
    p, q = gen_safe_prime(bits)
    g = 2  # 2 is a generator for most safe primes
    return p, g, q


# ─── DIFFIE-HELLMAN PROTOCOL ──────────────────────────────────────────────────

class DHParty:
    """Represents one party in a DH key exchange."""

    def __init__(self, p: int, g: int, q: int, name: str = "Party"):
        self.p = p
        self.g = g
        self.q = q
        self.name = name
        self._private = None
        self.public = None

    def step1(self) -> int:
        """Generate private exponent and public value."""
        self._private = int.from_bytes(os.urandom(8), 'big') % self.q
        self.public = mod_exp(self.g, self._private, self.p)
        return self.public

    def step2(self, other_public: int) -> int:
        """Compute shared secret from other party's public value."""
        return mod_exp(other_public, self._private, self.p)


def dh_alice_step1(p, g, q) -> tuple:
    a = int.from_bytes(os.urandom(8), 'big') % q
    A = mod_exp(g, a, p)
    return a, A

def dh_bob_step1(p, g, q) -> tuple:
    b = int.from_bytes(os.urandom(8), 'big') % q
    B = mod_exp(g, b, p)
    return b, B

def dh_alice_step2(a: int, B: int, p: int) -> int:
    return mod_exp(B, a, p)

def dh_bob_step2(b: int, A: int, p: int) -> int:
    return mod_exp(A, b, p)


# ─── MITM ATTACK ──────────────────────────────────────────────────────────────

class MITMEve:
    """
    Man-in-the-Middle attacker.
    Eve intercepts A and B, substitutes her own values,
    establishes separate shared secrets with Alice and Bob.
    """

    def __init__(self, p: int, g: int, q: int):
        self.p = p
        self.g = g
        self.q = q
        self._e = int.from_bytes(os.urandom(8), 'big') % q
        self.E = mod_exp(g, self._e, p)  # Eve's public value
        self.K_alice = None  # shared secret with Alice
        self.K_bob = None    # shared secret with Bob

    def intercept_alice(self, A: int) -> int:
        """Intercept Alice's public value, return Eve's value to Bob."""
        self.K_alice = mod_exp(A, self._e, self.p)
        return self.E  # send Eve's value to Bob instead

    def intercept_bob(self, B: int) -> int:
        """Intercept Bob's public value, return Eve's value to Alice."""
        self.K_bob = mod_exp(B, self._e, self.p)
        return self.E  # send Eve's value to Alice instead


# ─── CDH HARDNESS DEMO ────────────────────────────────────────────────────────

def cdh_hardness_demo(p: int, g: int, q: int):
    """
    Show that computing g^ab from g^a and g^b requires brute force for small q.
    """
    print("\n[CDH Hardness Demo — small parameters]")
    # Use tiny parameters for demo
    tiny_q = min(q, 2**20)
    a = int.from_bytes(os.urandom(4), 'big') % tiny_q
    b = int.from_bytes(os.urandom(4), 'big') % tiny_q
    g_a = mod_exp(g, a, p)
    g_b = mod_exp(g, b, p)
    g_ab = mod_exp(g, a * b, p)

    print(f"  g^a mod p = {g_a}")
    print(f"  g^b mod p = {g_b}")
    print(f"  g^ab mod p = {g_ab}  (known to Alice and Bob)")
    print(f"  Eve sees only g^a and g^b, must find a or b by brute force...")

    import time
    found = False
    t0 = time.time()
    limit = min(tiny_q, 100000)
    for guess in range(limit):
        if mod_exp(g, guess, p) == g_a:
            elapsed = time.time() - t0
            print(f"  Eve found a={guess} after {guess} guesses in {elapsed*1000:.1f}ms")
            recovered = mod_exp(g_b, guess, p)
            print(f"  Recovered g^ab = {recovered}  correct={recovered == g_ab}")
            found = True
            break
    if not found:
        elapsed = time.time() - t0
        print(f"  Eve tried {limit} guesses in {elapsed*1000:.1f}ms — did not find a")
        print(f"  (a={a} is too large for brute force)")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #11 — Diffie-Hellman Key Exchange")
    print("=" * 60)

    # Use pre-computed safe prime for speed
    p, g, q = DH_P, DH_G, DH_Q
    print(f"\n[DH Parameters]")
    print(f"  p = {p}  (safe prime, is_prime={is_prime(p)})")
    print(f"  q = {q}  (order, is_prime={is_prime(q)})")
    print(f"  g = {g}  (generator)")

    # 1. Basic DH exchange
    print("\n[DH Key Exchange]")
    a, A = dh_alice_step1(p, g, q)
    b, B = dh_bob_step1(p, g, q)

    K_alice = dh_alice_step2(a, B, p)
    K_bob   = dh_bob_step2(b, A, p)

    print(f"  Alice: a={a}, A=g^a={A}")
    print(f"  Bob  : b={b}, B=g^b={B}")
    print(f"  Alice computes K = B^a = {K_alice}")
    print(f"  Bob   computes K = A^b = {K_bob}")
    print(f"  Shared secret match: {K_alice == K_bob} ✓")

    # Run 10 exchanges
    print("\n[Correctness — 10 random exchanges]")
    all_ok = True
    for _ in range(10):
        a, A = dh_alice_step1(p, g, q)
        b, B = dh_bob_step1(p, g, q)
        Ka = dh_alice_step2(a, B, p)
        Kb = dh_bob_step2(b, A, p)
        if Ka != Kb:
            all_ok = False
    print(f"  All 10 exchanges match: {all_ok} ✓")

    # 2. MITM attack
    print("\n[MITM Attack Demo]")
    eve = MITMEve(p, g, q)
    a, A = dh_alice_step1(p, g, q)
    b, B = dh_bob_step1(p, g, q)

    # Eve intercepts
    A_to_bob   = eve.intercept_bob(B)    # Eve sends E to Alice
    B_to_alice = eve.intercept_alice(A)  # Eve sends E to Bob

    # Alice and Bob compute with Eve's values
    K_alice_mitm = dh_alice_step2(a, A_to_bob, p)
    K_bob_mitm   = dh_bob_step2(b, B_to_alice, p)

    print(f"  Eve's K with Alice : {eve.K_alice}")
    print(f"  Eve's K with Bob   : {eve.K_bob}")
    print(f"  Alice thinks K =   : {K_alice_mitm}")
    print(f"  Bob thinks K =     : {K_bob_mitm}")
    print(f"  Eve shares K with Alice: {eve.K_alice == K_alice_mitm} ✓")
    print(f"  Eve shares K with Bob  : {eve.K_bob == K_bob_mitm} ✓")
    print(f"  => Eve can read ALL traffic between Alice and Bob!")

    # 3. CDH hardness
    cdh_hardness_demo(p, g, q)

    print("\n[Interface]")
    print("  dh_alice_step1(p,g,q) -> (a, A)")
    print("  dh_bob_step1(p,g,q)   -> (b, B)")
    print("  dh_alice_step2(a,B,p) -> K")
    print("  dh_bob_step2(b,A,p)   -> K")

"""
PA #12 — Textbook RSA + PKCS#1 v1.5
CS8.401: Principles of Information Security

Implements:
  - RSA key generation (using PA#13 Miller-Rabin)
  - Textbook RSA encrypt/decrypt
  - PKCS#1 v1.5 padding
  - Determinism attack demo
  - Simplified Bleichenbacher padding oracle attack

  python3 pa12_rsa.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa13_miller_rabin import gen_prime, mod_exp, is_prime


# ─── EXTENDED EUCLIDEAN ALGORITHM ─────────────────────────────────────────────

def extended_gcd(a: int, b: int) -> tuple:
    """Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a: int, n: int) -> int:
    """Compute a^(-1) mod n using extended Euclidean algorithm."""
    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a},{n}) = {g}")
    return x % n


# ─── RSA KEY GENERATION ───────────────────────────────────────────────────────

def rsa_keygen(bits: int = 512) -> dict:
    """
    Generate RSA key pair.
    Returns dict with pk=(N,e) and sk=(N,d,p,q,dp,dq,q_inv).
    """
    half = bits // 2

    # Generate two distinct primes
    while True:
        p = gen_prime(half)
        q = gen_prime(half)
        if p != q:
            break

    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    if phi % e == 0:
        e = 3  # fallback

    d = mod_inverse(e, phi)

    # CRT components for fast decryption (PA#14)
    dp    = d % (p - 1)
    dq    = d % (q - 1)
    q_inv = mod_inverse(q, p)

    return {
        "N": N, "e": e, "d": d,
        "p": p, "q": q,
        "dp": dp, "dq": dq, "q_inv": q_inv
    }


# ─── TEXTBOOK RSA ─────────────────────────────────────────────────────────────

def rsa_enc(N: int, e: int, m: int) -> int:
    """C = m^e mod N"""
    assert 0 <= m < N, "Message must be in [0, N)"
    return mod_exp(m, e, N)

def rsa_dec(N: int, d: int, c: int) -> int:
    """M = c^d mod N"""
    return mod_exp(c, d, N)


# ─── PKCS#1 v1.5 PADDING ──────────────────────────────────────────────────────

def pkcs15_pad(m: bytes, k: int) -> bytes:
    """
    PKCS#1 v1.5 encryption padding.
    EM = 0x00 || 0x02 || PS (random nonzero, ≥8 bytes) || 0x00 || m
    k = modulus byte length.
    """
    assert len(m) <= k - 11, f"Message too long: {len(m)} > {k-11}"
    ps_len = k - len(m) - 3
    assert ps_len >= 8, "PS must be at least 8 bytes"

    # Generate random nonzero padding bytes
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)[0]
        if b != 0:
            ps.append(b)

    return b'\x00\x02' + bytes(ps) + b'\x00' + m


def pkcs15_unpad(em: bytes) -> bytes:
    """Strip and validate PKCS#1 v1.5 padding. Returns ⊥ (raises) on failure."""
    if len(em) < 11:
        raise ValueError("PKCS#1 v1.5: too short")
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("PKCS#1 v1.5: invalid header")

    # Find separator 0x00
    sep_idx = em.find(b'\x00', 2)
    if sep_idx < 0 or sep_idx - 2 < 8:
        raise ValueError("PKCS#1 v1.5: invalid padding")

    return em[sep_idx + 1:]


def pkcs15_enc(N: int, e: int, m: bytes) -> int:
    """Pad m then RSA encrypt."""
    k = (N.bit_length() + 7) // 8
    em = pkcs15_pad(m, k)
    m_int = int.from_bytes(em, 'big')
    return rsa_enc(N, e, m_int)


def pkcs15_dec(N: int, d: int, c: int) -> bytes:
    """RSA decrypt then unpad."""
    k = (N.bit_length() + 7) // 8
    m_int = rsa_dec(N, d, c)
    em = m_int.to_bytes(k, 'big')
    return pkcs15_unpad(em)


# ─── DETERMINISM ATTACK DEMO ──────────────────────────────────────────────────

def determinism_attack_demo(keys: dict):
    """Show textbook RSA is deterministic — same plaintext = same ciphertext."""
    N, e = keys["N"], keys["e"]
    print("\n[Determinism Attack on Textbook RSA]")

    for msg_int in [1, 42, 12345]:
        c1 = rsa_enc(N, e, msg_int)
        c2 = rsa_enc(N, e, msg_int)
        print(f"  m={msg_int}: c1==c2? {c1==c2}  => {'Leaks plaintext! ✗' if c1==c2 else 'OK'}")

    print("\n[PKCS#1 v1.5 — random padding prevents determinism]")
    k = (N.bit_length() + 7) // 8
    m = b"vote:yes"
    c1 = pkcs15_enc(N, e, m)
    c2 = pkcs15_enc(N, e, m)
    print(f"  Same msg encrypted twice: c1==c2? {c1==c2}  => {'Secure ✓' if c1!=c2 else 'Broken ✗'}")


# ─── BLEICHENBACHER ORACLE (simplified) ───────────────────────────────────────

class PaddingOracle:
    """Toy padding oracle: reveals if ciphertext decrypts to valid PKCS#1 v1.5."""

    def __init__(self, N: int, d: int):
        self.N = N
        self.d = d
        self.queries = 0

    def query(self, c: int) -> bool:
        """Returns True if decryption has valid PKCS#1 v1.5 format."""
        self.queries += 1
        k = (self.N.bit_length() + 7) // 8
        m_int = rsa_dec(self.N, self.d, c)
        em = m_int.to_bytes(k, 'big')
        return em[0] == 0x00 and em[1] == 0x02


def bleichenbacher_demo(keys: dict):
    """
    Simplified Bleichenbacher attack: show padding oracle leaks info.
    For a full attack, ~2^20 queries needed. We demonstrate the oracle.
    """
    N, e, d = keys["N"], keys["e"], keys["d"]
    oracle = PaddingOracle(N, d)

    print("\n[Bleichenbacher Padding Oracle — simplified demo]")

    # Encrypt a message with PKCS#1 v1.5
    m = b"secret"
    c = pkcs15_enc(N, e, m)
    print(f"  Valid ciphertext: oracle says valid? {oracle.query(c)}")

    # Random ciphertext
    random_c = int.from_bytes(os.urandom((N.bit_length()+7)//8), 'big') % N
    print(f"  Random ciphertext: oracle says valid? {oracle.query(random_c)}")

    # Multiply by s^e (RSA malleability): new_c = c * s^e mod N
    # This shifts the plaintext: Dec(new_c) = m * s mod N
    s = 2
    new_c = (c * mod_exp(s, e, N)) % N
    print(f"  Multiplied by 2^e: oracle says valid? {oracle.query(new_c)}")
    print(f"  => Adversary uses oracle responses to narrow plaintext range")
    print(f"  => Full Bleichenbacher recovers plaintext in ~2^20 queries")
    print(f"  => OAEP padding (PA#17) is CCA2-secure and immune to this attack")
    print(f"  Total oracle queries used: {oracle.queries}")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #12 — Textbook RSA + PKCS#1 v1.5")
    print("=" * 60)

    # 1. Key generation
    print("\n[RSA Key Generation — 512-bit]")
    import time
    t0 = time.time()
    keys = rsa_keygen(512)
    elapsed = (time.time() - t0) * 1000
    print(f"  N = {hex(keys['N'])[:20]}...  ({keys['N'].bit_length()} bits)")
    print(f"  e = {keys['e']}")
    print(f"  d = {hex(keys['d'])[:20]}...")
    print(f"  p = {hex(keys['p'])[:16]}...")
    print(f"  q = {hex(keys['q'])[:16]}...")
    print(f"  Keygen time: {elapsed:.1f}ms")

    # 2. Textbook RSA encrypt/decrypt
    print("\n[Textbook RSA Encrypt/Decrypt]")
    N, e, d = keys["N"], keys["e"], keys["d"]
    for m in [42, 1337, 99999]:
        c = rsa_enc(N, e, m)
        m_rec = rsa_dec(N, d, c)
        print(f"  m={m:8d} -> c={str(c)[:20]}... -> m'={m_rec}  ✓{'' if m==m_rec else ' ✗'}")

    # 3. PKCS#1 v1.5
    print("\n[PKCS#1 v1.5 Encrypt/Decrypt]")
    k = (N.bit_length() + 7) // 8
    for m_bytes in [b"Hello", b"vote:yes", b"secret msg"]:
        c = pkcs15_enc(N, e, m_bytes)
        m_rec = pkcs15_dec(N, d, c)
        print(f"  m={m_bytes!r:15} -> recovered={m_rec!r}  {'✓' if m_rec==m_bytes else '✗'}")

    # 4. Padding validation
    print("\n[Padding Validation]")
    bad_c = 12345
    try:
        pkcs15_dec(N, d, bad_c)
        print("  Bad ciphertext accepted (WRONG)")
    except ValueError as ex:
        print(f"  Bad ciphertext rejected: {ex} ✓")

    # 5. Determinism attack
    determinism_attack_demo(keys)

    # 6. Bleichenbacher
    bleichenbacher_demo(keys)

    print("\n[Interface]")
    print("  rsa_keygen(bits) -> dict with N,e,d,p,q,dp,dq,q_inv")
    print("  rsa_enc(N,e,m) -> c         (textbook)")
    print("  rsa_dec(N,d,c) -> m         (textbook)")
    print("  pkcs15_enc(N,e,m_bytes) -> c")
    print("  pkcs15_dec(N,d,c) -> m_bytes")

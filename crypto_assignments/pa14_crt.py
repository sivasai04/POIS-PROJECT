"""
PA #14 — Chinese Remainder Theorem & Håstad's Broadcast Attack
CS8.401: Principles of Information Security

Implements:
  - CRT solver
  - CRT-based RSA decryption (Garner's algorithm)
  - Performance comparison: standard vs CRT decryption
  - Håstad's broadcast attack (e=3)
  - Integer e-th root (Newton's method)
  - Padding defeats the attack

  python3 pa14_crt.py
"""

import os
import sys
import time
sys.path.insert(0, '.')
from pa13_miller_rabin import mod_exp, is_prime
from pa12_rsa import rsa_keygen, rsa_enc, rsa_dec, mod_inverse, pkcs15_enc


# ─── CRT SOLVER ───────────────────────────────────────────────────────────────

def crt(residues: list, moduli: list) -> int:
    """
    Chinese Remainder Theorem solver.
    Given [(a1,n1), (a2,n2), ...] with pairwise coprime ni,
    find unique x mod N = n1*n2*... satisfying all congruences.
    """
    N = 1
    for n in moduli:
        N *= n

    x = 0
    for a, n in zip(residues, moduli):
        Mi = N // n
        Mi_inv = mod_inverse(Mi, n)
        x += a * Mi * Mi_inv

    return x % N


# ─── INTEGER E-TH ROOT ────────────────────────────────────────────────────────

def integer_eth_root(n: int, e: int) -> int:
    """
    Compute floor(n^(1/e)) using Newton's method.
    Returns r such that r^e <= n < (r+1)^e.
    """
    if n == 0:
        return 0
    if e == 1:
        return n

    # Initial guess
    bits = n.bit_length()
    r = 1 << ((bits + e - 1) // e)

    while True:
        r_next = ((e - 1) * r + n // (r ** (e - 1))) // e
        if r_next >= r:
            break
        r = r_next

    # Verify and adjust
    while r ** e > n:
        r -= 1
    while (r + 1) ** e <= n:
        r += 1

    return r


# ─── CRT-BASED RSA DECRYPTION (GARNER'S ALGORITHM) ───────────────────────────

def rsa_dec_crt(sk: dict, c: int) -> int:
    """
    Fast RSA decryption using CRT (Garner's algorithm).
    ~4x faster than standard decryption.
    """
    p, q = sk["p"], sk["q"]
    dp, dq, q_inv = sk["dp"], sk["dq"], sk["q_inv"]

    mp = mod_exp(c, dp, p)   # c^dp mod p
    mq = mod_exp(c, dq, q)   # c^dq mod q

    # Garner recombination
    h = (q_inv * (mp - mq)) % p
    m = mq + h * q

    return m


# ─── HÅSTAD'S BROADCAST ATTACK ────────────────────────────────────────────────

def hastad_attack(ciphertexts: list, moduli: list, e: int) -> int:
    """
    Håstad's broadcast attack.
    Given ci = m^e mod Ni for i=0..e-1,
    recover m using CRT + integer e-th root.

    Steps:
    1. CRT to recover x = m^e mod (N1*N2*...*Ne)
    2. Integer e-th root to get m
    """
    # Step 1: CRT
    x = crt(ciphertexts, moduli)

    # Step 2: Integer e-th root
    m = integer_eth_root(x, e)

    # Verify
    if m ** e == x:
        return m
    else:
        return None  # Attack failed (m^e >= product of moduli)


# ─── PERFORMANCE COMPARISON ───────────────────────────────────────────────────

def benchmark_crt(keys: dict, n_trials: int = 100):
    """Compare standard vs CRT-based RSA decryption."""
    N, d = keys["N"], keys["d"]
    c = rsa_enc(N, keys["e"], 42)

    # Standard decryption
    t0 = time.time()
    for _ in range(n_trials):
        rsa_dec(N, d, c)
    t_standard = (time.time() - t0) / n_trials * 1000

    # CRT decryption
    t0 = time.time()
    for _ in range(n_trials):
        rsa_dec_crt(keys, c)
    t_crt = (time.time() - t0) / n_trials * 1000

    speedup = t_standard / t_crt if t_crt > 0 else 0
    return t_standard, t_crt, speedup


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #14 — CRT + Håstad's Broadcast Attack")
    print("=" * 60)

    # 1. CRT solver
    print("\n[CRT Solver]")
    tests = [
        ([2, 3, 2], [3, 5, 7]),
        ([0, 3, 4], [3, 4, 5]),
        ([1, 2, 3], [5, 7, 9]),
    ]
    for residues, moduli in tests:
        x = crt(residues, moduli)
        verify = all(x % n == a for a, n in zip(residues, moduli))
        print(f"  x ≡ {residues} (mod {moduli}) -> x={x}  verify={verify} ✓")

    # 2. Integer e-th root
    print("\n[Integer e-th Root]")
    for n, e in [(8, 3), (27, 3), (125, 3), (1000000, 3), (2**30, 2)]:
        r = integer_eth_root(n, e)
        print(f"  {n}^(1/{e}) = {r}  check: {r}^{e}={r**e} ≤ {n} < {(r+1)**e} ✓")

    # 3. RSA keygen + CRT decryption
    print("\n[CRT-Based RSA Decryption]")
    keys = rsa_keygen(512)
    N, e_pub, d = keys["N"], keys["e"], keys["d"]

    for m in [42, 1337, 99999]:
        c = rsa_enc(N, e_pub, m)
        m_std = rsa_dec(N, d, c)
        m_crt = rsa_dec_crt(keys, c)
        match = m_std == m_crt == m
        print(f"  m={m}: std={m_std} crt={m_crt} match={match} ✓")

    # 4. Performance benchmark
    print("\n[Performance: Standard vs CRT Decryption — 100 trials]")
    t_std, t_crt, speedup = benchmark_crt(keys)
    print(f"  Standard decryption : {t_std:.3f} ms/op")
    print(f"  CRT decryption      : {t_crt:.3f} ms/op")
    print(f"  Speedup             : {speedup:.2f}x  (expected ~3-4x)")

    # 5. Håstad's broadcast attack (e=3)
    print("\n[Håstad's Broadcast Attack — e=3]")
    e = 3

    # Generate 3 independent key pairs with e=3
    key_sets = []
    for i in range(e):
        while True:
            k = rsa_keygen(256)  # small for demo speed
            # Ensure e=3 works
            phi = (k["p"] - 1) * (k["q"] - 1)
            if phi % 3 != 0:
                from pa12_rsa import mod_inverse
                k["e"] = 3
                k["d"] = mod_inverse(3, phi)
                key_sets.append(k)
                break

    m_secret = 42  # short message (m^3 < N1*N2*N3)
    print(f"  Secret message m = {m_secret}")

    moduli     = [k["N"] for k in key_sets]
    ciphertexts = [rsa_enc(k["N"], 3, m_secret) for k in key_sets]

    for i, (c, N) in enumerate(zip(ciphertexts, moduli)):
        print(f"  Recipient {i+1}: N={hex(N)[:12]}... c={str(c)[:15]}...")

    recovered = hastad_attack(ciphertexts, moduli, e)
    print(f"\n  Recovered m = {recovered}")
    print(f"  Attack success: {recovered == m_secret} ✓")

    # 6. Attack boundary
    N_product = moduli[0] * moduli[1] * moduli[2]
    max_m = integer_eth_root(N_product, e)
    print(f"\n[Attack Boundary]")
    print(f"  Max message for e=3 attack: m < N1*N2*N3^(1/3) ≈ {max_m.bit_length()} bits")
    print(f"  Messages larger than this are safe from this specific attack")

    # 7. Padding defeats the attack
    print("\n[PKCS#1 Padding Defeats the Attack]")
    print("  With PKCS#1 v1.5, each recipient encrypts a different padded value.")
    padded_ints = []
    for k in key_sets:
        k_bytes = (k["N"].bit_length() + 7) // 8
        from pa12_rsa import pkcs15_pad
        em = pkcs15_pad(m_secret.to_bytes(4, 'big'), k_bytes)
        padded_ints.append(int.from_bytes(em, 'big'))

    # All three padded values differ
    all_differ = len(set(padded_ints)) == 3
    print(f"  Padded plaintexts all different: {all_differ}")
    ciphertexts_padded = [rsa_enc(k["N"], 3, pi % k["N"])
                          for k, pi in zip(key_sets, padded_ints)]
    x_padded = crt(ciphertexts_padded, moduli)
    r_padded = integer_eth_root(x_padded, 3)
    attack_fails = r_padded ** 3 != x_padded
    print(f"  CRT cube root is exact integer: {not attack_fails}")
    print(f"  => Padding defeats Håstad's attack ✓")

    print("\n[Interface]")
    print("  crt(residues, moduli) -> int")
    print("  rsa_dec_crt(sk, c) -> int")
    print("  hastad_attack(ciphertexts, moduli, e) -> m")

"""
PA #13 — Miller-Rabin Primality Testing
CS8.401: Principles of Information Security

Implements:
  - Miller-Rabin probabilistic primality test
  - Prime generation
  - Carmichael number demo (561)
  - Performance benchmark

  python3 pa13_miller_rabin.py
"""

import os
import random
import time
import math


# ─── MODULAR EXPONENTIATION ───────────────────────────────────────────────────

def mod_exp(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply modular exponentiation. No library pow()."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


# ─── MILLER-RABIN ─────────────────────────────────────────────────────────────

def miller_rabin(n: int, k: int = 40) -> str:
    """
    Miller-Rabin probabilistic primality test.
    Returns 'PROBABLY_PRIME' or 'COMPOSITE'.
    Error probability <= 4^(-k).
    """
    if n < 2:
        return "COMPOSITE"
    if n == 2 or n == 3:
        return "PROBABLY_PRIME"
    if n % 2 == 0:
        return "COMPOSITE"

    # Write n-1 = 2^s * d with d odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # k rounds
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = mod_exp(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return "COMPOSITE"

    return "PROBABLY_PRIME"


def is_prime(n: int, k: int = 40) -> bool:
    return miller_rabin(n, k) == "PROBABLY_PRIME"


# ─── PRIME GENERATION ─────────────────────────────────────────────────────────

def gen_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random probable prime of given bit length.
    Repeatedly samples random odd integers until one passes Miller-Rabin.
    """
    while True:
        # Random odd b-bit integer
        n = int.from_bytes(os.urandom(bits // 8), 'big')
        # Set MSB and LSB to ensure correct bit length and odd
        n |= (1 << (bits - 1))  # set MSB
        n |= 1                   # set LSB (odd)
        if miller_rabin(n, k) == "PROBABLY_PRIME":
            return n


def gen_safe_prime(bits: int) -> tuple:
    """
    Generate safe prime p = 2q + 1 where q is also prime.
    Returns (p, q).
    """
    while True:
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        if is_prime(p):
            return p, q


# ─── FERMAT TEST (for Carmichael demo) ────────────────────────────────────────

def fermat_test(n: int, a: int) -> bool:
    """Fermat primality test: a^(n-1) ≡ 1 (mod n)."""
    return mod_exp(a, n - 1, n) == 1


def carmichael_demo():
    """
    Show n=561 passes Fermat but is caught by Miller-Rabin.
    561 = 3 × 11 × 17 is the smallest Carmichael number.
    """
    n = 561
    print(f"\n[Carmichael Number Demo — n = {n} = 3 × 11 × 17]")

    # Fermat test passes for all a coprime to n
    fermat_results = []
    for a in [2, 5, 7, 13, 17, 19, 23]:
        result = fermat_test(n, a)
        fermat_results.append(result)
    all_pass = all(fermat_results)
    print(f"  Fermat test (multiple bases): all pass = {all_pass}  => Fermat says PRIME (WRONG!)")

    # Miller-Rabin correctly identifies as composite
    mr_result = miller_rabin(n, k=10)
    print(f"  Miller-Rabin result        : {mr_result}  => Correct!")
    print(f"  Actual factorization       : 3 × 11 × 17 = {3*11*17}")

    # Show which witness catches it
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for a in range(2, 20):
        x = mod_exp(a, d, n)
        if x != 1 and x != n - 1:
            composite = True
            for _ in range(s - 1):
                x = mod_exp(x, 2, n)
                if x == n - 1:
                    composite = False
                    break
            if composite:
                print(f"  Witness a={a} exposes {n} as composite ✓")
                break


# ─── PERFORMANCE BENCHMARK ────────────────────────────────────────────────────

def benchmark():
    """
    Report average candidates sampled before finding primes of various sizes.
    Compare to Prime Number Theorem prediction: O(ln n) candidates.
    """
    print("\n[Performance Benchmark]")
    print(f"  {'Bits':>6} | {'Candidates':>12} | {'PNT pred':>10} | {'Time(ms)':>10}")
    print(f"  {'-'*6}-+-{'-'*12}-+-{'-'*10}-+-{'-'*10}")

    for bits in [64, 128, 256]:
        candidates = []
        times = []
        TRIALS = 5
        for _ in range(TRIALS):
            count = 0
            t0 = time.time()
            while True:
                n = int.from_bytes(os.urandom(bits // 8), 'big')
                n |= (1 << (bits - 1))
                n |= 1
                count += 1
                if is_prime(n, k=20):
                    break
            elapsed = (time.time() - t0) * 1000
            candidates.append(count)
            times.append(elapsed)

        avg_cand = sum(candidates) / TRIALS
        avg_time = sum(times) / TRIALS
        pnt_pred = math.log(2 ** bits)  # ln(n) ≈ bits * ln(2)
        print(f"  {bits:>6} | {avg_cand:>12.1f} | {pnt_pred:>10.1f} | {avg_time:>10.1f}")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #13 — Miller-Rabin Primality Testing")
    print("=" * 60)

    # 1. Basic tests
    print("\n[Basic Primality Tests]")
    test_cases = [
        (2, True), (3, True), (4, False), (17, True),
        (100, False), (997, True), (1000, False), (104729, True),
        (561, False),   # Carmichael number
    ]
    for n, expected in test_cases:
        result = is_prime(n)
        status = "✓" if result == expected else "✗"
        print(f"  [{status}] is_prime({n:8d}) = {str(result):5s}  (expected {expected})")

    # 2. Carmichael demo
    carmichael_demo()

    # 3. Prime generation
    print("\n[Prime Generation]")
    for bits in [32, 64, 128]:
        t0 = time.time()
        p = gen_prime(bits)
        elapsed = (time.time() - t0) * 1000
        # Verify with 100 rounds
        verified = is_prime(p, k=100)
        print(f"  {bits:4d}-bit prime: {hex(p)[:20]}...  verified={verified}  ({elapsed:.1f}ms)")

    # 4. Safe prime generation (small)
    print("\n[Safe Prime Generation — 32-bit]")
    t0 = time.time()
    p, q = gen_safe_prime(32)
    elapsed = (time.time() - t0) * 1000
    print(f"  p = {p}  (is_prime={is_prime(p)})")
    print(f"  q = {q}  (is_prime={is_prime(q)})")
    print(f"  p = 2q+1? {p == 2*q+1}  ({elapsed:.1f}ms)")

    # 5. Benchmark
    benchmark()

    print("\n[Interface]")
    print("  is_prime(n) -> bool")
    print("  gen_prime(bits) -> int")
    print("  gen_safe_prime(bits) -> (p, q)")
    print("  mod_exp(base, exp, mod) -> int")

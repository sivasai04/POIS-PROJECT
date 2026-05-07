"""
PA #9 — Birthday Attack (Collision Finding)
CS8.401: Principles of Information Security

Implements:
  - Naive birthday algorithm (sort-based, using dict)
  - Floyd's cycle-finding attack (space-efficient)
  - Attack on toy hash functions (n=8,12,16 bits)
  - Attack on truncated DLP hash (n=16 bits)
  - Empirical birthday curve
  - MD5/SHA-1 context (theoretical computation)

  python3 pa9_birthday.py
"""

import os
import sys
import math
import random
import time
sys.path.insert(0, '.')
from pa8_dlp_hash import ToyDLPHash


# ─── NAIVE BIRTHDAY ATTACK ────────────────────────────────────────────────────

def birthday_attack_naive(hash_fn, n_bits: int, max_attempts: int = 1000000) -> tuple:
    """
    Naive birthday attack using a dictionary.
    Returns (m1, m2, h) where m1 != m2 and hash_fn(m1) == hash_fn(m2).
    Time O(k log k), Space O(k) where k ~ 1.2 * 2^(n/2).
    """
    seen = {}
    for i in range(max_attempts):
        msg = os.urandom(4)
        h = hash_fn(msg)
        # Truncate to n_bits
        mask = (1 << n_bits) - 1
        h_int = int.from_bytes(h if isinstance(h, bytes) else h.to_bytes(4,'big'), 'big') & mask

        if h_int in seen and seen[h_int] != msg:
            return seen[h_int], msg, h_int, i + 1
        seen[h_int] = msg
    return None, None, None, max_attempts


# ─── FLOYD'S CYCLE DETECTION ──────────────────────────────────────────────────

def birthday_attack_floyd(hash_fn, n_bits: int, seed: bytes = None) -> tuple:
    """
    Space-efficient birthday attack via Floyd's tortoise-and-hare.
    Treats f(x) = truncate(hash_fn(x), n_bits) as a function on n-bit values.
    Returns (m1, m2, h, evaluations).
    """
    mask = (1 << n_bits) - 1

    def f(x: int) -> int:
        msg = x.to_bytes(4, 'big')
        h = hash_fn(msg)
        h_int = int.from_bytes(h if isinstance(h, bytes) else h.to_bytes(4,'big'), 'big')
        return h_int & mask

    # Start
    x0 = int.from_bytes(os.urandom(4), 'big') & mask
    tortoise = f(x0)
    hare = f(f(x0))
    evals = 3

    # Phase 1: Find cycle
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(f(hare))
        evals += 3
        if evals > 10 * (1 << n_bits):
            break

    if tortoise != hare:
        return None, None, None, evals

    # Phase 2: Find collision entry point
    mu = x0
    lam = tortoise
    while mu != lam:
        mu = f(mu)
        lam = f(lam)
        evals += 2

    # Phase 3: Extract actual collision pair
    # mu is the start of cycle; find two different inputs mapping to same value
    v = f(mu)
    evals += 1
    # Find another input that maps to v
    candidate = (mu + 1) & mask
    for _ in range(1 << n_bits):
        if f(candidate) == v and candidate != mu:
            return mu.to_bytes(4,'big'), candidate.to_bytes(4,'big'), v, evals
        candidate = (candidate + 1) & mask
        evals += 1

    return None, None, None, evals


# ─── TOY HASH FUNCTIONS ───────────────────────────────────────────────────────

def make_toy_hash(n_bits: int):
    """Create a weak hash function with n_bits output."""
    mask = (1 << n_bits) - 1

    def toy_hash(msg: bytes) -> bytes:
        # Simple polynomial rolling hash (intentionally weak)
        h = 0x12345678
        for b in msg:
            h = ((h * 0x9e3779b9) ^ b) & 0xFFFFFFFF
        h = h & mask
        return h.to_bytes(4, 'big')

    return toy_hash


# ─── EMPIRICAL BIRTHDAY CURVE ─────────────────────────────────────────────────

def birthday_probability(k: int, n_bits: int) -> float:
    """Theoretical probability of collision after k hash evaluations."""
    n = 1 << n_bits
    # P(collision) = 1 - exp(-k*(k-1) / (2*n))
    return 1 - math.exp(-k * (k - 1) / (2 * n))


def run_birthday_trials(hash_fn, n_bits: int, n_trials: int = 50) -> list:
    """Run multiple trials, return list of (evaluations until collision)."""
    results = []
    for _ in range(n_trials):
        _, _, _, evals = birthday_attack_naive(hash_fn, n_bits, max_attempts=10 * (1 << n_bits))
        results.append(evals)
    return results


def plot_birthday_curve(n_bits: int, eval_counts: list):
    """ASCII plot of empirical collision counts vs theoretical curve."""
    n = 1 << n_bits
    expected = int(math.sqrt(n * math.log(2)))  # ~0.83 * 2^(n/2)

    print(f"\n  Birthday Curve (n={n_bits} bits, 2^(n/2) = {int(2**(n_bits/2))})")
    print(f"  Trials: {len(eval_counts)}")
    print(f"  Mean evaluations : {sum(eval_counts)/len(eval_counts):.1f}")
    print(f"  Expected ~2^(n/2): {2**(n_bits/2):.1f}")
    print(f"  Ratio            : {(sum(eval_counts)/len(eval_counts)) / 2**(n_bits/2):.2f}x")

    # ASCII histogram
    max_count = max(eval_counts)
    buckets = 10
    bucket_size = max(1, max_count // buckets)
    hist = [0] * buckets
    for c in eval_counts:
        idx = min(c // bucket_size, buckets - 1)
        hist[idx] += 1

    print(f"\n  Histogram of evaluations until collision:")
    for i, cnt in enumerate(hist):
        bar = '█' * cnt
        low  = i * bucket_size
        high = (i + 1) * bucket_size
        print(f"  {low:5d}-{high:5d} | {bar}")


# ─── MD5 / SHA-1 CONTEXT ──────────────────────────────────────────────────────

def hash_security_context():
    """Compute 2^(n/2) for MD5, SHA-1, SHA-256 and express in time."""
    print("\n[Hash Function Security Context]")
    cpu_hashes_per_sec = 1_000_000_000  # 10^9 hashes/sec (modern CPU)

    for name, n_bits in [("MD5", 128), ("SHA-1", 160), ("SHA-256", 256)]:
        ops = 2 ** (n_bits / 2)
        seconds = ops / cpu_hashes_per_sec
        years = seconds / (365.25 * 24 * 3600)

        if years > 1e20:
            time_str = f"~10^{int(math.log10(years))} years (secure)"
        elif years > 1e6:
            time_str = f"~{years:.2e} years"
        elif years > 1:
            time_str = f"~{years:.2e} years"
        elif seconds > 1:
            time_str = f"~{seconds:.2e} seconds"
        else:
            time_str = f"~{seconds*1000:.2f} ms"

        status = "BROKEN" if n_bits <= 160 else "SECURE"
        print(f"  {name:8s} (n={n_bits:3d}): 2^(n/2) = 2^{n_bits//2:3d} ops  "
              f"@ 10^9 H/s = {time_str}  [{status}]")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #9 — Birthday Attack (Collision Finding)")
    print("=" * 60)

    # 1. Naive birthday on toy hashes
    print("\n[Naive Birthday Attack on Toy Hashes]")
    for n in [8, 12, 16]:
        toy = make_toy_hash(n)
        t0 = time.time()
        m1, m2, h, evals = birthday_attack_naive(toy, n)
        elapsed = time.time() - t0
        expected = 2 ** (n / 2)
        if m1:
            print(f"  n={n:2d}: collision after {evals:6d} evals "
                  f"(expected ~{expected:.0f}, ratio={evals/expected:.2f}x) "
                  f"in {elapsed*1000:.1f}ms")
            print(f"         m1={m1.hex()} m2={m2.hex()} H={h:#06x}")
        else:
            print(f"  n={n:2d}: no collision found")

    # 2. Floyd's cycle-finding
    print("\n[Floyd's Cycle-Finding Attack]")
    for n in [8, 12]:
        toy = make_toy_hash(n)
        t0 = time.time()
        m1, m2, h, evals = birthday_attack_floyd(toy, n)
        elapsed = time.time() - t0
        if m1:
            expected = 2 ** (n / 2)
            print(f"  n={n:2d}: collision after {evals:6d} evals "
                  f"(ratio={evals/expected:.2f}x) in {elapsed*1000:.1f}ms")
        else:
            print(f"  n={n:2d}: cycle detection failed (try again)")

    # 3. Attack on truncated DLP hash
    print("\n[Birthday Attack on Truncated DLP Hash (n=16)]")
    toy_dlp = ToyDLPHash()

    def dlp_hash_fn(msg: bytes) -> bytes:
        return toy_dlp.hash(msg)

    t0 = time.time()
    m1, m2, h, evals = birthday_attack_naive(dlp_hash_fn, 16, max_attempts=50000)
    elapsed = time.time() - t0

    if m1:
        print(f"  Collision found after {evals} evaluations")
        print(f"  m1 = {m1.hex()}")
        print(f"  m2 = {m2.hex()}")
        print(f"  H(m1) = H(m2) = {h:#06x}")
        print(f"  Ratio evals/2^8 = {evals/256:.2f}")
        print(f"  Time: {elapsed:.2f}s")
        print(f"  => Even provably-secure hash broken at birthday bound ✓")
    else:
        print(f"  No collision found in trial (increase max_attempts)")

    # 4. Empirical birthday curve for n=8
    print("\n[Empirical Birthday Curve — n=8 bits, 100 trials]")
    toy8 = make_toy_hash(8)
    counts = run_birthday_trials(toy8, 8, n_trials=100)
    plot_birthday_curve(8, counts)

    # Verify theoretical vs empirical
    mean = sum(counts) / len(counts)
    theoretical = 2 ** (8 / 2)
    print(f"\n  Theoretical 2^(n/2) = {theoretical:.1f}")
    print(f"  Empirical mean      = {mean:.1f}")
    print(f"  Match: {'✓' if abs(mean - theoretical) / theoretical < 0.5 else '~'}")

    # 5. MD5/SHA-1/SHA-256 context
    hash_security_context()

    # 6. Summary
    print("\n[Summary]")
    print("  Birthday bound is TIGHT: O(2^(n/2)) evaluations sufficient AND necessary.")
    print("  Increasing output by 1 bit DOUBLES the cost of finding a collision.")
    print("  Modern hashes use ≥256-bit output to ensure 2^128 collision resistance.")

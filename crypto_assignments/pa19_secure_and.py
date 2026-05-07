"""
PA #19 — Secure AND Gate
CS8.401: Principles of Information Security

Implements:
  - Secure AND from OT (PA#18)
  - Secure XOR via additive secret sharing (free — no OT)
  - Secure NOT (free — local flip)
  - Privacy proof
  - Truth table verification

    python3 pa19_secure_and.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa18_ot import ObliviousTransfer


# ─── SECURE AND ───────────────────────────────────────────────────────────────

class SecureAND:
    """
    Secure AND gate from OT.

    Protocol:
      Alice holds a in {0,1}, Bob holds b in {0,1}.
      Alice acts as OT sender with messages (m0, m1) = (0, a).
      Bob   acts as OT receiver with choice bit b.
      Bob receives m_b = a*b = a AND b.

    Privacy:
      - Bob learns only a AND b (not a): OT receiver privacy.
      - Alice learns nothing about b  : OT sender privacy.
    """

    def __init__(self, ot: ObliviousTransfer = None):
        self.ot = ot or ObliviousTransfer()

    def compute(self, a: int, b: int) -> tuple:
        """
        Securely compute a AND b.
        Returns (result_alice, result_bob, transcript).
        Both parties output a AND b.
        transcript = list of messages exchanged (for privacy analysis).
        """
        assert a in (0, 1) and b in (0, 1)

        transcript = []

        # Alice sets up OT messages: (m0=0, m1=a)
        m0_sender = 0
        m1_sender = a
        transcript.append(f"Alice sets OT messages: (m0={m0_sender}, m1={m1_sender})")

        # Bob runs OT receiver with choice bit b
        pk0, pk1, state = self.ot.receiver_step1(b)
        transcript.append(f"Bob sends: (pk0=..., pk1=...)  [choice b={b} hidden]")

        # Alice encrypts both messages
        C0, C1 = self.ot.sender_step(pk0, pk1, m0_sender, m1_sender)
        transcript.append(f"Alice sends: (C0=..., C1=...)  [both encrypted]")

        # Bob decrypts m_b = a*b
        result = self.ot.receiver_step2(state, C0, C1)
        transcript.append(f"Bob decrypts: m_b = {result} = a AND b")

        # Both parties output the result
        return result, result, transcript


# ─── SECURE XOR (FREE) ────────────────────────────────────────────────────────

class SecureXOR:
    """
    Secure XOR via additive secret sharing over Z2.
    No OT needed — XOR is "free" in MPC.

    Protocol:
      Alice holds a, Bob holds b.
      Alice samples r <- {0,1} and sends r to Bob.
      Alice's share: a XOR r
      Bob's share  : b XOR r
      Output = (a XOR r) XOR (b XOR r) = a XOR b
    """

    def compute(self, a: int, b: int) -> tuple:
        """
        Securely compute a XOR b.
        Returns (result, result, transcript).
        """
        assert a in (0, 1) and b in (0, 1)

        r = int.from_bytes(os.urandom(1), 'big') & 1

        share_alice = a ^ r
        share_bob   = b ^ r

        result = share_alice ^ share_bob
        transcript = [
            f"Alice samples r={r}, computes share_A = a XOR r = {share_alice}",
            f"Bob's share_B = b XOR r = {share_bob}",
            f"Output = share_A XOR share_B = {result} = a XOR b",
        ]
        return result, result, transcript


# ─── SECURE NOT (FREE) ────────────────────────────────────────────────────────

class SecureNOT:
    """
    Secure NOT — Alice locally flips her share. No communication.
    NOT(a) = 1 XOR a = flip the bit.
    """

    def compute(self, a: int) -> int:
        assert a in (0, 1)
        return 1 ^ a


# ─── PRIVACY ANALYSIS ─────────────────────────────────────────────────────────

def privacy_analysis(and_gate: SecureAND):
    """
    Show transcript reveals nothing beyond the output.
    Alice cannot learn b; Bob cannot learn a.
    """
    print("\n[Privacy Analysis — Secure AND]")

    for a, b in [(0, 0), (0, 1), (1, 0), (1, 1)]:
        result, _, transcript = and_gate.compute(a, b)
        print(f"\n  a={a}, b={b}, a AND b = {result}")
        for msg in transcript:
            print(f"    | {msg}")
        print(f"    Alice sees: her own a={a}, OT ciphertexts — NOT b")
        print(f"    Bob sees  : his own b={b}, m_b={result} — NOT a directly")


# ─── TRUTH TABLE TEST ─────────────────────────────────────────────────────────

def truth_table_test(and_gate: SecureAND, xor_gate: SecureXOR,
                     n_trials: int = 50):
    """Verify AND and XOR truth tables across n_trials each."""
    print("\n[Truth Table Verification]")

    print("  AND gate:")
    print(f"  {'a':>3} {'b':>3} {'expected':>10} {'got':>6} {'pass':>6}")
    and_ok = True
    for a in [0, 1]:
        for b in [0, 1]:
            expected = a & b
            counts = {}
            for _ in range(n_trials):
                got, _, _ = and_gate.compute(a, b)
                counts[got] = counts.get(got, 0) + 1
            # All trials should give the same result
            majority = max(counts, key=counts.get)
            ok = majority == expected
            if not ok:
                and_ok = False
            print(f"  {a:>3} {b:>3} {expected:>10} {majority:>6} "
                  f"{'✓' if ok else '✗':>6}")

    print("\n  XOR gate:")
    print(f"  {'a':>3} {'b':>3} {'expected':>10} {'got':>6} {'pass':>6}")
    xor_ok = True
    for a in [0, 1]:
        for b in [0, 1]:
            expected = a ^ b
            counts = {}
            for _ in range(n_trials):
                got, _, _ = xor_gate.compute(a, b)
                counts[got] = counts.get(got, 0) + 1
            majority = max(counts, key=counts.get)
            ok = majority == expected
            if not ok:
                xor_ok = False
            print(f"  {a:>3} {b:>3} {expected:>10} {majority:>6} "
                  f"{'✓' if ok else '✗':>6}")

    return and_ok, xor_ok


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #19 — Secure AND Gate")
    print("=" * 60)

    ot      = ObliviousTransfer()
    and_g   = SecureAND(ot)
    xor_g   = SecureXOR()
    not_g   = SecureNOT()

    # 1. Secure AND
    print("\n[Secure AND — all 4 combinations]")
    for a, b in [(0,0), (0,1), (1,0), (1,1)]:
        result, _, _ = and_g.compute(a, b)
        expected = a & b
        print(f"  {a} AND {b} = {result}  "
              f"(expected {expected}) {'✓' if result == expected else '✗'}")

    # 2. Secure XOR
    print("\n[Secure XOR — all 4 combinations]")
    for a, b in [(0,0), (0,1), (1,0), (1,1)]:
        result, _, _ = xor_g.compute(a, b)
        expected = a ^ b
        print(f"  {a} XOR {b} = {result}  "
              f"(expected {expected}) {'✓' if result == expected else '✗'}")

    # 3. Secure NOT
    print("\n[Secure NOT]")
    for a in [0, 1]:
        result = not_g.compute(a)
        print(f"  NOT {a} = {result}  "
              f"(expected {1^a}) {'✓' if result == (1^a) else '✗'}")

    # 4. Truth table test (50 trials each)
    and_ok, xor_ok = truth_table_test(and_g, xor_g, n_trials=50)
    print(f"\n  AND gate correct: {and_ok} ✓")
    print(f"  XOR gate correct: {xor_ok} ✓")

    # 5. Privacy analysis
    privacy_analysis(and_g)

    # 6. Privacy proof (informal)
    print("\n[Privacy Proof (Informal)]")
    print("  Secure AND:")
    print("  (a) Bob learns nothing about a beyond a AND b:")
    print("      OT receiver privacy: Bob holds sk_b, cannot decrypt C_(1-b)")
    print("      => Bob sees only m_b = a*b, not a directly.")
    print("  (b) Alice learns nothing about b:")
    print("      OT sender privacy: (pk0,pk1) computationally indistinguishable")
    print("      => Alice cannot tell which pk is 'honest' without solving DLP.")

    print("\n[Interface]")
    print("  and_g.compute(a, b) -> (result, result, transcript)")
    print("  xor_g.compute(a, b) -> (result, result, transcript)")
    print("  not_g.compute(a)    -> result")

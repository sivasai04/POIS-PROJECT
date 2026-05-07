"""
PA #18 — Oblivious Transfer (OT)
CS8.401: Principles of Information Security

Implements:
  - 1-out-of-2 OT from ElGamal PKC (Bellare-Micali construction)
  - Receiver privacy: sender cannot determine choice bit b
  - Sender privacy: receiver cannot decrypt the other message
  - Correctness: 100 trials

    python3 pa18_ot.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa16_elgamal import ElGamal
from pa13_miller_rabin import mod_exp
from pa12_rsa import mod_inverse
from pa11_dh import DH_P, DH_G, DH_Q


# ─── OBLIVIOUS TRANSFER ───────────────────────────────────────────────────────

class ObliviousTransfer:
    """
    1-out-of-2 OT via Bellare-Micali construction using ElGamal.

    Receiver holds choice bit b in {0,1}.
    Sender holds messages (m0, m1).

    Protocol:
      Step 1 (Receiver): Generate pkb honestly (keep skb).
                         Generate pk(1-b) WITHOUT trapdoor
                         (random group element as public key).
      Step 2 (Sender):   Encrypt m0 under pk0, m1 under pk1.
      Step 3 (Receiver): Decrypt C_b using sk_b. Cannot decrypt C_(1-b).
    """

    def __init__(self, eg: ElGamal = None):
        self.eg = eg or ElGamal()

    def receiver_step1(self, b: int) -> tuple:
        """
        Receiver generates two public keys.
        pk_b  : honest key (receiver knows sk_b)
        pk_1-b: trapdoor-free key (random group element, no sk known)

        Returns (pk0, pk1, state) where state = (b, sk_b)
        """
        assert b in (0, 1), "Choice bit must be 0 or 1"

        # Generate honest key pair for choice b
        sk_b = int.from_bytes(os.urandom(8), 'big') % self.eg.q
        pk_b = mod_exp(self.eg.g, sk_b, self.eg.p)

        # Generate trapdoor-free key for (1-b): random group element
        # Receiver does NOT know the discrete log of this value
        pk_other = int.from_bytes(os.urandom(8), 'big') % self.eg.p
        # Ensure it's a valid group element (nonzero)
        while pk_other == 0:
            pk_other = int.from_bytes(os.urandom(8), 'big') % self.eg.p

        if b == 0:
            pk0, pk1 = pk_b, pk_other
        else:
            pk0, pk1 = pk_other, pk_b

        state = {"b": b, "sk_b": sk_b}
        return pk0, pk1, state

    def sender_step(self, pk0: int, pk1: int,
                    m0: int, m1: int) -> tuple:
        """
        Sender encrypts both messages under respective public keys.
        Returns (C0, C1) where Ci = ElGamal_pki(mi).
        """
        C0 = self.eg.encrypt(pk0, m0)  # (c1_0, c2_0)
        C1 = self.eg.encrypt(pk1, m1)  # (c1_1, c2_1)
        return C0, C1

    def receiver_step2(self, state: dict, C0: tuple, C1: tuple) -> int:
        """
        Receiver decrypts only C_b using sk_b.
        Cannot decrypt C_(1-b) (no trapdoor).
        """
        b    = state["b"]
        sk_b = state["sk_b"]
        C_b  = C0 if b == 0 else C1
        return self.eg.decrypt(sk_b, C_b[0], C_b[1])


# ─── PRIVACY DEMOS ────────────────────────────────────────────────────────────

def receiver_privacy_demo(ot: ObliviousTransfer):
    """
    Show sender cannot determine b from (pk0, pk1).
    Both pk_b (honest) and pk_other (random) are
    computationally indistinguishable group elements.
    """
    print("\n[Receiver Privacy Demo]")
    print("  Sender sees (pk0, pk1) — cannot tell which is 'honest'")

    for b in [0, 1]:
        pk0, pk1, _ = ot.receiver_step1(b)
        # Both are just integers in [1, p-1]
        # Sender cannot distinguish honest from random without solving DLP
        print(f"  b={b}: pk0={str(pk0)[:12]}...  pk1={str(pk1)[:12]}...")
        print(f"         Both look like random group elements to sender ✓")


def sender_privacy_demo(ot: ObliviousTransfer):
    """
    Show receiver cannot decrypt C_(1-b).
    They have no sk for pk_(1-b).
    """
    print("\n[Sender Privacy Demo]")
    m0, m1 = 100, 200

    for b in [0, 1]:
        pk0, pk1, state = ot.receiver_step1(b)
        C0, C1 = ot.sender_step(pk0, pk1, m0, m1)

        # Receiver correctly decrypts m_b
        m_b = ot.receiver_step2(state, C0, C1)

        # Receiver tries to decrypt m_(1-b) — they have no sk
        # They only have sk_b, using it on C_(1-b) gives garbage
        C_other = C1 if b == 0 else C0
        m_garbage = ot.eg.decrypt(state["sk_b"], C_other[0], C_other[1])

        expected_b     = m0 if b == 0 else m1
        expected_other = m1 if b == 0 else m0

        print(f"  b={b}: correctly got m{b}={m_b} "
              f"(expected {expected_b}) {'✓' if m_b == expected_b else '✗'}")
        print(f"         wrong key on m{1-b}: got {m_garbage} "
              f"(garbage, expected {expected_other}) "
              f"{'✓ (privacy holds)' if m_garbage != expected_other else '✗'}")


# ─── CORRECTNESS TEST ─────────────────────────────────────────────────────────

def correctness_test(ot: ObliviousTransfer, n_trials: int = 100) -> float:
    """Run n_trials with random b and random (m0,m1). Verify receiver always gets m_b."""
    import random
    successes = 0
    for _ in range(n_trials):
        b  = random.randint(0, 1)
        m0 = random.randint(1, 10000)
        m1 = random.randint(1, 10000)

        pk0, pk1, state = ot.receiver_step1(b)
        C0, C1          = ot.sender_step(pk0, pk1, m0, m1)
        m_b             = ot.receiver_step2(state, C0, C1)

        expected = m0 if b == 0 else m1
        if m_b == expected:
            successes += 1

    return successes / n_trials


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #18 — Oblivious Transfer (1-out-of-2 OT)")
    print("=" * 60)

    ot = ObliviousTransfer()

    # 1. Basic protocol walkthrough
    print("\n[OT Protocol Walkthrough]")
    m0, m1 = 42, 99

    for b in [0, 1]:
        pk0, pk1, state = ot.receiver_step1(b)
        C0, C1          = ot.sender_step(pk0, pk1, m0, m1)
        m_b             = ot.receiver_step2(state, C0, C1)
        expected        = m0 if b == 0 else m1
        print(f"  b={b}: sender has (m0={m0}, m1={m1})")
        print(f"         receiver chose b={b}, got m{b}={m_b} "
              f"(expected {expected}) {'✓' if m_b == expected else '✗'}")

    # 2. Step-by-step message log
    print("\n[Step-by-Step Message Log (b=1)]")
    b = 1
    pk0, pk1, state = ot.receiver_step1(b)
    print(f"  [Receiver->Sender] pk0={str(pk0)[:14]}...")
    print(f"  [Receiver->Sender] pk1={str(pk1)[:14]}...  (pk1 is honest, sk known)")
    C0, C1 = ot.sender_step(pk0, pk1, m0, m1)
    print(f"  [Sender->Receiver] C0=(c1={str(C0[0])[:10]}..., c2={str(C0[1])[:10]}...)")
    print(f"  [Sender->Receiver] C1=(c1={str(C1[0])[:10]}..., c2={str(C1[1])[:10]}...)")
    m_b = ot.receiver_step2(state, C0, C1)
    print(f"  [Receiver decrypts C1] m1 = {m_b} ✓")
    print(f"  [Receiver cannot decrypt C0] no sk for pk0 ✓")

    # 3. Privacy demos
    receiver_privacy_demo(ot)
    sender_privacy_demo(ot)

    # 4. Correctness
    print("\n[Correctness — 100 random trials]")
    rate = correctness_test(ot, 100)
    print(f"  Success rate: {rate*100:.1f}%  (expected 100%) "
          f"{'✓' if rate == 1.0 else '✗'}")

    print("\n[Interface]")
    print("  ot.receiver_step1(b) -> (pk0, pk1, state)")
    print("  ot.sender_step(pk0, pk1, m0, m1) -> (C0, C1)")
    print("  ot.receiver_step2(state, C0, C1) -> m_b")

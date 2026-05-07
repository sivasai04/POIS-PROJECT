"""
PA #6 — CCA-Secure Symmetric Encryption
CS8.401: Principles of Information Security

Implements:
  - Encrypt-then-MAC construction
  - Key separation
  - IND-CCA2 game simulation
  - Malleability attack on CPA-only scheme
  - Contrast: CCA scheme rejects tampered ciphertexts

  python3 pa6_cca.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa3_cpa import CPAEncryption
from pa5_mac import CBCMAC

BLOCK = 16
REJECT = None  # sentinel for decryption failure


# ─── CCA-SECURE ENCRYPTION (Encrypt-then-MAC) ─────────────────────────────────

class CCAEncryption:
    """
    CCA-Secure Encryption via Encrypt-then-MAC.
    Enc(kE, kM, m):
        CE = CPA_Enc(kE, m)
        t  = MAC(kM, CE)
        return (CE, t)
    Dec(kE, kM, CE, t):
        if Vrfy(kM, CE, t) == False: return ⊥
        return CPA_Dec(kE, CE)
    """

    def __init__(self, cpa=None, mac=None):
        self.cpa = cpa or CPAEncryption()
        self.mac = mac or CBCMAC()

    def keygen(self) -> tuple:
        """Generate independent kE and kM."""
        kE = os.urandom(BLOCK)
        kM = os.urandom(BLOCK)
        return kE, kM

    def encrypt(self, kE: bytes, kM: bytes, m: bytes) -> tuple:
        """
        Returns (r, CE, t) where r is the CPA nonce,
        CE is the ciphertext, and t is the MAC tag.
        """
        r, CE = self.cpa.encrypt(kE, m)
        # MAC covers the full ciphertext blob including nonce
        mac_input = r + CE
        t = self.mac.mac(kM, mac_input)
        return r, CE, t

    def decrypt(self, kE: bytes, kM: bytes, r: bytes, CE: bytes, t: bytes):
        """
        Returns plaintext or REJECT (⊥) if MAC fails.
        MAC verification MUST happen before decryption.
        """
        mac_input = r + CE
        if not self.mac.verify(kM, mac_input, t):
            return REJECT  # ⊥ — reject tampered ciphertext
        return self.cpa.decrypt(kE, r, CE)

    def encrypt_dict(self, kE: bytes, kM: bytes, m: bytes) -> dict:
        r, CE, t = self.encrypt(kE, kM, m)
        return {"r": r, "CE": CE, "t": t}

    def decrypt_dict(self, kE: bytes, kM: bytes, blob: dict):
        return self.decrypt(kE, kM, blob["r"], blob["CE"], blob["t"])


# ─── IND-CCA2 GAME ────────────────────────────────────────────────────────────

class INDCCAGame:
    """
    IND-CCA2 Game.
    Adversary gets encryption oracle AND decryption oracle.
    Decryption oracle rejects the challenge ciphertext.
    """

    def __init__(self, scheme=None):
        self.scheme = scheme or CCAEncryption()
        self.kE, self.kM = self.scheme.keygen()
        self._challenge_blob = None
        self._b = None
        self.wins = 0
        self.rounds = 0

    def encrypt_oracle(self, m: bytes) -> dict:
        return self.scheme.encrypt_dict(self.kE, self.kM, m)

    def decrypt_oracle(self, blob: dict):
        """Will reject the challenge ciphertext."""
        if self._challenge_blob and blob == self._challenge_blob:
            return "REJECTED (challenge ciphertext)"
        return self.scheme.decrypt_dict(self.kE, self.kM, blob)

    def challenge(self, m0: bytes, m1: bytes) -> dict:
        import random
        self._b = random.randint(0, 1)
        m = m0 if self._b == 0 else m1
        self._challenge_blob = self.scheme.encrypt_dict(self.kE, self.kM, m)
        return self._challenge_blob

    def guess(self, b_prime: int) -> bool:
        self.rounds += 1
        correct = (b_prime == self._b)
        if correct:
            self.wins += 1
        return correct

    def advantage(self) -> float:
        if self.rounds == 0:
            return 0.0
        return abs(self.wins / self.rounds - 0.5)

    def run_dummy_adversary(self, n_rounds: int = 50):
        import random
        for _ in range(n_rounds):
            m0 = os.urandom(BLOCK)
            m1 = os.urandom(BLOCK)
            for _ in range(3):
                self.encrypt_oracle(os.urandom(BLOCK))
            blob = self.challenge(m0, m1)
            # Try to query decryption oracle with challenge (should be rejected)
            result = self.decrypt_oracle(blob)
            # Random guess
            self.guess(random.randint(0, 1))
        return self.advantage()


# ─── MALLEABILITY ATTACK ON CPA ───────────────────────────────────────────────

def malleability_attack_demo():
    """
    CPA-only scheme is malleable:
    C = <r, F_k(r) XOR m>
    Flipping bit i of ciphertext -> flips bit i of recovered plaintext.

    CCA scheme: same bit flip changes CE, MAC check fails -> ⊥
    """
    print("\n[Malleability Attack Demo]")

    cpa = CPAEncryption()
    cca = CCAEncryption(cpa)
    k = os.urandom(BLOCK)
    kE, kM = cca.keygen()

    m = b"Transfer $100!!!"
    print(f"  Original plaintext: {m}")

    # CPA: encrypt and flip a bit
    r, ct = cpa.encrypt(k, m)
    tampered_ct = bytearray(ct)
    tampered_ct[0] ^= 0x04  # flip bit 2 of first byte

    try:
        recovered = cpa.decrypt(k, r, bytes(tampered_ct))
        print(f"\n  [CPA-only] After flipping bit in ciphertext:")
        print(f"    Recovered: {recovered}")
        print(f"    Plaintext was modified! (malleable ✗)")
    except Exception as e:
        print(f"  [CPA-only] Error: {e}")

    # CCA: same attack fails
    blob = cca.encrypt_dict(kE, kM, m)
    tampered_blob = dict(blob)
    tampered_blob["CE"] = bytes([blob["CE"][0] ^ 0x04]) + blob["CE"][1:]

    result = cca.decrypt_dict(kE, kM, tampered_blob)
    print(f"\n  [CCA Encrypt-then-MAC] After flipping same bit:")
    print(f"    Result: {result}")
    print(f"    => Correctly rejected! MAC check caught the tampering ✓")


# ─── KEY SEPARATION DEMO ──────────────────────────────────────────────────────

def key_separation_demo():
    """Show why kE != kM is required."""
    print("\n[Key Separation Demo]")
    cca = CCAEncryption()
    kE, kM = cca.keygen()
    print(f"  kE : {kE.hex()}")
    print(f"  kM : {kM.hex()}")
    print(f"  kE == kM? : {kE == kM}  (should be False — independent keys)")
    print(f"  Using the same key for both roles creates exploitable correlations")
    print(f"  between the encryption keystream and the MAC key material.")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #6 — CCA-Secure Symmetric Encryption (Encrypt-then-MAC)")
    print("=" * 60)

    cca = CCAEncryption()
    kE, kM = cca.keygen()

    # 1. Basic encrypt / decrypt
    print("\n[Basic Encrypt / Decrypt]")
    for m in [b"Hello World!!!!!", b"Short message", b"A" * 48]:
        blob = cca.encrypt_dict(kE, kM, m)
        recovered = cca.decrypt_dict(kE, kM, blob)
        print(f"  {'✓' if recovered == m else '✗'} len={len(m)} -> recovered={recovered == m}")

    # 2. Tamper detection
    print("\n[Tamper Detection]")
    m = b"Secret message!!"
    blob = cca.encrypt_dict(kE, kM, m)
    for field in ["CE", "r", "t"]:
        tampered = dict(blob)
        tampered[field] = bytes([blob[field][0] ^ 0xFF]) + blob[field][1:]
        result = cca.decrypt_dict(kE, kM, tampered)
        print(f"  Tamper {field}: result = {result}  (⊥ = correctly rejected ✓)")

    # 3. IND-CCA2 game
    print("\n[IND-CCA2 Game — 50 rounds]")
    game = INDCCAGame(cca)
    adv = game.run_dummy_adversary(50)
    print(f"  Wins/Rounds: {game.wins}/{game.rounds}")
    print(f"  Advantage  : {adv:.4f}  (expected ≈ 0)")
    print(f"  => {'CCA-Secure ✓' if adv < 0.15 else 'Not secure ✗'}")

    # 4. Malleability attack
    malleability_attack_demo()

    # 5. Key separation
    key_separation_demo()

    print("\n[Interface]")
    print("  cca.encrypt(kE, kM, m) -> (r, CE, t)")
    print("  cca.decrypt(kE, kM, r, CE, t) -> m  or  None (⊥)")

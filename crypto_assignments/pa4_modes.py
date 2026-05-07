"""
PA #4 — Modes of Operation
CS8.401: Principles of Information Security

Implements:
  - CBC (Cipher Block Chaining)
  - OFB (Output Feedback)
  - Randomized CTR (Counter Mode)
  - Unified API: Encrypt(mode, k, M) / Decrypt(mode, k, C)
  - Attack demos: CBC IV reuse, OFB keystream reuse

  python3 pa4_modes.py
"""

import os
import sys
sys.path.insert(0, '.')
from pa2_prf import AESPRF, aes128_encrypt

BLOCK = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def pkcs7_pad(m: bytes, block_size: int = BLOCK) -> bytes:
    pad_len = block_size - (len(m) % block_size)
    return m + bytes([pad_len] * pad_len)

def pkcs7_unpad(m: bytes) -> bytes:
    pad_len = m[-1]
    if pad_len == 0 or pad_len > BLOCK:
        raise ValueError("Bad padding")
    return m[:-pad_len]


# ─── CBC ──────────────────────────────────────────────────────────────────────

class CBCMode:
    """
    CBC: C_i = E_k(C_{i-1} XOR M_i),  C_0 = IV
    - Sequential encryption, parallel decryption
    - 2-block error propagation
    - Fatal on IV reuse
    """

    def __init__(self, prf=None):
        self.prf = prf or AESPRF()

    def encrypt(self, k: bytes, m: bytes, iv: bytes = None) -> tuple:
        if iv is None:
            iv = os.urandom(BLOCK)
        padded = pkcs7_pad(m)
        blocks = [padded[i:i+BLOCK] for i in range(0, len(padded), BLOCK)]
        prev = iv
        ciphertext = bytearray()
        for block in blocks:
            inp = xor_bytes(prev, block)
            ct_block = self.prf.evaluate(k, inp)
            ciphertext.extend(ct_block)
            prev = ct_block
        return iv, bytes(ciphertext)

    def decrypt(self, k: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        blocks = [ciphertext[i:i+BLOCK] for i in range(0, len(ciphertext), BLOCK)]
        prev = iv
        plaintext = bytearray()
        for ct_block in blocks:
            # AES decrypt: use AES encrypt with inverse (for demo, we use PRF eval trick)
            # For CBC decryption we need block cipher inverse.
            # We use the AES decrypt path.
            pt_block = xor_bytes(_aes_decrypt(k, ct_block), prev)
            plaintext.extend(pt_block)
            prev = ct_block
        return pkcs7_unpad(bytes(plaintext))


def _aes_decrypt(key: bytes, block: bytes) -> bytes:
    """AES-128 decryption (inverse cipher)."""
    # For correctness we implement full AES decryption
    from pa1_owf_prg import SBOX, RCON, _key_expand, _add_round_key

    INV_SBOX = [0] * 256
    for i, v in enumerate(SBOX):
        INV_SBOX[v] = i

    def inv_sub_bytes(s):
        return [INV_SBOX[b] for b in s]

    def inv_shift_rows(s):
        return [
            s[0],s[13],s[10],s[7],
            s[4],s[1],s[14],s[11],
            s[8],s[5],s[2],s[15],
            s[12],s[9],s[6],s[3],
        ]

    def _gmul(a, b):
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xff
            if hi: a ^= 0x1b
            b >>= 1
        return p

    def inv_mix_columns(s):
        out = []
        for i in range(4):
            c = s[i*4:(i+1)*4]
            out += [
                _gmul(c[0],0x0e)^_gmul(c[1],0x0b)^_gmul(c[2],0x0d)^_gmul(c[3],0x09),
                _gmul(c[0],0x09)^_gmul(c[1],0x0e)^_gmul(c[2],0x0b)^_gmul(c[3],0x0d),
                _gmul(c[0],0x0d)^_gmul(c[1],0x09)^_gmul(c[2],0x0e)^_gmul(c[3],0x0b),
                _gmul(c[0],0x0b)^_gmul(c[1],0x0d)^_gmul(c[2],0x09)^_gmul(c[3],0x0e),
            ]
        return out

    rks = _key_expand(key)
    state = list(block)
    state = _add_round_key(state, rks[10])
    for r in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = _add_round_key(state, rks[r])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = _add_round_key(state, rks[0])
    return bytes(state)


# ─── OFB ──────────────────────────────────────────────────────────────────────

class OFBMode:
    """
    OFB: keystream[i] = E_k(keystream[i-1]),  keystream[0] = IV
         C_i = M_i XOR keystream[i]
    - Pre-computable keystream
    - Encryption == Decryption
    - Fatal on IV reuse
    """

    def __init__(self, prf=None):
        self.prf = prf or AESPRF()

    def _keystream(self, k: bytes, iv: bytes, n_blocks: int) -> bytes:
        ks = bytearray()
        state = iv
        for _ in range(n_blocks):
            state = self.prf.evaluate(k, state)
            ks.extend(state)
        return bytes(ks)

    def encrypt(self, k: bytes, m: bytes, iv: bytes = None) -> tuple:
        if iv is None:
            iv = os.urandom(BLOCK)
        padded = pkcs7_pad(m)
        n_blocks = len(padded) // BLOCK
        ks = self._keystream(k, iv, n_blocks)
        ct = xor_bytes(padded, ks)
        return iv, ct

    def decrypt(self, k: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """Identical to encryption in OFB."""
        n_blocks = len(ciphertext) // BLOCK
        ks = self._keystream(k, iv, n_blocks)
        padded = xor_bytes(ciphertext, ks)
        return pkcs7_unpad(padded)


# ─── CTR ──────────────────────────────────────────────────────────────────────

class CTRMode:
    """
    Randomized CTR: r <- {0,1}^n
    C_i = M_i XOR F_k(r+i)
    - Fully parallelizable
    - Turns block cipher into stream cipher
    - Fatal on nonce reuse
    """

    def __init__(self, prf=None):
        self.prf = prf or AESPRF()

    def encrypt(self, k: bytes, m: bytes) -> tuple:
        r = os.urandom(BLOCK)
        padded = pkcs7_pad(m)
        ct = bytearray()
        for i, block_start in enumerate(range(0, len(padded), BLOCK)):
            block = padded[block_start:block_start+BLOCK]
            ctr_val = (int.from_bytes(r, 'big') + i) % (2**128)
            ctr_bytes = ctr_val.to_bytes(BLOCK, 'big')
            ks_block = self.prf.evaluate(k, ctr_bytes)
            ct.extend(xor_bytes(block, ks_block))
        return r, bytes(ct)

    def decrypt(self, k: bytes, r: bytes, ciphertext: bytes) -> bytes:
        plaintext = bytearray()
        for i, block_start in enumerate(range(0, len(ciphertext), BLOCK)):
            block = ciphertext[block_start:block_start+BLOCK]
            ctr_val = (int.from_bytes(r, 'big') + i) % (2**128)
            ctr_bytes = ctr_val.to_bytes(BLOCK, 'big')
            ks_block = self.prf.evaluate(k, ctr_bytes)
            plaintext.extend(xor_bytes(block, ks_block))
        try:
            return pkcs7_unpad(bytes(plaintext))
        except ValueError:
            return bytes(plaintext)


# ─── UNIFIED API ──────────────────────────────────────────────────────────────

class ModesOfOperation:
    """Unified API for all three modes."""

    def __init__(self):
        self.cbc = CBCMode()
        self.ofb = OFBMode()
        self.ctr = CTRMode()

    def encrypt(self, mode: str, k: bytes, m: bytes) -> dict:
        mode = mode.upper()
        if mode == "CBC":
            iv, ct = self.cbc.encrypt(k, m)
            return {"mode": "CBC", "iv": iv, "ciphertext": ct}
        elif mode == "OFB":
            iv, ct = self.ofb.encrypt(k, m)
            return {"mode": "OFB", "iv": iv, "ciphertext": ct}
        elif mode == "CTR":
            nonce, ct = self.ctr.encrypt(k, m)
            return {"mode": "CTR", "nonce": nonce, "ciphertext": ct}
        else:
            raise ValueError(f"Unknown mode: {mode}")

    def decrypt(self, mode: str, k: bytes, blob: dict) -> bytes:
        mode = mode.upper()
        if mode == "CBC":
            return self.cbc.decrypt(k, blob["iv"], blob["ciphertext"])
        elif mode == "OFB":
            return self.ofb.decrypt(k, blob["iv"], blob["ciphertext"])
        elif mode == "CTR":
            return self.ctr.decrypt(k, blob["nonce"], blob["ciphertext"])
        else:
            raise ValueError(f"Unknown mode: {mode}")


# ─── ATTACK DEMOS ─────────────────────────────────────────────────────────────

def cbc_iv_reuse_attack():
    """
    CBC IV-reuse: if IV is same, block i leaks if M_i == M'_i.
    C_i = E_k(IV XOR M_i). If M_i = M'_i and IV is same -> C_i = C'_i.
    """
    print("\n[CBC IV-Reuse Attack]")
    cbc = CBCMode()
    k = os.urandom(BLOCK)
    fixed_iv = os.urandom(BLOCK)

    m1 = b"AAAAAAAAAAAAAAAA" + b"BBBBBBBBBBBBBBBB" + b"CCCCCCCCCCCCCCCC"
    m2 = b"AAAAAAAAAAAAAAAA" + b"DDDDDDDDDDDDDDDD" + b"CCCCCCCCCCCCCCCC"

    _, c1 = cbc.encrypt(k, m1, iv=fixed_iv)
    _, c2 = cbc.encrypt(k, m2, iv=fixed_iv)

    blocks_c1 = [c1[i:i+BLOCK] for i in range(0, len(c1), BLOCK)]
    blocks_c2 = [c2[i:i+BLOCK] for i in range(0, len(c2), BLOCK)]

    print(f"  Block 0 same in both msgs: M[0]=M'[0]='AAAA...'")
    print(f"  C1[0] = C2[0]? : {blocks_c1[0] == blocks_c2[0]} (leaks M[0] == M'[0])")
    print(f"  Block 1 differs: M[1]≠M'[1]")
    print(f"  C1[1] = C2[1]? : {blocks_c1[1] == blocks_c2[1]}")
    print(f"  Block 2 same   : M[2]=M'[2]='CCCC...'")
    print(f"  C1[2] = C2[2]? : {blocks_c1[2] == blocks_c2[2]} (differs due to error propagation from block 1)")


def ofb_keystream_reuse_attack():
    """
    OFB keystream reuse: if same IV used twice,
    C1 XOR C2 = M1 XOR M2 (keystream cancels).
    """
    print("\n[OFB Keystream-Reuse Attack]")
    ofb = OFBMode()
    k = os.urandom(BLOCK)
    fixed_iv = os.urandom(BLOCK)

    m1 = b"Attack at dawn!!"
    m2 = b"Defend the fort!"

    _, c1 = ofb.encrypt(k, m1, iv=fixed_iv)
    _, c2 = ofb.encrypt(k, m2, iv=fixed_iv)

    xor_ct = xor_bytes(c1[:BLOCK], c2[:BLOCK])
    xor_pt = xor_bytes(m1, m2)

    print(f"  m1         : {m1}")
    print(f"  m2         : {m2}")
    print(f"  C1 XOR C2  : {xor_ct.hex()}")
    print(f"  M1 XOR M2  : {xor_pt.hex()}")
    print(f"  Equal?     : {xor_ct == xor_pt}")
    print(f"  => Attacker recovers M1 XOR M2 directly!")


def bit_flip_error_propagation():
    """Show error propagation patterns for each mode."""
    print("\n[Bit-Flip Error Propagation]")
    k = os.urandom(BLOCK)
    modes = ModesOfOperation()

    m = b"Block0_AAAAAAAAAA" + b"Block1_BBBBBBBBB" + b"Block2_CCCCCCCCC"

    for mode in ["CBC", "OFB", "CTR"]:
        blob = modes.encrypt(mode, k, m.ljust(48, b'\x00')[:48])
        ct = bytearray(blob["ciphertext"])
        ct[0] ^= 0x01  # flip first bit of first ciphertext block
        blob["ciphertext"] = bytes(ct)
        try:
            recovered = modes.decrypt(mode, k, blob)
            corrupted_blocks = sum(
                1 for i in range(0, min(len(recovered), 48), BLOCK)
                if recovered[i:i+BLOCK] != m[i:i+BLOCK]
            )
            print(f"  {mode}: {corrupted_blocks} block(s) corrupted after flipping 1 bit in C[0]")
        except Exception as e:
            print(f"  {mode}: decryption error ({e})")


# ─── DEMO ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("PA #4 — Modes of Operation (CBC / OFB / CTR)")
    print("=" * 60)

    modes = ModesOfOperation()
    k = os.urandom(BLOCK)

    test_msgs = [
        b"Short",
        b"Exactly16Bytes!!",
        b"A multi-block message that spans three blocks here!!"
    ]

    for mode in ["CBC", "OFB", "CTR"]:
        print(f"\n[{mode} Mode]")
        for m in test_msgs:
            blob = modes.encrypt(mode, k, m)
            recovered = modes.decrypt(mode, k, blob)
            ok = recovered == m
            print(f"  {'✓' if ok else '✗'} len={len(m):3d} -> ct_len={len(blob['ciphertext']):3d} | recovered={ok}")

    cbc_iv_reuse_attack()
    ofb_keystream_reuse_attack()
    bit_flip_error_propagation()

    print("\n[Mode Comparison Table]")
    print("  Mode | Parallel Enc | Parallel Dec | Random Access | Error Prop")
    print("  -----|-------------|-------------|---------------|----------")
    print("  CBC  |     No      |     Yes     |      No       |  2 blocks")
    print("  OFB  |     No      |     No      |      No       |  1 block ")
    print("  CTR  |     Yes     |     Yes     |      Yes      |  1 block ")

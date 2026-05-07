# Security Concepts & Implementation Reference

Each PA builds on the previous. This document describes **what was implemented**, the key algorithms, the security notions proved, and the attacks demonstrated.

---

## Table of Contents

1. [The Big Picture](#the-big-picture)
2. [PA#0 — Minicrypt Clique Web Explorer](#pa0--minicrypt-clique-web-explorer)
3. [Part I — Symmetric Crypto (PA#1–#6)](#part-i--symmetric-crypto-pa16)
4. [Part II — Hashing & MAC (PA#7–#10)](#part-ii--hashing--mac-pa710)
5. [Part III — Public-Key Crypto (PA#11–#17)](#part-iii--public-key-crypto-pa1117)
6. [Part IV — Secure MPC (PA#18–#20)](#part-iv--secure-mpc-pa1820)
7. [Reduction Chain Diagram](#reduction-chain-diagram)

---

## The Big Picture

Modern cryptography builds **confidentiality, integrity, and authentication** from a single assumption:

> **Some math problems are easy to compute but hard to reverse** — a One-Way Function (OWF).

The **Minicrypt Theorem** says: if any OWF exists, we can build everything. These 20 assignments trace that full chain from OWF → PRG → PRF → MAC → encryption → hashing → public-key crypto → secure computation.

---

## PA#0 — Minicrypt Clique Web Explorer

**File:** `minicrypt-explorer/` (React + Vite)  
**What it does:** A React single-page app that visualises the full reduction graph. Pick any two primitives, get the shortest reduction chain with real cryptographic data flowing through each step from the Flask API.

**Key components:**
- `App.jsx` — left sidebar navigation grouped by topic; main content area shows demo panels or the two-column reduction visualiser
- `api_server.py` — Flask server with 40+ endpoints (`/api/pa1/prg` through `/api/pa20/demo`) that run real Python crypto and return JSON
- Demos split across `Demos.jsx`, `Demos2.jsx`, `Demos3.jsx` for PA#1–#20

---

## Part I — Symmetric Crypto (PA#1–#6)

---

### PA#1 — One-Way Functions (OWF) & Pseudorandom Generators (PRG)

**File:** `pa1_owf_prg.py`

**Implemented:**
- `OWF_DLP`: `f(x) = g^x mod p` using a 64-bit safe prime. Hard to invert due to the Discrete Logarithm Problem.
- `OWF_AES`: `f(k) = AES_k(0^128) XOR k`. AES used as a permutation; XOR breaks invertibility.
- `PRG_OWF`: Iterates the OWF, extracting the **Goldreich-Levin hard-core bit** `b(x) = <x, r> mod 2` (inner product with random vector `r`) at each step. 128 bits of seed → 256+ bits of pseudorandom output.
- **Bidirectional:** Shows PRG → OWF reduction (if you invert the PRG output, you invert the OWF).
- **NIST statistical tests:** Frequency, runs, and serial tests on the output — all pass.

**Security notion:** Computational unpredictability of the output under unknown seed.

---

### PA#2 — Pseudorandom Functions (PRF) via GGM Tree

**File:** `pa2_prf.py`

**Implemented:**
- `GGMPRF`: Given a length-doubling PRG `G: {0,1}^n → {0,1}^{2n}`, builds a PRF via a binary tree. `F_k(x₁x₂...xₙ)` traverses the tree bit-by-bit, applying `G_left` or `G_right` at each level. `O(n)` PRG calls per evaluation.
- `AESPRFF`: AES-128 used directly as a PRF benchmark (constant-time).
- **Bidirectional:** `G(s) = F_s(0) || F_s(1)` recovers a PRG from the PRF.
- **Interactive demo:** Visualises the binary tree and traces the evaluation path.

**Security notion:** Computational indistinguishability from a truly random function.

---

### PA#3 — CPA-Secure Symmetric Encryption

**File:** `pa3_cpa.py`

**Implemented:**
- `CPAEncryption`: `Enc(k, m) = (r, F_k(r) XOR m)` where `r` is a fresh 128-bit random nonce. Uses `AESPRFF` from PA#2.
- `IND_CPA_Game`: The standard left-or-right oracle game. Challenger flips a coin `b`, returns `Enc(k, m_b)`. Attacker wins if they guess `b` with advantage > negligible.
- Demonstrates that encrypting twice with the same message gives different ciphertexts (probabilistic).
- Demonstrates that bit-flipping the ciphertext corrupts the plaintext with no detection.

**Security notion:** IND-CPA (indistinguishability under chosen-plaintext attack).

---

### PA#4 — Modes of Operation (CBC, OFB, CTR)

**File:** `pa4_modes.py`

**Implemented:**
- `CBCMode`, `OFBMode`, `CTRMode`: All use AES-128 as the underlying block cipher.
- **CBC:** `C_i = AES_k(M_i XOR C_{i-1})`. IV is random and prepended. IV reuse leaks `M_1 XOR M_1'`.
- **OFB:** `K_i = AES_k(K_{i-1})`, `C_i = M_i XOR K_i`. Keystream reuse is catastrophic: `C XOR C' = M XOR M'`.
- **CTR:** `C_i = M_i XOR AES_k(nonce || i)`. Parallelisable, supports random-access decryption.
- **Luby-Rackoff Feistel:** 4-round Feistel network proves PRP (block cipher) from PRF.
- **Bit-flip demo:** CBC and OFB show controlled plaintext corruption on ciphertext tampering.

**Security notion:** IND-CPA for variable-length messages; PRP ↔ PRF switching lemma.

---

### PA#5 — Message Authentication Codes (MAC)

**File:** `pa5_mac.py`

**Implemented:**
- `PRFMAC`: `tag = F_k(m)` — single PRF call, secure for fixed-length messages.
- `CBCMAC`: Chains message blocks through AES (CBC without IV). Length-extension vulnerable on variable-length messages without proper encoding.
- `EUF_CMA_Game`: 50 signing oracle queries + 20 forgery attempts on fresh messages. All forgeries rejected in tests.
- **Bidirectional:** Shows MAC → PRF: a MAC that is EUF-CMA secure on uniform messages is computationally indistinguishable from a PRF.

**Security notion:** EUF-CMA (existential unforgeability under chosen-message attack).

---

### PA#6 — CCA-Secure Symmetric Encryption

**File:** `pa6_cca.py`

**Implemented:**
- `CCAEncryption`: `Enc(kE, kM, m) = (c, t)` where `c = CPAEnc(kE, m)` and `t = MAC(kM, c)` — **Encrypt-then-MAC**.
- `Dec`: Verifies `t` first using constant-time comparison; returns `⊥` (rejection) on failure.
- `IND_CCA2_Game`: Attacker gets enc + dec oracle, except they cannot query the challenge ciphertext. Advantage verified to be negligible.
- **Malleability attack on CPA-only:** Demos flip a bit in the CPA ciphertext and recover a predictably corrupted plaintext; the CCA scheme rejects the same tampered ciphertext.
- **Key separation:** `kE` and `kM` are independently derived — sharing keys breaks security.

**Security notion:** IND-CCA2. Used by TLS 1.2, SSH, IPsec.

---

## Part II — Hashing & MAC (PA#7–#10)

---

### PA#7 — Merkle-Damgård Transform

**File:** `pa7_merkle.py`

**Implemented:**
- `MerkleDamgard`: Takes any compression function `h: {0,1}^{2n} → {0,1}^n` and produces an arbitrary-length hash.
- **Padding:** Appends `1 || 0*k || len(m)` (length in 64-bit big-endian) — the standard MD strengthening. Ensures distinct padded messages for equal-length messages.
- **Iterative compression:** `H_0 = IV`, `H_i = h(H_{i-1} || M_i)`, output `H_t`.
- Demonstrates **length-extension**: given `H(m)` and `len(m)`, an adversary can compute `H(m || pad || m')` without knowing the key. This is why plain `H(k||m)` is broken as a MAC.

**Security notion:** CRHF security reduces to collision resistance of the compression function.

---

### PA#8 — DLP-Based Collision-Resistant Hash Function

**File:** `pa8_dlp_hash.py`

**Implemented:**
- `DLPCompress`: `h(x, y) = g^x · α^y mod p` where `g`, `α` are generators of a prime-order group and `log_g(α)` is unknown. Finding a collision solves the DLP.
- `DLPHash`: Plugs `DLPCompress` into `MerkleDamgard` (PA#7) for variable-length input.
- **Provable collision resistance:** A collision in `DLPHash` directly gives an algorithm for DLP. Reduction is tight.
- Also used as the hash in PA#10 (HMAC), PA#15 (hash-then-sign).

**Security notion:** CRHF provably hard under the Discrete Logarithm assumption.

---

### PA#9 — Birthday Attack (Collision Finding)

**File:** `pa9_birthday.py`

**Implemented:**
- `BirthdayAttack`: Naive dictionary attack — hash random inputs until a collision is found. Expected `~2^(n/2)` queries by the birthday paradox.
- `FloydCycleAttack`: Finds collisions in `O(2^(n/2))` time and `O(1)` space using Floyd's tortoise-and-hare cycle detection on the hash chain `x_{i+1} = H(x_i)`.
- **Truncated DLP hash:** Truncates PA#8's output to 16/20/24 bits for demo — collisions found in milliseconds.
- **Birthday chart:** Plots empirical vs. theoretical collision probability as a function of queries.

**Key insight:** No matter how hard the hash, output size `n` bits means `O(2^{n/2})` collision resistance — not `O(2^n)`.

---

### PA#10 — HMAC & HMAC-Based CCA-Secure Encryption

**File:** `pa10_hmac.py`

**Implemented:**
- `HMAC`: `HMAC_k(m) = DLPHash((k XOR opad) || DLPHash((k XOR ipad) || m))`. Uses PA#8's `DLPHash`. `ipad = 0x36^128`, `opad = 0x5C^128`.
- **Constant-time verify:** Tag comparison via full XOR over all bytes — no early exit. Prevents timing side-channel.
- **Length-extension attack demo:** Shows `H(k||m)` is vulnerable; HMAC's outer hash blocks extension.
- `HMACEncryption`: Encrypt-then-HMAC using PA#3 CPA encryption + this HMAC. Replaces CBC-MAC from PA#6.
- **Bidirectional CRHF ↔ MAC:**
  - Forward: `DLPHash → HMAC → EUF-CMA MAC`
  - Backward: `HMAC(k, ·)` used as compression function in Merkle-Damgård → new CRHF

**Security notion:** EUF-CMA + IND-CCA2. Completes the Minicrypt clique bridge between hashing and symmetric crypto.

---

## Part III — Public-Key Crypto (PA#11–#17)

---

### PA#11 — Diffie-Hellman Key Exchange

**File:** `pa11_dh.py`

**Implemented:**
- `DiffieHellman`: Uses a 64-bit safe prime `p` (where `(p-1)/2` is also prime, generated by PA#13). `g` is a generator of the prime-order subgroup.
- `exchange()`: Alice samples `a`, sends `g^a mod p`; Bob samples `b`, sends `g^b mod p`; both compute `K = g^(ab) mod p`.
- **MITM attack demo:** `MITMAttack` intercepts `g^a` and `g^b`, substitutes `g^e` for both, establishes two independent shared secrets. Alice and Bob think they share a key but Eve reads everything.
- Security depends on the **Computational DH (CDH)** assumption.

**Security notion:** Session key indistinguishable from random under CDH. No authentication → vulnerable to MITM (motivates signatures, PA#15).

---

### PA#12 — Textbook RSA + PKCS#1 v1.5

**File:** `pa12_rsa.py`

**Implemented:**
- `RSA`: `keygen()` picks two 64-bit primes via PA#13 Miller-Rabin. `N = pq`, `e = 65537`, `d = e^{-1} mod φ(N)` via extended Euclidean. `encrypt(m) = m^e mod N`, `decrypt(c) = c^d mod N` using CRT speedup (PA#14).
- `PKCS1v15`: Pads `m` as `0x00 02 <random PS> 00 <m>` before RSA. PS is random non-zero bytes; makes encryption probabilistic.
- **Determinism attack:** Textbook RSA encrypts the same `m` to the same `c` — demonstrated by encrypting twice and checking equality.
- **Bleichenbacher oracle:** Simulates a padding oracle that returns whether decrypted bytes start with `0x00 02`. Adaptive attack recovers plaintext iteratively.

**Security notion:** IND-CPA under PKCS#1 v1.5 (random padding). Textbook RSA is not even OW-CPA secure.

---

### PA#13 — Miller-Rabin Primality Testing

**File:** `pa13_miller_rabin.py`

**Implemented:**
- `miller_rabin(n, k)`: Writes `n-1 = 2^r · d`. For `k` random witnesses `a`, checks `a^d ≢ 1` and `a^{2^j·d} ≢ -1` for all `j`. If any witness passes without hitting `±1`, `n` is definitely composite.
- `generate_prime(bits)`: Loops over random odd numbers, applying Miller-Rabin with `k=40`. Error probability `< 4^{-40} ≈ 2^{-80}`.
- `generate_safe_prime(bits)`: Generates `p` such that `q = (p-1)/2` is also prime — required for secure DH groups.
- **Carmichael number demo:** `561 = 3·11·17` passes Fermat but is detected composite by Miller-Rabin.

**Why it matters:** Every other PA that needs primes (PA#11, #12, #16) calls this module.

---

### PA#14 — Chinese Remainder Theorem & Hastad's Broadcast Attack

**File:** `pa14_crt.py`

**Implemented:**
- `CRT`: Solves `x ≡ aᵢ mod mᵢ` for pairwise coprime moduli using Garner's algorithm. `O(k²)` modular multiplications.
- **CRT-RSA decryption:** `dp = d mod (p-1)`, `dq = d mod (q-1)`. Compute `mp = c^dp mod p`, `mq = c^dq mod q`, combine via CRT. ~4× faster than direct `c^d mod N`.
- **Hastad's Broadcast Attack:** If `Enc(N₁,m)`, `Enc(N₂,m)`, `Enc(N₃,m)` use `e=3` with distinct moduli, CRT recovers `m³` over `N₁N₂N₃`, then takes the integer cube root. Attack works when `m³ < N₁N₂N₃`.
- **Padding countermeasure:** PKCS#1 randomises `m` for each recipient — attack fails because the three padded messages differ.

**Security notion:** Shows why low public exponent + no padding = catastrophically broken RSA.

---

### PA#15 — RSA Digital Signatures

**File:** `pa15_signatures.py`

**Implemented:**
- `RSASignature`: `sign(sk, m) = H(m)^d mod N` where `H = DLPHash` (PA#8). `verify(vk, m, σ)` checks `σ^e mod N = H(m)`.
- `EUFCMAGameSig`: Signs up to 50 oracle queries. `forge(m, σ)` rejects if `m` was previously signed — requires forging on a fresh message.
- **Raw RSA multiplicative forgery:** Without hashing: given `σ(m₁) = m₁^d` and `σ(m₂) = m₂^d`, the forger computes `σ(m₁·m₂) = σ(m₁)·σ(m₂) mod N`. Demo confirms this works on raw RSA and fails on hash-then-sign.
- **Tamper detection demo:** Signs `m`, flips one bit → signature verification returns `False`.

**Security notion:** EUF-CMA under RSA assumption + collision resistance of `DLPHash`.

---

### PA#16 — ElGamal Public-Key Cryptosystem

**File:** `pa16_elgamal.py`

**Implemented:**
- `ElGamal`: `keygen()` samples `x ∈ ℤ_q`, sets `h = g^x mod p`. `encrypt(h, m)`: pick `r ∈ ℤ_q`, return `(g^r, m·h^r) mod p`. `decrypt(x, c₁, c₂)`: recover `m = c₂·(c₁^x)^{-1} mod p`.
- `IND_CPA_Game`: Encryption is probabilistic — same message gives different ciphertexts every time. Advantage negligible under DDH.
- **Malleability demo:** Given `(c₁, c₂) = Enc(m)`, the ciphertext `(c₁, k·c₂)` decrypts to `k·m` — a predictable transformation without knowing `sk` or `m`. This is a CCA attack.

**Security notion:** IND-CPA under the Decision DH (DDH) assumption. Not CCA-secure — motivates PA#17.

---

### PA#17 — CCA-Secure Public-Key Cryptosystem

**File:** `pa17_cca_pkc.py`

**Implemented:**
- `CCASecurePKC`: `encrypt(enc_keys, sign_keys, m)`: ElGamal-encrypt `m` to get `(c₁, c₂)`, then RSA-sign `serialize(c₁, c₂)` → `σ`. Returns blob `{c₁, c₂, σ}`.
- `decrypt(enc_keys, sign_keys, blob)`: Verifies `σ` first. If invalid → returns `None` (⊥). If valid → ElGamal-decrypt.
- **Tamper-then-decrypt demo:** Multiplies `c₂` by 2. CCA scheme rejects (bad signature). Plain ElGamal returns `2·m`.
- `IND_CCA2_Game`: Attacker has enc + dec oracles but cannot query the challenge blob. Verified that malleability attack from PA#16 no longer applies.

**Security notion:** IND-CCA2 under DDH + RSA + CRHF of `DLPHash`. Sign-then-encrypt pattern (same as TLS 1.3 hybrid).

---

## Part IV — Secure MPC (PA#18–#20)

---

### PA#18 — Oblivious Transfer (1-out-of-2 OT)

**File:** `pa18_ot.py`

**Implemented:**
- `ObliviousTransfer` (Bellare-Micali construction over ElGamal, PA#16):
  - `receiver_step1(b)`: Samples `sk_b`, computes `pk_b = g^{sk_b}`. Generates `pk_{1-b}` as a random group element with **no known discrete log** (trapdoor-free). Sends `(pk_0, pk_1)` to Alice.
  - `sender_step(pk_0, pk_1, m_0, m_1)`: Encrypts `mᵢ` under `pkᵢ` using ElGamal. Returns `(C_0, C_1)`.
  - `receiver_step2(state, C_0, C_1)`: Decrypts `C_b` using `sk_b`. Cannot decrypt `C_{1-b}` — no secret key for `pk_{1-b}`.
- **Privacy demo:** Bob attempts to decrypt the other ciphertext with `sk_b` — gets garbage (CDH/DDH prevents this).
- **Cheat verification:** Verifies `m_cheat ≠ m_{1-b}` in 100% of trials.

**Security notion:** Receiver privacy (Alice learns nothing about `b`) + Sender privacy (Bob learns only `m_b`) under DDH.

---

### PA#19 — Secure AND, XOR, NOT Gates

**File:** `pa19_secure_and.py`

**Implemented:**
- `SecureAND`: OT-based. Alice is sender with messages `(0, a)`, Bob is receiver with choice bit `b`. Bob obtains `m_b = a·b = a AND b`. Full transcript logged.
- `SecureXOR`: Additive secret sharing over `ℤ_2`. Alice samples random bit `r`, sends `a XOR r` to Bob; Bob holds `b XOR r`. Result: `(a XOR r) XOR (b XOR r) = a XOR b`. Zero OT calls needed — XOR is "free" in GMW.
- `SecureNOT`: Local flip. `NOT(a) = 1 XOR a`. Alice computes it alone — zero communication.
- **Truth table verification:** All 4 input combinations `(0,0), (0,1), (1,0), (1,1)` verified for AND and XOR.
- **Privacy transcript:** Logged messages contain no raw inputs.

**Security notion:** Simulation security — Bob's view in AND is simulatable knowing only `a AND b`. Same for Alice.

**Why universal:** AND + XOR + NOT is a complete basis for boolean circuits → any function is computable securely.

---

### PA#20 — 2-Party Secure Computation (GMW Protocol)

**File:** `pa20_mpc.py`

**Implemented:**
- `Circuit`: DAG of `INPUT`, `AND`, `XOR`, `NOT` gates stored as a dict with topological sorting via DFS.
- `SecureEval`: Evaluates circuits gate-by-gate in topological order. Calls `SecureAND` / `SecureXOR` / `SecureNOT` from PA#19 per gate. Tracks OT calls, gate count, and ms per circuit.
- **Three circuits evaluated:**
  - **GT (`x > y`, n-bit):** Bitwise comparator using `n` AND gates + `O(n)` XOR/NOT. Solves Millionaire's Problem.
  - **EQ (`x == y`, n-bit):** XOR each bit pair, NOR the results. All-zero XOR means equal.
  - **ADD (`x + y mod 2^n`, n-bit):** Ripple-carry adder — `n` full-adder stages, each using 2 AND + 3 XOR gates.
- **Full dependency chain for one AND gate:**
  ```
  SecureEval (PA#20) → SecureAND (PA#19) → OT (PA#18)
    → ElGamal (PA#16) → DH group (PA#11) → Miller-Rabin primes (PA#13)
  ```
- **Privacy:** Neither Alice nor Bob sees the other's input bits at any point. Only final circuit output is revealed.

**Security notion:** Semi-honest GMW simulation security. No external library — every layer is hand-built.

---

## Reduction Chain Diagram

```
OWF (PA#1) ←→ PRG (PA#1) ←→ PRF (PA#2) ←→ PRP/AES (PA#4)
                                 ↕                 ↕
                              MAC (PA#5)     CBC-MAC (PA#5)
                                 ↕
                    CRHF (PA#7+#8) ←→ HMAC (PA#10) ←→ MAC
                                            ↕
                                    CCA-Sym (PA#6, #10)

Public-Key Track:
  Miller-Rabin (#13) → DH (#11) → ElGamal (#16) → CCA-PKC (#17)
  Miller-Rabin (#13) → RSA (#12) → Signatures (#15) ↗ CCA-PKC (#17)
                          ↓
                       CRT (#14)

MPC Track:
  ElGamal (#16) → OT (#18) → Secure AND (#19) → MPC (#20)
```

### Security Notions Summary

| Notion | PA(s) |
|--------|-------|
| OW (One-Wayness) | #1 |
| PRG (pseudorandomness) | #1 |
| PRF (keyed pseudorandomness) | #2 |
| IND-CPA (symmetric) | #3, #4 |
| EUF-CMA (MAC) | #5, #10 |
| IND-CCA2 (symmetric) | #6, #10 |
| CRHF (collision resistance) | #8, #9 |
| IND-CPA (public-key) | #12, #16 |
| EUF-CMA (signatures) | #15 |
| IND-CCA2 (public-key) | #17 |
| Receiver/Sender Privacy (OT) | #18 |
| Simulation Security (MPC) | #19, #20 |

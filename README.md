# CS8.401 — Principles of Information Security: Programming Assignments

A complete, self-contained implementation of the **Minicrypt Clique** and beyond — 20 programming assignments tracing the full reduction chain from One-Way Functions to Secure Multi-Party Computation.

> **No external cryptographic libraries.** Every primitive is built from scratch using only Python's built-in `int`, `os.urandom`, and standard-library utilities.

---

## Quick Start

### Step 1 — Prerequisites

- **Python 3.10+** — `python --version`
- **Node.js 20+** and **npm 10+** — `node --version && npm --version`

### Step 2 — Install Python dependencies

```bash
cd crypto_assignments
pip install -r requirements.txt
# installs: flask, flask-cors
```

### Step 3 — Install npm dependencies

```bash
cd minicrypt-explorer
npm install
# installs all packages from package.json into node_modules/
```

> Use `npm ci` instead for a reproducible install locked to `package-lock.json`.

### Step 4 — Run an individual PA (optional)

Each Python file is self-contained. Run any one directly:

```bash
cd crypto_assignments
python pa1_owf_prg.py        # PA#1: OWF + PRG
python pa2_prf.py             # PA#2: GGM PRF
python pa3_cpa.py             # PA#3: CPA-Secure Encryption
python pa4_modes.py           # PA#4: CBC / OFB / CTR Modes
python pa5_mac.py             # PA#5: PRF-MAC + CBC-MAC
python pa6_cca.py             # PA#6: CCA-Secure (Encrypt-then-MAC)
python pa7_merkle.py          # PA#7: Merkle-Damgard Transform
python pa8_dlp_hash.py        # PA#8: DLP-Based CRHF
python pa9_birthday.py        # PA#9: Birthday Attack
python pa10_hmac.py           # PA#10: HMAC + Encrypt-then-HMAC
python pa11_dh.py             # PA#11: Diffie-Hellman Key Exchange
python pa12_rsa.py            # PA#12: Textbook RSA + PKCS#1 v1.5
python pa13_miller_rabin.py   # PA#13: Miller-Rabin Primality
python pa14_crt.py            # PA#14: CRT + Hastad Attack
python pa15_signatures.py     # PA#15: RSA Digital Signatures
python pa16_elgamal.py        # PA#16: ElGamal PKC
python pa17_cca_pkc.py        # PA#17: CCA-Secure PKC (Sign-then-Encrypt)
python pa18_ot.py             # PA#18: Oblivious Transfer
python pa19_secure_and.py     # PA#19: Secure AND Gate
python pa20_mpc.py            # PA#20: 2-Party Secure Computation
```

### Step 5 — Run the Web Explorer (PA#0)

Needs **two terminals open simultaneously**:

**Terminal 1 — Flask API:**
```bash
cd crypto_assignments
python api_server.py
# → http://127.0.0.1:5000  (40+ endpoints listed on startup)
```

**Terminal 2 — Vite dev server:**
```bash
cd minicrypt-explorer
npm run dev
# → Vite prints the exact URL, e.g. http://localhost:5173
#   (port auto-increments if 5173 is taken)
```

Open the URL from Terminal 2 in your browser. The app proxies all `/api/*` calls to the Flask server automatically (`vite.config.js`). When the API is live, all demo panels show real cryptographic output.

---

## Assignment Index

| PA | Topic | Dependencies | Bidir. |
|----|-------|-------------|--------|
| #0 | Minicrypt Clique Web Explorer (React) | Stubs for PA#1–#10 | incremental |
| #1 | OWF + PRG | — | ✓ |
| #2 | PRF (GGM Tree) | #1 (or AES) | ✓ |
| #3 | CPA-Secure Symmetric Encryption | #2 | |
| #4 | Modes of Operation (CBC/OFB/CTR) | #3 | |
| #5 | Secure MACs (PRF-MAC, CBC-MAC) | #2 (or AES) | |
| #6 | CCA-Secure Symmetric Encryption | #3 + #5 | |
| #7 | Merkle-Damgard Transform | — | |
| #8 | DLP-Based CRHF | #7 | |
| #9 | Birthday Attack (Collision Finding) | #8 (truncated) | |
| #10 | HMAC + Encrypt-then-HMAC | #8 + #3 | ✓ |
| #11 | Diffie-Hellman Key Exchange | #13 | |
| #12 | Textbook RSA + PKCS#1 v1.5 | #13 | |
| #13 | Miller-Rabin Primality | — | |
| #14 | CRT + Hastad Broadcast Attack | #12 + #13 | |
| #15 | Digital Signatures | #12 or #16 | |
| #16 | ElGamal PKC | #11 | |
| #17 | CCA-Secure PKC (Sign-then-Encrypt) | #15 + #16 | |
| #18 | Oblivious Transfer | #12 or #16 | |
| #19 | Secure AND Gate | #18 | |
| #20 | All 2-Party Secure Computation | #19 + #18 | |

**Bidir. (✓)** = bidirectional reduction required (both A ⇒ B and B ⇒ A).

---

## Bidirectional Reductions

The Minicrypt Clique primitives form equivalence classes. The following pairs have **both forward and backward** implementations:

| Pair | Forward | Backward | PA |
|------|---------|----------|----|
| OWF ⇔ PRG | HILL hard-core bit | G(s) is a OWF | #1 |
| PRG ⇔ PRF | GGM Tree | G(s) = F_s(0) ‖ F_s(1) | #2 |
| PRF ⇔ PRP | Luby-Rackoff Feistel | Switching Lemma | #4 |
| PRF ⇔ MAC | F_k(m) = tag | EUF-CMA MAC on uniform → PRF | #5 |
| CRHF ⇔ HMAC | HMAC construction | HMAC as MD compression fn | #10 |
| HMAC ⇔ MAC | HMAC is EUF-CMA | MAC as HMAC inner step | #10 |
| MAC ⇔ CRHF | via HMAC bridge | MAC as MD compression fn | #10 |

---

## Dependency Graph

```
OWF (PA#1) ←→ PRG (PA#1) ←→ PRF (PA#2) ←→ PRP (PA#4)
                                ↕               ↕
                              MAC (PA#5) ←→ CBC-MAC
                                ↕
                         CRHF (PA#7+#8) ←→ HMAC (PA#10)

Public-Key Track:
  Miller-Rabin (PA#13) → DH (PA#11) → ElGamal (PA#16) → CCA-PKC (PA#17)
  Miller-Rabin (PA#13) → RSA (PA#12) → Signatures (PA#15) ↗
                            ↓
                        CRT (PA#14)

MPC Track:
  ElGamal (PA#16) → OT (PA#18) → Secure AND (PA#19) → MPC (PA#20)
```

---

## Project Structure

```
pois/
├── README.md                      # This file
├── pois_project.txt               # Full assignment specification
├── crypto_assignments/
│   ├── api_server.py              # Flask API for web explorer
│   ├── pa1_owf_prg.py             # OWF + PRG + AES-128
│   ├── pa2_prf.py                 # GGM PRF + AES PRF
│   ├── pa3_cpa.py                 # CPA-Secure Encryption
│   ├── pa4_modes.py               # CBC / OFB / CTR Modes
│   ├── pa5_mac.py                 # PRF-MAC + CBC-MAC (+ HMAC delegate)
│   ├── pa6_cca.py                 # CCA-Secure Encryption
│   ├── pa7_merkle.py              # Merkle-Damgard Transform
│   ├── pa8_dlp_hash.py            # DLP-Based CRHF
│   ├── pa9_birthday.py            # Birthday Attack
│   ├── pa10_hmac.py               # HMAC + Encrypt-then-HMAC
│   ├── pa11_dh.py                 # Diffie-Hellman Key Exchange
│   ├── pa12_rsa.py                # Textbook RSA + PKCS#1
│   ├── pa13_miller_rabin.py       # Miller-Rabin Primality
│   ├── pa14_crt.py                # CRT + Hastad Attack
│   ├── pa15_signatures.py         # RSA Digital Signatures
│   ├── pa16_elgamal.py            # ElGamal PKC
│   ├── pa17_cca_pkc.py            # CCA-Secure PKC
│   ├── pa18_ot.py                 # Oblivious Transfer
│   ├── pa19_secure_and.py         # Secure AND Gate
│   └── pa20_mpc.py                # 2-Party MPC
└── minicrypt-explorer/            # PA#0 React Web App
    ├── package.json
    ├── vite.config.js             # Dev proxy → Flask API
    ├── index.html
    └── src/
        ├── main.jsx
        └── App.jsx                # Main explorer component
```

---

## Security Notions Covered

| Notion | Implemented In |
|--------|---------------|
| One-Wayness | PA#1 |
| Pseudorandomness (PRG) | PA#1 |
| Pseudorandom Function | PA#2 |
| IND-CPA (symmetric) | PA#3 |
| EUF-CMA (MAC) | PA#5, PA#10 |
| IND-CCA2 (symmetric) | PA#6, PA#10 |
| Collision Resistance | PA#8, PA#9 |
| IND-CPA (public-key) | PA#16 |
| EUF-CMA (signatures) | PA#15 |
| IND-CCA2 (public-key) | PA#17 |
| Receiver/Sender Privacy (OT) | PA#18 |
| Simulation Security (MPC) | PA#19, PA#20 |

---

## Notes

- **No-Library Rule:** Every cryptographic primitive is self-implemented. The only external dependencies are `flask` / `flask-cors` (for the web API), React + Vite (for the web UI), and Python's built-in `int` / `os.urandom` / `math`.
- **Toy parameters:** Several demos use small parameters for speed (e.g., 64-bit primes in DH, 4-bit MPC circuits). Real security would require 2048+ bit primes.
- **Statistical tests:** PA#1's NIST frequency, runs, and serial tests all pass reliably. Occasional variance in the serial test is expected statistically and not a bug.
- **Verified:** All 20 PAs run without errors. AES-128 validated against NIST test vectors. 75 cross-file integration tests pass. API server and React app build and run correctly.

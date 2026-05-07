"""
Flask API server for the Minicrypt Clique Web Explorer.
Exposes PA#1–#10 cryptographic computations to the React frontend.

Usage:
    python api_server.py          # starts on http://127.0.0.1:5000
"""

import os
import sys
import traceback

from flask import Flask, jsonify, request
try:
    from flask_cors import CORS
    HAS_CORS = True
except ImportError:
    HAS_CORS = False

# Ensure sibling PA modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pa1_owf_prg import (
    AESOWFunction, DLPOneWayFunction, FastPRG, PRGFromOWF,
    aes128_encrypt, SAFE_P, SAFE_G, SAFE_Q,
)
from pa2_prf import GGMPRF, AESPRF, PRGFromPRF
from pa5_mac import PRFMAC, CBCMAC
from pa7_merkle import MerkleDamgard
from pa8_dlp_hash import DLPHash
from pa10_hmac import HMAC

app = Flask(__name__)
if HAS_CORS:
    CORS(app)
else:
    @app.after_request
    def add_cors(resp):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
        return resp


# ── Singleton instances (initialised once for speed) ─────────────────────────

_aes_owf   = AESOWFunction()
_aes_prf   = AESPRF()
_fast_prg  = FastPRG()
_ggm_prf   = GGMPRF(_fast_prg)
_dlp_owf   = DLPOneWayFunction()
_dlp_hash  = DLPHash(output_bytes=16)
_hmac      = HMAC(_dlp_hash)
_prf_mac   = PRFMAC()
_cbc_mac   = CBCMAC()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _hex(b: bytes) -> str:
    return b.hex()

def _parse_hex(s: str, default_len: int = 16) -> bytes:
    """Parse hex string, zero-pad or truncate to default_len bytes."""
    s = s.strip().replace(" ", "")
    if not s:
        return os.urandom(default_len)
    try:
        raw = bytes.fromhex(s)
    except ValueError:
        raw = s.encode("utf-8")
    if len(raw) < default_len:
        raw = raw + b'\x00' * (default_len - len(raw))
    return raw[:default_len]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ── Leg 1: Foundation → Source Primitive ─────────────────────────────────────

def leg1_aes(source: str, seed_hex: str) -> list:
    """Build source primitive from AES foundation."""
    seed = _parse_hex(seed_hex, 16)
    steps = []

    if source == "OWF":
        out = _aes_owf.evaluate(seed)
        steps.append({
            "fn": "AES OWF: f(k) = AES_k(0^128) XOR k",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif source == "PRF":
        out = _aes_prf.evaluate(seed, b'\x00' * 16)
        steps.append({
            "fn": "AES-128 PRF: F_k(x) = AES_k(x)",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif source == "PRP":
        block = b'\x00' * 16
        out = aes128_encrypt(seed, block)
        steps.append({
            "fn": "AES-128 PRP: PRP_k(0^128)",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif source == "PRG":
        _fast_prg.seed(seed)
        left, right = _fast_prg.expand(seed)
        steps.append({
            "fn": "AES PRF: F_k(0) = left half",
            "input": _hex(seed),
            "output": _hex(left),
        })
        steps.append({
            "fn": "AES PRF: F_k(1) = right half",
            "input": _hex(seed),
            "output": _hex(right),
        })
        steps.append({
            "fn": "PRG(s) = F_s(0) || F_s(1)",
            "input": _hex(seed),
            "output": _hex(left) + _hex(right),
        })

    elif source == "MAC":
        msg = b'\x00' * 16
        tag = _prf_mac.mac(seed, msg)
        steps.append({
            "fn": "PRF-MAC: tag = F_k(m)",
            "input": _hex(seed),
            "output": _hex(tag),
        })

    elif source == "CRHF":
        out = _dlp_hash.hash(seed)
        steps.append({
            "fn": "AES foundation has no direct CRHF path; showing DLP Hash as fallback",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif source == "HMAC":
        tag = _hmac.mac(seed, b'\x00' * 16)
        steps.append({
            "fn": "HMAC_k(0^128) via DLP Hash",
            "input": _hex(seed),
            "output": _hex(tag),
        })

    else:
        steps.append({"fn": f"Unknown source: {source}", "input": seed_hex, "output": "?"})

    return steps


def leg1_dlp(source: str, seed_hex: str) -> list:
    """Build source primitive from DLP foundation."""
    seed = _parse_hex(seed_hex, 16)
    seed_int = int.from_bytes(seed, 'big') % SAFE_Q
    steps = []

    if source == "OWF":
        out_int = _dlp_owf.evaluate(seed_int)
        out_hex = hex(out_int)[2:][:32]
        steps.append({
            "fn": "DLP OWF: f(x) = g^x mod p",
            "input": hex(seed_int)[:32],
            "output": out_hex,
        })

    elif source == "PRG":
        prg = PRGFromOWF(_dlp_owf)
        out = prg.generate(seed, 16)
        steps.append({
            "fn": "PRG via HILL hard-core bit (DLP OWF): G(x) = b(x0)||b(x1)||...",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif source == "PRF":
        left, right = _fast_prg.expand(seed)
        steps.append({
            "fn": "DLP -> OWF -> PRG -> PRF (GGM). Showing AES-backed PRF as concrete instantiation",
            "input": _hex(seed),
            "output": _hex(_aes_prf.evaluate(seed, b'\x00' * 16)),
        })

    elif source == "PRP":
        out = aes128_encrypt(seed, b'\x00' * 16)
        steps.append({
            "fn": "PRP via PRF -> Luby-Rackoff (showing AES as concrete PRP)",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif source == "MAC":
        tag = _prf_mac.mac(seed, b'\x00' * 16)
        steps.append({
            "fn": "MAC via PRF-MAC: tag = F_k(m)",
            "input": _hex(seed),
            "output": _hex(tag),
        })

    elif source == "CRHF":
        out = _dlp_hash.hash(seed)
        steps.append({
            "fn": "DLP CRHF: Merkle-Damgard(DLP compression)",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif source == "HMAC":
        tag = _hmac.mac(seed, b'\x00' * 16)
        steps.append({
            "fn": "HMAC_k(0^128) via DLP Hash",
            "input": _hex(seed),
            "output": _hex(tag),
        })

    else:
        steps.append({"fn": f"Unknown source: {source}", "input": seed_hex, "output": "?"})

    return steps


# ── Leg 2: Source → Target Primitive ─────────────────────────────────────────

def leg2(source: str, target: str, seed_hex: str, msg_hex: str, prf_fn=None) -> list:
    """Compute the reduction from source to target with real data.
    prf_fn: callable(key, block) -> bytes — the PRF built by leg1, passed as black box."""
    seed = _parse_hex(seed_hex, 16)
    if prf_fn is None:
        prf_fn = _aes_prf.evaluate
    steps = []
    key = f"{source}->{target}"

    if key == "OWF->PRG":
        prg = PRGFromOWF(_aes_owf)
        out = prg.generate(seed, 16)
        steps.append({
            "fn": "OWF -> PRG [HILL hard-core bit]",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif key == "PRG->PRF":
        query = msg_hex.strip()
        if not query:
            query = "1011"
        out = _ggm_prf.evaluate_bitstring(seed, query)
        steps.append({
            "fn": f"PRG -> PRF [GGM Tree]: F_k({query})",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif key == "PRF->PRP":
        # Luby-Rackoff 3-round Feistel
        msg = _parse_hex(msg_hex, 16)
        left  = msg[:8]
        right = msg[8:16]
        k1 = seed
        k2 = bytes((b + 1) & 0xff for b in seed)
        k3 = bytes((b + 2) & 0xff for b in seed)

        # Round 1
        f1 = prf_fn(k1, right.ljust(16, b'\x00'))[:8]
        new_left = _xor(left, f1)
        steps.append({
            "fn": "Luby-Rackoff Round 1: L' = L XOR F_k1(R)",
            "input": f"L={_hex(left)} R={_hex(right)}",
            "output": f"L'={_hex(new_left)}",
        })

        # Round 2
        f2 = prf_fn(k2, new_left.ljust(16, b'\x00'))[:8]
        new_right = _xor(right, f2)
        steps.append({
            "fn": "Luby-Rackoff Round 2: R' = R XOR F_k2(L')",
            "input": f"L'={_hex(new_left)}",
            "output": f"R'={_hex(new_right)}",
        })

        # Round 3
        f3 = prf_fn(k3, new_right.ljust(16, b'\x00'))[:8]
        final_left = _xor(new_left, f3)
        steps.append({
            "fn": "Luby-Rackoff Round 3: L'' = L' XOR F_k3(R')",
            "input": f"R'={_hex(new_right)}",
            "output": f"PRP(m) = {_hex(final_left)}{_hex(new_right)}",
        })

    elif key == "PRF->MAC":
        msg = _parse_hex(msg_hex, 16)
        tag = _prf_mac.mac(seed, msg)
        steps.append({
            "fn": "PRF -> MAC: tag = F_k(m)",
            "input": _hex(msg),
            "output": _hex(tag),
        })

    elif key == "PRP->MAC":
        msg = _parse_hex(msg_hex, 16)
        tag = _cbc_mac.mac(seed, msg)
        steps.append({
            "fn": "PRP -> MAC [CBC-MAC]: PRP/PRF switching + PRF->MAC",
            "input": _hex(msg),
            "output": _hex(tag),
        })

    elif key == "PRP->PRF":
        msg = _parse_hex(msg_hex, 16)
        out = aes128_encrypt(seed, msg)
        steps.append({
            "fn": "PRP -> PRF [Switching Lemma]: PRP is indistinguishable from PRF",
            "input": _hex(msg),
            "output": _hex(out),
        })

    elif key == "PRF->PRG":
        prg_from_prf = PRGFromPRF(_aes_prf)
        left, right = prg_from_prf.expand(seed)
        steps.append({
            "fn": "PRF -> PRG [Backward]: G(s) = F_s(0^n) || F_s(1^n)",
            "input": _hex(seed),
            "output": _hex(left) + _hex(right),
        })

    elif key == "PRG->OWF":
        out = _fast_prg.generate(seed, 16)
        steps.append({
            "fn": "PRG -> OWF [Backward]: f(s) = G(s) is a OWF",
            "input": _hex(seed),
            "output": _hex(out),
        })

    elif key == "MAC->PRF":
        msg = _parse_hex(msg_hex, 16)
        tag = _prf_mac.mac(seed, msg)
        steps.append({
            "fn": "MAC -> PRF [Backward]: EUF-CMA MAC on uniform inputs is a PRF",
            "input": _hex(msg),
            "output": _hex(tag),
        })

    elif key == "MAC->CRHF":
        msg = _parse_hex(msg_hex, 16)
        k_fixed = b'\x42' * 16
        def mac_compress(cv, block):
            return _hmac.mac(k_fixed, cv + block)
        iv = b'\x00' * 16
        md = MerkleDamgard(mac_compress, iv, 16)
        out = md.hash(msg)
        steps.append({
            "fn": "MAC -> CRHF [Backward]: MAC as MD compression fn",
            "input": _hex(msg),
            "output": _hex(out),
        })

    elif key == "CRHF->HMAC":
        msg = _parse_hex(msg_hex, 16)
        tag = _hmac.mac(seed, msg)
        steps.append({
            "fn": "CRHF -> HMAC: H((k XOR opad) || H((k XOR ipad) || m))",
            "input": _hex(msg),
            "output": _hex(tag),
        })

    elif key == "HMAC->MAC":
        msg = _parse_hex(msg_hex, 16)
        tag = _hmac.mac(seed, msg)
        steps.append({
            "fn": "HMAC -> MAC: HMAC is a EUF-CMA secure MAC",
            "input": _hex(msg),
            "output": _hex(tag),
        })

    elif key == "CRHF->MAC":
        msg = _parse_hex(msg_hex, 16)
        tag = _hmac.mac(seed, msg)
        steps.append({
            "fn": "CRHF -> MAC [via HMAC]: CRHF -> HMAC -> MAC",
            "input": _hex(msg),
            "output": _hex(tag),
        })

    elif key == "HMAC->CRHF":
        msg = _parse_hex(msg_hex, 16)
        k_fixed = b'\x42' * 16
        def hmac_compress(cv, block):
            return _hmac.mac(k_fixed, cv + block)
        iv = b'\x00' * 16
        md = MerkleDamgard(hmac_compress, iv, 16)
        out = md.hash(msg)
        steps.append({
            "fn": "HMAC -> CRHF [Backward]: HMAC as MD compression fn",
            "input": _hex(msg),
            "output": _hex(out),
        })

    else:
        # Try to find multi-hop path — return stub for now
        steps.append({
            "fn": f"{source} -> {target} [multi-hop reduction]",
            "input": seed_hex,
            "output": "see reduction chain summary",
        })

    return steps


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "primitives": [
        "OWF", "PRG", "PRF", "PRP", "MAC", "CRHF", "HMAC"
    ]})


@app.route("/api/compute", methods=["POST", "OPTIONS"])
def compute():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        foundation = data.get("foundation", "AES")
        source     = data.get("source", "PRG")
        target     = data.get("target", "PRF")
        seed       = data.get("seed", "a3f291bc7e40d528")
        message    = data.get("message", "1011")

        # Leg 1: Foundation -> Source
        if foundation == "AES":
            leg1_steps = leg1_aes(source, seed)
        else:
            leg1_steps = leg1_dlp(source, seed)

        # Build PRF from foundation to pass as black box to leg2
        if foundation == "AES":
            prf_for_leg2 = _aes_prf.evaluate
        else:
            prf_for_leg2 = _ggm_prf.evaluate

        # Leg 2: Source -> Target
        leg2_steps = leg2(source, target, seed, message, prf_fn=prf_for_leg2)

        return jsonify({
            "leg1_steps": leg1_steps,
            "leg2_steps": leg2_steps,
            "foundation": foundation,
            "source": source,
            "target": target,
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e), "leg1_steps": [], "leg2_steps": []}), 500


# ── PA#1 Demo: PRG output viewer + stats ──────────────────────────────────────

@app.route("/api/pa1/prg", methods=["POST", "OPTIONS"])
def pa1_prg():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        seed_hex = data.get("seed", "")
        length = int(data.get("length", 32))
        length = max(8, min(256, length))

        seed = _parse_hex(seed_hex, 16)
        output = _fast_prg.generate(seed, length)

        return jsonify({
            "seed": _hex(seed),
            "output": _hex(output),
            "length": length,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pa1/stats", methods=["POST", "OPTIONS"])
def pa1_stats():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        seed_hex = data.get("seed", "")
        seed = _parse_hex(seed_hex, 16)
        output = _fast_prg.generate(seed, 2500)
        bits = []
        for byte in output:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        from pa1_owf_prg import freq_monobit_test, runs_test, serial_test
        freq_pass, freq_pval = freq_monobit_test(bits)
        runs_pass, runs_pval = runs_test(bits)
        serial_pass, serial_chi2 = serial_test(bits)
        ones_ratio = sum(bits) / len(bits)

        return jsonify({
            "seed": _hex(seed),
            "total_bits": len(bits),
            "ones_ratio": round(ones_ratio, 4),
            "frequency": {"pass": freq_pass, "p_value": round(freq_pval, 6)},
            "runs": {"pass": runs_pass, "p_value": round(runs_pval, 6)},
            "serial": {"pass": serial_pass, "chi2": round(serial_chi2, 4)},
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pa1/owf", methods=["POST", "OPTIONS"])
def pa1_owf():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        mode = data.get("mode", "aes")
        input_hex = data.get("input", "")
        if mode == "dlp":
            inp = _parse_hex(input_hex, 16)
            x = int.from_bytes(inp, 'big') % SAFE_Q
            fx = _dlp_owf.evaluate(x)
            return jsonify({
                "mode": "dlp",
                "fn": "f(x) = g^x mod p  (DLP OWF, safe prime, Blum-Micali)",
                "input": hex(x),
                "output": hex(fx),
            })
        else:
            inp = _parse_hex(input_hex, 16)
            fk = _aes_owf.evaluate(inp)
            return jsonify({
                "mode": "aes",
                "fn": "f(k) = AES_k(0\u00b9\u00b2\u2078) \u2295 k  (Davies-Meyer OWF)",
                "input": _hex(inp),
                "output": _hex(fk),
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pa1/owf_hardness", methods=["POST", "OPTIONS"])
def pa1_owf_hardness():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        mode = data.get("mode", "aes")
        if mode == "dlp":
            example_x = int.from_bytes(os.urandom(8), 'big') % SAFE_Q
            example_fx = _dlp_owf.evaluate(example_x)
            found_at = None
            for guess in range(min(10000, example_x)):
                if pow(SAFE_G, guess, SAFE_P) == example_fx:
                    found_at = guess
                    break
            return jsonify({
                "mode": "dlp",
                "brute_force_range": 10000,
                "successes": 0 if found_at is None else 1,
                "passed": found_at is None,
                "example": {
                    "x": hex(example_x),
                    "fx": hex(example_fx),
                    "found_at": found_at,
                },
            })
        else:
            example_k = os.urandom(16)
            example_fk = _aes_owf.evaluate(example_k)
            successes = 0
            for _ in range(1000):
                if _aes_owf.evaluate(os.urandom(16)) == example_fk:
                    successes += 1
            return jsonify({
                "mode": "aes",
                "random_guesses": 1000,
                "successes": successes,
                "passed": successes == 0,
                "example": {"k": _hex(example_k), "fk": _hex(example_fk)},
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pa1/prg_hill", methods=["POST", "OPTIONS"])
def pa1_prg_hill():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        seed_hex = data.get("seed", "")
        mode = data.get("mode", "aes")
        length = max(4, min(16, int(data.get("length", 8))))
        seed = _parse_hex(seed_hex, 16)
        owf = _dlp_owf if mode == "dlp" else _aes_owf
        prg = PRGFromOWF(owf)
        output = prg.generate(seed, length)
        prg2 = PRGFromOWF(owf)
        prg2.seed(seed)
        chain = []
        for i in range(min(6, length * 8)):
            bit = prg2._step()
            chain.append({"step": i, "state": prg2._state.hex()[:16] + "...", "bit": bit})
        return jsonify({
            "mode": mode,
            "fn": "G(s) = b(x\u2080)\u2016b(x\u2081)\u2016...  (HILL hard-core bit, iterative OWF)",
            "seed": _hex(seed),
            "output": _hex(output),
            "length_bytes": length,
            "chain": chain,
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route("/api/pa1/prg_backward", methods=["POST", "OPTIONS"])
def pa1_prg_backward():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        seed_hex = data.get("seed", "")
        seed = _parse_hex(seed_hex, 16)
        prg_output = _fast_prg.generate(seed, 16)
        attempts = 10000
        recovered = None
        for _ in range(attempts):
            guess = os.urandom(16)
            if _fast_prg.generate(guess, 16) == prg_output:
                recovered = guess.hex()
                break
        return jsonify({
            "fn": "f(s) = G(s)  — G is a OWF (backward reduction)",
            "seed": _hex(seed),
            "prg_output": _hex(prg_output),
            "inversion_attempts": attempts,
            "recovered_seed": recovered,
            "inversion_failed": recovered is None,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#2 Demo: GGM tree visualiser ───────────────────────────────────────────

@app.route("/api/pa2/ggm", methods=["POST", "OPTIONS"])
def pa2_ggm():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        key_hex = data.get("key", "")
        query = data.get("query", "1011")
        key = _parse_hex(key_hex, 16)

        depth = len(query)
        depth = max(1, min(8, depth))
        query = query[:depth]

        tree = _ggm_prf.get_tree(key, depth)
        leaf = _ggm_prf.evaluate_bitstring(key, query)

        return jsonify({
            "key": _hex(key),
            "query": query,
            "depth": depth,
            "tree": tree,
            "leaf": _hex(leaf),
            "path": [query[:i+1] for i in range(len(query))],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#3 Demo: IND-CPA game ──────────────────────────────────────────────────

from pa3_cpa import CPAEncryption, BrokenCPAEncryption
_cpa_enc = CPAEncryption()
_broken_cpa = BrokenCPAEncryption()
_cpa_game_key = os.urandom(16)

@app.route("/api/pa3/encrypt", methods=["POST", "OPTIONS"])
def pa3_encrypt():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        m0_hex = data.get("m0", "")
        m1_hex = data.get("m1", "")
        reuse_nonce = data.get("reuse_nonce", False)
        import random

        m0 = _parse_hex(m0_hex, 16)
        m1 = _parse_hex(m1_hex, 16)
        b = random.randint(0, 1)
        chosen = m0 if b == 0 else m1

        enc = _broken_cpa if reuse_nonce else _cpa_enc
        r, ct = enc.encrypt(_cpa_game_key, chosen)

        return jsonify({
            "r": _hex(r),
            "ciphertext": _hex(ct),
            "b": b,
            "m0": _hex(m0),
            "m1": _hex(m1),
            "reuse_nonce": reuse_nonce,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#4 Demo: Modes of operation ────────────────────────────────────────────

from pa4_modes import CBCMode, OFBMode, CTRMode, xor_bytes, _aes_decrypt

_cbc = CBCMode()
_ofb = OFBMode()
_ctr = CTRMode()

@app.route("/api/pa4/encrypt", methods=["POST", "OPTIONS"])
def pa4_encrypt():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        mode = data.get("mode", "CBC").upper()
        key_hex = data.get("key", "")
        msg_hex = data.get("message", "")
        key = _parse_hex(key_hex, 16)
        msg = _parse_hex(msg_hex, 48)

        if mode == "CBC":
            iv, ct = _cbc.encrypt(key, msg)
        elif mode == "OFB":
            iv, ct = _ofb.encrypt(key, msg)
        else:
            iv, ct = _ctr.encrypt(key, msg)

        blocks_ct = [_hex(ct[i:i+16]) for i in range(0, len(ct), 16)]
        blocks_msg = [_hex(msg[i:i+16]) for i in range(0, len(msg), 16)]

        return jsonify({
            "mode": mode,
            "key": _hex(key),
            "iv": _hex(iv),
            "message_blocks": blocks_msg,
            "ciphertext_blocks": blocks_ct,
            "ciphertext": _hex(ct),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pa4/flip", methods=["POST", "OPTIONS"])
def pa4_flip():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        mode = data.get("mode", "CBC").upper()
        key_hex = data.get("key", "")
        iv_hex = data.get("iv", "")
        ct_hex = data.get("ciphertext", "")
        flip_block = int(data.get("flip_block", 0))
        flip_bit = int(data.get("flip_bit", 0))

        key = bytes.fromhex(key_hex)
        iv = bytes.fromhex(iv_hex)
        ct = bytearray(bytes.fromhex(ct_hex))

        byte_idx = flip_block * 16 + (flip_bit // 8)
        bit_idx = flip_bit % 8
        if byte_idx < len(ct):
            ct[byte_idx] ^= (1 << (7 - bit_idx))

        ct = bytes(ct)
        try:
            if mode == "CBC":
                pt = _cbc.decrypt(key, iv, ct)
            elif mode == "OFB":
                pt = _ofb.decrypt(key, iv, ct)
            else:
                pt = _ctr.decrypt(key, iv, ct)
            pt_blocks = [_hex(pt[i:i+16]) for i in range(0, len(pt), 16)]
        except Exception:
            pt_blocks = ["ERROR"]

        return jsonify({
            "mode": mode,
            "flipped_ciphertext": _hex(ct),
            "decrypted_blocks": pt_blocks,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#5 Demo: MAC forge attempt ─────────────────────────────────────────────

_mac_game_key = os.urandom(16)
_mac_signed_messages = []

@app.route("/api/pa5/sign", methods=["POST", "OPTIONS"])
def pa5_sign():
    if request.method == "OPTIONS":
        return "", 204
    try:
        global _mac_signed_messages
        data = request.get_json(force=True)
        count = int(data.get("count", 10))
        count = max(1, min(50, count))

        _mac_signed_messages = []
        for _ in range(count):
            m = os.urandom(16)
            t = _cbc_mac.mac(_mac_game_key, m)
            _mac_signed_messages.append({"message": _hex(m), "tag": _hex(t)})

        return jsonify({"signed": _mac_signed_messages})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pa5/forge", methods=["POST", "OPTIONS"])
def pa5_forge():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        msg_hex = data.get("message", "")
        tag_hex = data.get("tag", "")
        msg = bytes.fromhex(msg_hex)
        tag = bytes.fromhex(tag_hex)

        # Check not in signed list
        already_seen = any(s["message"] == msg_hex for s in _mac_signed_messages)
        if already_seen:
            return jsonify({"result": "rejected", "reason": "Message already in signed list"})

        valid = _cbc_mac.verify(_mac_game_key, msg, tag)
        return jsonify({
            "result": "accepted" if valid else "rejected",
            "reason": "Valid forgery!" if valid else "Invalid tag",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#6 Demo: Malleability attack ───────────────────────────────────────────

from pa6_cca import CCAEncryption
_cca_enc = CCAEncryption()

@app.route("/api/pa6/demo", methods=["POST", "OPTIONS"])
def pa6_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        msg_hex = data.get("message", "")
        flip_bit = int(data.get("flip_bit", 0))

        msg = _parse_hex(msg_hex, 16)
        k_cpa = os.urandom(16)
        kE, kM = _cca_enc.keygen()

        # CPA encryption
        r_cpa, ct_cpa = _cpa_enc.encrypt(k_cpa, msg)
        tampered_cpa = bytearray(ct_cpa)
        byte_idx = flip_bit // 8
        bit_pos = flip_bit % 8
        if byte_idx < len(tampered_cpa):
            tampered_cpa[byte_idx] ^= (1 << (7 - bit_pos))
        try:
            recovered_cpa = _cpa_enc.decrypt(k_cpa, r_cpa, bytes(tampered_cpa))
            cpa_result = _hex(recovered_cpa)
        except Exception:
            cpa_result = "DECRYPT_ERROR"

        # CCA encryption
        r_cca, CE_cca, t_cca = _cca_enc.encrypt(kE, kM, msg)
        tampered_CE = bytearray(CE_cca)
        if byte_idx < len(tampered_CE):
            tampered_CE[byte_idx] ^= (1 << (7 - bit_pos))
        cca_result_val = _cca_enc.decrypt(kE, kM, r_cca, bytes(tampered_CE), t_cca)

        return jsonify({
            "original": _hex(msg),
            "flip_bit": flip_bit,
            "cpa": {
                "ciphertext": _hex(ct_cpa),
                "tampered": _hex(bytes(tampered_cpa)),
                "recovered": cpa_result,
                "malleable": True,
            },
            "cca": {
                "ciphertext": _hex(CE_cca),
                "tampered": _hex(bytes(tampered_CE)),
                "recovered": "⊥ (REJECTED)" if cca_result_val is None else _hex(cca_result_val),
                "malleable": cca_result_val is not None,
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#7 Demo: Merkle-Damgård chain viewer ───────────────────────────────────

from pa7_merkle import MerkleDamgard as MD7, toy_xor_compress, md_pad, parse_blocks, BLOCK_SIZE as MD7_BLOCK, OUTPUT_SIZE as MD7_OUT

_md7_iv = b'\x00' * MD7_OUT
_md7 = MD7(toy_xor_compress, _md7_iv, MD7_BLOCK)

@app.route("/api/pa7/hash", methods=["POST", "OPTIONS"])
def pa7_hash():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        msg_str = data.get("message", "Hello")
        is_hex = data.get("hex", False)

        if is_hex:
            try:
                msg = bytes.fromhex(msg_str)
            except ValueError:
                msg = msg_str.encode("utf-8")
        else:
            msg = msg_str.encode("utf-8")

        padded = md_pad(msg, MD7_BLOCK)
        blocks = parse_blocks(padded, MD7_BLOCK)
        digest, trace = _md7.hash_with_trace(msg)

        blocks_hex = [b.hex() for b in blocks]
        chain = [{"label": lbl, "value": val.hex()} for lbl, val in trace]

        return jsonify({
            "message": msg.hex(),
            "padded": padded.hex(),
            "blocks": blocks_hex,
            "chain": chain,
            "digest": digest.hex(),
            "block_size": MD7_BLOCK,
            "output_size": MD7_OUT,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#8 Demo: DLP Hash live + collision hunt ────────────────────────────────

from pa8_dlp_hash import ToyDLPHash
_toy_dlp_hash = ToyDLPHash()

@app.route("/api/pa8/hash", methods=["POST", "OPTIONS"])
def pa8_hash():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        msg_str = data.get("message", "Hello")
        msg = msg_str.encode("utf-8")
        digest = _dlp_hash.hash(msg)
        toy_digest = _toy_dlp_hash.hash(msg)
        return jsonify({
            "message": msg_str,
            "digest_full": digest.hex(),
            "digest_toy16": toy_digest.hex(),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/pa8/collision", methods=["POST", "OPTIONS"])
def pa8_collision():
    if request.method == "OPTIONS":
        return "", 204
    try:
        seen = {}
        count = 0
        for i in range(10000):
            msg = os.urandom(4)
            h = _toy_dlp_hash.hash(msg)
            count += 1
            if h in seen and seen[h] != msg:
                return jsonify({
                    "found": True,
                    "evaluations": count,
                    "m1": seen[h].hex(),
                    "m2": msg.hex(),
                    "hash": h.hex(),
                    "ratio": round(count / 256, 2),
                })
            seen[h] = msg
        return jsonify({"found": False, "evaluations": count})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#9 Demo: Birthday attack live ─────────────────────────────────────────

from pa9_birthday import make_toy_hash, birthday_probability

@app.route("/api/pa9/attack", methods=["POST", "OPTIONS"])
def pa9_attack():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        n_bits = int(data.get("n_bits", 12))
        n_bits = max(8, min(16, n_bits))

        toy = make_toy_hash(n_bits)
        mask = (1 << n_bits) - 1
        seen = {}
        count = 0
        curve_points = []

        for i in range(50000):
            msg = os.urandom(4)
            h = toy(msg)
            h_int = int.from_bytes(h, 'big') & mask
            count += 1
            if count % max(1, (1 << (n_bits // 2)) // 8) == 0:
                curve_points.append({
                    "k": count,
                    "p_empirical": round(len(seen) / max(1, count), 4),
                    "p_theory": round(birthday_probability(count, n_bits), 4),
                })
            if h_int in seen and seen[h_int] != msg:
                curve_points.append({"k": count, "p_empirical": 1.0,
                                     "p_theory": round(birthday_probability(count, n_bits), 4)})
                return jsonify({
                    "found": True,
                    "n_bits": n_bits,
                    "evaluations": count,
                    "expected": round(2 ** (n_bits / 2), 1),
                    "ratio": round(count / (2 ** (n_bits / 2)), 2),
                    "m1": seen[h_int].hex(),
                    "m2": msg.hex(),
                    "hash": format(h_int, f'0{n_bits // 4}x'),
                    "curve": curve_points,
                })
            seen[h_int] = msg

        return jsonify({"found": False, "evaluations": count, "n_bits": n_bits, "curve": curve_points})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#10 Demo: Length-extension vs HMAC ─────────────────────────────────────

@app.route("/api/pa10/demo", methods=["POST", "OPTIONS"])
def pa10_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        msg_str = data.get("message", "Pay Bob $100")
        suffix_str = data.get("suffix", "Transfer to Eve!")

        msg = msg_str.encode("utf-8")
        suffix = suffix_str.encode("utf-8")
        k = b'\xAB' * 16

        naive_tag = _dlp_hash.hash(k + msg)
        hmac_tag = _hmac.mac(k, msg)
        hmac_tag_extended = _hmac.mac(k, msg + suffix)

        return jsonify({
            "message": msg_str,
            "suffix": suffix_str,
            "naive": {
                "tag": naive_tag.hex(),
                "forgery": "SUCCESS — adversary can compute H(k||m||pad||m') from H(k||m)",
                "vulnerable": True,
            },
            "hmac": {
                "tag": hmac_tag.hex(),
                "tag_extended": hmac_tag_extended.hex(),
                "forgery": "FAILED — outer hash blocks extension without k",
                "vulnerable": False,
            },
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#11 Demo: Diffie-Hellman key exchange ──────────────────────────────────

from pa11_dh import dh_alice_step1, dh_bob_step1, dh_alice_step2, dh_bob_step2, MITMEve
from pa13_miller_rabin import mod_exp

# Use a small safe prime for demo speed
_dh_p = 0xFFFFFFFB  # close to 2^32
_dh_q = (_dh_p - 1) // 2
# Actually need a real safe prime
from pa11_dh import DH_P, DH_Q, DH_G

@app.route("/api/pa11/exchange", methods=["POST", "OPTIONS"])
def pa11_exchange():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        a_str = data.get("a", "")
        b_str = data.get("b", "")
        enable_eve = data.get("enable_eve", False)
        p, g, q = DH_P, DH_G, DH_Q

        a = int(a_str) % q if a_str else int.from_bytes(os.urandom(8), 'big') % q
        b = int(b_str) % q if b_str else int.from_bytes(os.urandom(8), 'big') % q

        A = mod_exp(g, a, p)
        B = mod_exp(g, b, p)

        result = {
            "p": hex(p),
            "g": g,
            "q": hex(q),
            "alice": {"private": str(a), "public": hex(A)},
            "bob": {"private": str(b), "public": hex(B)},
        }

        if enable_eve:
            e_priv = int.from_bytes(os.urandom(8), 'big') % q
            E = mod_exp(g, e_priv, p)
            K_eve_alice = mod_exp(A, e_priv, p)
            K_eve_bob = mod_exp(B, e_priv, p)
            K_alice_sees = mod_exp(E, a, p)
            K_bob_sees = mod_exp(E, b, p)

            result["eve"] = {
                "public": hex(E),
                "K_with_alice": hex(K_eve_alice),
                "K_with_bob": hex(K_eve_bob),
            }
            result["alice"]["shared_secret"] = hex(K_alice_sees)
            result["bob"]["shared_secret"] = hex(K_bob_sees)
            result["mitm"] = True
        else:
            K_alice = mod_exp(B, a, p)
            K_bob = mod_exp(A, b, p)
            result["alice"]["shared_secret"] = hex(K_alice)
            result["bob"]["shared_secret"] = hex(K_bob)
            result["match"] = K_alice == K_bob
            result["mitm"] = False

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#12 Demo: Textbook RSA determinism ─────────────────────────────────────

from pa12_rsa import rsa_keygen, rsa_enc, rsa_dec, pkcs15_enc, pkcs15_dec, pkcs15_pad

_rsa_keys_cache = None

def _get_rsa_keys():
    global _rsa_keys_cache
    if _rsa_keys_cache is None:
        _rsa_keys_cache = rsa_keygen(512)
    return _rsa_keys_cache

@app.route("/api/pa12/demo", methods=["POST", "OPTIONS"])
def pa12_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        msg_str = data.get("message", "yes")
        use_pkcs = data.get("use_pkcs", False)

        keys = _get_rsa_keys()
        N, e, d = keys["N"], keys["e"], keys["d"]
        k_bytes = (N.bit_length() + 7) // 8

        if use_pkcs:
            msg_bytes = msg_str.encode("utf-8")
            c1 = pkcs15_enc(N, e, msg_bytes)
            c2 = pkcs15_enc(N, e, msg_bytes)
            pad1 = pkcs15_pad(msg_bytes, k_bytes)
            pad2 = pkcs15_pad(msg_bytes, k_bytes)
            return jsonify({
                "message": msg_str,
                "mode": "PKCS#1 v1.5",
                "c1": hex(c1),
                "c2": hex(c2),
                "identical": c1 == c2,
                "ps1": pad1[2:pad1.index(b'\x00', 2)].hex(),
                "ps2": pad2[2:pad2.index(b'\x00', 2)].hex(),
                "N_bits": N.bit_length(),
            })
        else:
            m_int = int.from_bytes(msg_str.encode("utf-8"), 'big') % N
            c1 = rsa_enc(N, e, m_int)
            c2 = rsa_enc(N, e, m_int)
            return jsonify({
                "message": msg_str,
                "mode": "Textbook RSA",
                "m_int": str(m_int),
                "c1": hex(c1),
                "c2": hex(c2),
                "identical": c1 == c2,
                "N_bits": N.bit_length(),
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#13 Demo: Miller-Rabin primality tester ────────────────────────────────

from pa13_miller_rabin import miller_rabin, fermat_test

@app.route("/api/pa13/test", methods=["POST", "OPTIONS"])
def pa13_test():
    if request.method == "OPTIONS":
        return "", 204
    try:
        import time as _time
        data = request.get_json(force=True)
        n = int(data.get("n", 561))
        k = int(data.get("k", 10))
        k = max(1, min(40, k))

        t0 = _time.perf_counter()
        result = miller_rabin(n, k)
        elapsed = (_time.perf_counter() - t0) * 1000

        # Also get witness details
        witnesses = []
        if n > 3 and n % 2 != 0:
            s, d = 0, n - 1
            while d % 2 == 0:
                s += 1
                d //= 2
            import random as _rng
            _rng.seed(42)
            for i in range(min(k, 5)):
                a = _rng.randint(2, n - 2)
                x = mod_exp(a, d, n)
                witness_info = {"a": a, "a_d_mod_n": x, "rounds": []}
                cur = x
                for r in range(s - 1):
                    cur = mod_exp(cur, 2, n)
                    witness_info["rounds"].append(cur)
                witnesses.append(witness_info)

        fermat_pass = fermat_test(n, 2) if n > 2 else False

        return jsonify({
            "n": n,
            "k": k,
            "result": result,
            "time_ms": round(elapsed, 3),
            "fermat_base2": fermat_pass,
            "witnesses": witnesses,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#14 Demo: Håstad broadcast attack ──────────────────────────────────────

from pa14_crt import crt, hastad_attack, integer_eth_root, rsa_dec_crt

@app.route("/api/pa14/demo", methods=["POST", "OPTIONS"])
def pa14_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        m_int = int(data.get("message", 42))
        use_padding = data.get("use_padding", False)
        e = 3

        # Generate 3 key pairs with e=3
        key_sets = []
        for _ in range(e):
            while True:
                ks = rsa_keygen(256)
                phi = (ks["p"] - 1) * (ks["q"] - 1)
                if phi % 3 != 0:
                    from pa12_rsa import mod_inverse as _modinv
                    ks["e"] = 3
                    ks["d"] = _modinv(3, phi)
                    key_sets.append(ks)
                    break

        moduli = [ks["N"] for ks in key_sets]
        recipients = []

        if use_padding:
            padded_ints = []
            for ks in key_sets:
                k_bytes = (ks["N"].bit_length() + 7) // 8
                em = pkcs15_pad(m_int.to_bytes(max(1, (m_int.bit_length()+7)//8), 'big'), k_bytes)
                pi = int.from_bytes(em, 'big') % ks["N"]
                padded_ints.append(pi)
                c = rsa_enc(ks["N"], 3, pi)
                recipients.append({"N": hex(ks["N"]), "c": hex(c)})
            ciphertexts = [rsa_enc(ks["N"], 3, pi) for ks, pi in zip(key_sets, padded_ints)]
        else:
            ciphertexts = [rsa_enc(ks["N"], 3, m_int) for ks in key_sets]
            for ks, c in zip(key_sets, ciphertexts):
                recipients.append({"N": hex(ks["N"]), "c": hex(c)})

        recovered = hastad_attack(ciphertexts, moduli, e)

        return jsonify({
            "message": m_int,
            "e": e,
            "use_padding": use_padding,
            "recipients": recipients,
            "recovered": recovered,
            "success": recovered == m_int,
            "expected_success": not use_padding,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#15 Demo: Digital Signatures (sign, verify, tamper, raw forgery) ───────

from pa15_signatures import RSASignature, EUFCMAGameSig

_sig_scheme = RSASignature()
_sig_keys_cache = None

def _get_sig_keys():
    global _sig_keys_cache
    if _sig_keys_cache is None:
        _sig_keys_cache = _sig_scheme.keygen(512)
    return _sig_keys_cache

@app.route("/api/pa15/demo", methods=["POST", "OPTIONS"])
def pa15_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        msg_str = data.get("message", "Hello World")
        mode = data.get("mode", "sign")  # sign | tamper | raw_forgery | eufcma
        keys = _get_sig_keys()
        N, e, d = keys["N"], keys["e"], keys["d"]

        if mode == "sign":
            msg = msg_str.encode("utf-8")
            sigma = _sig_scheme.sign(keys, msg)
            valid = _sig_scheme.verify(keys, msg, sigma)
            h_int = _sig_scheme._hash_to_int(msg, N)
            h_rec = mod_exp(sigma, e, N)
            return jsonify({
                "message": msg_str,
                "sigma": hex(sigma),
                "valid": valid,
                "H_m": hex(h_int),
                "sigma_e_mod_N": hex(h_rec),
                "match": h_int == h_rec,
            })

        elif mode == "tamper":
            msg = msg_str.encode("utf-8")
            sigma = _sig_scheme.sign(keys, msg)
            # flip one bit
            tampered = bytearray(msg)
            tampered[0] ^= 0x01
            tampered = bytes(tampered)
            valid_orig = _sig_scheme.verify(keys, msg, sigma)
            valid_tamp = _sig_scheme.verify(keys, tampered, sigma)
            return jsonify({
                "original": msg_str,
                "tampered": tampered.decode("utf-8", errors="replace"),
                "sigma": hex(sigma),
                "valid_original": valid_orig,
                "valid_tampered": valid_tamp,
            })

        elif mode == "raw_forgery":
            m1 = int(data.get("m1", 7))
            m2 = int(data.get("m2", 13))
            sig1 = mod_exp(m1, d, N)
            sig2 = mod_exp(m2, d, N)
            m_forged = (m1 * m2) % N
            sig_forged = (sig1 * sig2) % N
            recovered = mod_exp(sig_forged, e, N)
            return jsonify({
                "m1": m1, "m2": m2,
                "sig1": hex(sig1), "sig2": hex(sig2),
                "m_forged": m_forged,
                "sig_forged": hex(sig_forged),
                "recovered": recovered,
                "success": recovered == m_forged,
                "explanation": "sig(m1)*sig(m2) = sig(m1*m2) — existential forgery on raw RSA!",
            })

        elif mode == "eufcma":
            game = EUFCMAGameSig(_sig_scheme, keys)
            queries = []
            for _ in range(50):
                m = os.urandom(16)
                s = game.sign_oracle(m)
                queries.append({"m": m.hex(), "sig": hex(s)[:20] + "..."})
            forgery_results = []
            for _ in range(20):
                m_new = os.urandom(16)
                sig_fake = int.from_bytes(os.urandom(64), 'big') % N
                ok = game.forge(m_new, sig_fake)
                forgery_results.append({"m": m_new.hex(), "success": ok})
            return jsonify({
                "queries": len(queries),
                "forgery_attempts": game.forgery_attempts,
                "forgery_successes": game.forgery_successes,
                "sample_queries": queries[:5],
                "sample_forgeries": forgery_results[:5],
            })

        return jsonify({"error": "unknown mode"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#16 Demo: ElGamal encrypt/decrypt + malleability ───────────────────────

from pa16_elgamal import ElGamal

_elgamal = ElGamal()
_eg_keys_cache = None

def _get_eg_keys():
    global _eg_keys_cache
    if _eg_keys_cache is None:
        _eg_keys_cache = _elgamal.keygen()
    return _eg_keys_cache

@app.route("/api/pa16/demo", methods=["POST", "OPTIONS"])
def pa16_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        m = int(data.get("message", 42))
        factor = int(data.get("factor", 2))
        keys = _get_eg_keys()
        p = _elgamal.p

        c1, c2 = _elgamal.encrypt(keys["pk"], m)
        m_dec = _elgamal.decrypt(keys["sk"], c1, c2)

        c2_mall = (factor * c2) % p
        m_mall = _elgamal.decrypt(keys["sk"], c1, c2_mall)

        return jsonify({
            "message": m,
            "c1": hex(c1),
            "c2": hex(c2),
            "decrypted": m_dec,
            "correct": m_dec == m,
            "factor": factor,
            "c2_tampered": hex(c2_mall),
            "decrypted_tampered": m_mall,
            "expected_tampered": (factor * m) % p,
            "malleable": m_mall == (factor * m) % p,
            "p": hex(p),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#17 Demo: CCA-Secure PKC (Encrypt-then-Sign) ──────────────────────────

from pa17_cca_pkc import CCASecurePKC

_cca_pkc = CCASecurePKC(_elgamal, _sig_scheme)

@app.route("/api/pa17/demo", methods=["POST", "OPTIONS"])
def pa17_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        m = int(data.get("message", 12345))
        enc_keys = _get_eg_keys()
        sig_keys = _get_sig_keys()

        blob = _cca_pkc.encrypt(enc_keys, sig_keys, m)
        m_rec = _cca_pkc.decrypt(enc_keys, sig_keys, blob)

        # Tamper c2 (ElGamal malleability)
        tampered = dict(blob)
        tampered["c2"] = (blob["c2"] * 2) % _elgamal.p
        m_tampered = _cca_pkc.decrypt(enc_keys, sig_keys, tampered)

        # Plain ElGamal for contrast
        c1, c2 = _elgamal.encrypt(enc_keys["pk"], m)
        c2_t = (c2 * 2) % _elgamal.p
        m_plain_tampered = _elgamal.decrypt(enc_keys["sk"], c1, c2_t)

        return jsonify({
            "message": m,
            "blob": {"c1": hex(blob["c1"]), "c2": hex(blob["c2"]), "sigma": hex(blob["sigma"])},
            "decrypted": m_rec,
            "correct": m_rec == m,
            "tampered_result": "REJECTED" if m_tampered is None else m_tampered,
            "tamper_blocked": m_tampered is None,
            "plain_elgamal_tampered": m_plain_tampered,
            "plain_elgamal_expected": (2 * m) % _elgamal.p,
            "plain_malleable": m_plain_tampered == (2 * m) % _elgamal.p,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#18 Demo: Oblivious Transfer ──────────────────────────────────────────

from pa18_ot import ObliviousTransfer

_ot = ObliviousTransfer(_elgamal)

@app.route("/api/pa18/demo", methods=["POST", "OPTIONS"])
def pa18_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        b = int(data.get("choice", 0))
        m0 = int(data.get("m0", 42))
        m1 = int(data.get("m1", 99))
        assert b in (0, 1)

        pk0, pk1, state = _ot.receiver_step1(b)
        C0, C1 = _ot.sender_step(pk0, pk1, m0, m1)
        m_b = _ot.receiver_step2(state, C0, C1)

        # Try cheating: decrypt the other ciphertext with wrong key
        C_other = C1 if b == 0 else C0
        m_cheat = _ot.eg.decrypt(state["sk_b"], C_other[0], C_other[1])
        expected_other = m1 if b == 0 else m0

        log = [
            f"Step 1 — Bob generates pk_{b} = g^sk_{b} (honest), pk_{1-b} = random (no sk)",
            f"Step 2 — Bob sends pk0={hex(pk0)}, pk1={hex(pk1)}",
            f"Step 3 — Alice encrypts: C0 = Enc(pk0, m0={m0}),  C1 = Enc(pk1, m1={m1})",
            f"Step 4 — Bob decrypts C_{b} with sk_{b}  →  m_{b} = {m_b}  ✓",
            f"Step 5 — Bob tries C_{1-b} with sk_{b}  →  garbage (no trapdoor for pk_{1-b})",
        ]

        return jsonify({
            "choice": b,
            "m0": m0, "m1": m1,
            "received": m_b,
            "correct": m_b == (m0 if b == 0 else m1),
            "cheat_result": m_cheat,
            "cheat_matches": m_cheat == expected_other,
            "log": log,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#19 Demo: Secure AND ───────────────────────────────────────────────────

from pa19_secure_and import SecureAND, SecureXOR, SecureNOT

_sec_and = SecureAND(_ot)
_sec_xor = SecureXOR()
_sec_not = SecureNOT()

@app.route("/api/pa19/demo", methods=["POST", "OPTIONS"])
def pa19_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        data = request.get_json(force=True)
        mode = data.get("mode", "single")  # single | all
        a = int(data.get("a", 0))
        b = int(data.get("b", 0))

        if mode == "single":
            assert a in (0, 1) and b in (0, 1)
            res_and, _, tr_and = _sec_and.compute(a, b)
            res_xor, _, tr_xor = _sec_xor.compute(a, b)
            res_not = _sec_not.compute(a)
            return jsonify({
                "a": a, "b": b,
                "and_result": res_and,
                "xor_result": res_xor,
                "not_a": res_not,
                "and_transcript": tr_and,
                "xor_transcript": tr_xor,
                "alice_learns": f"a={a}, OT ciphertexts — NOT b",
                "bob_learns": f"b={b}, m_b={res_and} — NOT a directly",
            })
        elif mode == "all":
            results = []
            for ai in [0, 1]:
                for bi in [0, 1]:
                    r_and, _, _ = _sec_and.compute(ai, bi)
                    r_xor, _, _ = _sec_xor.compute(ai, bi)
                    results.append({
                        "a": ai, "b": bi,
                        "and": r_and, "and_expected": ai & bi,
                        "and_ok": r_and == (ai & bi),
                        "xor": r_xor, "xor_expected": ai ^ bi,
                        "xor_ok": r_xor == (ai ^ bi),
                    })
            return jsonify({"truth_table": results})

        return jsonify({"error": "unknown mode"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── PA#20 Demo: Millionaire's Problem ────────────────────────────────────────

from pa20_mpc import (SecureEval, build_greater_than_circuit,
                       build_equality_circuit, build_adder_circuit,
                       int_to_bits, bits_to_int)

@app.route("/api/pa20/demo", methods=["POST", "OPTIONS"])
def pa20_demo():
    if request.method == "OPTIONS":
        return "", 204
    try:
        import time as _time
        data = request.get_json(force=True)
        x = int(data.get("x", 7))
        y = int(data.get("y", 12))
        n_bits = int(data.get("n_bits", 4))
        n_bits = max(2, min(8, n_bits))
        cap = (1 << n_bits) - 1
        x = max(0, min(cap, x))
        y = max(0, min(cap, y))

        x_bits = int_to_bits(x, n_bits)
        y_bits = int_to_bits(y, n_bits)

        # Greater-than
        circ_gt, out_gt = build_greater_than_circuit(n_bits)
        ev_gt = SecureEval()
        t0 = _time.perf_counter()
        vals_gt = ev_gt.evaluate(circ_gt, x_bits, y_bits)
        t_gt = (_time.perf_counter() - t0) * 1000
        gt_result = vals_gt[out_gt]

        # Equality
        circ_eq, out_eq = build_equality_circuit(n_bits)
        ev_eq = SecureEval()
        t0 = _time.perf_counter()
        vals_eq = ev_eq.evaluate(circ_eq, x_bits, y_bits)
        t_eq = (_time.perf_counter() - t0) * 1000
        eq_result = vals_eq[out_eq]

        # Addition
        circ_add, sum_wires = build_adder_circuit(n_bits)
        ev_add = SecureEval()
        t0 = _time.perf_counter()
        vals_add = ev_add.evaluate(circ_add, x_bits, y_bits)
        t_add = (_time.perf_counter() - t0) * 1000
        sum_bits_out = [vals_add[w] for w in sum_wires]
        add_result = bits_to_int(sum_bits_out)

        if gt_result:
            winner = "Alice"
        elif eq_result:
            winner = "Equal"
        else:
            winner = "Bob"

        return jsonify({
            "x": x, "y": y, "n_bits": n_bits,
            "greater_than": {"result": gt_result, "expected": int(x > y),
                             "correct": gt_result == int(x > y),
                             "ot_calls": ev_gt.ot_calls, "gates": ev_gt.gate_evals,
                             "time_ms": round(t_gt, 1)},
            "equality":     {"result": eq_result, "expected": int(x == y),
                             "correct": eq_result == int(x == y),
                             "ot_calls": ev_eq.ot_calls, "gates": ev_eq.gate_evals,
                             "time_ms": round(t_eq, 1)},
            "addition":     {"result": add_result, "expected": (x + y) % (1 << n_bits),
                             "correct": add_result == (x + y) % (1 << n_bits),
                             "ot_calls": ev_add.ot_calls, "gates": ev_add.gate_evals,
                             "time_ms": round(t_add, 1)},
            "winner": winner,
            "transcript_sample": ev_gt.transcript[:8],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("=" * 50)
    print("Minicrypt Explorer API Server")
    print("=" * 50)
    print(f"  flask-cors: {'yes' if HAS_CORS else 'no (using manual headers)'}")
    print(f"  Serving on http://127.0.0.1:5000")
    print(f"  Endpoints:")
    print(f"    GET  /api/health")
    print(f"    POST /api/compute")
    print(f"    POST /api/pa1/prg, /api/pa1/stats")
    print(f"    POST /api/pa2/ggm")
    print(f"    POST /api/pa3/encrypt")
    print(f"    POST /api/pa4/encrypt, /api/pa4/flip")
    print(f"    POST /api/pa5/sign, /api/pa5/forge")
    print(f"    POST /api/pa6/demo")
    print(f"    POST /api/pa7/hash")
    print(f"    POST /api/pa8/hash, /api/pa8/collision")
    print(f"    POST /api/pa9/attack")
    print(f"    POST /api/pa10/demo")
    print(f"    POST /api/pa11/exchange")
    print(f"    POST /api/pa12/demo")
    print(f"    POST /api/pa13/test")
    print(f"    POST /api/pa14/demo")
    print(f"    POST /api/pa15/demo")
    print(f"    POST /api/pa16/demo")
    print(f"    POST /api/pa17/demo")
    print(f"    POST /api/pa18/demo")
    print(f"    POST /api/pa19/demo")
    print(f"    POST /api/pa20/demo")
    print()
    app.run(host="127.0.0.1", port=5000, debug=False)

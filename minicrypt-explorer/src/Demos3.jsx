import { useState } from "react";

const POST = (url, body) =>
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
    .then((r) => r.json());

// ─── PA #15 DEMO: Digital Signatures ────────────────────────────────────────
export function PA15Demo() {
  const [message, setMessage] = useState("Hello World");
  const [mode, setMode] = useState("sign");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = () => {
    setLoading(true);
    setResult(null);
    const body = { message, mode };
    if (mode === "raw_forgery") { body.m1 = 7; body.m2 = 13; }
    POST("/api/pa15/demo", body)
      .then(setResult)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #15 — Digital Signatures</h3>
      <p className="demo-desc">
        RSA hash-then-sign: σ = H(m)<sup>d</sup> mod N. Verify: σ<sup>e</sup> mod N = H(m).
      </p>

      <div className="preset-btns">
        {[["sign","Sign & Verify"],["tamper","Tamper"],["raw_forgery","Raw Forgery"],["eufcma","EUF-CMA Game"]].map(([m,l])=>(
          <button key={m} className={`demo-btn-small ${mode===m?"active":""}`} onClick={()=>setMode(m)}>{l}</button>
        ))}
      </div>

      {(mode === "sign" || mode === "tamper") && (
        <div className="demo-controls">
          <label className="demo-label">Message</label>
          <input type="text" className="demo-input" value={message} onChange={(e)=>setMessage(e.target.value)} />
        </div>
      )}

      <button className="demo-btn" onClick={run} disabled={loading}>{loading ? "Running..." : "Run"}</button>

      {result && mode === "sign" && (
        <div className="sig-result">
          <div className={`rsa-banner ${result.valid ? "good" : "bad"}`}>
            Signature {result.valid ? "VALID" : "INVALID"}
          </div>
          <div className="sig-row"><span>σ = H(m)<sup>d</sup> mod N</span><span className="mono">{result.sigma}</span></div>
          <div className="sig-row"><span>H(m) mod N</span><span className="mono">{result.H_m}</span></div>
          <div className="sig-row"><span>σ<sup>e</sup> mod N</span><span className="mono">{result.sigma_e_mod_N}</span></div>
          <div className="sig-row"><span>Match?</span><span className={result.match?"pass":"fail"}>{result.match?"YES":"NO"}</span></div>
        </div>
      )}

      {result && mode === "tamper" && (
        <div className="malleability-grid">
          <div className="mall-col cca-col">
            <div className="mall-col-header">Original</div>
            <div className="mall-row"><span className="mall-label">Message</span><span className="mall-val">{result.original}</span></div>
            <div className={`mall-verdict ${result.valid_original?"good":"bad"}`}>{result.valid_original?"VALID":"INVALID"}</div>
          </div>
          <div className="mall-col cpa-col">
            <div className="mall-col-header">Tampered (1 bit flipped)</div>
            <div className="mall-row"><span className="mall-label">Message</span><span className="mall-val tampered">{result.tampered}</span></div>
            <div className={`mall-verdict ${result.valid_tampered?"bad":"good"}`}>{result.valid_tampered?"VALID (BROKEN!)":"INVALID (rejected)"}</div>
          </div>
        </div>
      )}

      {result && mode === "raw_forgery" && (
        <div className="sig-result">
          <div className={`rsa-banner ${result.success?"bad":"good"}`}>
            {result.success ? "Forgery SUCCEEDED on raw RSA!" : "Forgery failed"}
          </div>
          <div className="sig-row"><span>m1 = {result.m1}</span><span className="mono">{result.sig1}</span></div>
          <div className="sig-row"><span>m2 = {result.m2}</span><span className="mono">{result.sig2}</span></div>
          <div className="sig-row"><span>m1 × m2 = {result.m_forged}</span><span className="mono">{result.sig_forged}</span></div>
          <div className="sig-explanation">{result.explanation}</div>
          <div className="sig-explanation good-text">Hash-then-sign prevents this: H(m1)*H(m2) ≠ H(m1*m2)</div>
        </div>
      )}

      {result && mode === "eufcma" && (
        <div className="sig-result">
          <div className={`rsa-banner ${result.forgery_successes===0?"good":"bad"}`}>
            Forgeries: {result.forgery_successes} / {result.forgery_attempts} (expected 0)
          </div>
          <div className="sig-row"><span>Signing oracle queries</span><span>{result.queries}</span></div>
          <div className="sig-row"><span>Forgery attempts</span><span>{result.forgery_attempts}</span></div>
          <div className="sig-row"><span>Successes</span><span className={result.forgery_successes===0?"pass":"fail"}>{result.forgery_successes}</span></div>
        </div>
      )}
    </div>
  );
}

// ─── PA #16 DEMO: ElGamal Malleability ──────────────────────────────────────
export function PA16Demo() {
  const [message, setMessage] = useState("42");
  const [factor, setFactor] = useState("2");
  const [result, setResult] = useState(null);
  const [count, setCount] = useState(0);
  const [loading, setLoading] = useState(false);

  const run = () => {
    setLoading(true);
    POST("/api/pa16/demo", { message: parseInt(message) || 42, factor: parseInt(factor) || 2 })
      .then((d) => { setResult(d); if (d.malleable) setCount((c) => c + 1); })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #16 — ElGamal Malleability</h3>
      <p className="demo-desc">
        Encrypt m, multiply c2 by k → Dec gives k·m. ElGamal is CPA-secure but NOT CCA-secure.
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{flex:2}}>
          <label className="demo-label">Plaintext m (integer)</label>
          <input type="text" className="demo-input" value={message} onChange={(e)=>setMessage(e.target.value)} />
        </div>
        <div className="demo-controls" style={{flex:1}}>
          <label className="demo-label">Multiply c2 by k =</label>
          <input type="text" className="demo-input" value={factor} onChange={(e)=>setFactor(e.target.value)} />
        </div>
      </div>

      <button className="demo-btn" onClick={run} disabled={loading}>{loading?"Encrypting...":"Encrypt & Tamper"}</button>

      {result && (
        <div className="eg-result">
          <div className="eg-enc-box">
            <div className="eg-enc-label">Ciphertext (c1, c2)</div>
            <div className="sig-row"><span>c1</span><span className="mono">{result.c1}</span></div>
            <div className="sig-row"><span>c2</span><span className="mono">{result.c2}</span></div>
            <div className="sig-row"><span>Dec(c1,c2)</span><span className="pass">{result.decrypted} {result.correct?"= m":"≠ m"}</span></div>
          </div>
          <div className="eg-mall-box">
            <div className="eg-mall-label">Tampered: (c1, {factor}·c2)</div>
            <div className="sig-row"><span>{factor}·c2</span><span className="mono">{result.c2_tampered}</span></div>
            <div className="sig-row"><span>Dec(c1, {factor}·c2)</span><span className="broken-tag">{result.decrypted_tampered}</span></div>
            <div className="sig-row"><span>Expected {factor}·m</span><span>{result.expected_tampered}</span></div>
            <div className={`mall-verdict ${result.malleable?"bad":"good"}`}>
              {result.malleable ? `Malleable! Dec = ${factor}·m without knowing m or sk` : "Not malleable"}
            </div>
          </div>
          <div className="eg-counter">Malleability confirmed: {count} times in a row (100% expected)</div>
        </div>
      )}
    </div>
  );
}

// ─── PA #17 DEMO: CCA Malleability Blocked ──────────────────────────────────
export function PA17Demo() {
  const [message, setMessage] = useState("12345");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = () => {
    setLoading(true);
    POST("/api/pa17/demo", { message: parseInt(message) || 12345 })
      .then(setResult)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #17 — CCA-Secure PKC (Encrypt-then-Sign)</h3>
      <p className="demo-desc">
        Sign the ciphertext. Tamper c2 → signature invalid → decryption aborted → output ⊥.
        Contrast: plain ElGamal lets the tamper through.
      </p>

      <div className="demo-controls">
        <label className="demo-label">Plaintext m (integer)</label>
        <input type="text" className="demo-input" value={message} onChange={(e)=>setMessage(e.target.value)} />
      </div>

      <button className="demo-btn" onClick={run} disabled={loading}>{loading?"Running...":"Encrypt-then-Sign"}</button>

      {result && (
        <>
          <div className="sig-result" style={{marginBottom:12}}>
            <div className="sig-row"><span>c1 (ElGamal)</span><span className="mono">{result.blob?.c1}</span></div>
            <div className="sig-row"><span>c2 (ElGamal)</span><span className="mono">{result.blob?.c2}</span></div>
            <div className="sig-row"><span>σ (RSA signature over c1‖c2)</span><span className="mono">{result.blob?.sigma}</span></div>
            <div className="sig-row"><span>Decrypted m</span><span className="pass">{result.decrypted} {result.correct ? "= m" : "≠ m"}</span></div>
          </div>

          <div className="malleability-grid">
            <div className="mall-col cca-col">
              <div className="mall-col-header">CCA-Secure (Encrypt-then-Sign)</div>
              <div className="mall-row"><span className="mall-label">Tamper c2 × 2</span><span className="mall-val tampered">Modified ciphertext</span></div>
              <div className="mall-row"><span className="mall-label">Sig check</span><span className="mall-val rejected">INVALID</span></div>
              <div className="mall-row"><span className="mall-label">Dec result</span><span className="mall-val rejected">{result.tampered_result === "REJECTED" ? "⊥ (REJECTED)" : result.tampered_result}</span></div>
              <div className={`mall-verdict ${result.tamper_blocked?"good":"bad"}`}>
                {result.tamper_blocked ? "Tamper BLOCKED — sig fires first" : "Tamper NOT blocked"}
              </div>
            </div>

            <div className="mall-col cpa-col">
              <div className="mall-col-header">Plain ElGamal (malleable)</div>
              <div className="mall-row"><span className="mall-label">Tamper c2 × 2</span><span className="mall-val tampered">No sig — goes through!</span></div>
              <div className="mall-row"><span className="mall-label">Dec result</span><span className="mall-val broken-tag">{result.plain_elgamal_tampered}</span></div>
              <div className="mall-row"><span className="mall-label">Expected 2·m</span><span className="mall-val">{result.plain_elgamal_expected}</span></div>
              <div className={`mall-verdict ${result.plain_malleable?"bad":"good"}`}>
                {result.plain_malleable ? "Malleable — 2·m returned!" : "OK"}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ─── PA #18 DEMO: Oblivious Transfer ───────────────────────────────────────
export function PA18Demo() {
  const [choice, setChoice] = useState(0);
  const [m0, setM0] = useState("42");
  const [m1, setM1] = useState("99");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = () => {
    setLoading(true);
    POST("/api/pa18/demo", { choice, m0: parseInt(m0)||42, m1: parseInt(m1)||99 })
      .then(setResult)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #18 — Oblivious Transfer (1-out-of-2)</h3>
      <p className="demo-desc">
        Alice holds m0, m1. Bob picks b ∈ {"{0,1}"}. Bob learns m_b only. Alice never learns b.
      </p>

      <div className="ot-layout">
        <div className="ot-party ot-alice">
          <div className="dh-party-name">Alice (Sender)</div>
          <div className="demo-controls">
            <label className="demo-label">m0 (hidden from Bob)</label>
            <input type="text" className="demo-input" value={m0} onChange={(e)=>setM0(e.target.value)} />
          </div>
          <div className="demo-controls">
            <label className="demo-label">m1 (hidden from Bob)</label>
            <input type="text" className="demo-input" value={m1} onChange={(e)=>setM1(e.target.value)} />
          </div>
        </div>

        <div className="ot-party ot-bob">
          <div className="dh-party-name">Bob (Receiver)</div>
          <div className="ot-choice-btns">
            <button className={`demo-btn ${choice===0?"active":""}`} onClick={()=>setChoice(0)}>Choose 0</button>
            <button className={`demo-btn ${choice===1?"active":""}`} onClick={()=>setChoice(1)}>Choose 1</button>
          </div>
        </div>
      </div>

      <button className="demo-btn" onClick={run} disabled={loading} style={{marginTop:10}}>
        {loading ? "Running OT..." : "Run OT Protocol"}
      </button>

      {result && (
        <div className="ot-result">
          <div className="ot-log">
            {result.log?.map((l,i) => <div key={i} className="ot-log-line">{l}</div>)}
          </div>
          <div className="ot-outcome">
            <div className="ot-outcome-row">
              <span>m_{result.choice} received:</span>
              <span className="pass">{result.received}</span>
              <span>{result.correct ? "Correct" : "Wrong"}</span>
            </div>
            <div className="ot-outcome-row">
              <span>m_{1-result.choice} (other):</span>
              <span className="ot-hidden">??</span>
              <span>Hidden from Bob</span>
            </div>
          </div>
          <div className="ot-cheat">
            <div className="ot-cheat-header">Cheat Attempt: decrypt C_{1-result.choice} with wrong key</div>
            <div className="ot-cheat-result">
              Got: {result.cheat_result} — {result.cheat_matches
                ? <span className="broken-tag">LEAKED (should not happen)</span>
                : <span className="pass">Garbage (privacy holds)</span>
              }
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── PA #19 DEMO: Secure AND Step-by-Step ───────────────────────────────────
export function PA19Demo() {
  const [a, setA] = useState(1);
  const [b, setB] = useState(1);
  const [result, setResult] = useState(null);
  const [ttResult, setTtResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runSingle = () => {
    setLoading(true);
    POST("/api/pa19/demo", { mode: "single", a, b })
      .then(setResult)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  const runAll = () => {
    setLoading(true);
    POST("/api/pa19/demo", { mode: "all" })
      .then(setTtResult)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #19 — Secure AND Step-by-Step</h3>
      <p className="demo-desc">
        Alice holds a, Bob holds b. OT computes a ∧ b without revealing inputs.
      </p>

      <div className="ot-layout">
        <div className="ot-party ot-alice">
          <div className="dh-party-name">Alice</div>
          <div className="ot-choice-btns">
            <button className={`demo-btn-small ${a===0?"active":""}`} onClick={()=>setA(0)}>a = 0</button>
            <button className={`demo-btn-small ${a===1?"active":""}`} onClick={()=>setA(1)}>a = 1</button>
          </div>
        </div>
        <div className="ot-party ot-bob">
          <div className="dh-party-name">Bob</div>
          <div className="ot-choice-btns">
            <button className={`demo-btn-small ${b===0?"active":""}`} onClick={()=>setB(0)}>b = 0</button>
            <button className={`demo-btn-small ${b===1?"active":""}`} onClick={()=>setB(1)}>b = 1</button>
          </div>
        </div>
      </div>

      <div style={{display:"flex",gap:8,marginTop:10}}>
        <button className="demo-btn" onClick={runSingle} disabled={loading}>Compute AND</button>
        <button className="demo-btn" onClick={runAll} disabled={loading}>Run All 4</button>
      </div>

      {result && (
        <div className="and-result">
          <div className="and-gates">
            <div className="and-gate-box"><span>a ∧ b</span><span className="and-val">{result.and_result}</span></div>
            <div className="and-gate-box"><span>a ⊕ b</span><span className="and-val">{result.xor_result}</span></div>
            <div className="and-gate-box"><span>¬a</span><span className="and-val">{result.not_a}</span></div>
          </div>
          <div className="ot-log">
            <div className="ot-log-line" style={{fontWeight:"bold"}}>AND Transcript:</div>
            {result.and_transcript?.map((l,i)=><div key={i} className="ot-log-line">{l}</div>)}
          </div>
          <div className="and-privacy">
            <div className="and-priv-row"><span>Alice learns:</span><span>{result.alice_learns}</span></div>
            <div className="and-priv-row"><span>Bob learns:</span><span>{result.bob_learns}</span></div>
          </div>
        </div>
      )}

      {ttResult && ttResult.truth_table && (
        <div className="tt-table">
          <div className="tt-header">
            <span>a</span><span>b</span><span>AND</span><span>exp</span><span></span><span>XOR</span><span>exp</span><span></span>
          </div>
          {ttResult.truth_table.map((r,i) => (
            <div key={i} className="tt-row">
              <span>{r.a}</span><span>{r.b}</span>
              <span>{r.and}</span><span>{r.and_expected}</span><span className={r.and_ok?"pass":"fail"}>{r.and_ok?"OK":"FAIL"}</span>
              <span>{r.xor}</span><span>{r.xor_expected}</span><span className={r.xor_ok?"pass":"fail"}>{r.xor_ok?"OK":"FAIL"}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── PA #20 DEMO: Millionaire's Problem Live ────────────────────────────────
export function PA20Demo() {
  const [x, setX] = useState(7);
  const [y, setY] = useState(12);
  const [nBits, setNBits] = useState(4);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const cap = (1 << nBits) - 1;

  const run = () => {
    setLoading(true);
    setResult(null);
    POST("/api/pa20/demo", { x, y, n_bits: nBits })
      .then(setResult)
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #20 — Millionaire's Problem Live</h3>
      <p className="demo-desc">
        Alice holds x, Bob holds y. Secure circuit computes x {">"} y without revealing values.
        Gate-by-gate using PA#19 AND + XOR over PA#18 OT.
      </p>

      <div className="demo-controls">
        <label className="demo-label">Bit width: n = {nBits} (values 0–{cap})</label>
        <input type="range" min="2" max="6" value={nBits} onChange={(e)=>setNBits(Number(e.target.value))} className="demo-slider" />
      </div>

      <div className="ot-layout">
        <div className="ot-party ot-alice">
          <div className="dh-party-name">Alice (wealth hidden)</div>
          <label className="demo-label">x = {x}</label>
          <input type="range" min="0" max={cap} value={x} onChange={(e)=>setX(Number(e.target.value))} className="demo-slider" />
        </div>
        <div className="ot-party ot-bob">
          <div className="dh-party-name">Bob (wealth hidden)</div>
          <label className="demo-label">y = {y}</label>
          <input type="range" min="0" max={cap} value={y} onChange={(e)=>setY(Number(e.target.value))} className="demo-slider" />
        </div>
      </div>

      <button className="demo-btn" onClick={run} disabled={loading} style={{marginTop:10}}>
        {loading ? "Computing securely..." : "Who is Richer?"}
      </button>

      {result && (
        <div className="mpc-result">
          <div className={`mpc-winner ${result.winner === "Equal" ? "" : result.winner === "Alice" ? "alice-wins" : "bob-wins"}`}>
            {result.winner === "Equal" ? "Equal — same wealth!" : `${result.winner} is richer!`}
          </div>

          <div className="mpc-circuits">
            {[
              ["x > y", result.greater_than],
              ["x == y", result.equality],
              [`x + y mod ${1<<nBits}`, result.addition],
            ].map(([label, d]) => (
              <div key={label} className="mpc-circuit-box">
                <div className="mpc-circuit-label">{label}</div>
                <div className="mpc-circuit-val">{d.result}</div>
                <div className={`mpc-circuit-check ${d.correct?"pass":"fail"}`}>
                  {d.correct ? "Correct" : `Expected ${d.expected}`}
                </div>
                <div className="mpc-circuit-stats">
                  {d.gates} gates | {d.ot_calls} OT calls | {d.time_ms}ms
                </div>
              </div>
            ))}
          </div>

          {result.transcript_sample?.length > 0 && (
            <details className="mpc-trace">
              <summary>Circuit trace (first {result.transcript_sample.length} gates)</summary>
              <div className="ot-log">
                {result.transcript_sample.map((l,i) => <div key={i} className="ot-log-line">{l}</div>)}
              </div>
            </details>
          )}

          <div className="mpc-privacy-note">
            Neither panel reveals x={result.x} or y={result.y} to the other party.
            Only the comparison result is shared.
          </div>
        </div>
      )}
    </div>
  );
}

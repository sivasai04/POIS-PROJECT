import { useState, useEffect, useRef } from "react";

// ─── PA #7 DEMO: Merkle-Damgård Chain Viewer ────────────────────────────────
export function PA7Demo() {
  const [message, setMessage] = useState("Hello World!");
  const [isHex, setIsHex] = useState(false);
  const [result, setResult] = useState(null);
  const debounce = useRef(null);

  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current);
    debounce.current = setTimeout(() => {
      fetch("/api/pa7/hash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, hex: isHex }),
      })
        .then((r) => r.json())
        .then((d) => { if (!d.error) setResult(d); })
        .catch(() => {});
    }, 250);
  }, [message, isHex]);

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #7 — Merkle-Damgård Chain Viewer</h3>
      <p className="demo-desc">
        Toy XOR-based compression (block=8B, output=4B). Edit the message to see the
        chain recompute with avalanche effect.
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 3 }}>
          <label className="demo-label">Message ({isHex ? "hex" : "text"})</label>
          <input
            type="text"
            className="demo-input"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </div>
        <div className="demo-controls" style={{ flex: 1, justifyContent: "flex-end" }}>
          <label className="demo-toggle-label">
            <input type="checkbox" checked={isHex} onChange={(e) => setIsHex(e.target.checked)} />
            <span>Hex input</span>
          </label>
        </div>
      </div>

      {result && (
        <>
          <div className="md-blocks-row">
            <div className="md-blocks-label">Padded Blocks</div>
            {result.blocks?.map((b, i) => (
              <div key={i} className="md-block">
                <div className="md-block-idx">M{i + 1}</div>
                <div className="md-block-val">{b}</div>
              </div>
            ))}
          </div>

          <div className="md-chain">
            {result.chain?.map((step, i) => (
              <div key={i} className="md-chain-step">
                <div className="md-chain-node">
                  <div className="md-chain-label">{step.label}</div>
                  <div className="md-chain-val">{step.value}</div>
                </div>
                {i < result.chain.length - 1 && (
                  <div className="md-chain-arrow">
                    <span>h(z{i}, M{i + 1})</span>
                    <span className="arrow-symbol">→</span>
                  </div>
                )}
              </div>
            ))}
          </div>

          <div className="demo-output-box highlight">
            <div className="demo-output-label">H(M) = final digest</div>
            <div className="demo-output-hex">{result.digest}</div>
          </div>
        </>
      )}
    </div>
  );
}

// ─── PA #8 DEMO: DLP Hash Live + Collision Hunt ─────────────────────────────
export function PA8Demo() {
  const [message, setMessage] = useState("Hello");
  const [hashResult, setHashResult] = useState(null);
  const [collision, setCollision] = useState(null);
  const [hunting, setHunting] = useState(false);
  const debounce = useRef(null);

  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current);
    debounce.current = setTimeout(() => {
      fetch("/api/pa8/hash", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message }),
      })
        .then((r) => r.json())
        .then((d) => setHashResult(d))
        .catch(() => {});
    }, 300);
  }, [message]);

  const huntCollision = () => {
    setHunting(true);
    setCollision(null);
    fetch("/api/pa8/collision", { method: "POST" })
      .then((r) => r.json())
      .then((d) => setCollision(d))
      .catch(() => {})
      .finally(() => setHunting(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #8 — DLP Hash Live</h3>
      <p className="demo-desc">
        h(x,y) = g^x * ĥ^y mod p plugged into Merkle-Damgård. Full hash + toy 16-bit variant.
      </p>

      <div className="demo-controls">
        <label className="demo-label">Message</label>
        <input
          type="text"
          className="demo-input"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
        />
      </div>

      {hashResult && (
        <div className="demo-hash-results">
          <div className="demo-output-box">
            <div className="demo-output-label">Full DLP Hash (128-bit)</div>
            <div className="demo-output-hex">{hashResult.digest_full}</div>
          </div>
          <div className="demo-output-box">
            <div className="demo-output-label">Toy DLP Hash (16-bit)</div>
            <div className="demo-output-hex">{hashResult.digest_toy16}</div>
          </div>
        </div>
      )}

      <button className="demo-btn" onClick={huntCollision} disabled={hunting}>
        {hunting ? "Hunting..." : "Collision Hunt (16-bit)"}
      </button>

      {collision && collision.found && (
        <div className="collision-result">
          <div className="collision-header">
            Collision found after {collision.evaluations} evaluations
            (expected ~256, ratio: {collision.ratio}x)
          </div>
          <div className="collision-bar-container">
            <div className="collision-bar">
              <div
                className="collision-bar-fill"
                style={{ width: `${Math.min(100, (collision.evaluations / 256) * 100)}%` }}
              />
              <div className="collision-bar-marker" style={{ left: "100%" }} />
            </div>
            <span className="collision-bar-legend">2^(n/2) = 256</span>
          </div>
          <div className="demo-test-row">
            <span className="pass">m1</span>
            <span>{collision.m1}</span>
            <span></span>
          </div>
          <div className="demo-test-row">
            <span className="pass">m2</span>
            <span>{collision.m2}</span>
            <span></span>
          </div>
          <div className="demo-test-row">
            <span className="pass">H</span>
            <span>{collision.hash}</span>
            <span>H(m1) = H(m2)</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── PA #9 DEMO: Live Birthday Attack ───────────────────────────────────────
export function PA9Demo() {
  const [nBits, setNBits] = useState(12);
  const [result, setResult] = useState(null);
  const [running, setRunning] = useState(false);

  const runAttack = () => {
    setRunning(true);
    setResult(null);
    fetch("/api/pa9/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n_bits: nBits }),
    })
      .then((r) => r.json())
      .then((d) => setResult(d))
      .catch(() => {})
      .finally(() => setRunning(false));
  };

  const expected = Math.pow(2, nBits / 2);

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #9 — Live Birthday Attack</h3>
      <p className="demo-desc">
        Pick output bit-length, run the attack, see collision found near 2^(n/2).
      </p>

      <div className="demo-controls">
        <label className="demo-label">
          Output bits: <strong>n = {nBits}</strong> (2^(n/2) = {expected})
        </label>
        <input
          type="range"
          min="8"
          max="16"
          step="2"
          value={nBits}
          onChange={(e) => setNBits(Number(e.target.value))}
          className="demo-slider"
        />
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.58rem", color: "var(--text-dim)" }}>
          <span>8</span><span>10</span><span>12</span><span>14</span><span>16</span>
        </div>
      </div>

      <button className="demo-btn" onClick={runAttack} disabled={running}>
        {running ? "Running attack..." : "Run Attack"}
      </button>

      {result && result.found && (
        <>
          <div className="collision-result">
            <div className="collision-header">
              Collision found after {result.evaluations} hashes
              (expected ~{result.expected}, ratio: {result.ratio}x)
            </div>
            <div className="demo-test-row">
              <span className="pass">m1</span><span>{result.m1}</span><span></span>
            </div>
            <div className="demo-test-row">
              <span className="pass">m2</span><span>{result.m2}</span><span></span>
            </div>
            <div className="demo-test-row">
              <span className="pass">H</span><span>{result.hash}</span><span>H(m1) = H(m2)</span>
            </div>
          </div>

          {result.curve && result.curve.length > 0 && (
            <div className="birthday-chart">
              <div className="birthday-chart-header">Hashes Computed vs Collision Probability</div>
              <div className="birthday-chart-body">
                {result.curve.map((pt, i) => (
                  <div key={i} className="birthday-chart-row">
                    <span className="bc-k">k={pt.k}</span>
                    <div className="bc-bars">
                      <div className="bc-bar theory" style={{ width: `${pt.p_theory * 100}%` }} />
                      <div className="bc-bar empirical" style={{ width: `${Math.min(1, pt.p_empirical) * 100}%` }} />
                    </div>
                    <span className="bc-val">{pt.p_theory.toFixed(2)}</span>
                  </div>
                ))}
                <div className="bc-legend">
                  <span className="bc-dot theory" /> Theory (1-e^(-k²/2^n))
                  <span className="bc-dot empirical" /> Empirical
                </div>
              </div>
              <div className="birthday-marker">
                Expected collision: 2^(n/2) = {expected}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ─── PA #10 DEMO: Length-Extension vs HMAC ──────────────────────────────────
export function PA10Demo() {
  const [message, setMessage] = useState("Pay Bob $100");
  const [suffix, setSuffix] = useState("Transfer to Eve!");
  const [result, setResult] = useState(null);

  const runDemo = () => {
    fetch("/api/pa10/demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, suffix }),
    })
      .then((r) => r.json())
      .then((d) => setResult(d))
      .catch(() => {});
  };

  useEffect(() => { runDemo(); }, [message, suffix]);

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #10 — Length-Extension vs HMAC</h3>
      <p className="demo-desc">
        Left: naive H(k||m) broken by length extension. Right: HMAC blocks it.
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Original message m</label>
          <input type="text" className="demo-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Suffix m' (attacker appends)</label>
          <input type="text" className="demo-input" value={suffix} onChange={(e) => setSuffix(e.target.value)} />
        </div>
      </div>

      {result && (
        <div className="malleability-grid">
          <div className="mall-col cpa-col">
            <div className="mall-col-header">Naive: H(k || m)</div>
            <div className="mall-row">
              <span className="mall-label">Tag t = H(k||m)</span>
              <span className="mall-val mono-val">{result.naive?.tag}</span>
            </div>
            <div className="mall-row">
              <span className="mall-label">Forgery for m||pad||m'</span>
              <span className="mall-val tampered">{result.naive?.forgery}</span>
            </div>
            <div className="mall-verdict bad">Forgery SUCCEEDED</div>
          </div>

          <div className="mall-col cca-col">
            <div className="mall-col-header">HMAC_k(m)</div>
            <div className="mall-row">
              <span className="mall-label">HMAC tag</span>
              <span className="mall-val mono-val">{result.hmac?.tag}</span>
            </div>
            <div className="mall-row">
              <span className="mall-label">Forgery attempt</span>
              <span className="mall-val rejected">{result.hmac?.forgery}</span>
            </div>
            <div className="mall-verdict good">Forgery FAILED</div>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── PA #11 DEMO: Live Diffie-Hellman Exchange ──────────────────────────────
export function PA11Demo() {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const [enableEve, setEnableEve] = useState(false);
  const [result, setResult] = useState(null);

  const exchange = () => {
    fetch("/api/pa11/exchange", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a, b, enable_eve: enableEve }),
    })
      .then((r) => r.json())
      .then((d) => setResult(d))
      .catch(() => {});
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #11 — Live Diffie-Hellman Exchange</h3>
      <p className="demo-desc">
        Two panels: Alice and Bob. Click Exchange to see g^a, g^b, and shared secret K = g^(ab).
        Enable Eve for MITM attack.
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Alice's private a (or leave blank for random)</label>
          <input type="text" className="demo-input" value={a} onChange={(e) => setA(e.target.value)} placeholder="integer" />
        </div>
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Bob's private b (or leave blank for random)</label>
          <input type="text" className="demo-input" value={b} onChange={(e) => setB(e.target.value)} placeholder="integer" />
        </div>
      </div>

      <div className="demo-toggle-row">
        <label className="demo-toggle-label">
          <input type="checkbox" checked={enableEve} onChange={(e) => setEnableEve(e.target.checked)} />
          <span className={enableEve ? "broken-tag" : ""}>
            {enableEve ? "MITM: Eve enabled" : "Enable Eve (MITM)"}
          </span>
        </label>
      </div>

      <button className="demo-btn" onClick={exchange}>Exchange</button>

      {result && (
        <div className="dh-panels">
          <div className={`dh-party ${enableEve ? "compromised" : "secure"}`}>
            <div className="dh-party-name">Alice</div>
            <div className="dh-field"><span>Private a:</span><span className="mono-val">{result.alice?.private}</span></div>
            <div className="dh-field"><span>Public g^a:</span><span className="mono-val">{result.alice?.public}</span></div>
            <div className="dh-field shared">
              <span>Shared K:</span>
              <span className={`mono-val ${result.match || enableEve ? "" : "broken-tag"}`}>
                {result.alice?.shared_secret}
              </span>
            </div>
          </div>

          {enableEve && result.eve && (
            <div className="dh-party eve-party">
              <div className="dh-party-name">Eve (MITM)</div>
              <div className="dh-field"><span>Public g^e:</span><span className="mono-val">{result.eve?.public}</span></div>
              <div className="dh-field"><span>K with Alice:</span><span className="mono-val">{result.eve?.K_with_alice}</span></div>
              <div className="dh-field"><span>K with Bob:</span><span className="mono-val">{result.eve?.K_with_bob}</span></div>
              <div className="mall-verdict bad">Eve reads ALL traffic!</div>
            </div>
          )}

          <div className={`dh-party ${enableEve ? "compromised" : "secure"}`}>
            <div className="dh-party-name">Bob</div>
            <div className="dh-field"><span>Private b:</span><span className="mono-val">{result.bob?.private}</span></div>
            <div className="dh-field"><span>Public g^b:</span><span className="mono-val">{result.bob?.public}</span></div>
            <div className="dh-field shared">
              <span>Shared K:</span>
              <span className={`mono-val ${result.match || enableEve ? "" : "broken-tag"}`}>
                {result.bob?.shared_secret}
              </span>
            </div>
          </div>

          {!enableEve && result.match !== undefined && (
            <div className={`dh-match ${result.match ? "good" : "bad"}`}>
              K_Alice = K_Bob: {result.match ? "MATCH" : "MISMATCH"}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── PA #12 DEMO: Textbook RSA Determinism Attack ───────────────────────────
export function PA12Demo() {
  const [message, setMessage] = useState("yes");
  const [usePkcs, setUsePkcs] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const encrypt = () => {
    setLoading(true);
    fetch("/api/pa12/demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, use_pkcs: usePkcs }),
    })
      .then((r) => r.json())
      .then((d) => setResult(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #12 — Textbook RSA Determinism Attack</h3>
      <p className="demo-desc">
        Encrypt the same message twice. Textbook RSA: identical ciphertexts (leaks info).
        PKCS#1 v1.5: different ciphertexts (random padding).
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 2 }}>
          <label className="demo-label">Message (e.g. "yes" or "no" — simulating a vote)</label>
          <input type="text" className="demo-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
      </div>

      <div className="demo-toggle-row">
        <label className="demo-toggle-label">
          <input type="checkbox" checked={usePkcs} onChange={(e) => setUsePkcs(e.target.checked)} />
          <span className={usePkcs ? "" : "broken-tag"}>
            {usePkcs ? "PKCS#1 v1.5 mode (secure)" : "Textbook RSA (deterministic)"}
          </span>
        </label>
      </div>

      <button className="demo-btn" onClick={encrypt} disabled={loading}>
        {loading ? "Encrypting..." : "Encrypt Twice"}
      </button>

      {result && (
        <div className="rsa-result">
          <div className={`rsa-banner ${result.identical ? "bad" : "good"}`}>
            {result.identical
              ? "IDENTICAL ciphertexts: plaintext leaked!"
              : "DIFFERENT ciphertexts: plaintext protected"}
          </div>
          <div className="rsa-ct-box">
            <div className="rsa-ct-label">C1</div>
            <div className="rsa-ct-val mono-val">{result.c1}</div>
          </div>
          <div className="rsa-ct-box">
            <div className="rsa-ct-label">C2</div>
            <div className="rsa-ct-val mono-val">{result.c2}</div>
          </div>
          {result.ps1 && (
            <div className="rsa-padding-panel">
              <div className="rsa-padding-header">Random Padding Bytes (PS)</div>
              <div className="demo-test-row">
                <span className="pass">PS1</span><span className="mono-val">{result.ps1}</span><span></span>
              </div>
              <div className="demo-test-row">
                <span className="pass">PS2</span><span className="mono-val">{result.ps2}</span><span></span>
              </div>
            </div>
          )}
          <div className="rsa-info">
            Mode: {result.mode} | N: {result.N_bits}-bit
          </div>
        </div>
      )}
    </div>
  );
}

// ─── PA #13 DEMO: Miller-Rabin Primality Tester ─────────────────────────────
export function PA13Demo() {
  const [n, setN] = useState("561");
  const [k, setK] = useState(10);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const presets = [
    { label: "561 (Carmichael)", value: "561" },
    { label: "104729 (prime)", value: "104729" },
    { label: "1000000007 (prime)", value: "1000000007" },
    { label: "1000000006 (composite)", value: "1000000006" },
  ];

  const test = () => {
    setLoading(true);
    fetch("/api/pa13/test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ n: parseInt(n), k }),
    })
      .then((r) => r.json())
      .then((d) => setResult(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #13 — Miller-Rabin Primality Tester</h3>
      <p className="demo-desc">
        Enter any integer. Miller-Rabin with k rounds. Shows witnesses and Fermat comparison.
      </p>

      <div className="preset-btns">
        {presets.map((p) => (
          <button key={p.value} className="demo-btn-small" onClick={() => setN(p.value)}>
            {p.label}
          </button>
        ))}
      </div>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 2 }}>
          <label className="demo-label">Number to test</label>
          <input type="text" className="demo-input" value={n} onChange={(e) => setN(e.target.value)} />
        </div>
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Rounds k = {k}</label>
          <input type="range" min="1" max="40" value={k} onChange={(e) => setK(Number(e.target.value))} className="demo-slider" />
        </div>
      </div>

      <button className="demo-btn" onClick={test} disabled={loading}>
        {loading ? "Testing..." : "Test"}
      </button>

      {result && (
        <div className="mr-result">
          <div className={`rsa-banner ${result.result === "PROBABLY_PRIME" ? "good" : "bad"}`}>
            {result.result} ({result.time_ms}ms, {result.k} rounds)
          </div>
          <div className="mr-fermat">
            Fermat test (base 2): {result.fermat_base2 ? "PASS (says prime)" : "FAIL"}
            {result.n === 561 && result.fermat_base2 && (
              <span className="broken-tag"> — Fermat FOOLED by Carmichael number!</span>
            )}
          </div>
          {result.witnesses?.length > 0 && (
            <div className="mr-witnesses">
              <div className="mr-witnesses-header">Witnesses (first {result.witnesses.length})</div>
              {result.witnesses.map((w, i) => (
                <div key={i} className="mr-witness-row">
                  <span>a={w.a}</span>
                  <span>a^d mod n = {w.a_d_mod_n}</span>
                  {w.rounds.length > 0 && (
                    <span className="mr-rounds">
                      squares: [{w.rounds.slice(0, 3).join(", ")}{w.rounds.length > 3 ? "..." : ""}]
                    </span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── PA #14 DEMO: Håstad Broadcast Attack ───────────────────────────────────
export function PA14Demo() {
  const [message, setMessage] = useState("42");
  const [usePadding, setUsePadding] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runAttack = () => {
    setLoading(true);
    setResult(null);
    fetch("/api/pa14/demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: parseInt(message) || 42, use_padding: usePadding }),
    })
      .then((r) => r.json())
      .then((d) => setResult(d))
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #14 — Håstad Broadcast Attack Visualiser</h3>
      <p className="demo-desc">
        Same message m encrypted to 3 recipients with e=3. CRT recovers m³, cube root reveals m.
        PKCS padding defeats the attack.
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 2 }}>
          <label className="demo-label">Secret message m (integer)</label>
          <input type="text" className="demo-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
      </div>

      <div className="demo-toggle-row">
        <label className="demo-toggle-label">
          <input type="checkbox" checked={usePadding} onChange={(e) => setUsePadding(e.target.checked)} />
          <span className={usePadding ? "" : "broken-tag"}>
            {usePadding ? "PKCS#1 v1.5 padding (attack fails)" : "No padding (textbook RSA)"}
          </span>
        </label>
      </div>

      <button className="demo-btn" onClick={runAttack} disabled={loading}>
        {loading ? "Running..." : "Run Attack"}
      </button>

      {result && (
        <div className="hastad-result">
          <div className="hastad-recipients">
            {result.recipients?.map((r, i) => (
              <div key={i} className="hastad-recipient">
                <div className="hastad-recipient-header">Recipient {i + 1}</div>
                <div className="hastad-field"><span>N{i + 1}:</span><span className="mono-val">{r.N}</span></div>
                <div className="hastad-field"><span>c{i + 1} = m³ mod N{i + 1}:</span><span className="mono-val">{r.c}</span></div>
              </div>
            ))}
          </div>

          <div className="hastad-attacker">
            <div className="hastad-attacker-header">Attacker Panel</div>
            <div className="hastad-field">
              <span>CRT recovers m³ mod (N1·N2·N3)</span>
              <span></span>
            </div>
            <div className="hastad-field">
              <span>Cube root:</span>
              <span>{result.recovered !== null ? result.recovered : "NOT an integer — attack FAILED"}</span>
            </div>
            <div className={`rsa-banner ${result.success ? "bad" : "good"}`}>
              {result.success
                ? `Plaintext recovered: m = ${result.recovered} (matches original ${result.message})`
                : "Attack FAILED — PKCS padding randomizes each ciphertext"}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

import { useState, useEffect, useRef } from "react";

// ─── PA #1 DEMO: OWF + PRG (both directions) ────────────────────────────────
export function PA1Demo() {
  const [tab, setTab] = useState("owf");
  const [mode, setMode] = useState("aes");
  const [seed, setSeed] = useState("a3f291bc7e40d528a3f291bc7e40d528");
  const [length, setLength] = useState(16);

  const [owfResult, setOwfResult]         = useState(null);
  const [hardnessResult, setHardnessResult] = useState(null);
  const [hardnessLoading, setHardnessLoading] = useState(false);

  const [prgOutput, setPrgOutput]   = useState("");
  const [hillResult, setHillResult] = useState(null);

  const [backwardResult, setBackwardResult]   = useState(null);
  const [backwardLoading, setBackwardLoading] = useState(false);

  const [stats, setStats]           = useState(null);
  const [statsLoading, setStatsLoading] = useState(false);

  const db = useRef(null);

  // OWF live eval (always)
  useEffect(() => {
    if (db.current) clearTimeout(db.current);
    db.current = setTimeout(() => {
      fetch("/api/pa1/owf", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode, input: seed }),
      }).then(r => r.json()).then(d => setOwfResult(d)).catch(() => {});
    }, 250);
  }, [mode, seed]);

  // FastPRG live (forward tab)
  useEffect(() => {
    if (tab !== "forward") return;
    if (db.current) clearTimeout(db.current);
    db.current = setTimeout(() => {
      fetch("/api/pa1/prg", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ seed, length }),
      }).then(r => r.json()).then(d => { if (d.output) setPrgOutput(d.output); }).catch(() => {});
    }, 200);
  }, [seed, length, tab]);

  // HILL PRG live (forward tab)
  useEffect(() => {
    if (tab !== "forward") return;
    if (db.current) clearTimeout(db.current);
    db.current = setTimeout(() => {
      fetch("/api/pa1/prg_hill", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ seed, mode, length: Math.min(length, 16) }),
      }).then(r => r.json()).then(d => setHillResult(d)).catch(() => {});
    }, 300);
  }, [seed, mode, length, tab]);

  const runHardness = () => {
    setHardnessLoading(true);
    fetch("/api/pa1/owf_hardness", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode }),
    }).then(r => r.json()).then(d => setHardnessResult(d)).catch(() => {})
      .finally(() => setHardnessLoading(false));
  };

  const runBackward = () => {
    setBackwardLoading(true);
    fetch("/api/pa1/prg_backward", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ seed }),
    }).then(r => r.json()).then(d => setBackwardResult(d)).catch(() => {})
      .finally(() => setBackwardLoading(false));
  };

  const runStats = () => {
    setStatsLoading(true);
    fetch("/api/pa1/stats", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ seed }),
    }).then(r => r.json()).then(d => setStats(d)).catch(() => {})
      .finally(() => setStatsLoading(false));
  };

  const TABS = [
    { id: "owf",      label: "OWF" },
    { id: "forward",  label: "OWF → PRG" },
    { id: "backward", label: "PRG → OWF" },
    { id: "stats",    label: "NIST Tests" },
  ];

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #1 — One-Way Functions & PRG</h3>
      <p className="demo-desc">
        Both directions: <strong>OWF ⇒ PRG</strong> (HILL hard-core bit construction) and{" "}
        <strong>PRG ⇒ OWF</strong> (backward reduction). Concrete instantiations: AES-128
        (Davies-Meyer) and DLP (g^x mod p, safe prime).
      </p>

      {/* Mode toggle */}
      <div className="demo-mode-toggle">
        {["aes", "dlp"].map(m => (
          <button key={m} className={`demo-mode-btn ${mode === m ? "active" : ""}`}
            onClick={() => setMode(m)}>
            {m === "aes" ? "AES-128 (Davies-Meyer)" : "DLP  (g\u02e3 mod p)"}
          </button>
        ))}
      </div>

      {/* Shared seed */}
      <div className="demo-controls">
        <label className="demo-label">Seed / Input key (hex, 16 bytes)</label>
        <input type="text" className="demo-input" value={seed}
          onChange={e => setSeed(e.target.value)} placeholder="32 hex chars" />
      </div>

      {/* Tabs */}
      <div className="demo-tabs">
        {TABS.map(t => (
          <button key={t.id} className={`demo-tab ${tab === t.id ? "active" : ""}`}
            onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {/* ── OWF TAB ── */}
      {tab === "owf" && (
        <div className="demo-tab-content">
          {owfResult && !owfResult.error && (
            <>
              <div className="demo-formula-box">
                <span className="demo-formula-label">Function</span>
                <span className="demo-formula">{owfResult.fn}</span>
              </div>
              <div className="demo-io-grid">
                <div className="demo-io-row">
                  <span className="demo-io-label">input</span>
                  <span className="demo-io-val mono-val">{owfResult.input}</span>
                </div>
                <div className="demo-io-row">
                  <span className="demo-io-label">f(x)</span>
                  <span className="demo-io-val mono-val">{owfResult.output}</span>
                </div>
              </div>
            </>
          )}
          <button className="demo-btn" onClick={runHardness} disabled={hardnessLoading}>
            {hardnessLoading ? "Running..." : "verify_hardness() — Run Inversion Attack"}
          </button>
          {hardnessResult && (
            <div className="demo-result-box">
              <div className="demo-result-title">Inversion Attack Result</div>
              <div className="demo-io-row">
                <span className="demo-io-label">attempts</span>
                <span className="demo-io-val">
                  {(hardnessResult.brute_force_range ?? hardnessResult.random_guesses)?.toLocaleString()}
                </span>
              </div>
              <div className="demo-io-row">
                <span className="demo-io-label">successes</span>
                <span className={`demo-io-val ${hardnessResult.passed ? "pass" : "fail"}`}>
                  {hardnessResult.successes} — {hardnessResult.passed ? "✓ OWF holds" : "✗ Inverted!"}
                </span>
              </div>
              {hardnessResult.example && (
                <>
                  <div className="demo-io-row">
                    <span className="demo-io-label">input x</span>
                    <span className="demo-io-val mono-val">
                      {hardnessResult.example.k ?? hardnessResult.example.x}
                    </span>
                  </div>
                  <div className="demo-io-row">
                    <span className="demo-io-label">f(x)</span>
                    <span className="demo-io-val mono-val">
                      {hardnessResult.example.fk ?? hardnessResult.example.fx}
                    </span>
                  </div>
                </>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── FORWARD TAB ── */}
      {tab === "forward" && (
        <div className="demo-tab-content">
          <div className="demo-controls">
            <label className="demo-label">
              Output length: <strong>{length} bytes</strong> ({length * 8} bits)
            </label>
            <input type="range" min="4" max="64" value={length}
              onChange={e => setLength(Number(e.target.value))} className="demo-slider" />
          </div>

          <div className="demo-section-label">FastPRG — AES-CTR: G(s) = AES_s(0) ‖ AES_s(1) ‖ …</div>
          <div className="demo-output-box">
            <div className="demo-output-label">G(s)  [{length}B / {length * 8} bits]</div>
            <div className="demo-output-hex">{prgOutput || "..."}</div>
          </div>

          <div className="demo-section-label" style={{ marginTop: 10 }}>
            HILL PRG — {mode === "dlp" ? "DLP OWF" : "AES OWF"}: G(s) = b(x₀) ‖ b(x₁) ‖ …
          </div>
          {hillResult && !hillResult.error ? (
            <>
              <div className="demo-formula-box">
                <span className="demo-formula-label">Function</span>
                <span className="demo-formula">{hillResult.fn}</span>
              </div>
              <div className="demo-output-box">
                <div className="demo-output-label">G(s) HILL [{hillResult.length_bytes}B]</div>
                <div className="demo-output-hex">{hillResult.output || "..."}</div>
              </div>
              {hillResult.chain?.length > 0 && (
                <div className="demo-chain-box">
                  <div className="demo-chain-header">Iterative hard-core bit extraction (first 6 steps)</div>
                  {hillResult.chain.map((s, i) => (
                    <div key={i} className="demo-chain-step">
                      <span className="demo-chain-idx">x{s.step}</span>
                      <span className="demo-chain-state">{s.state}</span>
                      <span className="demo-chain-bit">b = {s.bit}</span>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : <div className="demo-output-hex" style={{ color: "var(--text-dim)", fontSize: "0.65rem" }}>...</div>}
        </div>
      )}

      {/* ── BACKWARD TAB ── */}
      {tab === "backward" && (
        <div className="demo-tab-content">
          <div className="demo-result-box" style={{ marginBottom: 12 }}>
            <div className="demo-result-title">Reduction Argument (PRG ⇒ OWF)</div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-dim)", lineHeight: 1.75 }}>
              Define <strong style={{ color: "var(--accent)" }}>f(s) = G(s)</strong>.{" "}
              If adversary A inverts f — given G(s), finds s′ with G(s′) = G(s) — then A
              distinguishes G(s) from uniform random (by testing whether A's output maps back).
              This contradicts PRG security. Therefore any secure PRG is also a OWF.
            </div>
          </div>
          <button className="demo-btn" onClick={runBackward} disabled={backwardLoading}>
            {backwardLoading ? "Running…" : "next_bits(128) → attempt inversion (10 000 guesses)"}
          </button>
          {backwardResult && (
            <div className="demo-result-box" style={{ marginTop: 10 }}>
              <div className="demo-result-title">Demo: f(s) = G(s), try to recover s</div>
              <div className="demo-io-row">
                <span className="demo-io-label">seed(s)</span>
                <span className="demo-io-val mono-val">{backwardResult.seed}</span>
              </div>
              <div className="demo-io-row">
                <span className="demo-io-label">G(s) = next_bits(128)</span>
                <span className="demo-io-val mono-val">{backwardResult.prg_output}</span>
              </div>
              <div className="demo-io-row">
                <span className="demo-io-label">attempts</span>
                <span className="demo-io-val">{backwardResult.inversion_attempts?.toLocaleString()}</span>
              </div>
              <div className="demo-io-row">
                <span className="demo-io-label">result</span>
                <span className={`demo-io-val ${backwardResult.inversion_failed ? "pass" : "fail"}`}>
                  {backwardResult.inversion_failed
                    ? "✓ Inversion failed — OWF property holds"
                    : `✗ Recovered: ${backwardResult.recovered_seed}`}
                </span>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── STATS TAB ── */}
      {tab === "stats" && (
        <div className="demo-tab-content">
          <button className="demo-btn" onClick={runStats} disabled={statsLoading}>
            {statsLoading ? "Running..." : "Run NIST SP 800-22 Tests (20 000 bits)"}
          </button>
          {stats && (
            <div className="demo-stats">
              <div className="demo-stats-header">Results — {stats.total_bits} bits</div>
              <div className="demo-bar-container">
                <div className="demo-bar-label">Bit ratio (expect ≈ 0.50)</div>
                <div className="demo-bar">
                  <div className="demo-bar-fill" style={{ width: `${(stats.ones_ratio || 0.5) * 100}%` }} />
                </div>
                <span className="demo-bar-val">{stats.ones_ratio}</span>
              </div>
              <div className="demo-test-row">
                <span className={stats.frequency?.pass ? "pass" : "fail"}>
                  {stats.frequency?.pass ? "PASS" : "FAIL"}
                </span>
                <span>Frequency (Monobit)</span>
                <span>p = {stats.frequency?.p_value}</span>
              </div>
              <div className="demo-test-row">
                <span className={stats.runs?.pass ? "pass" : "fail"}>
                  {stats.runs?.pass ? "PASS" : "FAIL"}
                </span>
                <span>Runs Test</span>
                <span>p = {stats.runs?.p_value}</span>
              </div>
              <div className="demo-test-row">
                <span className={stats.serial?.pass ? "pass" : "fail"}>
                  {stats.serial?.pass ? "PASS" : "FAIL"}
                </span>
                <span>Serial (2-bit)</span>
                <span>chi² = {stats.serial?.chi2}</span>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── PA #2 DEMO: GGM Tree Visualiser ────────────────────────────────────────
export function PA2Demo() {
  const [key, setKey] = useState("a3f291bc7e40d528a3f291bc7e40d528");
  const [query, setQuery] = useState("1011");
  const [tree, setTree] = useState(null);
  const [leaf, setLeaf] = useState("");
  const [path, setPath] = useState([]);
  const debounce = useRef(null);

  useEffect(() => {
    if (debounce.current) clearTimeout(debounce.current);
    debounce.current = setTimeout(() => {
      const q = query.replace(/[^01]/g, "").slice(0, 8) || "0";
      fetch("/api/pa2/ggm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, query: q }),
      })
        .then((r) => r.json())
        .then((d) => {
          if (d.tree) setTree(d.tree);
          if (d.leaf) setLeaf(d.leaf);
          if (d.path) setPath(d.path);
        })
        .catch(() => {});
    }, 300);
  }, [key, query]);

  const renderTree = () => {
    if (!tree) return null;
    const rawDepth = query.replace(/[^01]/g, "").length || 1;
    const depth = Math.min(rawDepth, 5);
    const levels = [];
    for (let d = 0; d <= depth; d++) {
      const nodes = [];
      const count = Math.pow(2, d);
      for (let i = 0; i < count; i++) {
        const nodePath = d === 0 ? "" : i.toString(2).padStart(d, "0");
        const val = tree[nodePath];
        const isOnPath = d === 0 || path.includes(nodePath);
        nodes.push(
          <div
            key={nodePath}
            className={`ggm-node ${isOnPath ? "on-path" : "off-path"}`}
          >
            <div className="ggm-node-label">
              {d === 0 ? "k" : nodePath}
            </div>
            <div className="ggm-node-val">
              {val ? val.slice(0, 8) + "..." : "?"}
            </div>
          </div>
        );
      }
      levels.push(
        <div key={d} className="ggm-level">
          {nodes}
        </div>
      );
    }
    return levels;
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #2 — GGM Tree Visualiser</h3>
      <p className="demo-desc">
        GGM PRF: F_k(x) = G_{'{x_n}'}(...G_{'{x_1}'}(k)...). Path highlighted in blue.
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Key k (hex)</label>
          <input
            type="text"
            className="demo-input"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        </div>
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Query x (bits, 1-8)</label>
          <input
            type="text"
            className="demo-input"
            value={query}
            onChange={(e) => setQuery(e.target.value.replace(/[^01]/g, "").slice(0, 8))}
            placeholder="e.g. 1011"
          />
        </div>
      </div>

      <div className="ggm-tree-container">{renderTree()}</div>

      <div className="demo-output-box highlight">
        <div className="demo-output-label">F_k({query}) =</div>
        <div className="demo-output-hex">{leaf || "..."}</div>
      </div>
    </div>
  );
}

// ─── PA #3 DEMO: IND-CPA Game ───────────────────────────────────────────────
export function PA3Demo() {
  const [m0, setM0] = useState("48656c6c6f20576f726c642121212121");
  const [m1, setM1] = useState("476f6f646279652121212121212121");
  const [reuseNonce, setReuseNonce] = useState(false);
  const [rounds, setRounds] = useState([]);
  const [currentChallenge, setCurrentChallenge] = useState(null);

  const wins = rounds.filter((r) => r.correct).length;
  const total = rounds.length;
  const advantage = total > 0 ? Math.abs(wins / total - 0.5) : 0;

  const encrypt = () => {
    fetch("/api/pa3/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ m0, m1, reuse_nonce: reuseNonce }),
    })
      .then((r) => r.json())
      .then((d) => setCurrentChallenge(d))
      .catch(() => {});
  };

  const guess = (g) => {
    if (!currentChallenge) return;
    const correct = g === currentChallenge.b;
    setRounds((prev) => [
      ...prev,
      { round: prev.length + 1, guess: g, actual: currentChallenge.b, correct },
    ]);
    setCurrentChallenge(null);
  };

  const reset = () => {
    setRounds([]);
    setCurrentChallenge(null);
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #3 — Play the IND-CPA Game</h3>
      <p className="demo-desc">
        You are the adversary. Submit two messages, receive an encryption of one.
        Guess which was encrypted. Advantage should be ~0 in secure mode.
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">m0 (hex)</label>
          <input
            type="text"
            className="demo-input"
            value={m0}
            onChange={(e) => setM0(e.target.value)}
          />
        </div>
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">m1 (hex)</label>
          <input
            type="text"
            className="demo-input"
            value={m1}
            onChange={(e) => setM1(e.target.value)}
          />
        </div>
      </div>

      <div className="demo-toggle-row">
        <label className="demo-toggle-label">
          <input
            type="checkbox"
            checked={reuseNonce}
            onChange={(e) => { setReuseNonce(e.target.checked); reset(); }}
          />
          <span className={reuseNonce ? "broken-tag" : ""}>
            {reuseNonce ? "BROKEN MODE (nonce reuse)" : "Secure Mode (fresh nonce)"}
          </span>
        </label>
      </div>

      {!currentChallenge && (
        <button className="demo-btn" onClick={encrypt}>
          Encrypt Challenge
        </button>
      )}

      {currentChallenge && (
        <div className="cpa-challenge">
          <div className="cpa-challenge-label">Challenge Ciphertext:</div>
          <div className="cpa-challenge-val">
            <span className="label">r =</span> {currentChallenge.r}
          </div>
          <div className="cpa-challenge-val">
            <span className="label">C =</span> {currentChallenge.ciphertext}
          </div>
          <div className="cpa-guess-btns">
            <button className="demo-btn guess-btn" onClick={() => guess(0)}>
              Guess b=0 (m0)
            </button>
            <button className="demo-btn guess-btn" onClick={() => guess(1)}>
              Guess b=1 (m1)
            </button>
          </div>
        </div>
      )}

      <div className="cpa-scoreboard">
        <div className="cpa-score-item">
          <span>Rounds</span>
          <strong>{total}</strong>
        </div>
        <div className="cpa-score-item">
          <span>Wins</span>
          <strong>{wins}</strong>
        </div>
        <div className="cpa-score-item">
          <span>Advantage</span>
          <strong className={advantage > 0.3 ? "broken-tag" : ""}>
            {advantage.toFixed(4)}
          </strong>
        </div>
      </div>

      {rounds.length > 0 && (
        <div className="cpa-history">
          {rounds.slice(-10).map((r) => (
            <div key={r.round} className={`cpa-round ${r.correct ? "win" : "lose"}`}>
              R{r.round}: guessed {r.guess}, actual {r.actual} — {r.correct ? "WIN" : "LOSE"}
            </div>
          ))}
        </div>
      )}

      <button className="demo-btn-small" onClick={reset}>Reset Game</button>
    </div>
  );
}

// ─── PA #4 DEMO: Block Cipher Mode Animator ─────────────────────────────────
export function PA4Demo() {
  const [mode, setMode] = useState("CBC");
  const [key, setKey] = useState("a3f291bc7e40d528a3f291bc7e40d528");
  const [message, setMessage] = useState("48656c6c6f20576f726c642121212121" + "5365636f6e64426c6f636b2121212121" + "5468697264426c6f636b212121212121");
  const [encResult, setEncResult] = useState(null);
  const [flipResult, setFlipResult] = useState(null);
  const [flipBlock, setFlipBlock] = useState(0);

  const encrypt = () => {
    fetch("/api/pa4/encrypt", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode, key, message }),
    })
      .then((r) => r.json())
      .then((d) => { setEncResult(d); setFlipResult(null); })
      .catch(() => {});
  };

  const flipBit = (blockIdx) => {
    if (!encResult) return;
    fetch("/api/pa4/flip", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        mode,
        key: encResult.key,
        iv: encResult.iv,
        ciphertext: encResult.ciphertext,
        flip_block: blockIdx,
        flip_bit: 0,
      }),
    })
      .then((r) => r.json())
      .then((d) => { setFlipResult(d); setFlipBlock(blockIdx); })
      .catch(() => {});
  };

  const expectedCorruption = {
    CBC: "2 blocks (flipped + next)",
    OFB: "1 block (same block only)",
    CTR: "1 block (same block only)",
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #4 — Block Cipher Mode Animator</h3>
      <p className="demo-desc">
        Encrypt a 3-block message, then flip bits to see error propagation.
      </p>

      <div className="mode-tabs">
        {["CBC", "OFB", "CTR"].map((m) => (
          <button
            key={m}
            className={`mode-tab ${mode === m ? "active" : ""}`}
            onClick={() => { setMode(m); setEncResult(null); setFlipResult(null); }}
          >
            {m}
          </button>
        ))}
      </div>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Key (hex)</label>
          <input type="text" className="demo-input" value={key} onChange={(e) => setKey(e.target.value)} />
        </div>
      </div>

      <button className="demo-btn" onClick={encrypt}>Encrypt 3 Blocks</button>

      {encResult && (
        <div className="mode-blocks-container">
          <div className="mode-blocks-row">
            <div className="mode-blocks-label">Plaintext</div>
            {encResult.message_blocks?.map((b, i) => (
              <div key={i} className="mode-block pt-block">
                <div className="mode-block-idx">M{i}</div>
                <div className="mode-block-val">{b.slice(0, 8)}...</div>
              </div>
            ))}
          </div>
          <div className="mode-arrow-row">
            <span>{mode} Encryption (IV: {encResult.iv?.slice(0, 8)}...)</span>
          </div>
          <div className="mode-blocks-row">
            <div className="mode-blocks-label">Ciphertext</div>
            {encResult.ciphertext_blocks?.map((b, i) => (
              <div key={i} className="mode-block ct-block" onClick={() => flipBit(i)}>
                <div className="mode-block-idx">C{i}</div>
                <div className="mode-block-val">{b.slice(0, 8)}...</div>
                <div className="mode-block-action">Click to flip</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {flipResult && (
        <div className="flip-result">
          <div className="flip-result-header">
            Flipped bit 0 of block C{flipBlock} — Error propagation ({mode}):
          </div>
          <div className="flip-result-info">Expected: {expectedCorruption[mode]}</div>
          <div className="mode-blocks-row">
            <div className="mode-blocks-label">Decrypted</div>
            {flipResult.decrypted_blocks?.map((b, i) => {
              const original = encResult.message_blocks?.[i];
              const corrupted = b !== original;
              return (
                <div key={i} className={`mode-block ${corrupted ? "corrupted" : "ok"}`}>
                  <div className="mode-block-idx">P{i}</div>
                  <div className="mode-block-val">{b?.slice(0, 8)}...</div>
                  {corrupted && <div className="mode-block-corrupt">CORRUPTED</div>}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── PA #5 DEMO: MAC Forge Attempt ──────────────────────────────────────────
export function PA5Demo() {
  const [signed, setSigned] = useState([]);
  const [forgeMsg, setForgeMsg] = useState("");
  const [forgeTag, setForgeTag] = useState("");
  const [forgeResult, setForgeResult] = useState(null);
  const [attempts, setAttempts] = useState(0);
  const [successes, setSuccesses] = useState(0);

  const loadSigned = () => {
    fetch("/api/pa5/sign", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ count: 50 }),
    })
      .then((r) => r.json())
      .then((d) => { if (d.signed) setSigned(d.signed); })
      .catch(() => {});
  };

  useEffect(() => { loadSigned(); }, []);

  const submitForgery = () => {
    if (!forgeMsg || !forgeTag) return;
    fetch("/api/pa5/forge", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: forgeMsg, tag: forgeTag }),
    })
      .then((r) => r.json())
      .then((d) => {
        setForgeResult(d);
        setAttempts((a) => a + 1);
        if (d.result === "accepted") setSuccesses((s) => s + 1);
      })
      .catch(() => {});
  };

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #5 — MAC Forge Attempt (EUF-CMA Game)</h3>
      <p className="demo-desc">
        You see 50 signed messages. Try to forge a valid tag on a NEW message.
        Expect 0 successes in 20 attempts.
      </p>

      <div className="mac-signed-list">
        <div className="mac-signed-header">
          Signed Messages ({signed.length})
          <button className="demo-btn-small" onClick={loadSigned}>Refresh</button>
        </div>
        <div className="mac-signed-scroll">
          {signed.slice(0, 10).map((s, i) => (
            <div key={i} className="mac-signed-item">
              <span className="mac-msg">m: {s.message}</span>
              <span className="mac-tag">t: {s.tag}</span>
            </div>
          ))}
          {signed.length > 10 && (
            <div className="mac-signed-more">...and {signed.length - 10} more</div>
          )}
        </div>
      </div>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 2 }}>
          <label className="demo-label">New message (hex, not in list)</label>
          <input
            type="text"
            className="demo-input"
            value={forgeMsg}
            onChange={(e) => setForgeMsg(e.target.value)}
            placeholder="32 hex chars"
          />
        </div>
        <div className="demo-controls" style={{ flex: 2 }}>
          <label className="demo-label">Forged tag (hex)</label>
          <input
            type="text"
            className="demo-input"
            value={forgeTag}
            onChange={(e) => setForgeTag(e.target.value)}
            placeholder="32 hex chars"
          />
        </div>
      </div>

      <button className="demo-btn" onClick={submitForgery}>Submit Forgery</button>

      {forgeResult && (
        <div className={`forge-result ${forgeResult.result}`}>
          Forgery {forgeResult.result}: {forgeResult.reason}
        </div>
      )}

      <div className="cpa-scoreboard">
        <div className="cpa-score-item">
          <span>Attempts</span>
          <strong>{attempts}</strong>
        </div>
        <div className="cpa-score-item">
          <span>Successes</span>
          <strong className={successes > 0 ? "broken-tag" : ""}>{successes}</strong>
        </div>
        <div className="cpa-score-item">
          <span>Status</span>
          <strong>{successes === 0 ? "EUF-CMA Secure" : "BROKEN"}</strong>
        </div>
      </div>
    </div>
  );
}

// ─── PA #6 DEMO: Malleability Attack Panel ──────────────────────────────────
export function PA6Demo() {
  const [message, setMessage] = useState("5472616e73666572202431303021");
  const [flipBit, setFlipBit] = useState(2);
  const [result, setResult] = useState(null);

  const runDemo = () => {
    fetch("/api/pa6/demo", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message, flip_bit: flipBit }),
    })
      .then((r) => r.json())
      .then((d) => setResult(d))
      .catch(() => {});
  };

  useEffect(() => { runDemo(); }, [message, flipBit]);

  return (
    <div className="demo-panel">
      <h3 className="demo-title">PA #6 — Malleability Attack Panel</h3>
      <p className="demo-desc">
        Left: CPA-only (malleable). Right: CCA / Encrypt-then-MAC (rejects tampering).
      </p>

      <div className="demo-controls-row">
        <div className="demo-controls" style={{ flex: 2 }}>
          <label className="demo-label">Plaintext message (hex)</label>
          <input
            type="text"
            className="demo-input"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
        </div>
        <div className="demo-controls" style={{ flex: 1 }}>
          <label className="demo-label">Flip bit # (0-127)</label>
          <input
            type="number"
            className="demo-input"
            min="0"
            max="127"
            value={flipBit}
            onChange={(e) => setFlipBit(Number(e.target.value))}
          />
        </div>
      </div>

      {result && (
        <div className="malleability-grid">
          <div className="mall-col cpa-col">
            <div className="mall-col-header">CPA-Only (Malleable)</div>
            <div className="mall-row">
              <span className="mall-label">Original CT:</span>
              <span className="mall-val mono-val">{result.cpa?.ciphertext}</span>
            </div>
            <div className="mall-row">
              <span className="mall-label">Tampered CT:</span>
              <span className="mall-val tampered mono-val">{result.cpa?.tampered}</span>
            </div>
            <div className="mall-row">
              <span className="mall-label">Recovered:</span>
              <span className="mall-val recovered mono-val">{result.cpa?.recovered}</span>
            </div>
            <div className="mall-verdict bad">Plaintext modified! MALLEABLE</div>
          </div>

          <div className="mall-col cca-col">
            <div className="mall-col-header">CCA / Encrypt-then-MAC</div>
            <div className="mall-row">
              <span className="mall-label">Original CT:</span>
              <span className="mall-val mono-val">{result.cca?.ciphertext}</span>
            </div>
            <div className="mall-row">
              <span className="mall-label">Tampered CT:</span>
              <span className="mall-val tampered mono-val">{result.cca?.tampered}</span>
            </div>
            <div className="mall-row">
              <span className="mall-label">Recovered:</span>
              <span className="mall-val rejected">{result.cca?.recovered}</span>
            </div>
            <div className="mall-verdict good">MAC rejected! NOT malleable</div>
          </div>
        </div>
      )}
    </div>
  );
}

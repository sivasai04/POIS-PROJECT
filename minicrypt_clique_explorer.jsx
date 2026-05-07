import { useState, useEffect, useRef } from "react";

// ─── STYLE ────────────────────────────────────────────────────────────────────
const STYLES = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@400;600;800&display=swap');

  :root {
    --bg: #0a0c10;
    --surface: #0f1318;
    --surface2: #151a22;
    --border: #1e2736;
    --accent: #00e5ff;
    --accent2: #ff3d71;
    --accent3: #a259ff;
    --text: #c8d8e8;
    --text-dim: #4a6070;
    --green: #00ff9d;
    --yellow: #ffe066;
    --mono: 'Share Tech Mono', monospace;
    --sans: 'Syne', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--mono);
    min-height: 100vh;
  }

  .app {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    background:
      radial-gradient(ellipse 60% 40% at 20% 10%, rgba(0,229,255,0.04) 0%, transparent 70%),
      radial-gradient(ellipse 40% 50% at 80% 80%, rgba(162,89,255,0.05) 0%, transparent 70%),
      var(--bg);
  }

  /* ── TOP BAR ── */
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 28px;
    border-bottom: 1px solid var(--border);
    background: rgba(10,12,16,0.95);
    backdrop-filter: blur(10px);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .topbar-title {
    font-family: var(--sans);
    font-weight: 800;
    font-size: 1rem;
    letter-spacing: 0.08em;
    color: var(--accent);
    text-transform: uppercase;
  }

  .topbar-sub {
    font-size: 0.65rem;
    color: var(--text-dim);
    letter-spacing: 0.12em;
    margin-top: 2px;
  }

  .foundation-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 4px;
  }

  .foundation-btn {
    padding: 6px 16px;
    border: none;
    border-radius: 3px;
    background: transparent;
    color: var(--text-dim);
    font-family: var(--mono);
    font-size: 0.75rem;
    cursor: pointer;
    letter-spacing: 0.06em;
    transition: all 0.2s;
  }

  .foundation-btn.active {
    background: var(--accent);
    color: #000;
    font-weight: bold;
  }

  .bidir-toggle {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.72rem;
    color: var(--text-dim);
  }

  .toggle-switch {
    position: relative;
    width: 36px;
    height: 18px;
    cursor: pointer;
  }
  .toggle-switch input { opacity: 0; width: 0; height: 0; }
  .toggle-slider {
    position: absolute; inset: 0;
    background: var(--border);
    border-radius: 18px;
    transition: 0.2s;
  }
  .toggle-slider:before {
    content: '';
    position: absolute;
    width: 12px; height: 12px;
    left: 3px; top: 3px;
    background: var(--text-dim);
    border-radius: 50%;
    transition: 0.2s;
  }
  .toggle-switch input:checked + .toggle-slider { background: var(--accent3); }
  .toggle-switch input:checked + .toggle-slider:before {
    transform: translateX(18px);
    background: #fff;
  }

  /* ── MAIN AREA ── */
  .main {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1px;
    flex: 1;
    background: var(--border);
  }

  .column {
    background: var(--bg);
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 18px;
    min-height: 520px;
  }

  .col-header {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .col-badge {
    font-family: var(--sans);
    font-size: 0.6rem;
    font-weight: 800;
    letter-spacing: 0.15em;
    padding: 3px 8px;
    border-radius: 2px;
    text-transform: uppercase;
  }
  .col-badge.build { background: rgba(0,229,255,0.12); color: var(--accent); border: 1px solid rgba(0,229,255,0.2); }
  .col-badge.reduce { background: rgba(162,89,255,0.12); color: var(--accent3); border: 1px solid rgba(162,89,255,0.2); }

  .col-title {
    font-family: var(--sans);
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--text);
    letter-spacing: 0.04em;
  }

  .col-subtitle {
    font-size: 0.62rem;
    color: var(--text-dim);
    letter-spacing: 0.06em;
  }

  /* ── CONTROLS ── */
  .control-row {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .control-label {
    font-size: 0.62rem;
    color: var(--text-dim);
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }

  select, input[type="text"] {
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.78rem;
    padding: 8px 12px;
    border-radius: 3px;
    outline: none;
    transition: border-color 0.2s;
    appearance: none;
  }
  select:focus, input[type="text"]:focus {
    border-color: var(--accent);
  }
  select option { background: var(--surface2); }

  /* ── STEP DISPLAY ── */
  .steps-container {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 14px;
    flex: 1;
    min-height: 200px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .step-row {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 10px;
    background: var(--surface2);
    border-radius: 3px;
    border-left: 3px solid var(--border);
    animation: fadeIn 0.3s ease;
  }

  .step-row.active { border-left-color: var(--accent); }
  .step-row.pending { border-left-color: var(--text-dim); opacity: 0.5; }
  .step-row.done { border-left-color: var(--green); }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .step-fn {
    font-size: 0.7rem;
    color: var(--accent);
    letter-spacing: 0.04em;
  }

  .step-fn.col2 { color: var(--accent3); }

  .step-io {
    display: grid;
    grid-template-columns: 40px 1fr;
    gap: 4px 8px;
    font-size: 0.65rem;
  }

  .step-io-label { color: var(--text-dim); }
  .step-io-val {
    color: var(--yellow);
    word-break: break-all;
    font-size: 0.62rem;
  }

  .step-output-box {
    margin-top: 6px;
    padding: 8px 12px;
    background: rgba(0,255,157,0.06);
    border: 1px solid rgba(0,255,157,0.2);
    border-radius: 3px;
  }

  .step-output-label {
    font-size: 0.6rem;
    color: var(--green);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 3px;
  }

  .step-output-val {
    font-size: 0.72rem;
    color: #fff;
    word-break: break-all;
  }

  .stub-notice {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px;
    background: rgba(255,61,113,0.06);
    border: 1px solid rgba(255,61,113,0.2);
    border-radius: 3px;
    font-size: 0.68rem;
    color: var(--accent2);
  }

  .stub-icon { font-size: 1rem; }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    flex: 1;
    gap: 8px;
    color: var(--text-dim);
    font-size: 0.7rem;
    letter-spacing: 0.08em;
  }

  .empty-icon { font-size: 2rem; opacity: 0.3; }

  /* ── BOTTOM PANEL ── */
  .bottom-panel {
    border-top: 1px solid var(--border);
    background: var(--surface);
  }

  .bottom-toggle {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 28px;
    cursor: pointer;
    user-select: none;
    transition: background 0.2s;
  }
  .bottom-toggle:hover { background: var(--surface2); }

  .bottom-toggle-title {
    font-family: var(--sans);
    font-size: 0.75rem;
    font-weight: 600;
    letter-spacing: 0.08em;
    color: var(--text);
    text-transform: uppercase;
  }

  .bottom-toggle-arrow {
    font-size: 0.7rem;
    color: var(--text-dim);
    transition: transform 0.2s;
  }
  .bottom-toggle-arrow.open { transform: rotate(180deg); }

  .bottom-content {
    padding: 0 28px 20px;
    display: flex;
    flex-direction: column;
    gap: 12px;
    animation: fadeIn 0.2s ease;
  }

  .chain-row {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    padding: 10px 14px;
    background: var(--surface2);
    border-radius: 3px;
    font-size: 0.68rem;
  }

  .chain-node {
    padding: 4px 10px;
    border-radius: 2px;
    background: rgba(0,229,255,0.08);
    border: 1px solid rgba(0,229,255,0.2);
    color: var(--accent);
    font-size: 0.65rem;
    letter-spacing: 0.06em;
  }

  .chain-node.foundation {
    background: rgba(255,224,102,0.08);
    border-color: rgba(255,224,102,0.2);
    color: var(--yellow);
  }

  .chain-node.target {
    background: rgba(162,89,255,0.1);
    border-color: rgba(162,89,255,0.3);
    color: var(--accent3);
  }

  .chain-arrow {
    color: var(--text-dim);
    font-size: 0.7rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 1px;
  }

  .chain-arrow span {
    font-size: 0.5rem;
    color: var(--text-dim);
    white-space: nowrap;
  }

  .security-claim {
    padding: 10px 14px;
    background: rgba(0,255,157,0.04);
    border: 1px solid rgba(0,255,157,0.1);
    border-radius: 3px;
    font-size: 0.65rem;
    color: var(--text-dim);
    line-height: 1.7;
  }

  .security-claim strong { color: var(--green); }

  .pa-tag {
    display: inline-block;
    padding: 1px 6px;
    background: rgba(162,89,255,0.12);
    border: 1px solid rgba(162,89,255,0.25);
    border-radius: 2px;
    color: var(--accent3);
    font-size: 0.6rem;
    margin-left: 4px;
  }

  /* ── INPUT LIVE UPDATE PULSE ── */
  @keyframes pulse-border {
    0% { border-color: var(--accent); }
    50% { border-color: rgba(0,229,255,0.3); }
    100% { border-color: var(--accent); }
  }
  .updating { animation: pulse-border 0.6s ease; }
`;

// ─── DATA ─────────────────────────────────────────────────────────────────────

const PRIMITIVES = ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF", "HMAC"];

const PA_MAP = {
  OWF: "#1", PRG: "#1", PRF: "#2", PRP: "#4 (AES)",
  MAC: "#5", CRHF: "#7+#8", HMAC: "#10"
};

// Which primitives are "implemented" (stubs for PA#0 — all are stubs)
const IMPLEMENTED = new Set([]); // none yet in PA#0

const REDUCTIONS = {
  "OWF→PRG":   { name: "HILL Hard-Core Bit",    theorem: "Håstad-Impagliazzo-Levin-Luby", pa: "#1" },
  "OWF→OWP":   { name: "DLP is already OWP",    theorem: "Domain restriction", pa: "#1" },
  "PRG→PRF":   { name: "GGM Tree Construction", theorem: "Goldreich-Goldwasser-Micali", pa: "#2" },
  "PRF→PRP":   { name: "Luby-Rackoff 3-Round Feistel", theorem: "Luby-Rackoff", pa: "#4" },
  "PRF→MAC":   { name: "Fk(m) = MAC tag",       theorem: "PRF→EUF-CMA", pa: "#5" },
  "PRP→MAC":   { name: "PRP/PRF switching lemma + PRF→MAC", theorem: "Switching Lemma", pa: "#5" },
  "CRHF→HMAC": { name: "Double-hash HMAC construction", theorem: "HMAC Security (Bellare)", pa: "#10" },
  "HMAC→MAC":  { name: "HMAC is EUF-CMA secure", theorem: "PRF-compression ⇒ MAC", pa: "#10" },
  "MAC→CRHF":  { name: "MAC as MD compression fn", theorem: "MAC⇒CRHF via MD", pa: "#10" },
  "MAC→PRF":   { name: "EUF-CMA MAC on uniform inputs is PRF", theorem: "MAC⇒PRF", pa: "#5" },
  "PRF→PRG":   { name: "G(s) = Fs(0)‖Fs(1)", theorem: "PRF→PRG (backward)", pa: "#2" },
  "PRP→PRF":   { name: "PRF/PRP switching lemma", theorem: "Switching Lemma (reverse)", pa: "#4" },
  "PRG→OWF":   { name: "G(s) is itself a OWF", theorem: "PRG⇒OWF (trivial)", pa: "#1" },
};

// Shortest path routing table
function getReductionChain(src, tgt, backward) {
  if (backward) {
    const key = `${tgt}→${src}`;
    if (REDUCTIONS[key]) return [key];
    return getPath(tgt, src);
  }
  const key = `${src}→${tgt}`;
  if (REDUCTIONS[key]) return [key];
  return getPath(src, tgt);
}

function getPath(a, b) {
  const graph = {
    OWF:  ["PRG","OWP"],
    OWP:  ["OWF","PRG"],
    PRG:  ["PRF","OWF"],
    PRF:  ["PRP","MAC","PRG"],
    PRP:  ["PRF","MAC"],
    MAC:  ["PRF","CRHF"],
    CRHF: ["HMAC","MAC"],
    HMAC: ["MAC","CRHF"],
  };
  const visited = new Set();
  const queue = [[a, []]];
  while (queue.length) {
    const [node, path] = queue.shift();
    if (node === b) return path;
    if (visited.has(node)) continue;
    visited.add(node);
    for (const nb of (graph[node] || [])) {
      const key = `${node}→${nb}`;
      const rkey = REDUCTIONS[key] ? key : null;
      queue.push([nb, rkey ? [...path, rkey] : path]);
    }
  }
  return null;
}

// Stub hex outputs
const STUB_OUTPUTS = {
  OWF:  "a3f291bc",
  PRG:  "a3f291bc7e40d528",
  PRF:  "88d4c3a1",
  PRP:  "f2190c44",
  MAC:  "3d7a9e11",
  CRHF: "c4b2a918",
  HMAC: "9f3e7a22",
};

const FOUNDATION_TO_PRIM = {
  AES: { OWF: "AESk(0¹²⁸) ⊕ k", PRG: "Fk(0)‖Fk(1)", PRF: "AESk(x)", PRP: "AES(k,x)" },
  DLP: { OWF: "gˣ mod p",         PRG: "HILL(f,x)",  PRF: "GGM(PRG)", OWP: "gˣ mod p" },
};

// ─── COMPONENT ────────────────────────────────────────────────────────────────

export default function MinicryptExplorer() {
  const [foundation, setFoundation] = useState("AES");
  const [backward, setBackward] = useState(false);
  const [sourceA, setSourceA] = useState("PRG");
  const [targetB, setTargetB] = useState("PRF");
  const [inputSeed, setInputSeed] = useState("a3f291bc7e40d528");
  const [inputMsg,  setInputMsg]  = useState("1011");
  const [proofOpen, setProofOpen] = useState(false);
  const [tick, setTick] = useState(0);

  // Re-trigger animations on input change
  useEffect(() => { setTick(t => t + 1); }, [foundation, sourceA, targetB, inputSeed, inputMsg, backward]);

  const effectiveSrc = backward ? targetB : sourceA;
  const effectiveTgt = backward ? sourceA : targetB;

  const chain = getReductionChain(sourceA, targetB, backward);
  const col1Steps = buildCol1Steps(foundation, effectiveSrc, inputSeed);
  const col2Steps = buildCol2Steps(effectiveSrc, effectiveTgt, inputMsg, chain);

  return (
    <>
      <style>{STYLES}</style>
      <div className="app">
        {/* ── TOP BAR ── */}
        <div className="topbar">
          <div>
            <div className="topbar-title">CS8.401 · Minicrypt Clique Explorer</div>
            <div className="topbar-sub">PA #0 — Interactive Reduction Visualiser</div>
          </div>

          <div className="foundation-toggle">
            {["AES", "DLP"].map(f => (
              <button
                key={f}
                className={`foundation-btn ${foundation === f ? "active" : ""}`}
                onClick={() => setFoundation(f)}
              >
                {f === "AES" ? "AES-128 (PRP)" : "DLP (gˣ mod p)"}
              </button>
            ))}
          </div>

          <div className="bidir-toggle">
            <span>Forward A→B</span>
            <label className="toggle-switch">
              <input type="checkbox" checked={backward} onChange={e => setBackward(e.target.checked)} />
              <span className="toggle-slider" />
            </label>
            <span>Backward B→A</span>
          </div>
        </div>

        {/* ── TWO COLUMNS ── */}
        <div className="main">
          {/* Column 1: Build */}
          <div className="column">
            <div className="col-header">
              <span className="col-badge build">LEG 1</span>
              <div>
                <div className="col-title">Build Source Primitive from Foundation</div>
                <div className="col-subtitle">Foundation → {backward ? targetB : sourceA}</div>
              </div>
            </div>

            <div className="control-row">
              <label className="control-label">Source Primitive A</label>
              <select value={sourceA} onChange={e => setSourceA(e.target.value)}>
                {PRIMITIVES.filter(p => p !== targetB).map(p =>
                  <option key={p} value={p}>{p}</option>
                )}
              </select>
            </div>

            <div className="control-row">
              <label className="control-label">Input Key / Seed (hex)</label>
              <input
                type="text"
                value={inputSeed}
                onChange={e => setInputSeed(e.target.value)}
                placeholder="e.g. a3f291bc7e40d528"
              />
            </div>

            <div className="steps-container" key={`col1-${tick}`}>
              {col1Steps.length === 0
                ? <div className="empty-state"><div className="empty-icon">⛓</div><span>SELECT A SOURCE PRIMITIVE</span></div>
                : col1Steps.map((s, i) => <StepCard key={i} step={s} col={1} />)
              }
            </div>
          </div>

          {/* Column 2: Reduce */}
          <div className="column">
            <div className="col-header">
              <span className="col-badge reduce">LEG 2</span>
              <div>
                <div className="col-title">Reduce Source to Target Primitive</div>
                <div className="col-subtitle">{backward ? targetB : sourceA} → {backward ? sourceA : targetB}</div>
              </div>
            </div>

            <div className="control-row">
              <label className="control-label">Target Primitive B</label>
              <select value={targetB} onChange={e => setTargetB(e.target.value)}>
                {PRIMITIVES.filter(p => p !== sourceA).map(p =>
                  <option key={p} value={p}>{p}</option>
                )}
              </select>
            </div>

            <div className="control-row">
              <label className="control-label">Message / Query Input</label>
              <input
                type="text"
                value={inputMsg}
                onChange={e => setInputMsg(e.target.value)}
                placeholder="e.g. 1011 (bit string or hex)"
              />
            </div>

            <div className="steps-container" key={`col2-${tick}`}>
              {!chain || chain.length === 0
                ? <NoPathNotice src={effectiveSrc} tgt={effectiveTgt} />
                : col2Steps.map((s, i) => <StepCard key={i} step={s} col={2} />)
              }
            </div>
          </div>
        </div>

        {/* ── BOTTOM PROOF PANEL ── */}
        <div className="bottom-panel">
          <div className="bottom-toggle" onClick={() => setProofOpen(o => !o)}>
            <span className="bottom-toggle-title">▸ Reduction Chain Summary &amp; Security Claims</span>
            <span className={`bottom-toggle-arrow ${proofOpen ? "open" : ""}`}>▼</span>
          </div>
          {proofOpen && (
            <div className="bottom-content">
              <ChainSummary
                foundation={foundation}
                src={effectiveSrc}
                tgt={effectiveTgt}
                chain={chain}
                backward={backward}
              />
            </div>
          )}
        </div>
      </div>
    </>
  );
}

// ─── SUB-COMPONENTS ───────────────────────────────────────────────────────────

function StepCard({ step, col }) {
  const isStub = !IMPLEMENTED.has(step.primitive);
  if (isStub) {
    return (
      <div className="stub-notice">
        <span className="stub-icon">🔒</span>
        <div>
          <div style={{ fontWeight: "bold", marginBottom: 3 }}>{step.fn}</div>
          <div>Not implemented yet — due: PA <span style={{ color: "#fff" }}>{step.pa}</span></div>
          <div style={{ marginTop: 3, opacity: 0.7, fontSize: "0.62rem" }}>
            Showing stub output for PA #0 demo
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className={`step-row done`}>
      <div className={`step-fn ${col === 2 ? "col2" : ""}`}>{step.fn}</div>
      <div className="step-io">
        <span className="step-io-label">in:</span>
        <span className="step-io-val">{step.input}</span>
        <span className="step-io-label">out:</span>
        <span className="step-io-val">{step.output}</span>
      </div>
    </div>
  );
}

function NoPathNotice({ src, tgt }) {
  return (
    <div className="empty-state" style={{ gap: 12 }}>
      <div className="empty-icon">⚡</div>
      <div style={{ textAlign: "center", maxWidth: 260, lineHeight: 1.8 }}>
        <div style={{ color: "var(--accent2)", marginBottom: 6 }}>No direct path found</div>
        <div style={{ fontSize: "0.62rem", color: "var(--text-dim)" }}>
          {src} → {tgt} has no known reduction in this direction.<br />
          Try the <strong style={{ color: "var(--text)" }}>Backward B→A</strong> toggle,
          or choose a different primitive pair.
        </div>
      </div>
    </div>
  );
}

function ChainSummary({ foundation, src, tgt, chain, backward }) {
  const nodes = chain ? buildChainNodes(foundation, src, tgt, chain) : null;

  return (
    <>
      <div className="chain-row">
        <div className="chain-node foundation">{foundation} ({foundation === "AES" ? "PRP" : "OWF"})</div>
        <ChainArrow label="instantiates" />
        <div className="chain-node">{src}</div>
        {chain && chain.map((key, i) => {
          const r = REDUCTIONS[key];
          const parts = key.split("→");
          return (
            <span key={i} style={{ display: "contents" }}>
              <ChainArrow label={r?.name || key} />
              <div className="chain-node target">{parts[1]}</div>
            </span>
          );
        })}
        {!chain && (
          <span style={{ color: "var(--accent2)", fontSize: "0.65rem" }}> ✗ no path</span>
        )}
      </div>

      {chain && chain.map((key, i) => {
        const r = REDUCTIONS[key];
        if (!r) return null;
        return (
          <div key={i} className="security-claim">
            <strong>{r.theorem}</strong>
            <span className="pa-tag">PA {r.pa}</span>
            <br />
            {securityText(key, backward)}
          </div>
        );
      })}

      <div className="security-claim">
        <strong>Note:</strong> All intermediate values shown are <em>stub outputs</em> for PA #0.
        Real cryptographic computations will replace these in PA {PA_MAP[src]} and later assignments.
        Full credit requires both forward (A⇒B) and backward (B⇒A) directions for clique pairs.
      </div>
    </>
  );
}

function ChainArrow({ label }) {
  return (
    <div className="chain-arrow">
      <span>{label}</span>
      <span>──→</span>
    </div>
  );
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function buildCol1Steps(foundation, src, seed) {
  const fLabel = foundation === "AES" ? "AES-128" : "DLP gˣ mod p";
  const concreteFn = (FOUNDATION_TO_PRIM[foundation] || {})[src] || src;
  const stubOut = STUB_OUTPUTS[src] || "deadbeef";
  return [
    {
      fn: `${fLabel} → ${src}  [${concreteFn}]`,
      input: seed || "0000000000000000",
      output: stubOut,
      pa: PA_MAP[src] || "?",
      primitive: src,
    }
  ];
}

function buildCol2Steps(src, tgt, msg, chain) {
  if (!chain) return [];
  return chain.map(key => {
    const r = REDUCTIONS[key] || {};
    const parts = key.split("→");
    const inPrim = parts[0], outPrim = parts[1];
    return {
      fn: `${inPrim} → ${outPrim}  [${r.name || key}]`,
      input: msg || "0000",
      output: STUB_OUTPUTS[outPrim] || "cafebabe",
      pa: r.pa || "?",
      primitive: outPrim,
    };
  });
}

function buildChainNodes(foundation, src, tgt, chain) {
  return [foundation, src, ...(chain || []).map(k => k.split("→")[1])];
}

function securityText(key, backward) {
  const texts = {
    "OWF→PRG":   "If adversary breaks PRG with advantage ε, it inverts OWF with advantage ε′ ≥ ε (via hard-core bit).",
    "PRG→PRF":   "If adversary distinguishes Fk from random with q queries, it distinguishes G from random with advantage ε/q (GGM hybrid argument).",
    "PRF→PRP":   "3-round Feistel: any CPA adversary against the PRP can be converted to a PRF distinguisher with negligible overhead.",
    "PRF→MAC":   "Any MAC forger (EUF-CMA) with advantage ε is a PRF distinguisher with advantage ε.",
    "CRHF→HMAC": "If compression fn is a PRF, HMAC is EUF-CMA secure — even if collisions in H are found (HMAC-MD5 remained secure after MD5 collisions).",
    "HMAC→MAC":  "HMAC is a secure EUF-CMA MAC when the inner compression function is a PRF.",
    "MAC→CRHF":  "Any collision in MAC-based MD hash yields a MAC forgery. Security reduces to EUF-CMA hardness.",
    "PRG→OWF":   "G(s) is a OWF: inverting it recovers seed s, which would break PRG pseudorandomness.",
    "MAC→PRF":   "A secure EUF-CMA MAC on uniform messages is computationally indistinguishable from a PRF oracle.",
    "PRF→PRG":   "G(s) = Fs(0‥0)‖Fs(1‥1): if G were distinguishable from random, the distinguisher breaks PRF security.",
    "PRP→MAC":   "By PRP/PRF switching lemma the PRP is indistinguishable from a PRF, then PRF⇒MAC applies.",
    "PRP→PRF":   "PRF/PRP switching lemma: statistical distance ≤ q²/2ⁿ, negligible for polynomial q.",
  };
  return texts[key] || "Security reduction follows from the composition theorem for the corresponding primitives.";
}

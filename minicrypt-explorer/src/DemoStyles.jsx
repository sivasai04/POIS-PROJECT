export const DEMO_STYLES = `
  /* ── DEMO PANEL ── */
  .demo-panel {
    background: var(--bg);
    min-height: 200px;
    animation: fadeIn 0.2s ease;
  }

  .demo-title {
    font-family: var(--sans);
    font-size: 1.1rem;
    font-weight: 700;
    color: var(--accent);
    margin-bottom: 8px;
    letter-spacing: 0.02em;
  }

  .demo-desc {
    font-size: 0.76rem;
    color: var(--text-dim);
    margin-bottom: 18px;
    line-height: 1.75;
  }

  .demo-controls {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 12px;
  }

  .demo-controls-row {
    display: flex;
    gap: 12px;
    margin-bottom: 12px;
  }

  .demo-label {
    font-size: 0.68rem;
    color: var(--text-dim);
    letter-spacing: 0.06em;
    text-transform: uppercase;
  }

  .demo-input {
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: var(--mono);
    font-size: 0.75rem;
    padding: 8px 12px;
    border-radius: 3px;
    outline: none;
    transition: border-color 0.2s;
  }
  .demo-input:focus { border-color: var(--accent); }

  .demo-slider {
    width: 100%;
    height: 6px;
    appearance: none;
    background: var(--border);
    border-radius: 3px;
    outline: none;
    margin-top: 4px;
  }
  .demo-slider::-webkit-slider-thumb {
    appearance: none;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--accent);
    cursor: pointer;
  }

  .demo-btn {
    padding: 10px 20px;
    background: rgba(0,229,255,0.1);
    border: 1px solid var(--accent);
    color: var(--accent);
    font-family: var(--mono);
    font-size: 0.72rem;
    border-radius: 4px;
    cursor: pointer;
    transition: all 0.2s;
    margin-bottom: 12px;
  }
  .demo-btn:hover { background: rgba(0,229,255,0.2); }
  .demo-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .demo-btn-small {
    padding: 4px 10px;
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-dim);
    font-family: var(--mono);
    font-size: 0.62rem;
    border-radius: 3px;
    cursor: pointer;
  }
  .demo-btn-small:hover { border-color: var(--accent); color: var(--accent); }

  /* ── OUTPUT BOX ── */
  .demo-output-box {
    padding: 12px 16px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 14px;
  }
  .demo-output-box.highlight {
    background: rgba(0,255,157,0.05);
    border-color: rgba(0,255,157,0.3);
  }

  .demo-output-label {
    font-size: 0.6rem;
    color: var(--green);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-bottom: 4px;
  }

  .demo-output-hex {
    font-size: 0.72rem;
    color: #fff;
    word-break: break-all;
    line-height: 1.6;
    max-height: 120px;
    overflow-y: auto;
  }

  /* ── STATS ── */
  .demo-stats {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 14px;
  }

  .demo-stats-header {
    font-size: 0.68rem;
    color: var(--text);
    font-weight: bold;
    margin-bottom: 10px;
    letter-spacing: 0.04em;
  }

  .demo-bar-container {
    display: flex;
    align-items: center;
    gap: 10px;
    margin-bottom: 10px;
  }

  .demo-bar-label {
    font-size: 0.6rem;
    color: var(--text-dim);
    min-width: 140px;
  }

  .demo-bar {
    flex: 1;
    height: 10px;
    background: var(--surface2);
    border-radius: 5px;
    overflow: hidden;
  }

  .demo-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--green));
    border-radius: 5px;
    transition: width 0.3s;
  }

  .demo-bar-val {
    font-size: 0.65rem;
    color: var(--text);
    min-width: 40px;
  }

  .demo-test-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 6px 0;
    font-size: 0.65rem;
    border-top: 1px solid var(--border);
  }

  .demo-test-row .pass {
    color: var(--green);
    font-weight: bold;
    min-width: 40px;
  }
  .demo-test-row .fail {
    color: var(--accent2);
    font-weight: bold;
    min-width: 40px;
  }
  .demo-test-row span:nth-child(2) { flex: 1; color: var(--text); }
  .demo-test-row span:nth-child(3) { color: var(--text-dim); }

  /* ── MODE TOGGLE ── */
  .demo-mode-toggle {
    display: flex;
    gap: 8px;
    margin-bottom: 14px;
  }
  .demo-mode-btn {
    padding: 6px 14px;
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-dim);
    font-family: var(--mono);
    font-size: 0.68rem;
    border-radius: 3px;
    cursor: pointer;
    transition: all 0.2s;
  }
  .demo-mode-btn:hover { border-color: var(--accent); color: var(--accent); }
  .demo-mode-btn.active {
    background: rgba(0,229,255,0.12);
    border-color: var(--accent);
    color: var(--accent);
    font-weight: bold;
  }

  /* ── TABS ── */
  .demo-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 14px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 0;
  }
  .demo-tab {
    padding: 6px 14px;
    background: transparent;
    border: 1px solid transparent;
    border-bottom: none;
    color: var(--text-dim);
    font-family: var(--mono);
    font-size: 0.68rem;
    border-radius: 3px 3px 0 0;
    cursor: pointer;
    transition: all 0.15s;
  }
  .demo-tab:hover { color: var(--text); }
  .demo-tab.active {
    border-color: var(--border);
    border-bottom-color: var(--bg);
    color: var(--accent);
    background: var(--bg);
    margin-bottom: -1px;
  }
  .demo-tab-content { padding-top: 6px; }

  /* ── FORMULA BOX ── */
  .demo-formula-box {
    display: flex;
    align-items: baseline;
    gap: 10px;
    padding: 8px 12px;
    background: rgba(0,229,255,0.05);
    border: 1px solid rgba(0,229,255,0.15);
    border-radius: 3px;
    margin-bottom: 10px;
  }
  .demo-formula-label {
    font-size: 0.58rem;
    color: var(--accent);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    white-space: nowrap;
  }
  .demo-formula {
    font-family: var(--mono);
    font-size: 0.72rem;
    color: var(--text);
  }

  /* ── IO GRID ── */
  .demo-io-grid { display: flex; flex-direction: column; gap: 6px; margin-bottom: 12px; }
  .demo-io-row {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 6px 10px;
    background: var(--surface);
    border-radius: 3px;
    border-left: 2px solid var(--border);
  }
  .demo-io-label {
    font-size: 0.58rem;
    color: var(--text-dim);
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .demo-io-val {
    font-family: var(--mono);
    font-size: 0.7rem;
    color: var(--yellow);
    word-break: break-all;
  }
  .demo-io-val.pass { color: var(--green); }
  .demo-io-val.fail { color: var(--accent2); }

  /* ── RESULT BOX ── */
  .demo-result-box {
    padding: 12px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .demo-result-title {
    font-size: 0.62rem;
    color: var(--accent3);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 4px;
    font-weight: bold;
  }

  /* ── SECTION LABEL ── */
  .demo-section-label {
    font-size: 0.62rem;
    color: var(--text-dim);
    letter-spacing: 0.06em;
    text-transform: uppercase;
    margin-bottom: 6px;
    margin-top: 4px;
  }

  /* ── CHAIN ── */
  .demo-chain-box {
    padding: 10px 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-top: 8px;
  }
  .demo-chain-header {
    font-size: 0.6rem;
    color: var(--text-dim);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .demo-chain-step {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 0;
    border-top: 1px solid var(--border);
    font-size: 0.64rem;
  }
  .demo-chain-idx  { color: var(--accent); min-width: 24px; font-weight: bold; }
  .demo-chain-state { color: var(--text-dim); font-family: var(--mono); flex: 1; }
  .demo-chain-bit  { color: var(--yellow); min-width: 40px; }

  /* ── PASS / FAIL ── */
  .pass { color: var(--green); font-weight: bold; }
  .fail { color: var(--accent2); font-weight: bold; }

  /* ── GGM TREE ── */
  .ggm-tree-container {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 16px;
    margin-bottom: 14px;
    overflow-x: auto;
  }

  .ggm-level {
    display: flex;
    justify-content: center;
    gap: 6px;
    margin-bottom: 10px;
  }

  .ggm-node {
    padding: 6px 10px;
    border-radius: 4px;
    text-align: center;
    min-width: 60px;
    border: 1px solid var(--border);
    transition: all 0.3s;
  }

  .ggm-node.on-path {
    background: rgba(0,229,255,0.12);
    border-color: var(--accent);
    box-shadow: 0 0 8px rgba(0,229,255,0.2);
  }

  .ggm-node.off-path {
    background: var(--surface2);
    opacity: 0.4;
  }

  .ggm-node-label {
    font-size: 0.55rem;
    color: var(--text-dim);
    letter-spacing: 0.08em;
    margin-bottom: 2px;
  }

  .ggm-node-val {
    font-size: 0.6rem;
    color: var(--yellow);
    word-break: break-all;
  }

  .on-path .ggm-node-val { color: var(--accent); }

  /* ── IND-CPA GAME ── */
  .demo-toggle-row {
    margin-bottom: 12px;
  }

  .demo-toggle-label {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 0.68rem;
    color: var(--text);
    cursor: pointer;
  }

  .broken-tag {
    color: var(--accent2) !important;
    font-weight: bold;
  }

  .cpa-challenge {
    background: var(--surface);
    border: 1px solid var(--accent);
    border-radius: 4px;
    padding: 14px;
    margin-bottom: 14px;
  }

  .cpa-challenge-label {
    font-size: 0.62rem;
    color: var(--accent);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .cpa-challenge-val {
    font-size: 0.68rem;
    color: var(--yellow);
    word-break: break-all;
    margin-bottom: 4px;
  }

  .cpa-challenge-val .label {
    color: var(--text-dim);
    margin-right: 6px;
  }

  .cpa-guess-btns {
    display: flex;
    gap: 10px;
    margin-top: 12px;
  }

  .guess-btn {
    flex: 1;
    background: rgba(162,89,255,0.1);
    border-color: var(--accent3);
    color: var(--accent3);
  }
  .guess-btn:hover { background: rgba(162,89,255,0.2); }

  .cpa-scoreboard {
    display: flex;
    gap: 16px;
    margin: 14px 0;
    padding: 12px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
  }

  .cpa-score-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    flex: 1;
  }

  .cpa-score-item span {
    font-size: 0.58rem;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }

  .cpa-score-item strong {
    font-size: 1rem;
    color: var(--text);
  }

  .cpa-history {
    max-height: 120px;
    overflow-y: auto;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px;
    margin-bottom: 10px;
  }

  .cpa-round {
    font-size: 0.62rem;
    padding: 3px 8px;
    border-radius: 2px;
    margin-bottom: 2px;
  }
  .cpa-round.win { color: var(--green); background: rgba(0,255,157,0.06); }
  .cpa-round.lose { color: var(--accent2); background: rgba(255,61,113,0.06); }

  /* ── MODES ── */
  .mode-tabs {
    display: flex;
    gap: 4px;
    margin-bottom: 14px;
  }

  .mode-tab {
    padding: 8px 20px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text-dim);
    font-family: var(--mono);
    font-size: 0.72rem;
    cursor: pointer;
    transition: all 0.2s;
  }
  .mode-tab:hover { border-color: var(--accent); }
  .mode-tab.active {
    background: rgba(0,229,255,0.1);
    border-color: var(--accent);
    color: var(--accent);
    font-weight: bold;
  }

  .mode-blocks-container {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 16px;
    margin: 14px 0;
  }

  .mode-blocks-row {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }

  .mode-blocks-label {
    font-size: 0.6rem;
    color: var(--text-dim);
    letter-spacing: 0.08em;
    text-transform: uppercase;
    min-width: 70px;
  }

  .mode-block {
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 3px;
    text-align: center;
    flex: 1;
    cursor: default;
    transition: all 0.2s;
  }

  .mode-block.pt-block { background: rgba(0,229,255,0.06); border-color: rgba(0,229,255,0.2); }
  .mode-block.ct-block {
    background: rgba(162,89,255,0.06);
    border-color: rgba(162,89,255,0.2);
    cursor: pointer;
  }
  .mode-block.ct-block:hover {
    border-color: var(--accent2);
    background: rgba(255,61,113,0.08);
  }
  .mode-block.corrupted {
    background: rgba(255,61,113,0.12);
    border-color: var(--accent2);
  }
  .mode-block.ok {
    background: rgba(0,255,157,0.06);
    border-color: rgba(0,255,157,0.2);
  }

  .mode-block-idx {
    font-size: 0.55rem;
    color: var(--text-dim);
    margin-bottom: 2px;
  }

  .mode-block-val {
    font-size: 0.62rem;
    color: var(--yellow);
  }

  .mode-block-action {
    font-size: 0.5rem;
    color: var(--accent2);
    margin-top: 2px;
    opacity: 0.7;
  }

  .mode-block-corrupt {
    font-size: 0.5rem;
    color: var(--accent2);
    font-weight: bold;
    margin-top: 2px;
  }

  .mode-arrow-row {
    text-align: center;
    font-size: 0.6rem;
    color: var(--text-dim);
    padding: 6px 0;
  }

  .flip-result {
    margin-top: 10px;
    padding: 12px;
    background: rgba(255,61,113,0.04);
    border: 1px solid rgba(255,61,113,0.2);
    border-radius: 4px;
  }

  .flip-result-header {
    font-size: 0.68rem;
    color: var(--accent2);
    margin-bottom: 6px;
    font-weight: bold;
  }

  .flip-result-info {
    font-size: 0.62rem;
    color: var(--text-dim);
    margin-bottom: 8px;
  }

  /* ── MAC ── */
  .mac-signed-list {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 14px;
  }

  .mac-signed-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 12px;
    border-bottom: 1px solid var(--border);
    font-size: 0.65rem;
    color: var(--text);
    font-weight: bold;
  }

  .mac-signed-scroll {
    max-height: 160px;
    overflow-y: auto;
    padding: 6px;
  }

  .mac-signed-item {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 6px 8px;
    font-size: 0.6rem;
    border-bottom: 1px solid rgba(30,39,54,0.5);
  }

  .mac-msg { color: var(--text-dim); font-size: 0.67rem; }
  .mac-tag { color: var(--yellow); font-family: "Share Tech Mono",monospace; word-break: break-all; font-size: 0.7rem; }
  .mac-signed-more { font-size: 0.58rem; color: var(--text-dim); padding: 4px 8px; }

  .forge-result {
    padding: 10px 14px;
    border-radius: 4px;
    font-size: 0.72rem;
    margin-bottom: 12px;
    font-weight: bold;
  }
  .forge-result.accepted { background: rgba(0,255,157,0.1); color: var(--green); border: 1px solid rgba(0,255,157,0.3); }
  .forge-result.rejected { background: rgba(255,61,113,0.08); color: var(--accent2); border: 1px solid rgba(255,61,113,0.2); }

  /* ── MALLEABILITY ── */
  .malleability-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
    margin-top: 14px;
  }

  .mall-col {
    padding: 14px;
    border-radius: 4px;
    border: 1px solid var(--border);
  }

  .mall-col.cpa-col { background: rgba(255,61,113,0.04); border-color: rgba(255,61,113,0.2); }
  .mall-col.cca-col { background: rgba(0,255,157,0.04); border-color: rgba(0,255,157,0.2); }

  .mall-col-header {
    font-size: 0.7rem;
    font-weight: bold;
    margin-bottom: 10px;
    letter-spacing: 0.04em;
  }
  .cpa-col .mall-col-header { color: var(--accent2); }
  .cca-col .mall-col-header { color: var(--green); }

  .mall-row {
    display: flex;
    flex-direction: column;
    gap: 2px;
    margin-bottom: 8px;
  }

  .mall-label {
    font-size: 0.66rem;
    color: var(--text-dim);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  /* shared utility: full-width monospace hex value */
  .mono-val {
    font-family: "Share Tech Mono", monospace;
    font-size: 0.72rem;
    color: var(--accent);
    word-break: break-all;
    line-height: 1.6;
    display: block;
    margin-top: 3px;
  }

  .mall-val {
    font-size: 0.72rem;
    color: var(--text);
    word-break: break-all;
  }

  .mall-val.tampered { color: var(--accent2); }
  .mall-val.recovered { color: var(--yellow); }
  .mall-val.rejected { color: var(--green); font-weight: bold; }

  .mall-verdict {
    padding: 8px;
    border-radius: 3px;
    text-align: center;
    font-size: 0.68rem;
    font-weight: bold;
    letter-spacing: 0.04em;
  }
  .mall-verdict.bad { background: rgba(255,61,113,0.1); color: var(--accent2); }
  .mall-verdict.good { background: rgba(0,255,157,0.1); color: var(--green); }

  /* ── PA#7: Merkle-Damgård chain ── */

  .demo-controls-row {
    display: flex;
    gap: 12px;
    align-items: flex-end;
    margin-bottom: 10px;
  }

  .demo-toggle-label {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 0.68rem;
    color: var(--text-dim);
    cursor: pointer;
  }
  .demo-toggle-label input[type="checkbox"] { accent-color: var(--accent); }

  .md-blocks-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: flex-start;
    margin-bottom: 12px;
  }
  .md-blocks-label {
    font-size: 0.62rem;
    color: var(--text-dim);
    width: 100%;
    margin-bottom: 2px;
    font-weight: bold;
  }
  .md-block {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 6px 10px;
    text-align: center;
    min-width: 90px;
  }
  .md-block-idx {
    font-size: 0.58rem;
    color: var(--accent);
    font-weight: bold;
    margin-bottom: 2px;
  }
  .md-block-val {
    font-size: 0.58rem;
    font-family: "Share Tech Mono", monospace;
    color: var(--text);
    word-break: break-all;
  }

  .md-chain {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0;
    margin-bottom: 12px;
    overflow-x: auto;
    padding: 8px 0;
  }
  .md-chain-step {
    display: flex;
    align-items: center;
    gap: 0;
  }
  .md-chain-node {
    background: var(--surface2);
    border: 1px solid var(--accent);
    border-radius: 6px;
    padding: 8px 12px;
    text-align: center;
    min-width: 80px;
  }
  .md-chain-label {
    font-size: 0.56rem;
    color: var(--accent);
    font-weight: bold;
  }
  .md-chain-val {
    font-size: 0.58rem;
    font-family: "Share Tech Mono", monospace;
    color: var(--text);
    margin-top: 2px;
  }
  .md-chain-arrow {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 0 6px;
    font-size: 0.5rem;
    color: var(--text-dim);
  }
  .arrow-symbol {
    font-size: 1rem;
    color: var(--accent);
  }

  .demo-output-box.highlight {
    border-color: var(--green);
    background: rgba(0,255,157,0.05);
  }

  /* ── PA#8: Collision bar ── */

  .demo-hash-results {
    display: flex;
    gap: 12px;
    margin-bottom: 12px;
  }
  .demo-hash-results .demo-output-box { flex: 1; }

  .collision-result {
    margin-top: 10px;
    padding: 12px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .collision-header {
    font-size: 0.7rem;
    font-weight: bold;
    color: var(--green);
    margin-bottom: 8px;
  }
  .collision-bar-container {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .collision-bar {
    flex: 1;
    height: 12px;
    background: var(--surface);
    border-radius: 6px;
    overflow: visible;
    position: relative;
  }
  .collision-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--green));
    border-radius: 6px;
    transition: width 0.3s;
  }
  .collision-bar-marker {
    position: absolute;
    top: -3px;
    width: 2px;
    height: 18px;
    background: var(--accent2);
  }
  .collision-bar-legend {
    font-size: 0.56rem;
    color: var(--accent2);
    white-space: nowrap;
  }

  /* ── PA#9: Birthday chart ── */

  .birthday-chart {
    margin-top: 12px;
    padding: 12px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  .birthday-chart-header {
    font-size: 0.68rem;
    font-weight: bold;
    color: var(--text);
    margin-bottom: 8px;
  }
  .birthday-chart-body { display: flex; flex-direction: column; gap: 3px; }
  .birthday-chart-row { display: flex; align-items: center; gap: 8px; }
  .bc-k { font-size: 0.64rem; color: var(--text-dim); width: 68px; text-align: right; font-family: "Share Tech Mono",monospace; }
  .bc-bars { flex: 1; height: 10px; position: relative; background: var(--surface); border-radius: 3px; overflow: hidden; }
  .bc-bar { position: absolute; top: 0; left: 0; height: 100%; border-radius: 3px; }
  .bc-bar.theory { background: rgba(0,255,157,0.3); z-index: 1; }
  .bc-bar.empirical { background: rgba(88,166,255,0.5); z-index: 2; height: 6px; top: 2px; }
  .bc-val { font-size: 0.64rem; color: var(--text-dim); width: 46px; }
  .bc-legend { display: flex; gap: 12px; font-size: 0.65rem; color: var(--text-dim); margin-top: 8px; }
  .bc-dot { display: inline-block; width: 8px; height: 8px; border-radius: 2px; margin-right: 3px; vertical-align: middle; }
  .bc-dot.theory { background: rgba(0,255,157,0.4); }
  .bc-dot.empirical { background: rgba(88,166,255,0.6); }
  .birthday-marker { font-size: 0.68rem; color: var(--accent2); margin-top: 6px; text-align: center; }

  /* ── PA#10: reuses malleability grid ── */

  /* ── PA#11: DH panels ── */

  .dh-panels {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-top: 10px;
  }
  .dh-party {
    flex: 1;
    min-width: 200px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
  }
  .dh-party.compromised { border-color: rgba(255,61,113,0.3); }
  .dh-party.secure { border-color: rgba(0,255,157,0.2); }
  .dh-party.eve-party {
    background: rgba(255,61,113,0.04);
    border-color: var(--accent2);
  }
  .dh-party-name {
    font-size: 0.72rem;
    font-weight: bold;
    color: var(--accent);
    margin-bottom: 8px;
  }
  .eve-party .dh-party-name { color: var(--accent2); }
  .dh-field {
    display: flex;
    flex-direction: column;
    gap: 3px;
    font-size: 0.72rem;
    color: var(--text-dim);
    padding: 5px 0;
    font-family: "Share Tech Mono", monospace;
  }
  .dh-field span:first-child { color: var(--text-dim); font-family: "Syne", sans-serif; font-size: 0.66rem; letter-spacing: 0.04em; }
  .dh-field.shared .mono-val { color: var(--green); font-weight: bold; }
  .dh-match {
    width: 100%;
    text-align: center;
    padding: 8px;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: bold;
  }
  .dh-match.good { background: rgba(0,255,157,0.1); color: var(--green); }
  .dh-match.bad { background: rgba(255,61,113,0.1); color: var(--accent2); }

  .demo-toggle-row {
    margin-bottom: 10px;
  }
  .broken-tag { color: var(--accent2); }

  /* ── PA#12: RSA result ── */

  .rsa-result {
    margin-top: 10px;
  }
  .rsa-banner {
    padding: 10px 14px;
    border-radius: 4px;
    font-size: 0.72rem;
    font-weight: bold;
    text-align: center;
    margin-bottom: 10px;
    letter-spacing: 0.03em;
  }
  .rsa-banner.bad { background: rgba(255,61,113,0.1); color: var(--accent2); border: 1px solid rgba(255,61,113,0.25); }
  .rsa-banner.good { background: rgba(0,255,157,0.1); color: var(--green); border: 1px solid rgba(0,255,157,0.25); }

  .rsa-ct-box {
    display: flex;
    gap: 8px;
    align-items: center;
    padding: 6px 10px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 4px;
  }
  .rsa-ct-label { font-size: 0.7rem; color: var(--accent); font-weight: bold; width: 32px; }
  .rsa-ct-val { font-size: 0.7rem; font-family: "Share Tech Mono", monospace; color: var(--text-dim); word-break: break-all; }

  .rsa-padding-panel {
    margin-top: 8px;
    padding: 10px;
    background: var(--surface2);
    border: 1px solid rgba(0,255,157,0.15);
    border-radius: 4px;
  }
  .rsa-padding-header { font-size: 0.7rem; color: var(--green); font-weight: bold; margin-bottom: 6px; }
  .rsa-info { font-size: 0.68rem; color: var(--text-dim); margin-top: 8px; text-align: center; }

  /* ── PA#13: Miller-Rabin ── */

  .preset-btns {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-bottom: 10px;
  }
  .demo-btn-small {
    background: var(--surface2);
    color: var(--text-dim);
    border: 1px solid var(--border);
    border-radius: 3px;
    padding: 4px 10px;
    font-size: 0.58rem;
    cursor: pointer;
    font-family: "Syne", sans-serif;
    transition: border-color 0.15s, color 0.15s;
  }
  .demo-btn-small:hover { border-color: var(--accent); color: var(--accent); }

  .mr-result { margin-top: 10px; }
  .mr-fermat { font-size: 0.64rem; color: var(--text-dim); margin-bottom: 8px; padding: 6px; background: var(--surface2); border-radius: 4px; }
  .mr-witnesses { background: var(--surface2); border: 1px solid var(--border); border-radius: 4px; padding: 10px; }
  .mr-witnesses-header { font-size: 0.64rem; font-weight: bold; color: var(--text); margin-bottom: 6px; }
  .mr-witness-row {
    display: flex;
    gap: 12px;
    font-size: 0.58rem;
    font-family: "Share Tech Mono", monospace;
    color: var(--text-dim);
    padding: 3px 0;
    border-bottom: 1px solid rgba(255,255,255,0.03);
  }
  .mr-rounds { color: var(--accent2); font-size: 0.54rem; }

  /* ── PA#14: Håstad panels ── */

  .hastad-result { margin-top: 10px; }
  .hastad-recipients {
    display: flex;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 12px;
  }
  .hastad-recipient {
    flex: 1;
    min-width: 180px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
  }
  .hastad-recipient-header {
    font-size: 0.66rem;
    font-weight: bold;
    color: var(--accent);
    margin-bottom: 6px;
  }
  .hastad-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    font-size: 0.7rem;
    color: var(--text-dim);
    font-family: "Share Tech Mono", monospace;
    padding: 3px 0;
  }
  .hastad-field span:first-child { color: var(--text); font-family: "Syne", sans-serif; font-size: 0.68rem; }

  .hastad-attacker {
    background: rgba(255,61,113,0.03);
    border: 1px solid rgba(255,61,113,0.2);
    border-radius: 6px;
    padding: 12px;
  }
  .hastad-attacker-header {
    font-size: 0.7rem;
    font-weight: bold;
    color: var(--accent2);
    margin-bottom: 8px;
  }

  /* ── PA#15: Signatures ── */

  .sig-result { margin-top: 10px; }
  .sig-row {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 7px 10px;
    background: var(--surface2);
    border-bottom: 1px solid rgba(255,255,255,0.03);
    font-size: 0.62rem;
  }
  .sig-row span:first-child { color: var(--text-dim); font-size: 0.66rem; letter-spacing: 0.05em; text-transform: uppercase; }
  .sig-row .mono {
    font-family: "Share Tech Mono",monospace;
    color: var(--accent);
    word-break: break-all;
    line-height: 1.6;
    font-size: 0.72rem;
  }
  .sig-row .pass { color: var(--green); font-weight: bold; font-size: 0.82rem; }
  .sig-row .fail { color: var(--accent2); font-weight: bold; font-size: 0.82rem; }
  .sig-explanation {
    font-size: 0.72rem;
    color: var(--accent2);
    padding: 9px 12px;
    background: rgba(255,61,113,0.06);
    border-radius: 4px;
    margin-top: 6px;
    line-height: 1.6;
  }
  .sig-explanation.good-text { color: var(--green); background: rgba(0,255,157,0.04); }

  .demo-btn-small.active, .demo-btn.active {
    border-color: var(--accent);
    color: var(--accent);
    background: rgba(88,166,255,0.08);
  }

  /* ── PA#16: ElGamal result ── */

  .eg-result { margin-top: 10px; }
  .eg-enc-box, .eg-mall-box {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    margin-bottom: 8px;
  }
  .eg-enc-label, .eg-mall-label {
    font-size: 0.66rem;
    font-weight: bold;
    margin-bottom: 6px;
  }
  .eg-enc-label { color: var(--accent); }
  .eg-mall-label { color: var(--accent2); }
  .eg-counter {
    font-size: 0.6rem;
    color: var(--text-dim);
    text-align: center;
    padding: 6px;
  }

  /* ── PA#18: OT layout ── */

  .ot-layout {
    display: flex;
    gap: 12px;
    margin-top: 8px;
  }
  .ot-party {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
  }
  .ot-alice { border-color: rgba(255,61,113,0.2); }
  .ot-bob { border-color: rgba(0,255,157,0.2); }
  .ot-choice-btns { display: flex; gap: 6px; margin-top: 6px; }

  .ot-result { margin-top: 10px; }
  .ot-log {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px;
    margin-bottom: 8px;
  }
  .ot-log-line {
    font-size: 0.68rem;
    font-family: "Share Tech Mono",monospace;
    color: var(--text-dim);
    padding: 4px 0;
    word-break: break-all;
    line-height: 1.65;
    border-bottom: 1px solid rgba(255,255,255,0.04);
  }
  .ot-log-line:last-child { border-bottom: none; }
  .ot-outcome {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px;
    margin-bottom: 8px;
  }
  .ot-outcome-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.64rem;
    padding: 4px 0;
  }
  .ot-outcome-row .pass { color: var(--green); font-weight: bold; }
  .ot-hidden {
    color: var(--accent2);
    font-weight: bold;
    font-size: 0.72rem;
  }
  .ot-cheat {
    background: rgba(255,61,113,0.03);
    border: 1px solid rgba(255,61,113,0.15);
    border-radius: 4px;
    padding: 10px;
  }
  .ot-cheat-header { font-size: 0.64rem; font-weight: bold; color: var(--accent2); margin-bottom: 4px; }
  .ot-cheat-result { font-size: 0.62rem; color: var(--text-dim); }
  .ot-cheat-result .pass { color: var(--green); }

  /* ── PA#19: AND gate ── */

  .and-result { margin-top: 10px; }
  .and-gates {
    display: flex;
    gap: 10px;
    margin-bottom: 10px;
  }
  .and-gate-box {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    text-align: center;
  }
  .and-gate-box span:first-child {
    display: block;
    font-size: 0.62rem;
    color: var(--text-dim);
    margin-bottom: 4px;
  }
  .and-val {
    font-size: 1.2rem;
    font-weight: bold;
    color: var(--accent);
  }
  .and-privacy {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px;
    margin-top: 8px;
  }
  .and-priv-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.6rem;
    color: var(--text-dim);
    padding: 3px 0;
  }
  .and-priv-row span:first-child { color: var(--text); font-weight: bold; }

  /* Truth table */
  .tt-table {
    margin-top: 10px;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 10px;
  }
  .tt-header, .tt-row {
    display: grid;
    grid-template-columns: 30px 30px 40px 40px 40px 40px 40px 40px;
    gap: 4px;
    font-size: 0.58rem;
    font-family: "Share Tech Mono",monospace;
    padding: 3px 0;
    text-align: center;
  }
  .tt-header { color: var(--accent); font-weight: bold; border-bottom: 1px solid var(--border); }
  .tt-row { color: var(--text-dim); }
  .tt-row .pass { color: var(--green); }
  .tt-row .fail { color: var(--accent2); }

  /* ── PA#20: MPC result ── */

  .mpc-result { margin-top: 10px; }
  .mpc-winner {
    padding: 14px;
    border-radius: 6px;
    text-align: center;
    font-size: 0.9rem;
    font-weight: bold;
    letter-spacing: 0.04em;
    margin-bottom: 12px;
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text);
  }
  .mpc-winner.alice-wins { background: rgba(88,166,255,0.08); border-color: rgba(88,166,255,0.3); color: var(--accent); }
  .mpc-winner.bob-wins { background: rgba(0,255,157,0.08); border-color: rgba(0,255,157,0.3); color: var(--green); }

  .mpc-circuits {
    display: flex;
    gap: 10px;
    margin-bottom: 12px;
  }
  .mpc-circuit-box {
    flex: 1;
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    text-align: center;
  }
  .mpc-circuit-label {
    font-size: 0.62rem;
    color: var(--text-dim);
    margin-bottom: 4px;
  }
  .mpc-circuit-val {
    font-size: 1.1rem;
    font-weight: bold;
    color: var(--accent);
    margin-bottom: 4px;
  }
  .mpc-circuit-check { font-size: 0.58rem; margin-bottom: 4px; }
  .mpc-circuit-check.pass { color: var(--green); }
  .mpc-circuit-check.fail { color: var(--accent2); }
  .mpc-circuit-stats { font-size: 0.52rem; color: var(--text-dim); }

  .mpc-trace {
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 8px 10px;
    margin-bottom: 8px;
  }
  .mpc-trace summary {
    font-size: 0.64rem;
    color: var(--accent);
    cursor: pointer;
    font-weight: bold;
  }

  .mpc-privacy-note {
    font-size: 0.58rem;
    color: var(--text-dim);
    text-align: center;
    padding: 8px;
    background: rgba(0,255,157,0.03);
    border: 1px solid rgba(0,255,157,0.1);
    border-radius: 4px;
  }
`;

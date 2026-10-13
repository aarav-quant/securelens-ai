import { useEffect, useMemo, useRef, useState } from "react";
import { analyzeFindings, downloadReport, getHealth, scanFile } from "./api.js";

const EXTENSIONS = [".py", ".js", ".jsx", ".ts", ".tsx", ".java"];
const SEVERITIES = ["HIGH", "MEDIUM", "LOW", "INFO"];
const PRIORITY_LABEL = { P1: "Fix first", P2: "Fix soon", P3: "Review" };

export default function App() {
  const [health, setHealth] = useState(null);
  const [file, setFile] = useState(null);
  const [scan, setScan] = useState(null);
  const [analyses, setAnalyses] = useState({});
  const [busy, setBusy] = useState(""); // "scan" | "ai" | "html" | "json" | ""
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [priority, setPriority] = useState("ALL");

  useEffect(() => {
    getHealth().then(setHealth).catch((e) => setError(e.message));
  }, []);

  const maxBytes = health?.max_upload_bytes ?? 500000;

  function chooseFile(f) {
    setError("");
    setNotice("");
    if (!f) return;
    const ext = f.name.slice(f.name.lastIndexOf(".")).toLowerCase();
    if (!EXTENSIONS.includes(ext)) return setError(`Unsupported file type. Allowed: ${EXTENSIONS.join(", ")}`);
    if (f.size === 0) return setError("File is empty.");
    if (f.size > maxBytes) return setError(`File too large. Maximum is ${Math.round(maxBytes / 1000)} KB.`);
    setFile(f);
  }

  async function runScan() {
    if (!file) return;
    setBusy("scan");
    setError("");
    setNotice("");
    setAnalyses({});
    setQuery("");
    setSeverity("ALL");
    setPriority("ALL");
    try {
      setScan(await scanFile(file));
    } catch (e) {
      setScan(null);
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  async function runAI() {
    setBusy("ai");
    setError("");
    setNotice("");
    try {
      const res = await analyzeFindings(scan.language, scan.findings);
      setAnalyses((prev) => ({ ...prev, ...res.analyses }));
      setNotice(
        `Gemini explained ${res.analyzed} finding(s)` +
          (res.skipped ? `; ${res.skipped} lower-priority finding(s) skipped to stay within limits.` : ".")
      );
    } catch (e) {
      setError(`AI explanations unavailable: ${e.message}`);
    } finally {
      setBusy("");
    }
  }

  async function download(format) {
    setBusy(format);
    try {
      await downloadReport(format, scan, analyses);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  const visible = useMemo(() => {
    if (!scan) return [];
    const q = query.trim().toLowerCase();
    return scan.findings.filter(
      (f) =>
        (severity === "ALL" || f.severity === severity) &&
        (priority === "ALL" || f.priority === priority) &&
        (!q || [f.title, f.rule_id, f.message, f.cwe, String(f.line)].some((v) => v?.toLowerCase().includes(q)))
    );
  }, [scan, query, severity, priority]);

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <Logo />
          <div>
            <h1>SecureLens <span>AI</span></h1>
            <p>See vulnerabilities. Understand risks. Build secure code.</p>
          </div>
        </div>
        <StatusChips health={health} />
      </header>

      <main>
        <UploadPanel file={file} onFile={chooseFile} onScan={runScan} busy={busy === "scan"} maxBytes={maxBytes} />

        {error && <div className="alert error" role="alert">{error}</div>}
        {notice && <div className="alert info" role="status">{notice}</div>}

        {busy === "scan" && <div className="loading" aria-live="polite"><span className="spinner" /> Scanning {file?.name}…</div>}

        {scan && busy !== "scan" && (
          <>
            <section className="scan-meta">
              <div>
                <strong>{scan.filename}</strong>
                <span className="muted"> · {scan.language} · scanned with {scan.scanner} in {(scan.duration_ms / 1000).toFixed(1)}s</span>
              </div>
              <div className="actions">
                <button
                  className="btn ai"
                  onClick={runAI}
                  disabled={!health?.ai_enabled || !scan.findings.length || busy !== ""}
                  title={health?.ai_enabled ? "Explain findings with Gemini" : "Set GEMINI_API_KEY on the server to enable"}
                >
                  {busy === "ai" ? <><span className="spinner small" /> Explaining…</> : "✦ Explain with Gemini"}
                </button>
                <button className="btn ghost" onClick={() => download("json")} disabled={busy !== ""}>
                  {busy === "json" ? "Preparing…" : "Download JSON"}
                </button>
                <button className="btn ghost" onClick={() => download("html")} disabled={busy !== ""}>
                  {busy === "html" ? "Preparing…" : "Download HTML"}
                </button>
              </div>
            </section>

            <Summary scan={scan} active={severity} onPick={(s) => setSeverity(severity === s ? "ALL" : s)} />

            {scan.findings.length > 0 ? (
              <>
                <div className="filters">
                  <input
                    type="search"
                    placeholder="Search title, rule, CWE, line…"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    aria-label="Search findings"
                  />
                  <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filter by severity">
                    <option value="ALL">All severities</option>
                    {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                  <select value={priority} onChange={(e) => setPriority(e.target.value)} aria-label="Filter by priority">
                    <option value="ALL">All priorities</option>
                    {Object.entries(PRIORITY_LABEL).map(([p, l]) => <option key={p} value={p}>{p} · {l}</option>)}
                  </select>
                  <span className="muted count">{visible.length} of {scan.findings.length}</span>
                </div>
                <ul className="findings">
                  {visible.map((f) => <FindingCard key={f.id} f={f} ai={analyses[f.id]} />)}
                  {!visible.length && <li className="empty">No findings match your filters.</li>}
                </ul>
              </>
            ) : (
              <div className="clean">
                <h3>No findings reported</h3>
                <p>The scanner found no matches for its rules in this file.</p>
              </div>
            )}
            <p className="disclaimer">{scan.disclaimer}</p>
          </>
        )}

        {!scan && busy !== "scan" && <HowItWorks />}
      </main>
      <footer>Uploaded code is scanned statically and never executed. Results stay in your browser.</footer>
    </div>
  );
}

function StatusChips({ health }) {
  if (!health) return <div className="chips"><span className="chip">Connecting…</span></div>;
  const s = health.scanners || {};
  return (
    <div className="chips">
      <span className={`chip ${s.bandit ? "ok" : "bad"}`}>Bandit {s.bandit ? "ready" : "missing"}</span>
      <span className={`chip ${s.semgrep ? "ok" : "bad"}`}>Semgrep {s.semgrep ? "ready" : "missing"}</span>
      <span className={`chip ${health.ai_enabled ? "ok" : "off"}`}>Gemini {health.ai_enabled ? "on" : "off"}</span>
    </div>
  );
}

function UploadPanel({ file, onFile, onScan, busy, maxBytes }) {
  const input = useRef(null);
  const [drag, setDrag] = useState(false);
  return (
    <section className="upload">
      <div
        className={`drop ${drag ? "drag" : ""}`}
        role="button"
        tabIndex={0}
        aria-label="Choose a source file to scan"
        onClick={() => input.current?.click()}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={(e) => { e.preventDefault(); setDrag(false); onFile(e.dataTransfer.files?.[0]); }}
      >
        <input
          ref={input}
          type="file"
          accept={EXTENSIONS.join(",")}
          hidden
          onChange={(e) => { onFile(e.target.files?.[0]); e.target.value = ""; }}
        />
        <div className="drop-icon">⇪</div>
        {file ? (
          <p><strong>{file.name}</strong> <span className="muted">({(file.size / 1024).toFixed(1)} KB)</span></p>
        ) : (
          <p><strong>Drop a source file here</strong> or click to browse</p>
        )}
        <p className="muted small">{EXTENSIONS.join(" ")} · max {Math.round(maxBytes / 1000)} KB</p>
      </div>
      <button className="btn primary" onClick={onScan} disabled={!file || busy}>
        {busy ? "Scanning…" : "Scan for vulnerabilities"}
      </button>
    </section>
  );
}

function Summary({ scan, active, onPick }) {
  const s = scan.summary.by_severity || {};
  const p = scan.summary.by_priority || {};
  return (
    <section className="summary">
      <div className="card total">
        <span>Total findings</span>
        <b>{scan.summary.total}</b>
        <small>P1 {p.P1 || 0} · P2 {p.P2 || 0} · P3 {p.P3 || 0}</small>
      </div>
      {SEVERITIES.map((sev) => (
        <button
          key={sev}
          className={`card sev-${sev.toLowerCase()} ${active === sev ? "active" : ""}`}
          onClick={() => onPick(sev)}
          aria-pressed={active === sev}
        >
          <span>{sev}</span>
          <b>{s[sev] || 0}</b>
        </button>
      ))}
    </section>
  );
}

function FindingCard({ f, ai }) {
  const [open, setOpen] = useState(false);
  return (
    <li className={`finding ${open ? "open" : ""}`}>
      <button className="finding-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className={`badge sev-${f.severity.toLowerCase()}`}>{f.severity}</span>
        <span className={`badge pri ${f.priority.toLowerCase()}`} title={PRIORITY_LABEL[f.priority]}>{f.priority}</span>
        <span className="title">{f.title}</span>
        <span className="where">line {f.line}</span>
        {ai && <span className="badge ai-tag" title="Gemini explanation available">AI</span>}
        <span className="chev" aria-hidden>{open ? "▴" : "▾"}</span>
      </button>
      {open && (
        <div className="finding-body">
          <dl className="facts">
            <div><dt>Rule</dt><dd><code>{f.rule_id}</code></dd></div>
            <div><dt>Scanner</dt><dd>{f.scanner}</dd></div>
            <div><dt>Confidence</dt><dd>{f.confidence || "n/a"}</dd></div>
            <div><dt>Location</dt><dd>{f.filename}:{f.line}</dd></div>
            {f.cwe && <div><dt>CWE</dt><dd>{f.cwe}</dd></div>}
          </dl>
          {f.message && <p>{f.message}</p>}
          {f.code_snippet && <pre className="code">{f.code_snippet}</pre>}
          {ai ? (
            <div className="ai-box">
              <h4>✦ What this means</h4><p>{ai.explanation}</p>
              <h4>Potential impact</h4><p>{ai.impact}</p>
              <h4>How to fix</h4><p>{ai.remediation}</p>
              {ai.secure_example && <><h4>Secure example</h4><pre className="code">{ai.secure_example}</pre></>}
              <p className="muted small">AI-generated guidance — verify before applying.</p>
            </div>
          ) : null}
        </div>
      )}
    </li>
  );
}

function HowItWorks() {
  const steps = ["Upload code", "Static scan", "Gemini explains", "Prioritize", "Export report"];
  return (
    <section className="how">
      {steps.map((s, i) => (
        <div key={s} className="step"><span>{i + 1}</span>{s}</div>
      ))}
    </section>
  );
}

function Logo() {
  return (
    <svg width="40" height="40" viewBox="0 0 32 32" aria-hidden>
      <circle cx="14" cy="14" r="9" fill="none" stroke="currentColor" strokeWidth="2.5" />
      <path d="M10 14l3 3 5-6" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
      <path d="M21 21l7 7" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" />
    </svg>
  );
}

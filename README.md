# SecureLens AI

**See vulnerabilities. Understand risks. Build secure code.**

SecureLens AI scans a single source file with real static analyzers, ranks the findings, optionally asks
Google Gemini to explain them in plain language, and exports JSON/HTML reports.

```
Upload → Bandit / Semgrep → (optional) Gemini explanations → Prioritization → Dashboard → Report
```

| Language | Extensions | Scanner |
|---|---|---|
| Python | `.py` | Bandit (built-in rules) |
| JavaScript | `.js` `.jsx` | Semgrep + `backend/rules/semgrep.yml` |
| TypeScript | `.ts` `.tsx` | Semgrep + `backend/rules/semgrep.yml` |
| Java | `.java` | Semgrep + `backend/rules/semgrep.yml` |

Semgrep rules are local (no registry download, no login, works offline) and cover: eval / Function injection,
command injection, SQL injection, DOM/React XSS, hardcoded secrets, weak hashes/ciphers, insecure
deserialization and insecure randomness.

> A clean scan does **not** mean the code is secure. Static analysis only matches known patterns.

---

## 1. Add your Gemini API key (optional)

Scanning works without it; the "Explain with Gemini" button is simply disabled.

1. Create a key at <https://aistudio.google.com/apikey>.
2. Copy the template and paste your key:
   ```bash
   cp backend/.env.example backend/.env
   # edit backend/.env →  GEMINI_API_KEY=your-real-key
   ```
3. Restart the backend (or `docker compose up -d --force-recreate backend`).
4. The header chip should now say **Gemini on**.

`backend/.env` is git-ignored. The key is only read by the backend and is never sent to the browser.
Default model is `gemini-3.1-flash-lite` with `gemini-3.6-flash` as an automatic fallback when the main
model is busy (429/5xx). Change `GEMINI_MODEL` / `GEMINI_FALLBACK_MODEL` in the same file.
Run `python check_gemini.py` (inside the venv) to see which models your key can use and how fast they respond.
Note: college / Google Workspace accounts are often blocked from the Gemini API (403); use a personal Gmail.

## 2. Run with Docker Compose (easiest)

```bash
docker compose up --build
```
Open <http://localhost:8080>. Nginx serves the UI and proxies `/api/*` to FastAPI; the backend port is not exposed.
The backend image build fails if Bandit or Semgrep is not usable inside it.

## 3. Run locally (development)

Requires Python 3.11+ and Node 20+.

```bash
# backend  (terminal 1)
cd backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# frontend (terminal 2)
cd frontend
npm install
npm run dev                        # http://localhost:5173  (proxies /api to :8000)
```

> Semgrep does not support native Windows. On Windows use WSL2 or Docker; Bandit-only (Python) scanning still works.

## 4. Tests

```bash
cd backend
python -m pytest -q
# inside Docker:
docker compose exec backend python -m pytest -q
```
Covers health, real detection for every extension, unsupported/oversized/empty/binary uploads, scanner
timeout/crash/missing/bad output, `shell=False`, missing Gemini key, Gemini failure, invented-finding
filtering, AI rate limit, prompt bounding, prioritization and HTML escaping. Gemini is always mocked.

```bash
cd frontend && npm run build       # production build check
```

---

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Status, scanner availability, whether Gemini is configured |
| POST | `/api/scan` | `multipart/form-data` field `file` → normalized, prioritized findings |
| POST | `/api/analyze` | `{language, findings}` → Gemini explanations keyed by finding id |
| POST | `/api/report?format=html\|json` | `{scan, analyses}` → downloadable report |

Errors always look like `{"error": {"status": 415, "message": "Unsupported file type…"}}`.
Codes: 400 empty/binary/non-UTF-8, 413 too large, 415 bad extension, 422 invalid body or unparsable file,
429 rate limit, 502 scanner or Gemini failure, 503 scanner missing / Gemini not configured / busy, 504 scan timeout.

Finding schema: `id, language, scanner, rule_id, title, message, severity, confidence, cwe, filename, line, code_snippet, priority, priority_score`.

## Prioritization rules

Original scanner severity and confidence are kept unchanged; priority is added on top.

- `score = severity_weight × 10 + confidence_weight` — severity HIGH 3 / MEDIUM 2 / LOW 1 / INFO 0; confidence HIGH 3 / MEDIUM 2 / LOW 1 / unknown 2
- **P1 (fix first)**: HIGH severity with MEDIUM, HIGH or unknown confidence
- **P2 (fix soon)**: HIGH severity with LOW confidence, or any MEDIUM severity
- **P3 (review)**: LOW and INFO
- Sorted by score, then line number. Semgrep `ERROR/WARNING/INFO` map to `HIGH/MEDIUM/LOW`.

## Security design

- Uploaded code is written to a private temp dir, read by the scanner, and deleted. It is never run, imported, or used to install packages.
- Scanners run via `subprocess.run([...], shell=False, timeout=…)`; max 2 concurrent scans.
- Extension allow-list, size limit (default 500 KB, read with a hard cap), UTF-8 and binary checks, filename sanitizing.
- Gemini: at most 20 highest-priority findings per call, snippets/messages truncated, output token cap, code marked as untrusted
  data in the prompt, and any result for a finding id that wasn't sent is discarded, so the AI cannot add findings.
- Per-IP rate limits: 20 scans/min, 5 AI calls/min (in memory; resets on restart).
- HTML reports escape every value and include a CSP that blocks scripts.
- CORS restricted to configured origins; Nginx adds security headers.

All limits are configurable in `backend/.env` (see `.env.example`).

## Deployment (Vercel) and CI/CD

The whole app runs as **one Vercel project**: the React build is served as static files and
`api/index.py` runs the FastAPI backend as a Python function (Bandit and Semgrep are bundled as
Python packages; 2 GB memory, up to 120 s per request, see `vercel.json`).

`.github/workflows/ci-cd.yml` runs on every push and pull request:

| Job | What it checks |
|---|---|
| Backend tests | `pytest` with real Bandit/Semgrep and mocked Gemini |
| Frontend build | `npm ci && npm run build` |
| Docker images build | `docker compose build` (the self-hosting path still works) |
| Deploy | Only if all three pass: production deploy on `main`, preview deploy on PRs |

Vercel's Git integration also deploys every push to `main` automatically. If you want deployments to happen
**only** after CI passes, add `"git": {"deploymentEnabled": false}` to `vercel.json` and set up the three
secrets below so the Deploy job takes over.

### Optional: deploy from GitHub Actions instead

1. **Create the Vercel project**: vercel.com → *Add New → Project* → import this GitHub repo →
   keep the defaults (settings come from `vercel.json`) → Deploy.
2. **Add environment variables** in Vercel → Project → *Settings → Environment Variables*
   (Production and Preview):
   - `GEMINI_API_KEY` = your key (optional; scanning works without it)
   - `TRUST_PROXY` = `true`
   - optional: `GEMINI_MODEL`, `GEMINI_FALLBACK_MODEL`
3. **Create a Vercel token**: vercel.com/account/tokens → *Create* (scope: your account).
4. **Add three GitHub secrets**: repo → *Settings → Secrets and variables → Actions → New repository secret*
   - `VERCEL_TOKEN`: the token from step 3
   - `VERCEL_ORG_ID`: Vercel → *Account/Team Settings → General → ID* (starts with `team_`)
   - `VERCEL_PROJECT_ID`: Vercel → Project → *Settings → General → Project ID* (starts with `prj_`)
5. Re-run the workflow (Actions → CI/CD → *Run workflow*) or push a commit.

Until the secrets exist the Deploy job is skipped with a warning; CI still runs.

### Self-hosting instead

Any VM with Docker: `git clone`, create `backend/.env`, `docker compose up -d --build`, and put HTTPS in front.
The in-memory rate limiter is per instance (on Vercel, per function instance), which is fine for a demo but not a
hard global limit.

## Project layout

```
securelens-ai/
├── frontend/   index.html, vite.config.js, nginx.conf, Dockerfile, src/{main.jsx, App.jsx, api.js, style.css}
├── backend/    app/{__init__,main,config,scanner,ai_service,risk,report}.py, rules/semgrep.yml,
│               tests/test_api.py, requirements.txt, .env.example, Dockerfile
├── api/index.py              Vercel entry point (imports backend/app)
├── vercel.json, requirements.txt
├── .github/workflows/ci-cd.yml
├── compose.yaml
└── README.md
```
Small deviations from the original spec: `app/__init__.py` (Python needs this exact name), `rules/semgrep.yml`
(the explicit Semgrep rules), and a `/api/report` endpoint so the HTML report is escaped server-side.

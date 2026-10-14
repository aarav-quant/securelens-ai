"""API tests. Real Bandit/Semgrep are used for detection tests; Gemini is always mocked."""

import shutil
import subprocess
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app import ai_service, main
from app.config import settings
from app.report import build_html_report
from app.risk import Finding, prioritize

client = TestClient(main.app)

SAMPLES = {
    "app.py": ("import subprocess\npassword = 'hunter2'\ndef run(u):\n    subprocess.call('ls ' + u, shell=True)\n    eval(u)\n",
               "python", "B602"),
    "app.js": ("function f(userInput, db, req) {\n  eval(userInput);\n  db.query('SELECT * FROM t WHERE id = ' + req.params.id);\n}\n",
               "javascript", "js-eval-injection"),
    "app.ts": ("export function f(input: string, el: HTMLElement): void {\n  el.innerHTML = input;\n  eval(input);\n}\n",
               "typescript", "js-innerhtml-xss"),
    "View.tsx": ("export const V = ({ h }: { h: string }) => <div dangerouslySetInnerHTML={{ __html: h }} />;\n",
                 "typescript", "react-dangerously-set-inner-html"),
    "View.jsx": ("export const V = ({ h }) => <div dangerouslySetInnerHTML={{ __html: h }} />;\n",
                 "javascript", "react-dangerously-set-inner-html"),
    "App.java": ("public class App {\n  void run(String u, java.sql.Statement st) throws Exception {\n"
                 "    Runtime.getRuntime().exec(\"ping \" + u);\n"
                 "    st.executeQuery(\"SELECT * FROM t WHERE n='\" + u + \"'\");\n  }\n}\n",
                 "java", "java-command-injection"),
}


@pytest.fixture(autouse=True)
def reset_state(monkeypatch):
    main._hits.clear()
    monkeypatch.setattr(settings, "gemini_api_key", "")


def upload(name, content, ctype="text/plain"):
    data = content.encode() if isinstance(content, str) else content
    return client.post("/api/scan", files={"file": (name, data, ctype)})


def make_finding(fid="S1", severity="HIGH", confidence="HIGH", line=3):
    f = Finding(id=fid, language="javascript", scanner="semgrep", rule_id="js-eval-injection",
                title="Code injection via eval()", message="eval is dangerous", severity=severity,
                confidence=confidence, filename="app.js", line=line, code_snippet="   3 | eval(x)")
    return prioritize([f])[0]


# ---------- health ----------
def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["ai_enabled"] is False
    assert ".java" in body["supported_extensions"]


# ---------- real detection, one test per language / extension ----------
@pytest.mark.parametrize("name", list(SAMPLES))
def test_detects_vulnerabilities(name):
    tool = "bandit" if name.endswith(".py") else "semgrep"
    if not shutil.which(tool):
        pytest.skip(f"{tool} not installed")
    content, language, expected_rule = SAMPLES[name]
    r = upload(name, content)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["language"] == language and body["scanner"] == tool
    assert body["summary"]["total"] == len(body["findings"]) > 0
    rules = [f["rule_id"] for f in body["findings"]]
    assert any(expected_rule in rule for rule in rules), rules
    first = body["findings"][0]
    assert first["filename"] == name and first["line"] > 0 and first["code_snippet"]


def test_detects_sql_injection_java_and_js():
    if not shutil.which("semgrep"):
        pytest.skip("semgrep not installed")
    for name in ("App.java", "app.js"):
        rules = [f["rule_id"] for f in upload(name, SAMPLES[name][0]).json()["findings"]]
        assert any("sql-injection" in r for r in rules), (name, rules)


def test_clean_file_has_no_findings():
    if not shutil.which("semgrep"):
        pytest.skip("semgrep not installed")
    r = upload("ok.js", "const add = (a, b) => a + b;\nexport default add;\n")
    assert r.status_code == 200 and r.json()["findings"] == []
    assert "does not guarantee" in r.json()["disclaimer"]


# ---------- input validation ----------
@pytest.mark.parametrize("name", ["notes.txt", "script.sh", "evil.py.exe", "noext"])
def test_unsupported_file_type(name):
    r = upload(name, "print(1)")
    assert r.status_code == 415
    assert "Unsupported" in r.json()["error"]["message"]


def test_oversized_file(monkeypatch):
    monkeypatch.setattr(settings, "max_upload_bytes", 100)
    r = upload("big.py", "x = 1\n" * 50)
    assert r.status_code == 413


def test_empty_and_binary_files():
    assert upload("empty.py", "   \n").status_code == 400
    assert upload("bin.js", b"\x00\x01\x02").status_code == 400
    assert upload("latin.py", "x = 'caf\xe9'".encode("latin-1")).status_code == 400


def test_path_traversal_filename_is_sanitized():
    if not shutil.which("bandit"):
        pytest.skip("bandit not installed")
    r = upload("../../etc/evil name.py", "eval(input())\n")
    assert r.status_code == 200
    assert r.json()["filename"] == "evil_name.py"


# ---------- scanner failures ----------
def test_scanner_timeout(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="bandit", timeout=1)
    monkeypatch.setattr("app.scanner.subprocess.run", boom)
    r = upload("a.py", "eval(input())\n")
    assert r.status_code == 504 and "timed out" in r.json()["error"]["message"]


def test_scanner_crash(monkeypatch):
    monkeypatch.setattr("app.scanner.subprocess.run",
                        lambda *a, **k: SimpleNamespace(returncode=2, stdout="", stderr="crash"))
    r = upload("a.js", "eval(x)\n")
    assert r.status_code == 502 and "failed" in r.json()["error"]["message"]


def test_scanner_bad_output(monkeypatch):
    monkeypatch.setattr("app.scanner.subprocess.run",
                        lambda *a, **k: SimpleNamespace(returncode=0, stdout="not json", stderr=""))
    r = upload("A.java", "class A {}\n")
    assert r.status_code == 502


def test_scanner_missing(monkeypatch):
    def missing(*a, **k):
        raise FileNotFoundError("semgrep")
    monkeypatch.setattr("app.scanner.subprocess.run", missing)
    assert upload("a.ts", "let x = 1;\n").status_code == 503


def test_subprocess_never_uses_shell(monkeypatch):
    seen = {}

    def fake_run(cmd, **kwargs):
        seen.update(kwargs, cmd=cmd)
        return SimpleNamespace(returncode=0, stdout='{"results": [], "errors": []}', stderr="")
    monkeypatch.setattr("app.scanner.subprocess.run", fake_run)
    assert upload("x; rm -rf ~.py", "x = 1\n").status_code == 200
    assert seen["shell"] is False and isinstance(seen["cmd"], list) and "timeout" in seen


# ---------- Gemini (mocked) ----------
def analyze_payload():
    return {"language": "javascript", "findings": [make_finding().model_dump()]}


def test_analyze_without_api_key():
    r = client.post("/api/analyze", json=analyze_payload())
    assert r.status_code == 503 and "GEMINI_API_KEY" in r.json()["error"]["message"]


def fake_client(response=None, error=None):
    def generate_content(**kwargs):
        if error:
            raise error
        return response
    return lambda: SimpleNamespace(models=SimpleNamespace(generate_content=generate_content))


def test_analyze_api_failure(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-key")
    monkeypatch.setattr(ai_service, "_client", fake_client(error=RuntimeError("quota exceeded")))
    r = client.post("/api/analyze", json=analyze_payload())
    assert r.status_code == 502 and "unaffected" in r.json()["error"]["message"]


def test_analyze_success_drops_invented_findings(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-key")
    parsed = [
        ai_service.AIExplanation(finding_id="S1", explanation="eval runs strings as code",
                                 impact="RCE in the browser", remediation="Use JSON.parse", secure_example="JSON.parse(x)"),
        ai_service.AIExplanation(finding_id="FAKE9", explanation="invented", impact="", remediation=""),
    ]
    monkeypatch.setattr(ai_service, "_client", fake_client(response=SimpleNamespace(parsed=parsed, text="")))
    r = client.post("/api/analyze", json=analyze_payload())
    assert r.status_code == 200
    analyses = r.json()["analyses"]
    assert list(analyses) == ["S1"] and analyses["S1"]["remediation"] == "Use JSON.parse"


def test_analyze_json_text_fallback(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-key")
    text = '[{"finding_id":"S1","explanation":"e","impact":"i","remediation":"r","secure_example":""}]'
    monkeypatch.setattr(ai_service, "_client", fake_client(response=SimpleNamespace(parsed=None, text=text)))
    assert client.post("/api/analyze", json=analyze_payload()).json()["analyses"]["S1"]["impact"] == "i"


def test_analyze_rate_limited(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-key")
    monkeypatch.setattr(settings, "ai_requests_per_minute", 2)
    monkeypatch.setattr(ai_service, "_client", fake_client(response=SimpleNamespace(parsed=[], text="[]")))
    codes = [client.post("/api/analyze", json=analyze_payload()).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_prompt_is_bounded():
    f = make_finding()
    f.code_snippet = "A" * 10_000
    prompt = ai_service.build_prompt("javascript", [f])
    assert len(prompt) < 2_000 and "[truncated]" in prompt


# ---------- prioritization ----------
def test_severity_prioritization():
    findings = prioritize([
        make_finding("a", "LOW", "HIGH", line=1),
        make_finding("b", "HIGH", "LOW", line=2),
        make_finding("c", "MEDIUM", "HIGH", line=3),
        make_finding("d", "HIGH", "HIGH", line=9),
        make_finding("e", "HIGH", None, line=4),
    ])
    assert [f.id for f in findings] == ["d", "e", "b", "c", "a"]
    assert {f.id: f.priority for f in findings} == {"d": "P1", "e": "P1", "b": "P2", "c": "P2", "a": "P3"}
    # Original scanner values are preserved.
    assert findings[2].severity == "HIGH" and findings[2].confidence == "LOW"


# ---------- reports ----------
def test_html_report_escapes_content():
    evil = "<script>alert('x')</script>"
    f = make_finding().model_dump()
    f.update(title=evil, message=evil, code_snippet=evil)
    scan = {"scan_id": "1", "filename": "<img src=x onerror=alert(1)>.js", "language": "javascript",
            "scanner": "semgrep", "scanned_at": "now", "summary": {"total": 1}, "findings": [f]}
    html = build_html_report(scan, {"S1": {"explanation": evil, "impact": "", "remediation": "", "secure_example": evil}})
    assert "<script>" not in html and "<img" not in html
    assert "&lt;script&gt;" in html and "Content-Security-Policy" in html


def test_report_endpoint_html_and_json():
    scan = {"scan_id": "1", "filename": "app.js", "language": "javascript", "scanner": "semgrep",
            "scanned_at": "now", "summary": {"total": 1}, "findings": [make_finding().model_dump()]}
    r = client.post("/api/report?format=html", json={"scan": scan, "analyses": {}})
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "attachment" in r.headers["content-disposition"]
    j = client.post("/api/report?format=json", json={"scan": scan, "analyses": {"S1": {"explanation": "x"}}}).json()
    assert j["findings"][0]["ai"]["explanation"] == "x" and j["tool"] == "SecureLens AI"


def test_analyze_retries_then_falls_back_on_503(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-key")
    monkeypatch.setattr(settings, "gemini_model", "main-model")
    monkeypatch.setattr(settings, "gemini_fallback_models", ["backup-model"])
    monkeypatch.setattr(ai_service, "RETRY_DELAY_SECONDS", 0)
    calls = []
    ok = SimpleNamespace(parsed=[ai_service.AIExplanation(finding_id="S1", explanation="e", impact="i", remediation="r")], text="")

    class Busy(Exception):
        code = 503

    def generate_content(model, **kwargs):
        calls.append(model)
        if model == "main-model":
            raise Busy("high demand")
        return ok
    monkeypatch.setattr(ai_service, "_client",
                        lambda: SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)))
    r = client.post("/api/analyze", json=analyze_payload())
    assert r.status_code == 200 and "S1" in r.json()["analyses"]
    assert calls == ["main-model", "main-model", "backup-model"]


def test_analyze_does_not_retry_auth_errors(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-key")
    calls = []

    class Denied(Exception):
        code = 403

    def generate_content(model, **kwargs):
        calls.append(model)
        raise Denied("denied access")
    monkeypatch.setattr(ai_service, "_client",
                        lambda: SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)))
    r = client.post("/api/analyze", json=analyze_payload())
    assert r.status_code == 502 and "403" in r.json()["error"]["message"] and len(calls) == 1


def test_analyze_walks_fallback_list(monkeypatch):
    monkeypatch.setattr(settings, "gemini_api_key", "test-key")
    monkeypatch.setattr(settings, "gemini_model", "main")
    monkeypatch.setattr(settings, "gemini_fallback_models", ["gone", "busy", "ok"])
    monkeypatch.setattr(ai_service, "RETRY_DELAY_SECONDS", 0)
    calls = []
    ok = SimpleNamespace(parsed=[ai_service.AIExplanation(finding_id="S1", explanation="e", impact="i", remediation="r")], text="")

    def err(code):
        e = Exception(f"error {code}")
        e.code = code
        return e

    def generate_content(model, **kwargs):
        calls.append(model)
        if model == "main" or model == "busy":
            raise err(503)
        if model == "gone":
            raise err(404)
        return ok
    monkeypatch.setattr(ai_service, "_client",
                        lambda: SimpleNamespace(models=SimpleNamespace(generate_content=generate_content)))
    r = client.post("/api/analyze", json=analyze_payload())
    assert r.status_code == 200
    assert calls == ["main", "main", "gone", "busy", "ok"]

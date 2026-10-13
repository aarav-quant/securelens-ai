"""Runs Bandit (Python) or Semgrep (JS/TS/Java) on an uploaded file and normalizes results.

Uploaded code is only written to a private temp file and read by the scanners.
It is never imported, executed, or used to install dependencies.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from .config import settings
from .risk import Finding, normalize_level, prioritize

LANGUAGES = {
    ".py": ("python", "bandit"),
    ".js": ("javascript", "semgrep"),
    ".jsx": ("javascript", "semgrep"),
    ".ts": ("typescript", "semgrep"),
    ".tsx": ("typescript", "semgrep"),
    ".java": ("java", "semgrep"),
}

_scan_slots = threading.BoundedSemaphore(settings.max_concurrent_scans)


class ScanError(Exception):
    """Scanner crashed, returned bad output, or is missing (-> HTTP 502/503)."""

    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class ScanTimeout(ScanError):
    def __init__(self, message: str):
        super().__init__(message, status_code=504)


def detect_language(filename: str) -> tuple[str, str] | None:
    return LANGUAGES.get(Path(filename).suffix.lower())


def safe_filename(name: str) -> str:
    base = os.path.basename(name or "").strip()
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return base[-100:] or "upload"


# How to start each scanner when its command is not on PATH (e.g. on Vercel, where only
# the Python packages are bundled): run it through the current Python interpreter.
_MODULE_CMD = {
    "bandit": [sys.executable, "-m", "bandit"],
    "semgrep": [sys.executable, "-c", "import sys, semgrep.main; sys.exit(semgrep.main.main())"],
}


def tool_cmd(tool: str) -> list[str]:
    path = shutil.which(tool)
    return [path] if path else list(_MODULE_CMD[tool])


def scanners_available() -> dict[str, bool]:
    import importlib.util

    return {t: shutil.which(t) is not None or importlib.util.find_spec(t) is not None for t in _MODULE_CMD}


def _snippet(lines: list[str], line: int, context: int = 1) -> str | None:
    if line < 1 or line > len(lines):
        return None
    start, end = max(1, line - context), min(len(lines), line + context)
    return "\n".join(f"{n:>4} | {lines[n - 1][:300]}" for n in range(start, end + 1))


def _run(tool: str, args: list[str], ok_codes: tuple[int, ...], workdir: str) -> dict:
    # Argument list + no shell: the file path can never be interpreted as shell syntax.
    cmd = tool_cmd(tool) + args
    env = {**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"}
    if not os.access(os.path.expanduser("~"), os.W_OK):
        # Serverless hosts have a read-only home; Semgrep needs somewhere to write its settings.
        env.update(HOME=workdir, XDG_CACHE_HOME=workdir, XDG_CONFIG_HOME=workdir)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=settings.scan_timeout_seconds,
            shell=False, check=False, env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanTimeout(f"{tool} timed out after {settings.scan_timeout_seconds}s") from exc
    except FileNotFoundError as exc:
        raise ScanError(f"{tool} is not installed on the server", status_code=503) from exc
    if proc.returncode not in ok_codes:
        raise ScanError(f"{tool} failed (exit code {proc.returncode})")
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ScanError(f"{tool} returned unreadable output") from exc


def _bandit(path: str, display_name: str, lines: list[str]) -> list[Finding]:
    # Exit code 0 = no issues, 1 = issues found; anything else is a failure.
    data = _run("bandit", ["-f", "json", "-q", path], ok_codes=(0, 1), workdir=os.path.dirname(path))
    if data.get("errors"):
        raise ScanError("Bandit could not parse the file (is it valid Python?)", status_code=422)
    out = []
    for i, r in enumerate(data.get("results", []), 1):
        line = int(r.get("line_number") or 0)
        cwe = r.get("issue_cwe") or {}
        out.append(Finding(
            id=f"B{i}", language="python", scanner="bandit",
            rule_id=f"{r.get('test_id', '')}:{r.get('test_name', '')}"[:200],
            title=(r.get("issue_text") or "Bandit finding")[:300],
            message=(r.get("issue_text") or "")[:2000],
            severity=normalize_level(r.get("issue_severity")) or "LOW",
            confidence=normalize_level(r.get("issue_confidence")),
            cwe=f"CWE-{cwe['id']}" if cwe.get("id") else None,
            filename=display_name, line=line, code_snippet=_snippet(lines, line),
        ))
    return out


def _semgrep(path: str, language: str, display_name: str, lines: list[str]) -> list[Finding]:
    if not settings.semgrep_rules.exists():
        raise ScanError("Semgrep rules file is missing on the server", status_code=503)
    args = [
        "scan", "--config", str(settings.semgrep_rules), "--json", "--quiet",
        "--metrics=off", "--disable-version-check", "--no-git-ignore",
        "--timeout", str(settings.scan_timeout_seconds), path,
    ]
    data = _run("semgrep", args, ok_codes=(0, 1), workdir=os.path.dirname(path))
    out, seen = [], set()
    for i, r in enumerate(data.get("results", []), 1):
        # Two rule variants can flag the same issue on the same line: keep one.
        key = (r.get("start", {}).get("line"), r.get("extra", {}).get("metadata", {}).get("title"))
        if key in seen:
            continue
        seen.add(key)
        extra, meta = r.get("extra", {}), r.get("extra", {}).get("metadata", {})
        line = int(r.get("start", {}).get("line") or 0)
        cwe = meta.get("cwe")
        out.append(Finding(
            id=f"S{i}", language=language, scanner="semgrep",
            rule_id=str(r.get("check_id", "")).split(".")[-1][:200],
            title=str(meta.get("title") or r.get("check_id", "Semgrep finding"))[:300],
            message=str(extra.get("message", ""))[:2000],
            severity=normalize_level(extra.get("severity")) or "LOW",
            confidence=normalize_level(meta.get("confidence")),
            cwe=(", ".join(cwe) if isinstance(cwe, list) else cwe) or None,
            filename=display_name, line=line, code_snippet=_snippet(lines, line),
        ))
    return out


def scan_source(filename: str, source: str) -> tuple[str, str, list[Finding]]:
    """Scan one file's source text. Returns (language, scanner, prioritized findings)."""
    detected = detect_language(filename)
    if not detected:
        raise ValueError("Unsupported file type")
    language, scanner = detected
    display_name = safe_filename(filename)
    lines = source.splitlines()

    if not _scan_slots.acquire(timeout=30):
        raise ScanError("Server is busy, please retry shortly", status_code=503)
    try:
        # Private (0700) temp dir, random file name, keeps only the extension; always removed.
        with tempfile.TemporaryDirectory(prefix="securelens-") as tmp:
            path = os.path.join(tmp, "target" + Path(filename).suffix.lower())
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(source)
            if scanner == "bandit":
                findings = _bandit(path, display_name, lines)
            else:
                findings = _semgrep(path, language, display_name, lines)
    finally:
        _scan_slots.release()
    return language, scanner, prioritize(findings)

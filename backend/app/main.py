"""SecureLens AI FastAPI app: /api/health, /api/scan, /api/analyze, /api/report."""

import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .ai_service import AIFailure, AIUnavailable, analyze_findings
from .config import settings
from .report import DISCLAIMER, build_html_report, build_json_report
from .risk import Finding, summarize
from .scanner import LANGUAGES, ScanError, detect_language, safe_filename, scan_source, scanners_available

app = FastAPI(title="SecureLens AI", version=__version__)
app.add_middleware(
    CORSMiddleware, allow_origins=settings.cors_origins, allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"], allow_credentials=False,
)


# ---------- consistent error shape: {"error": {"status": int, "message": str}} ----------
@app.exception_handler(StarletteHTTPException)
async def http_error(_: Request, exc: StarletteHTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": {"status": exc.status_code, "message": exc.detail}})


@app.exception_handler(RequestValidationError)
async def validation_error(_: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    where = ".".join(str(p) for p in first.get("loc", []) if p != "body")
    msg = f"Invalid request: {where} {first.get('msg', '')}".strip()
    return JSONResponse(status_code=422, content={"error": {"status": 422, "message": msg}})


# ---------- tiny in-memory rate limiter (per client IP, sliding 60 s window) ----------
_hits: dict[str, deque] = defaultdict(deque)
_hits_lock = threading.Lock()


def rate_limit(request: Request, bucket: str, per_minute: int) -> None:
    ip = request.headers.get("x-real-ip") if settings.trust_proxy else None
    key = f"{bucket}:{ip or (request.client.host if request.client else 'unknown')}"
    now = time.monotonic()
    with _hits_lock:
        q = _hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= per_minute:
            raise HTTPException(429, f"Too many requests. Limit is {per_minute} per minute; please wait.")
        q.append(now)


# ---------- schemas ----------
class ScanResult(BaseModel):
    scan_id: str = Field(max_length=64)
    filename: str = Field(max_length=120)
    language: str = Field(max_length=20)
    scanner: str = Field(max_length=20)
    scanned_at: str = Field(max_length=64)
    duration_ms: int = 0
    summary: dict = {}
    findings: list[Finding] = Field(default=[], max_length=1000)
    disclaimer: str = DISCLAIMER


class AnalyzeRequest(BaseModel):
    language: Literal["python", "javascript", "typescript", "java"]
    findings: list[Finding] = Field(min_length=1, max_length=200)


class AIResult(BaseModel):
    explanation: str = Field(default="", max_length=3100)
    impact: str = Field(default="", max_length=3100)
    remediation: str = Field(default="", max_length=3100)
    secure_example: str = Field(default="", max_length=3100)


class ReportRequest(BaseModel):
    scan: ScanResult
    analyses: dict[str, AIResult] = {}


# ---------- routes ----------
@app.get("/api/health")
def health():
    return {
        "status": "ok", "version": __version__, "scanners": scanners_available(),
        "ai_enabled": settings.ai_enabled, "ai_model": settings.gemini_model if settings.ai_enabled else None,
        "supported_extensions": sorted(LANGUAGES), "max_upload_bytes": settings.max_upload_bytes,
    }


@app.post("/api/scan", response_model=ScanResult)
async def scan(request: Request, file: UploadFile = File(...)):
    rate_limit(request, "scan", settings.scan_requests_per_minute)
    name = file.filename or ""
    if not detect_language(name):
        raise HTTPException(415, f"Unsupported file type. Allowed: {', '.join(sorted(LANGUAGES))}")
    raw = await file.read(settings.max_upload_bytes + 1)  # never read more than the limit + 1 byte
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(413, f"File too large. Maximum is {settings.max_upload_bytes // 1000} KB.")
    if b"\x00" in raw:
        raise HTTPException(400, "File looks binary. Upload a plain-text source file.")
    try:
        source = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be UTF-8 encoded text.")
    if not source.strip():
        raise HTTPException(400, "File is empty.")

    started = time.perf_counter()
    try:
        language, scanner, findings = await run_in_threadpool(scan_source, name, source)
    except ScanError as exc:
        raise HTTPException(exc.status_code, str(exc))
    return ScanResult(
        scan_id=uuid.uuid4().hex, filename=safe_filename(name), language=language, scanner=scanner,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        duration_ms=int((time.perf_counter() - started) * 1000),
        summary=summarize(findings), findings=findings,
    )


@app.post("/api/analyze")
async def analyze(request: Request, body: AnalyzeRequest):
    if not settings.ai_enabled:
        raise HTTPException(503, "Gemini is not configured. Set GEMINI_API_KEY to enable AI explanations.")
    rate_limit(request, "ai", settings.ai_requests_per_minute)
    # Highest-priority findings first, capped to bound prompt size and cost.
    selected = sorted(body.findings, key=lambda f: -f.priority_score)[: settings.ai_max_findings]
    try:
        analyses = await run_in_threadpool(analyze_findings, body.language, selected)
    except AIUnavailable as exc:
        raise HTTPException(503, str(exc))
    except AIFailure as exc:
        raise HTTPException(502, f"{exc}. Scan results are unaffected; try again later.")
    return {
        "model": settings.gemini_model, "analyses": analyses,
        "analyzed": len(analyses), "requested": len(body.findings),
        "skipped": max(0, len(body.findings) - len(selected)),
    }


@app.post("/api/report")
def report(body: ReportRequest, format: Literal["html", "json"] = Query("html")):
    scan_dict = body.scan.model_dump()
    analyses = {k: v.model_dump() for k, v in body.analyses.items()}
    stem = safe_filename(body.scan.filename).rsplit(".", 1)[0] or "report"
    headers = {"Content-Disposition": f'attachment; filename="securelens-{stem}.{format}"'}
    if format == "json":
        return JSONResponse(build_json_report(scan_dict, analyses), headers=headers)
    return HTMLResponse(build_html_report(scan_dict, analyses), headers=headers)

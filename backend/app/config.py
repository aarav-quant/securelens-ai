"""Application settings, read once from environment variables (and an optional .env file)."""

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()  # loads backend/.env when running locally; harmless if missing


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


class Settings:
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "").strip()
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite").strip()
    gemini_fallback_model: str = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-3.6-flash").strip()
    gemini_timeout_seconds: int = _int("GEMINI_TIMEOUT_SECONDS", 90)

    max_upload_bytes: int = _int("MAX_UPLOAD_BYTES", 500_000)        # 500 KB
    scan_timeout_seconds: int = _int("SCAN_TIMEOUT_SECONDS", 60)
    max_concurrent_scans: int = _int("MAX_CONCURRENT_SCANS", 2)

    ai_max_findings: int = _int("AI_MAX_FINDINGS", 20)               # findings per /analyze call
    ai_requests_per_minute: int = _int("AI_REQUESTS_PER_MINUTE", 5)  # per client IP
    scan_requests_per_minute: int = _int("SCAN_REQUESTS_PER_MINUTE", 20)

    cors_origins: list[str] = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")
        if o.strip()
    ]
    trust_proxy: bool = os.getenv("TRUST_PROXY", "false").lower() == "true"

    semgrep_rules: Path = Path(__file__).resolve().parent.parent / "rules" / "semgrep.yml"

    @property
    def ai_enabled(self) -> bool:
        return bool(self.gemini_api_key)


settings = Settings()

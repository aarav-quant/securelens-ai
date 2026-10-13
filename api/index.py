"""Vercel entry point: exposes the FastAPI app from backend/ as a Python serverless function.

vercel.json rewrites every /api/* request here; FastAPI then routes /api/health, /api/scan, ...
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.main import app  # noqa: E402,F401  (Vercel looks for a variable named `app`)

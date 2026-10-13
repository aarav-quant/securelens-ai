"""Shared finding schema and documented risk-prioritization rules.

Prioritization (original scanner severity/confidence are never changed):
  score    = severity_weight * 10 + confidence_weight
             severity:   HIGH=3, MEDIUM=2, LOW=1, INFO=0
             confidence: HIGH=3, MEDIUM=2, LOW=1, unknown=2 (treated as MEDIUM)
  priority = P1  HIGH severity with MEDIUM/HIGH/unknown confidence   -> fix first
             P2  HIGH severity with LOW confidence, or MEDIUM severity
             P3  everything else (LOW / INFO)
Sort order: score descending, then line number ascending.
"""

from typing import Optional

from pydantic import BaseModel, Field

SEVERITIES = ("HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
CONFIDENCE_WEIGHT = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


class Finding(BaseModel):
    id: str = Field(max_length=40)
    language: str = Field(max_length=20)
    scanner: str = Field(max_length=20)
    rule_id: str = Field(max_length=200)
    title: str = Field(max_length=300)
    message: str = Field(default="", max_length=2000)
    severity: str = Field(max_length=10)
    confidence: Optional[str] = Field(default=None, max_length=10)
    cwe: Optional[str] = Field(default=None, max_length=200)
    filename: str = Field(max_length=120)
    line: int = Field(ge=0)
    code_snippet: Optional[str] = Field(default=None, max_length=2000)
    priority: str = Field(default="P3", max_length=2)
    priority_score: int = 0


def normalize_level(value: Optional[str]) -> Optional[str]:
    """Map scanner-specific labels (ERROR/WARNING/INFO, HIGH/...) onto HIGH/MEDIUM/LOW/INFO."""
    if not value:
        return None
    v = str(value).strip().upper()
    return {"ERROR": "HIGH", "CRITICAL": "HIGH", "WARNING": "MEDIUM", "MODERATE": "MEDIUM"}.get(
        v, v if v in SEVERITIES else None
    )


def score(severity: str, confidence: Optional[str]) -> tuple[int, str]:
    sev = SEVERITY_WEIGHT.get(severity, 0)
    conf = CONFIDENCE_WEIGHT.get(confidence or "", 2)
    if severity == "HIGH" and conf >= 2:
        priority = "P1"
    elif severity in ("HIGH", "MEDIUM"):
        priority = "P2"
    else:
        priority = "P3"
    return sev * 10 + conf, priority


def prioritize(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        f.priority_score, f.priority = score(f.severity, f.confidence)
    return sorted(findings, key=lambda f: (-f.priority_score, f.line))


def summarize(findings: list[Finding]) -> dict:
    by_sev = {s: 0 for s in SEVERITIES}
    by_pri = {"P1": 0, "P2": 0, "P3": 0}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_pri[f.priority] = by_pri.get(f.priority, 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_priority": by_pri}

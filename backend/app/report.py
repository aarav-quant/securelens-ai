"""HTML / JSON report generation. Every value from the scan is HTML-escaped."""

from datetime import datetime, timezone
from html import escape

from . import __version__

DISCLAIMER = (
    "Static analysis finds potential issues using known patterns. A clean scan does not "
    "guarantee the code is secure; review findings and test your application."
)

SEV_COLOR = {"HIGH": "#ff5c7a", "MEDIUM": "#ffb547", "LOW": "#4fc3f7", "INFO": "#9aa8bd"}


def _e(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def build_json_report(scan: dict, analyses: dict) -> dict:
    findings = [{**f, "ai": analyses.get(f.get("id"))} for f in scan.get("findings", [])]
    return {
        "tool": "SecureLens AI", "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan": {k: scan.get(k) for k in ("scan_id", "filename", "language", "scanner", "scanned_at", "duration_ms")},
        "summary": scan.get("summary", {}),
        "findings": findings,
        "disclaimer": DISCLAIMER,
    }


def build_html_report(scan: dict, analyses: dict) -> str:
    data = build_json_report(scan, analyses)
    s = data["summary"].get("by_severity", {})
    rows = []
    for f in data["findings"]:
        sev = f.get("severity", "INFO")
        ai = f.get("ai") or {}
        ai_html = ""
        if ai:
            ai_html = (
                f"<div class='ai'><h4>AI explanation</h4><p>{_e(ai.get('explanation'))}</p>"
                f"<h4>Impact</h4><p>{_e(ai.get('impact'))}</p>"
                f"<h4>Recommendation</h4><p>{_e(ai.get('remediation'))}</p>"
                + (f"<h4>Secure example</h4><pre>{_e(ai.get('secure_example'))}</pre>" if ai.get("secure_example") else "")
                + "</div>"
            )
        rows.append(
            f"<section class='f'><div class='hd'><span class='sev' style='background:{SEV_COLOR.get(sev, '#9aa8bd')}'>{_e(sev)}</span>"
            f"<span class='pri'>{_e(f.get('priority'))}</span><strong>{_e(f.get('title'))}</strong></div>"
            f"<p class='meta'>{_e(f.get('filename'))}:{_e(f.get('line'))} · rule {_e(f.get('rule_id'))} · "
            f"confidence {_e(f.get('confidence') or 'n/a')} · {_e(f.get('cwe') or '')}</p>"
            f"<p>{_e(f.get('message'))}</p>"
            + (f"<pre>{_e(f.get('code_snippet'))}</pre>" if f.get("code_snippet") else "")
            + ai_html + "</section>"
        )
    sc = data["scan"]
    body = "".join(rows) or "<p>No findings were reported by the scanner.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureLens AI Report - {_e(sc.get('filename'))}</title>
<style>
body{{font-family:system-ui,sans-serif;background:#0b1426;color:#dbe4f3;margin:0;padding:24px;line-height:1.5}}
.wrap{{max-width:960px;margin:auto}} h1{{color:#5ce1e6;margin-bottom:4px}} .muted,.meta{{color:#8b9bb4;font-size:14px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}} .card{{background:#13213d;border-radius:10px;padding:12px 16px;min-width:110px}}
.card b{{display:block;font-size:24px}} .f{{background:#13213d;border-radius:10px;padding:16px;margin:12px 0;border:1px solid #1f3257}}
.hd{{display:flex;gap:8px;align-items:center;flex-wrap:wrap}} .sev,.pri{{border-radius:6px;padding:2px 8px;font-size:12px;font-weight:700;color:#0b1426}}
.pri{{background:#5ce1e6}} pre{{background:#08101f;padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap}}
.ai{{border-left:3px solid #5ce1e6;padding-left:12px;margin-top:12px}} h4{{margin:10px 0 2px;color:#5ce1e6}}
.note{{background:#1a2747;border-radius:8px;padding:12px;margin-top:20px;font-size:14px}}
</style></head><body><div class="wrap">
<h1>SecureLens AI — Security Report</h1>
<p class="muted">File: {_e(sc.get('filename'))} · Language: {_e(sc.get('language'))} · Scanner: {_e(sc.get('scanner'))}
 · Scanned: {_e(sc.get('scanned_at'))} · Report generated: {_e(data['generated_at'])}</p>
<div class="cards"><div class="card">Total<b>{_e(data['summary'].get('total', 0))}</b></div>
<div class="card">High<b>{_e(s.get('HIGH', 0))}</b></div><div class="card">Medium<b>{_e(s.get('MEDIUM', 0))}</b></div>
<div class="card">Low<b>{_e(s.get('LOW', 0))}</b></div><div class="card">Info<b>{_e(s.get('INFO', 0))}</b></div></div>
{body}
<p class="note">{_e(DISCLAIMER)}</p>
</div></body></html>"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlalchemy.orm import Session

from ...db import Finding, Run, get_db_dep, db_get
from ...report import generate_html_report

router = APIRouter(tags=["reports"])

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Rough CVSS 3.1 anchors per severity — a starting point for the triage form,
# never a final score (report-writing skill owns the full CVSS guide).
_CVSS_HINT = {
    "critical": "9.0–10.0 (AV:N/AC:L/PR:N/UI:N/…)",
    "high":     "7.0–8.9  (AV:N/…)",
    "medium":   "4.0–6.9  (AV:N/…)",
    "low":      "0.1–3.9  (AV:N/…)",
}

_PLATFORM_SECTIONS = {
    "hackerone": ["## Summary", "## Steps to Reproduce", "## Impact",
                  "## Supporting Material/References"],
    "bugcrowd":  ["## Description", "## Proof of Concept", "## Impact",
                  "## Remediation"],
}


def _draft_title(f: Finding, target: str) -> str:
    """Title formula: Attack + Component + Impact."""
    attack = (f.template_id or f.name or "Misconfiguration").replace("-", " ").strip()
    return f"{attack.title()} in {f.host} Leads to {f.severity.title()}-Impact Exposure"


def _finding_draft(f: Finding, target: str, sections: list[str]) -> str:
    lines = [f"# {_draft_title(f, target)}", ""]
    lines += [
        f"- **Severity:** {f.severity}",
        f"- **CVSS 3.1 (starting point):** {_CVSS_HINT.get(f.severity, '—')}",
        f"- **Asset:** `{f.host}` ({f.url or '—'})",
        f"- **Template:** `{f.template_id or '—'}`",
        "",
    ]
    body_hdr, poc_hdr = sections[0], sections[1]
    lines += [body_hdr, ""]
    if f.description:
        lines += [f.description.strip(), ""]
    else:
        lines += ["<one-paragraph description — what is broken and why it matters>", ""]
    lines += [poc_hdr, ""]
    if f.evidence:
        lines += ["```", f.evidence.strip(), "```", ""]
    else:
        lines += ["<minimal reproducible curl/request>", ""]
    lines += [sections[2], "", "<business impact — data at risk, blast radius>", ""]
    if len(sections) > 3:
        lines += [sections[3], "", "- " + (f.url or ""), ""]
    return "\n".join(lines)


@router.get("/runs/{run_id}/report", response_class=HTMLResponse)
def get_report(run_id: str, db: Session = Depends(get_db_dep)):
    run = db_get(db, Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status not in ("completed", "failed", "paused"):
        raise HTTPException(400, f"Report not available for status: {run.status}")
    html = generate_html_report(run_id)
    return HTMLResponse(content=html, headers={"Content-Disposition": f'inline; filename="report-{run_id}.html"'})


@router.get("/runs/{run_id}/report-draft", response_class=PlainTextResponse)
def report_draft(
    run_id: str,
    format: str = Query("hackerone", pattern="^(hackerone|bugcrowd|markdown)$"),
    db: Session = Depends(get_db_dep),
):
    """Submission-ready markdown drafts for every open vuln finding in a run —
    one section per finding, structured for the target platform's template."""
    run = db_get(db, Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")

    vulns = (
        db.query(Finding)
        .filter(Finding.run_id == run_id, Finding.kind == "vuln", Finding.status == "open")
        .all()
    )
    vulns.sort(key=lambda f: (_SEV_RANK.get(f.severity or "info", 9), f.host or ""))

    sections = _PLATFORM_SECTIONS.get(format, ["## Description", "## Proof of Concept", "## Impact"])
    header = (
        f"# Draft submissions — {run.target}\n"
        f"_Run `{run_id}` · workflow `{run.workflow}` · {len(vulns)} open vuln(s)_\n"
        f"_Validate every draft against the program scope + triage gate before submitting._\n"
    )
    if not vulns:
        return PlainTextResponse(header + "\nNo open vulnerability findings in this run.\n")

    parts = [header] + [
        "\n\n---\n\n" + _finding_draft(f, run.target, sections) for f in vulns
    ]
    text = "".join(parts)
    return PlainTextResponse(
        text,
        headers={"Content-Disposition": f'attachment; filename="draft-{run_id}-{format}.md"'},
    )

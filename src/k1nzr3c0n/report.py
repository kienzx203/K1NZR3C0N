"""Generate a self-contained HTML run report from DB findings + workspace files."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .db import Finding, Run, SessionLocal


_SEV_COLOR = {
    "critical": "#ff4444",
    "high":     "#f85149",
    "medium":   "#f0b429",
    "low":      "#58a6ff",
    "info":     "#8b949e",
}
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _fmt_dur(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    m, s = divmod(seconds, 60)
    if m < 60:
        return f"{m}m {s}s" if s else f"{m}m"
    h, m = divmod(m, 60)
    return f"{h}h {m}m" if m else f"{h}h"


def generate_html_report(run_id: str) -> str:
    db = SessionLocal()
    try:
        run = db.get(Run, run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found")

        findings = db.query(Finding).filter(Finding.run_id == run_id).all()
        findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity or "info", 9), f.host or ""))

        vulns      = [f for f in findings if f.kind == "vuln"]
        ports      = [f for f in findings if f.kind == "port"]
        http_alive = [f for f in findings if f.kind == "http"]
        subdomains = [f for f in findings if f.kind == "subdomain"]
        urls       = [f for f in findings if f.kind == "url"]

        by_sev: dict[str, int] = {}
        for f in vulns:
            k = f.severity or "info"
            by_sev[k] = by_sev.get(k, 0) + 1

        # Aggregate technologies from HTTP findings
        tech_set: dict[str, int] = {}
        for f in http_alive:
            try:
                for t in json.loads(f.tech or "[]"):
                    tech_set[t] = tech_set.get(t, 0) + 1
            except Exception:
                pass

        dur = ""
        started_str = finished_str = ""
        if run.started_at and run.finished_at:
            s = int((run.finished_at - run.started_at).total_seconds())
            dur = _fmt_dur(s)
        if run.started_at:
            started_str = run.started_at.strftime("%Y-%m-%d %H:%M UTC")
        if run.finished_at:
            finished_str = run.finished_at.strftime("%Y-%m-%d %H:%M UTC")

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        note = " (partial — run was paused)" if run.status == "paused" else ""

        return _TEMPLATE.format(
            target=_esc(run.target),
            run_id=run_id,
            workflow=_esc(run.workflow),
            status=run.status + note,
            status_color="#06D6A0" if run.status == "completed" else ("#f0b429" if run.status == "paused" else "#FF4D4D"),
            duration=dur or "—",
            started=started_str or "—",
            finished=finished_str or "—",
            generated=now,
            total_vulns=len(vulns),
            total_ports=len(ports),
            total_http=len(http_alive),
            total_subs=len(subdomains),
            total_urls=len(urls),
            sev_cards=_render_sev_cards(by_sev),
            vulns_table=_render_vulns(vulns),
            http_table=_render_http(http_alive),
            ports_table=_render_ports(ports),
            subs_list=_render_subdomains(subdomains),
            tech_section=_render_tech(tech_set),
            urls_section=_render_urls(urls),
        )
    finally:
        db.close()


# ── Renderers ─────────────────────────────────────────────────────────────────

def _render_sev_cards(by_sev: dict[str, int]) -> str:
    if not by_sev:
        return '<p style="color:#666;font-size:13px">No vulnerabilities found.</p>'
    html = ""
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = by_sev.get(sev, 0)
        if cnt:
            color = _SEV_COLOR.get(sev, "#aaa")
            html += (
                f'<div class="sev-card" style="border-color:{color}">'
                f'<div class="sev-num" style="color:{color}">{cnt}</div>'
                f'<div class="sev-label">{sev.upper()}</div></div>'
            )
    return html


def _render_vulns(vulns: list[Finding]) -> str:
    if not vulns:
        return "<tr><td colspan='5' style='text-align:center;color:#888;padding:20px'>No vulnerabilities found</td></tr>"
    rows = ""
    for f in vulns:
        color = _SEV_COLOR.get(f.severity or "info", "#aaa")
        url_cell = (
            f"<a href='{_esc(f.url)}' style='color:#58a6ff;font-family:monospace;font-size:11px'>{_esc(f.url[:80])}{'…' if len(f.url or '') > 80 else ''}</a>"
            if f.url else ""
        )
        rows += (
            f"<tr>"
            f"<td><span class='badge' style='background:{color}22;color:{color};border:1px solid {color}'>"
            f"{(f.severity or 'info').upper()}</span></td>"
            f"<td style='font-family:monospace;font-size:11px'>{_esc(f.template_id or '')}</td>"
            f"<td>{_esc(f.name or '')}</td>"
            f"<td style='font-family:monospace;font-size:12px'>{_esc(f.host or '')}</td>"
            f"<td>{url_cell}</td>"
            f"</tr>"
        )
    return rows


def _render_http(items: list[Finding]) -> str:
    if not items:
        return "<tr><td colspan='4' style='text-align:center;color:#888;padding:20px'>No HTTP services found</td></tr>"
    rows = ""
    for f in items[:500]:
        tech = ", ".join(json.loads(f.tech or "[]"))
        url = f.url or f.host or ""
        url_cell = f"<a href='{_esc(url)}' style='color:#58a6ff;font-family:monospace;font-size:12px'>{_esc(url)}</a>"
        rows += (
            f"<tr>"
            f"<td>{url_cell}</td>"
            f"<td>{_esc(f.title or '')}</td>"
            f"<td style='font-family:monospace;font-size:11px'>{f.port or ''}</td>"
            f"<td style='font-size:11px'>{_esc(tech)}</td>"
            f"</tr>"
        )
    if len(items) > 500:
        rows += f"<tr><td colspan='4' style='color:#666;text-align:center;padding:8px'>{len(items) - 500} more rows truncated</td></tr>"
    return rows


def _render_ports(ports: list[Finding]) -> str:
    if not ports:
        return "<tr><td colspan='3' style='text-align:center;color:#888;padding:20px'>No open ports found</td></tr>"
    rows = ""
    for f in ports[:1000]:
        rows += (
            f"<tr>"
            f"<td style='font-family:monospace;font-size:12px'>{_esc(f.host or '')}</td>"
            f"<td style='font-family:monospace'>{f.port or ''}</td>"
            f"<td>{f.protocol or 'tcp'}</td>"
            f"</tr>"
        )
    if len(ports) > 1000:
        rows += f"<tr><td colspan='3' style='color:#666;text-align:center;padding:8px'>{len(ports) - 1000} more rows truncated</td></tr>"
    return rows


def _render_subdomains(subs: list[Finding]) -> str:
    if not subs:
        return '<p style="color:#666;font-size:13px">No subdomains found.</p>'
    items = "".join(
        f"<li><a href='https://{_esc(f.host)}' style='font-family:monospace;font-size:12px;color:#58a6ff'>{_esc(f.host)}</a></li>"
        for f in subs[:5000]
    )
    note = f'<p style="color:#666;font-size:11px;margin-top:8px">{len(subs) - 5000} more not shown</p>' if len(subs) > 5000 else ""
    return f"<ul style='list-style:none;padding:0;column-count:3;column-gap:24px'>{items}</ul>{note}"


def _render_tech(tech_set: dict[str, int]) -> str:
    if not tech_set:
        return ""
    sorted_tech = sorted(tech_set.items(), key=lambda x: -x[1])
    chips = "".join(
        f"<span style='display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:4px;"
        f"padding:4px 10px;margin:3px;font-size:12px;font-family:monospace'>"
        f"{_esc(t)} <span style='color:#8b949e'>×{n}</span></span>"
        for t, n in sorted_tech
    )
    return f"""
<div class="section">
  <h2>Technologies Detected ({len(tech_set)})</h2>
  <div style="margin-top:8px">{chips}</div>
</div>"""


def _render_urls(urls: list[Finding]) -> str:
    if not urls:
        return ""
    rows = "".join(
        f"<tr><td style='font-family:monospace;font-size:12px'>"
        f"<a href='{_esc(f.url or f.host or '')}' style='color:#58a6ff'>{_esc(f.url or f.host or '')}</a>"
        f"</td><td style='font-size:11px;color:#8b949e'>{_esc(f.title or '')}</td></tr>"
        for f in urls[:200]
    )
    note = f"<tr><td colspan='2' style='color:#666;text-align:center;padding:8px'>{len(urls) - 200} more not shown</td></tr>" if len(urls) > 200 else ""
    return f"""
<div class="section">
  <h2>Discovered URLs ({len(urls)})</h2>
  <table>
    <thead><tr><th>URL</th><th>Title</th></tr></thead>
    <tbody>{rows}{note}</tbody>
  </table>
</div>"""


# ── HTML Template ─────────────────────────────────────────────────────────────

_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>k1nzr3c0n Report — {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;padding:40px 24px;font-size:14px}}
.container{{max-width:1200px;margin:0 auto}}
.header{{border-bottom:2px solid #30363d;padding-bottom:24px;margin-bottom:32px}}
.header h1{{font-family:monospace;font-size:24px;color:#58a6ff;margin-bottom:8px}}
.header-label{{font-family:monospace;font-size:11px;color:#484f58;margin-bottom:10px;letter-spacing:.15em;text-transform:uppercase}}
.meta{{display:flex;gap:28px;flex-wrap:wrap;margin-top:12px}}
.meta-item{{font-size:12px;color:#8b949e}}
.meta-item strong{{color:#e6edf3}}
.section{{margin-bottom:44px}}
.section h2{{font-family:monospace;font-size:14px;color:#8b949e;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid #21262d;text-transform:uppercase;letter-spacing:.08em}}
.sev-cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.sev-card{{background:#161b22;border:1px solid;border-radius:6px;padding:16px 24px;min-width:110px;text-align:center}}
.sev-num{{font-size:32px;font-weight:700;font-family:monospace;line-height:1}}
.sev-label{{font-size:10px;color:#8b949e;margin-top:6px;letter-spacing:.12em}}
.summary-cards{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:36px}}
.sum-card{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:16px;text-align:center}}
.sum-num{{font-size:28px;font-weight:700;font-family:monospace;color:#58a6ff}}
.sum-label{{font-size:11px;color:#8b949e;margin-top:4px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:8px 12px;font-size:10px;color:#8b949e;letter-spacing:.08em;text-transform:uppercase;border-bottom:1px solid #30363d;background:#161b22}}
td{{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
tr:hover td{{background:#161b22}}
.badge{{display:inline-block;font-family:monospace;font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;letter-spacing:.06em}}
.status-pill{{display:inline-block;padding:3px 12px;border-radius:12px;font-size:12px;font-weight:600;background:{status_color}22;color:{status_color};border:1px solid {status_color}55}}
@media print{{
  body{{background:#fff !important;color:#000 !important}}
  .header,.section{{break-inside:avoid}}
  table th{{background:#f0f0f0 !important;color:#333 !important}}
  td{{border-color:#ddd !important;color:#000 !important}}
  .sum-card,.sev-card{{background:#f8f8f8 !important;border-color:#ddd !important}}
  .sum-num{{color:#1a1a1a !important}}
  a{{color:#0066cc !important}}
}}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <div class="header-label">k1nzr3c0n · Security Recon Report</div>
  <h1>{target}</h1>
  <div class="meta">
    <div class="meta-item"><strong>Run ID</strong><br><span style="font-family:monospace;font-size:11px">{run_id}</span></div>
    <div class="meta-item"><strong>Workflow</strong><br>{workflow}</div>
    <div class="meta-item"><strong>Status</strong><br><span class="status-pill">{status}</span></div>
    <div class="meta-item"><strong>Started</strong><br>{started}</div>
    <div class="meta-item"><strong>Finished</strong><br>{finished}</div>
    <div class="meta-item"><strong>Duration</strong><br>{duration}</div>
    <div class="meta-item"><strong>Generated</strong><br>{generated}</div>
  </div>
</div>

<div class="section">
  <h2>Summary</h2>
  <div class="summary-cards">
    <div class="sum-card"><div class="sum-num">{total_vulns}</div><div class="sum-label">Vulnerabilities</div></div>
    <div class="sum-card"><div class="sum-num">{total_subs}</div><div class="sum-label">Subdomains</div></div>
    <div class="sum-card"><div class="sum-num">{total_http}</div><div class="sum-label">HTTP Services</div></div>
    <div class="sum-card"><div class="sum-num">{total_ports}</div><div class="sum-label">Open Ports</div></div>
    <div class="sum-card"><div class="sum-num">{total_urls}</div><div class="sum-label">URLs Found</div></div>
  </div>
</div>

<div class="section">
  <h2>Vulnerabilities by Severity</h2>
  <div class="sev-cards">{sev_cards}</div>
  <table>
    <thead><tr><th>Severity</th><th>Template</th><th>Name</th><th>Host</th><th>URL</th></tr></thead>
    <tbody>{vulns_table}</tbody>
  </table>
</div>

<div class="section">
  <h2>HTTP Services ({total_http})</h2>
  <table>
    <thead><tr><th>URL</th><th>Title</th><th>Port</th><th>Technologies</th></tr></thead>
    <tbody>{http_table}</tbody>
  </table>
</div>

{tech_section}

<div class="section">
  <h2>Open Ports ({total_ports})</h2>
  <table>
    <thead><tr><th>Host</th><th>Port</th><th>Protocol</th></tr></thead>
    <tbody>{ports_table}</tbody>
  </table>
</div>

{urls_section}

<div class="section">
  <h2>Subdomains ({total_subs})</h2>
  {subs_list}
</div>

</div>
</body>
</html>
"""

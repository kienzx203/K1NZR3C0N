"""Parse tool output files from a run workspace into structured Finding rows."""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..db import Finding


def parse_workspace(run_id: str, workspace: str) -> list[Finding]:
    """Scan a run workspace for known output files and return Finding objects."""
    ws = Path(workspace)
    if not ws.exists():
        return []

    findings: list[Finding] = []
    _scan_nuclei(run_id, ws, findings)
    _scan_httpx(run_id, ws, findings)
    _scan_naabu(run_id, ws, findings)
    _scan_subdomains(run_id, ws, findings)
    _scan_katana(run_id, ws, findings)
    _scan_gau(run_id, ws, findings)
    return findings


# ── Nuclei JSONL ──────────────────────────────────────────────────────────────

def _scan_nuclei(run_id: str, ws: Path, out: list[Finding]) -> None:
    _VALID_SEV = {"critical", "high", "medium", "low", "info", "unknown"}
    for path in _find_files(ws, ["nuclei.jsonl", "nuclei_results.jsonl", "nuclei_urls.jsonl", "nuclei*.jsonl"]):
        for row in _iter_jsonl(path):
            sev = (row.get("info", {}).get("severity") or "info").lower()
            if sev not in _VALID_SEV:
                sev = "info"
            host = row.get("host") or row.get("ip") or ""
            out.append(Finding(
                run_id=run_id,
                kind="vuln",
                severity=sev,
                host=host,
                ip=row.get("ip"),
                name=row.get("info", {}).get("name") or row.get("template-id"),
                template_id=row.get("template-id"),
                url=row.get("matched-at") or row.get("host"),
                description=row.get("info", {}).get("description"),
                evidence=row.get("curl-command"),
                tech=json.dumps([]),
                status="open",
            ))


# ── httpx JSONL / plain-text fallback ────────────────────────────────────────

def _scan_httpx(run_id: str, ws: Path, out: list[Finding]) -> None:
    # Prefer JSONL: contains tech/title/IP
    jsonl_files = _find_files(ws, ["httpx.jsonl", "httpx.json", "http_alive.jsonl"])
    for path in jsonl_files:
        for row in _iter_jsonl(path):
            url = row.get("url") or row.get("input") or ""
            host = row.get("host") or _host_from_url(url)
            tech = row.get("technologies") or row.get("tech") or []
            if isinstance(tech, str):
                tech = [tech]
            out.append(Finding(
                run_id=run_id,
                kind="http",
                severity="info",
                host=host,
                ip=_first(row.get("a")) or row.get("ip"),
                port=_int_or_none(row.get("port")),
                url=url,
                title=row.get("title"),
                tech=json.dumps(tech),
                status="open",
            ))
        return  # stop after first JSONL file

    # Fallback: plain-text URL list (one URL per line, from httpx without -json)
    for path in _find_files(ws, ["alive.txt", "http_alive.txt", "httpx.txt"]):
        for line in _iter_lines(path):
            if not line.startswith("http"):
                continue
            host = _host_from_url(line)
            out.append(Finding(
                run_id=run_id,
                kind="http",
                severity="info",
                host=host,
                url=line,
                tech=json.dumps([]),
                status="open",
            ))
        return


# ── naabu JSONL / plain-text fallback ────────────────────────────────────────

_NAABU_PLAIN_RE = re.compile(r'^(.+):(\d+)$')  # host:port

def _scan_naabu(run_id: str, ws: Path, out: list[Finding]) -> None:
    jsonl_files = _find_files(ws, ["naabu.jsonl", "naabu.json", "ports.jsonl"])
    for path in jsonl_files:
        for row in _iter_jsonl(path):
            host = row.get("host") or row.get("ip") or ""
            out.append(Finding(
                run_id=run_id,
                kind="port",
                severity="info",
                host=host,
                ip=row.get("ip"),
                port=_int_or_none(row.get("port")),
                protocol=row.get("protocol", "tcp"),
                name=f"Open port {row.get('port')}",
                tech=json.dumps([]),
                status="open",
            ))
        return  # stop after first JSONL file

    # Fallback: naabu plain text (host:port or ip:port one per line)
    for path in _find_files(ws, ["naabu.txt", "ports.txt"]):
        for line in _iter_lines(path):
            m = _NAABU_PLAIN_RE.match(line)
            if not m:
                continue
            host, port = m.group(1), m.group(2)
            out.append(Finding(
                run_id=run_id,
                kind="port",
                severity="info",
                host=host,
                port=_int_or_none(port),
                protocol="tcp",
                name=f"Open port {port}",
                tech=json.dumps([]),
                status="open",
            ))
        return


# ── Subdomains TXT ────────────────────────────────────────────────────────────

def _scan_subdomains(run_id: str, ws: Path, out: list[Finding]) -> None:
    for path in _find_files(ws, ["subdomains_resolved.txt", "subdomains.txt"]):
        seen: set[str] = set()
        for sub in _iter_lines(path):
            if sub and sub not in seen:
                seen.add(sub)
                out.append(Finding(
                    run_id=run_id,
                    kind="subdomain",
                    severity="info",
                    host=sub,
                    name=sub,
                    tech=json.dumps([]),
                    status="open",
                ))
        break  # prefer _resolved; don't double-count


# ── Katana JSONL (JS/endpoint crawl) ─────────────────────────────────────────

def _scan_katana(run_id: str, ws: Path, out: list[Finding]) -> None:
    seen_urls: set[str] = set()
    for path in _find_files(ws, ["katana.jsonl"]):
        for row in _iter_jsonl(path):
            # katana jsonl may have endpoint at row.request.endpoint or row.endpoint
            req = row.get("request") or {}
            url = req.get("endpoint") or row.get("endpoint") or row.get("url") or ""
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            host = _host_from_url(url)
            tech = []
            resp = row.get("response") or {}
            if resp.get("technologies"):
                tech = resp["technologies"] if isinstance(resp["technologies"], list) else [resp["technologies"]]
            out.append(Finding(
                run_id=run_id,
                kind="url",
                severity="info",
                host=host,
                url=url,
                title=req.get("tag") or req.get("attribute"),
                tech=json.dumps(tech),
                status="open",
            ))


# ── GAU JSONL (passive URL discovery) ────────────────────────────────────────

def _scan_gau(run_id: str, ws: Path, out: list[Finding]) -> None:
    seen_urls: set[str] = set()
    for path in _find_files(ws, ["gau.jsonl"]):
        for row in _iter_jsonl(path):
            url = row.get("url") or ""
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            host = _host_from_url(url)
            out.append(Finding(
                run_id=run_id,
                kind="url",
                severity="info",
                host=host,
                url=url,
                name=row.get("technique"),
                tech=json.dumps([]),
                status="open",
            ))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_files(ws: Path, patterns: list[str]) -> list[Path]:
    results: list[Path] = []
    for pat in patterns:
        results.extend(ws.glob(pat))
    return results


def _iter_jsonl(path: Path):
    try:
        for line in path.read_text(errors="replace").splitlines():
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass
    except OSError:
        pass


def _iter_lines(path: Path) -> list[str]:
    try:
        return [l.strip() for l in path.read_text(errors="replace").splitlines() if l.strip()]
    except OSError:
        return []


def _host_from_url(url: str) -> str:
    if "://" in url:
        return url.split("://", 1)[1].split("/")[0].split(":")[0]
    return url


def _int_or_none(val) -> int | None:
    try:
        return int(val)
    except (TypeError, ValueError):
        return None


def _first(lst) -> str | None:
    if isinstance(lst, list) and lst:
        return str(lst[0])
    return None

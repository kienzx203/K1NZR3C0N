"""Cross-run asset inventory — dedupes `kind="http"` Finding rows (from every
run's parsed httpx output) down to one row per host:port, keeping the most
recent sighting. Screenshot + tech data ride along on the Finding row already
(see parsers/__init__.py::_scan_httpx), so no extra joins are needed here.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import Finding, Run, get_db_dep

router = APIRouter(tags=["assets"])


class AssetDelete(BaseModel):
    host: str
    port: int | None = None


def _asset_key(f: Finding) -> str:
    return f'{f.host}:{f.port}' if f.port else f.host


def _to_asset(f: Finding, target: str | None) -> dict[str, Any]:
    return {
        'host': f.host,
        'port': f.port,
        'ip': f.ip,
        'url': f.url,
        'title': f.title,
        'status_code': f.status_code,
        'tech': json.loads(f.tech or '[]'),
        'screenshot': f.screenshot,
        'run_id': f.run_id,
        'target': target or f.host,
        'last_seen': f.created_at.isoformat() if f.created_at else None,
    }


def _dedupe_latest(rows: list[Finding]) -> list[Finding]:
    """`rows` must already be ordered most-recent-first; keeps the first (latest) per host:port."""
    seen: set[str] = set()
    out: list[Finding] = []
    for f in rows:
        key = _asset_key(f)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _run_target_map(db: Session) -> dict[str, str]:
    return {r.id: r.target for r in db.query(Run.id, Run.target).all()}


@router.get("/assets")
def list_assets(
    q: str | None = Query(None, description="Search host names"),
    tech: list[str] = Query([], description="Filter by technology name — matches ANY of these"),
    target: list[str] = Query([], description="Filter by source target — matches ANY of these"),
    status_code: list[int] = Query([], description="Filter by HTTP status code — matches ANY of these"),
    port: list[int] = Query([], description="Filter by port — matches ANY of these"),
    limit: int = Query(500, le=5000),
    offset: int = Query(0),
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    rows = (
        db.query(Finding)
        .filter(Finding.kind == "http")
        .order_by(Finding.created_at.desc())
        .all()
    )
    assets = _dedupe_latest(rows)
    targets = _run_target_map(db)

    if q:
        ql = q.lower()
        assets = [f for f in assets if ql in (f.host or '').lower()]
    if tech:
        tech_set = set(tech)
        assets = [f for f in assets if tech_set & set(json.loads(f.tech or '[]'))]
    if target:
        target_set = set(target)
        assets = [f for f in assets if targets.get(f.run_id) in target_set]
    if status_code:
        assets = [f for f in assets if f.status_code in status_code]
    if port:
        assets = [f for f in assets if f.port in port]

    total = len(assets)
    page = assets[offset: offset + limit]
    return {
        "total": total, "offset": offset, "limit": limit,
        "items": [_to_asset(f, targets.get(f.run_id)) for f in page],
    }


@router.get("/assets/stats")
def assets_stats(db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    rows = db.query(Finding).filter(Finding.kind == "http").order_by(Finding.created_at.desc()).all()
    assets = _dedupe_latest(rows)
    targets = _run_target_map(db)
    tech_counts: dict[str, int] = {}
    target_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    port_counts: dict[str, int] = {}
    for f in assets:
        for t in json.loads(f.tech or '[]'):
            tech_counts[t] = tech_counts.get(t, 0) + 1
        tgt = targets.get(f.run_id) or f.host
        target_counts[tgt] = target_counts.get(tgt, 0) + 1
        if f.status_code is not None:
            status_counts[str(f.status_code)] = status_counts.get(str(f.status_code), 0) + 1
        if f.port is not None:
            port_counts[str(f.port)] = port_counts.get(str(f.port), 0) + 1
    return {
        "total": len(assets),
        "with_screenshot": sum(1 for f in assets if f.screenshot),
        "by_tech": dict(sorted(tech_counts.items(), key=lambda kv: -kv[1])[:50]),
        "by_target": dict(sorted(target_counts.items(), key=lambda kv: -kv[1])),
        "by_status": dict(sorted(status_counts.items(), key=lambda kv: kv[0])),
        "by_port": dict(sorted(port_counts.items(), key=lambda kv: -kv[1])[:20]),
    }


@router.delete("/assets", status_code=204)
def delete_asset(body: AssetDelete, db: Session = Depends(get_db_dep)) -> None:
    """Removes this host:port from the inventory by deleting its Finding rows
    across every run. Does not touch run files/logs — only the aggregate view."""
    query = db.query(Finding).filter(Finding.kind == "http", Finding.host == body.host)
    query = query.filter(Finding.port == body.port) if body.port is not None else query.filter(Finding.port.is_(None))
    query.delete(synchronize_session=False)
    db.commit()

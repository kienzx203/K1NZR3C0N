from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from ...db import Finding, Run, finding_to_dict, get_db_dep, db_get
from ...tasks import parse_findings

router = APIRouter(tags=["findings"])

# SQL-side severity ordering (SQLite-friendly CASE) — avoids loading every row
# into Python just to sort, which mattered at 100k+ finding tables.
_SEV_ORDER = case(
    [(Finding.severity == "critical", 0),
     (Finding.severity == "high",     1),
     (Finding.severity == "medium",   2),
     (Finding.severity == "low",      3)],
    else_=4,
)


class FindingPatch(BaseModel):
    status: str | None = None       # open | fp | resolved
    notes: str | None = None
    tags: list[str] | None = None


@router.get("/findings")
def list_findings(
    kind: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    host: str | None = Query(None),
    run_id: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    q = db.query(Finding).order_by(Finding.id.desc())
    if kind:
        q = q.filter(Finding.kind == kind)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    if host:
        q = q.filter(Finding.host.contains(host))
    if run_id:
        q = q.filter(Finding.run_id == run_id)
    total = q.count()
    items = q.offset(offset).limit(limit).all()
    return {"total": total, "offset": offset, "limit": limit, "items": [finding_to_dict(f) for f in items]}


@router.get("/findings/stats")
def findings_stats(db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    rows = (
        db.query(Finding.severity, Finding.kind, func.count(Finding.id))
        .group_by(Finding.severity, Finding.kind)
        .all()
    )
    by_severity: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for sev, kind, cnt in rows:
        by_severity[sev or "info"] = by_severity.get(sev or "info", 0) + cnt
        by_kind[kind] = by_kind.get(kind, 0) + cnt
    total = sum(by_severity.values())
    return {"total": total, "by_severity": by_severity, "by_kind": by_kind}


@router.get("/findings/duplicates")
def duplicate_groups(db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    """Open vulns seen more than once (same host + template_id) across runs.
    The newest row is the keeper; older ones are candidates to resolve."""
    rows = (
        db.query(
            Finding.host,
            Finding.template_id,
            func.count(Finding.id).label("n"),
        )
        .filter(Finding.kind == "vuln", Finding.status == "open", Finding.template_id.isnot(None))
        .group_by(Finding.host, Finding.template_id)
        .having(func.count(Finding.id) > 1)
        .order_by(func.count(Finding.id).desc())
        .limit(200)
        .all()
    )
    groups = []
    for host, tid, n in rows:
        items = (
            db.query(Finding)
            .filter(Finding.kind == "vuln", Finding.status == "open",
                    Finding.host == host, Finding.template_id == tid)
            .order_by(Finding.id.desc())
            .all()
        )
        if len(items) < 2:
            continue
        groups.append({
            "host": host,
            "template_id": tid,
            "count": len(items),
            "severity": items[0].severity,
            "keep_id": items[0].id,
            "duplicate_ids": [f.id for f in items[1:]],
        })
    return {"total": len(groups), "groups": groups}


@router.post("/findings/duplicates/resolve")
def resolve_duplicates(db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    """Resolve older duplicates in-place (keeps newest open, tags the rest)."""
    data = duplicate_groups(db=db)
    resolved = 0
    for g in data["groups"]:
        for fid in g["duplicate_ids"]:
            f = db_get(db, Finding, fid)
            if f and f.status == "open":
                f.status = "resolved"
                tags = json.loads(f.tags or "[]")
                if "duplicate" not in tags:
                    tags.append("duplicate")
                f.tags = json.dumps(tags)
                resolved += 1
    db.commit()
    return {"resolved": resolved}


@router.get("/runs/{run_id}/findings")
def run_findings(
    run_id: str,
    kind: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(200, le=1000),
    offset: int = Query(0),
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    run = db_get(db, Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    q = db.query(Finding).filter(Finding.run_id == run_id)
    if kind:
        q = q.filter(Finding.kind == kind)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)

    total = q.count()
    items = q.order_by(_SEV_ORDER, Finding.host).offset(offset).limit(limit).all()
    return {"total": total, "offset": offset, "limit": limit, "items": [finding_to_dict(f) for f in items]}


@router.patch("/findings/{finding_id}")
def patch_finding(
    finding_id: int,
    body: FindingPatch,
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    f = db_get(db, Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    if body.status is not None:
        if body.status not in ("open", "fp", "resolved"):
            raise HTTPException(400, "status must be one of: open, fp, resolved")
        f.status = body.status
    if body.notes is not None:
        f.notes = body.notes
    if body.tags is not None:
        f.tags = json.dumps([t.strip() for t in body.tags if t.strip()])
    db.commit()
    return finding_to_dict(f)


@router.post("/runs/{run_id}/findings/reparse", status_code=202)
def reparse_findings(run_id: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    run = db_get(db, Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    task = parse_findings.delay(run_id)
    return {"task_id": task.id, "run_id": run_id}

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from ...db import Finding, Run, finding_to_dict, get_db_dep
from ...tasks import parse_findings

router = APIRouter(tags=["findings"])


class FindingPatch(BaseModel):
    status: str  # open | fp | resolved


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
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    q = db.query(Finding).filter(Finding.run_id == run_id)
    if kind:
        q = q.filter(Finding.kind == kind)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items = q.all()
    items.sort(key=lambda f: (SEV_ORDER.get(f.severity or "info", 9), f.host))

    total = len(items)
    page = items[offset: offset + limit]
    return {"total": total, "offset": offset, "limit": limit, "items": [finding_to_dict(f) for f in page]}


@router.patch("/findings/{finding_id}")
def patch_finding(
    finding_id: int,
    body: FindingPatch,
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    if body.status not in ("open", "fp", "resolved"):
        raise HTTPException(400, "status must be one of: open, fp, resolved")
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = body.status
    db.commit()
    return finding_to_dict(f)


@router.post("/runs/{run_id}/findings/reparse", status_code=202)
def reparse_findings(run_id: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    task = parse_findings.delay(run_id)
    return {"task_id": task.id, "run_id": run_id}

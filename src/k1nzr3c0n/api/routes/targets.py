"""Target registry — target-centric view + deny-wins scope definitions."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ...db import (Finding, NewAsset, Run, ScopeAudit, Target, get_db_dep,
                   new_asset_to_dict, target_to_dict, db_get)
from ...scope import check_target_scope, match_scope

router = APIRouter(tags=["targets"])

_MODES = ("bounty", "vdp", "oos")


class TargetCreate(BaseModel):
    name: str
    scope: list[str] = []
    mode: str = "bounty"
    notes: str | None = None


class TargetPatch(BaseModel):
    scope: list[str] | None = None
    mode: str | None = None
    notes: str | None = None


def _host_filter(name: str):
    """Findings whose host is the target itself or a subdomain of it."""
    return or_(Finding.host == name, Finding.host.like(f"%.{name}"))


def _summary(db: Session, name: str) -> dict[str, Any]:
    runs_q = db.query(Run).filter(Run.target == name)
    total_runs = runs_q.count()
    last_run = runs_q.order_by(Run.created_at.desc()).first()

    open_vulns = (
        db.query(func.count(Finding.id))
        .filter(_host_filter(name), Finding.kind == "vuln", Finding.status == "open")
        .scalar() or 0
    )
    sev_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(_host_filter(name), Finding.kind == "vuln", Finding.status == "open")
        .group_by(Finding.severity)
        .all()
    )
    return {
        "total_runs": total_runs,
        "last_run_id": last_run.id if last_run else None,
        "last_run_at": last_run.created_at.isoformat() if last_run and last_run.created_at else None,
        "last_status": last_run.status if last_run else None,
        "open_vulns": open_vulns,
        "by_severity": {sev or "info": n for sev, n in sev_rows},
    }


@router.get("/targets")
def list_targets(db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    targets = db.query(Target).order_by(Target.name).all()
    items = []
    for t in targets:
        d = target_to_dict(t)
        d.update(_summary(db, t.name))
        items.append(d)
    return {"total": len(items), "items": items}


@router.post("/targets", status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    name = body.name.strip().lower()
    if not name or "/" in name or " " in name:
        raise HTTPException(400, "Invalid target name (expected a domain)")
    if body.mode not in _MODES:
        raise HTTPException(400, f"mode must be one of: {', '.join(_MODES)}")
    if db_get(db, Target, name):
        raise HTTPException(409, f"Target already exists: {name}")
    t = Target(
        name=name,
        scope_json=json.dumps(body.scope or []),
        mode=body.mode,
        notes=body.notes,
    )
    db.add(t)
    db.commit()
    return target_to_dict(t)


@router.get("/targets/{name}")
def get_target(name: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    t = db_get(db, Target, name)
    if not t:
        raise HTTPException(404, "Target not found")
    d = target_to_dict(t)
    d.update(_summary(db, name))
    # recent runs for this target
    runs = (
        db.query(Run)
        .filter(Run.target == name)
        .order_by(Run.created_at.desc())
        .limit(10)
        .all()
    )
    from ...db import run_to_dict
    d["recent_runs"] = [run_to_dict(r) for r in runs]
    return d


@router.patch("/targets/{name}")
def patch_target(name: str, body: TargetPatch, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    t = db_get(db, Target, name)
    if not t:
        raise HTTPException(404, "Target not found")
    if body.scope is not None:
        t.scope_json = json.dumps(body.scope)
    if body.mode is not None:
        if body.mode not in _MODES:
            raise HTTPException(400, f"mode must be one of: {', '.join(_MODES)}")
        t.mode = body.mode
    if body.notes is not None:
        t.notes = body.notes
    t.updated_at = datetime.utcnow()
    db.commit()
    return target_to_dict(t)


@router.delete("/targets/{name}", status_code=204)
def delete_target(name: str, db: Session = Depends(get_db_dep)) -> None:
    t = db_get(db, Target, name)
    if not t:
        raise HTTPException(404, "Target not found")
    db.delete(t)
    db.commit()


@router.get("/targets/{name}/audit")
def target_audit(
    name: str,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    rows = (
        db.query(ScopeAudit)
        .filter(ScopeAudit.target == name)
        .order_by(ScopeAudit.id.desc())
        .limit(limit)
        .all()
    )
    return {
        "total": len(rows),
        "items": [
            {"id": r.id, "action": r.action, "result": r.result, "detail": r.detail,
             "ts": r.ts.isoformat() if r.ts else None}
            for r in rows
        ],
    }


@router.get("/scope/check")
def scope_check(host: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    """Ad-hoc scope question: is `host` covered by any registered target?"""
    h = host.strip().lower()
    covered_by = None
    for t in db.query(Target).all():
        patterns = [t.name] + (json.loads(t.scope_json or "[]"))
        if match_scope(h, patterns):
            covered_by = {"name": t.name, "mode": t.mode}
            break
    denied = bool(covered_by and covered_by["mode"] == "oos")
    return {
        "host": h,
        "covered_by": covered_by,
        "in_scope": covered_by is not None and not denied,
        "denied": denied,
        "reason": ("marked out-of-scope" if denied
                   else f"covered by {covered_by['name']}" if covered_by
                   else "unregistered — no scope defined"),
    }


@router.get("/targets/{name}/new-assets")
def target_new_assets(
    name: str,
    limit: int = Query(100, le=500),
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    """Assets first seen across this target's runs — the continuous-recon feed."""
    rows = (
        db.query(NewAsset)
        .filter(NewAsset.target == name)
        .order_by(NewAsset.first_seen.desc())
        .limit(limit)
        .all()
    )
    return {"total": len(rows), "items": [new_asset_to_dict(a) for a in rows]}

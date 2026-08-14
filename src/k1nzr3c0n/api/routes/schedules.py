"""Continuous recon — cron schedules that launch workflow runs automatically."""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from croniter import croniter
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...config import WORKFLOWS_DIR
from ...db import Schedule, get_db_dep, schedule_to_dict, db_get
from .runs import launch_run

router = APIRouter(tags=["schedules"])


class ScheduleCreate(BaseModel):
    name: str
    workflow: str
    target: str
    cron_expr: str
    vars: dict[str, str] = {}
    enabled: bool = True
    alert_new_assets: bool = True


class SchedulePatch(BaseModel):
    name: str | None = None
    cron_expr: str | None = None
    vars: dict[str, str] | None = None
    enabled: bool | None = None
    alert_new_assets: bool | None = None


def _validate_cron(expr: str) -> None:
    try:
        croniter(expr, datetime.now())
    except Exception:
        raise HTTPException(400, f"Invalid cron expression: {expr!r} (expected 5 fields, local time)")


def _next_run(expr: str) -> datetime:
    return croniter(expr, datetime.now()).get_next(datetime)


def _validate_workflow(name: str) -> None:
    if not (WORKFLOWS_DIR / name).exists():
        raise HTTPException(404, f"Workflow not found: {name}")


@router.get("/schedules")
def list_schedules(db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    items = db.query(Schedule).order_by(Schedule.id.desc()).all()
    return {"total": len(items), "items": [schedule_to_dict(s) for s in items]}


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleCreate, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    _validate_workflow(body.workflow)
    _validate_cron(body.cron_expr)
    s = Schedule(
        name=body.name,
        workflow=body.workflow,
        target=body.target,
        cron_expr=body.cron_expr,
        vars_json=json.dumps(body.vars or {}),
        enabled=body.enabled,
        alert_new_assets=body.alert_new_assets,
        next_run_at=_next_run(body.cron_expr) if body.enabled else None,
    )
    db.add(s)
    db.commit()
    return schedule_to_dict(s)


@router.get("/schedules/{schedule_id}")
def get_schedule(schedule_id: int, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    s = db_get(db, Schedule, schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    return schedule_to_dict(s)


@router.patch("/schedules/{schedule_id}")
def patch_schedule(schedule_id: int, body: SchedulePatch, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    s = db_get(db, Schedule, schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    if body.name is not None:
        s.name = body.name
    if body.cron_expr is not None:
        _validate_cron(body.cron_expr)
        s.cron_expr = body.cron_expr
    if body.vars is not None:
        s.vars_json = json.dumps(body.vars)
    if body.enabled is not None:
        s.enabled = body.enabled
    if body.alert_new_assets is not None:
        s.alert_new_assets = body.alert_new_assets
    s.next_run_at = _next_run(s.cron_expr) if s.enabled else None
    db.commit()
    return schedule_to_dict(s)


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int, db: Session = Depends(get_db_dep)) -> None:
    s = db_get(db, Schedule, schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    db.delete(s)
    db.commit()


@router.post("/schedules/{schedule_id}/trigger")
def trigger_schedule(schedule_id: int, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    """Launch the scheduled run immediately (does not shift the cron clock)."""
    s = db_get(db, Schedule, schedule_id)
    if not s:
        raise HTTPException(404, "Schedule not found")
    _validate_workflow(s.workflow)
    vars_dict = json.loads(s.vars_json or "{}")
    run = launch_run(
        db,
        workflow=s.workflow,
        target=s.target,
        vars_dict=vars_dict,
        origin=f"schedule:{s.id}",
    )
    s.last_run_id = run.id
    s.last_run_at = datetime.utcnow()
    db.commit()
    return {"run_id": run.id, "schedule": schedule_to_dict(s)}

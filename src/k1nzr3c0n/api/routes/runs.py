from __future__ import annotations

import json
import re
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from ...config import RUNS_DIR, WORKFLOWS_DIR
from ...db import Finding, Run, RunLog, get_db_dep, run_to_dict
from ...tasks import execute_run

router = APIRouter(tags=["runs"])


class RunCreate(BaseModel):
    workflow: str
    target: str
    out: str | None = None
    vars: list[str] = []
    resume: bool = False
    continue_on_error: bool = False


@router.post("/runs", status_code=201)
def create_run(body: RunCreate, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    wf_path = (WORKFLOWS_DIR / body.workflow).resolve()
    if not wf_path.is_relative_to(WORKFLOWS_DIR.resolve()):
        raise HTTPException(400, "Invalid workflow path")
    if not wf_path.exists():
        raise HTTPException(404, f"Workflow not found: {body.workflow}")

    if body.out:
        workspace = str((RUNS_DIR / body.out).resolve())
        if not (RUNS_DIR / body.out).resolve().is_relative_to(RUNS_DIR.resolve()):
            raise HTTPException(400, "Invalid output path")
    else:
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", body.target)
        ts = time.strftime("%Y%m%d-%H%M%S")
        workspace = str(RUNS_DIR / safe_target / ts)

    try:
        wf_data = yaml.safe_load(wf_path.read_text(encoding="utf-8"))
        step_ids = [s["id"] for s in wf_data.get("steps", []) if isinstance(s, dict) and "id" in s]
    except Exception:
        step_ids = []
    steps_json = json.dumps([{"id": sid, "status": "pending"} for sid in step_ids])

    run_id = uuid.uuid4().hex[:12]
    run = Run(
        id=run_id,
        workflow=body.workflow,
        target=body.target,
        workspace=workspace,
        steps_json=steps_json,
        vars_json=json.dumps(
            {k: v for item in body.vars for k, v in [item.split("=", 1)]} if body.vars else {}
        ),
        out_dir=body.out,
        continue_on_error=body.continue_on_error,
        resume=body.resume,
        status="queued",
    )
    db.add(run)
    db.commit()

    cmd = [sys.executable, "-m", "k1nzr3c0n", "run", "-w", str(wf_path), "-t", body.target, "-o", workspace]
    if body.resume:
        cmd.append("--resume")
    if body.continue_on_error:
        cmd.append("--continue-on-error")
    if body.vars:
        cmd += ["--vars"] + body.vars

    task = execute_run.delay(run_id, cmd)
    run.celery_task_id = task.id
    db.commit()
    return run_to_dict(run)


@router.get("/runs")
def list_runs(
    status: str | None = Query(None),
    workflow: str | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    q = db.query(Run).order_by(Run.created_at.desc())
    if status:
        q = q.filter(Run.status == status)
    if workflow:
        q = q.filter(Run.workflow == workflow)
    total = q.count()
    runs = q.offset(offset).limit(limit).all()
    return {"total": total, "items": [run_to_dict(r) for r in runs]}


@router.get("/runs/stats")
def run_stats(db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    row = db.query(
        func.count(Run.id).label("total"),
        func.sum(case((Run.status == "queued", 1), else_=0)).label("queued"),
        func.sum(case((Run.status == "running", 1), else_=0)).label("running"),
        func.sum(case((Run.status == "completed", 1), else_=0)).label("completed"),
        func.sum(case((Run.status == "failed", 1), else_=0)).label("failed"),
    ).one()

    total_findings = db.query(func.count(Finding.id)).scalar() or 0
    open_vulns = db.query(func.count(Finding.id)).filter(
        Finding.kind == "vuln", Finding.status == "open"
    ).scalar() or 0

    sev_rows = (
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.kind == "vuln")
        .group_by(Finding.severity)
        .all()
    )
    by_severity = {(sev or "info"): cnt for sev, cnt in sev_rows}

    recent = db.query(Run).order_by(Run.created_at.desc()).limit(8).all()
    return {
        "total": row.total or 0,
        "by_status": {
            "queued":    row.queued    or 0,
            "running":   row.running   or 0,
            "completed": row.completed or 0,
            "failed":    row.failed    or 0,
        },
        "findings": {
            "total":       total_findings,
            "open_vulns":  open_vulns,
            "by_severity": by_severity,
        },
        "recent": [run_to_dict(r) for r in recent],
    }


@router.get("/runs/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    result = run_to_dict(run)
    total_logs = db.query(func.count(RunLog.id)).filter(RunLog.run_id == run_id).scalar() or 0
    result["total_logs"] = total_logs

    findings_count = db.query(func.count(Finding.id)).filter(Finding.run_id == run_id).scalar() or 0
    result["findings_count"] = findings_count
    return result


@router.get("/runs/{run_id}/logs")
def get_run_logs(
    run_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(500, le=2000),
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    total = db.query(func.count(RunLog.id)).filter(RunLog.run_id == run_id).scalar() or 0
    logs = (
        db.query(RunLog)
        .filter(RunLog.run_id == run_id)
        .order_by(RunLog.id)
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {"total": total, "offset": offset, "limit": limit, "items": [l.message for l in logs]}


@router.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status not in ("queued", "running"):
        raise HTTPException(400, f"Cannot cancel run with status: {run.status}")

    # Write cancel flag so execute_run detects it and kills the subprocess cleanly
    if run.workspace:
        flag = Path(run.workspace) / "cancel.flag"
        flag.parent.mkdir(parents=True, exist_ok=True)
        flag.touch()

    # Revoke the Celery task (handles queued tasks that haven't started yet)
    if run.celery_task_id:
        from ...tasks import celery_app
        celery_app.control.revoke(run.celery_task_id, terminate=False)

    run.status = "cancelled"
    run.finished_at = datetime.utcnow()
    db.commit()
    return run_to_dict(run)


@router.post("/runs/{run_id}/pause")
def pause_run(run_id: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status != "running":
        raise HTTPException(400, f"Cannot pause run with status: {run.status}")
    if not run.workspace:
        raise HTTPException(400, "Run has no workspace")

    flag = Path(run.workspace) / "pause.flag"
    flag.parent.mkdir(parents=True, exist_ok=True)
    flag.touch()

    return {"ok": True, "message": "Pause requested — run will stop after the current step completes."}


@router.delete("/runs/{run_id}/pause")
def cancel_pause(run_id: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    """Remove the pause flag while a run is still running (cancel a pending pause)."""
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status != "running":
        raise HTTPException(400, f"Run is not running (status: {run.status})")
    if not run.workspace:
        raise HTTPException(400, "Run has no workspace")

    flag = Path(run.workspace) / "pause.flag"
    flag.unlink(missing_ok=True)

    return {"ok": True}


@router.post("/runs/{run_id}/resume")
def resume_run(run_id: str, db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status not in ("paused", "failed"):
        raise HTTPException(400, f"Cannot resume run with status: {run.status}")
    if not run.workspace:
        raise HTTPException(400, "Run has no workspace")

    # Clear pause flag so the next execution doesn't immediately pause again
    flag = Path(run.workspace) / "pause.flag"
    flag.unlink(missing_ok=True)

    # Reset any step that is paused/failed/running back to pending for the UI
    steps = json.loads(run.steps_json or "[]")
    for s in steps:
        if s.get("status") in ("paused", "failed", "running"):
            s["status"] = "pending"

    run.status = "running"
    run.finished_at = None
    run.paused_at = None
    run.steps_json = json.dumps(steps)
    db.commit()

    wf_path = (WORKFLOWS_DIR / run.workflow).resolve()
    vars_dict = json.loads(run.vars_json or "{}")
    cmd = [
        sys.executable, "-m", "k1nzr3c0n", "run",
        "-w", str(wf_path),
        "-t", run.target,
        "-o", run.workspace,
        "--resume",
    ]
    if run.continue_on_error:
        cmd.append("--continue-on-error")
    if vars_dict:
        cmd += ["--vars"] + [f"{k}={v}" for k, v in vars_dict.items()]

    from ...tasks import execute_run
    task = execute_run.delay(run_id, cmd)
    run.celery_task_id = task.id
    db.commit()

    return run_to_dict(run)


@router.delete("/runs/{run_id}", status_code=204)
def delete_run(run_id: str, db: Session = Depends(get_db_dep)) -> None:
    run = db.get(Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    db.query(RunLog).filter(RunLog.run_id == run_id).delete()
    db.query(Finding).filter(Finding.run_id == run_id).delete()
    db.delete(run)
    db.commit()

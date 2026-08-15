from __future__ import annotations

import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

from ...config import DB_PATH, RUNS_DIR
from ...db import (ApiKey, Finding, NewAsset, Run, RunLog, ScopeAudit,
                   Schedule, Target, ToolVersion, get_db_dep)

router = APIRouter(tags=["system"])

_DB_FILES = {DB_PATH.name, DB_PATH.name + "-wal", DB_PATH.name + "-shm"}

# Tables tied to run history — cleared by scope="runs". Targets + schedules
# additionally go with scope="all".
# NEVER wiped (user requirement): api_keys AND tool_versions — plus templates
# are structurally safe: workflow YAMLs live in WORKFLOWS_DIR and nuclei
# templates in /root/nuclei-templates, both outside RUNS_DIR. Installed tool
# binaries are system packages, also outside RUNS_DIR.
_RUN_TABLES: dict[str, type] = {
    "runs": Run,
    "run_logs": RunLog,
    "findings": Finding,
    "new_assets": NewAsset,
    "scope_audit": ScopeAudit,
}
_ALL_TABLES: dict[str, type] = {
    **_RUN_TABLES,
    "targets": Target,
    "schedules": Schedule,
}


class ResetRequest(BaseModel):
    scope: str = "runs"          # runs | all
    confirm: str = ""


def _dir_size(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


@router.get("/system/usage")
def system_usage(db: Session = Depends(get_db_dep)) -> dict:
    """What a reset would wipe — shown in the Danger Zone before confirming."""
    workspace_dirs = 0
    used_bytes = 0
    if RUNS_DIR.exists():
        for child in RUNS_DIR.iterdir():
            if child.name in _DB_FILES:
                continue
            workspace_dirs += 1
            used_bytes += _dir_size(child)
    return {
        "runs": db.query(Run).count(),
        "findings": db.query(Finding).count(),
        "new_assets": db.query(NewAsset).count(),
        "run_logs": db.query(RunLog).count(),
        "api_keys": db.query(ApiKey).count(),
        "targets": db.query(Target).count(),
        "schedules": db.query(Schedule).count(),
        "tool_versions": db.query(ToolVersion).count(),
        "workspace_dirs": workspace_dirs,
        "workspace_bytes": used_bytes,
    }


@router.post("/system/reset")
def system_reset(body: ResetRequest, db: Session = Depends(get_db_dep)) -> dict:
    """DANGEROUS: wipe DB tables and delete run workspaces.

    scope=runs → run history tables only (runs/logs/findings/new_assets/
                 scope_audit); targets, schedules, tool_versions are kept.
    scope=all  → additionally clears targets and schedules.
    BOTH scopes keep api_keys + tool_versions (never wiped) and never touch
    templates or tool binaries (workflow YAMLs in WORKFLOWS_DIR, nuclei
    templates in /root/nuclei-templates — all outside RUNS_DIR). The DB file
    itself stays; rows are deleted in place, then VACUUMed.
    """
    if body.confirm != "RESET":
        raise HTTPException(400, "confirm must be the literal string 'RESET'")
    if body.scope not in ("runs", "all"):
        raise HTTPException(400, "scope must be 'runs' or 'all'")

    active = (
        db.query(Run)
        .filter(Run.status.in_(["queued", "running", "paused"]))
        .count()
    )
    if active:
        raise HTTPException(
            409, f"{active} run(s) still active — cancel them before resetting"
        )

    tables = _ALL_TABLES if body.scope == "all" else _RUN_TABLES
    deleted = {}
    for name, model in tables.items():
        deleted[name] = db.query(model).delete(synchronize_session=False)
    db.commit()

    # Shrink the DB file after mass deletes. VACUUM cannot run inside a
    # transaction → fresh AUTOCOMMIT connection. Best-effort only.
    try:
        eng = create_engine(f"sqlite:///{DB_PATH}")
        with eng.connect() as conn:
            conn.execution_options(isolation_level="AUTOCOMMIT")
            conn.execute(text("VACUUM"))
        eng.dispose()
    except Exception:
        pass

    # Delete every workspace dir/file under RUNS_DIR except the DB files.
    freed = 0
    removed = 0
    if RUNS_DIR.exists():
        for child in RUNS_DIR.iterdir():
            if child.name in _DB_FILES:
                continue
            freed += _dir_size(child)
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                try:
                    child.unlink()
                except OSError:
                    pass
            removed += 1

    return {
        "scope": body.scope,
        "deleted_rows": deleted,
        "removed_workspace_dirs": removed,
        "freed_bytes": freed,
    }

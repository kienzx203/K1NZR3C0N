from __future__ import annotations

import shutil
import tempfile
import time

import yaml
from fastapi import APIRouter, Body, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from ...config import WORKFLOWS_DIR
from ...workflow import WorkflowError, load_workflow

router = APIRouter(tags=["workflows"])

# Every overwrite/import snapshots the previous version here (keep last 10).
_HISTORY_DIR = WORKFLOWS_DIR / ".history"
_HISTORY_KEEP = 10


def _check_name(name: str) -> None:
    if not name.endswith(".yaml") or "/" in name or "\\" in name or name.startswith("."):
        raise HTTPException(400, "Invalid workflow name")


def _snapshot(name: str) -> None:
    """Copy the current file into .history/<name>.<timestamp>.yaml (if it exists)."""
    src = WORKFLOWS_DIR / name
    if not src.exists():
        return
    _HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    shutil.copy2(src, _HISTORY_DIR / f"{name}.{ts}.yaml")
    # Prune old snapshots of this workflow, keep newest _HISTORY_KEEP
    snaps = sorted(_HISTORY_DIR.glob(f"{name}.*.yaml"))
    for old in snaps[:-_HISTORY_KEEP]:
        old.unlink(missing_ok=True)


def _validate_yaml_text(text: str) -> None:
    """Full engine validation (schema + topology) before accepting a workflow."""
    fd, tmp = tempfile.mkstemp(suffix=".yaml", prefix=".import_", dir=str(WORKFLOWS_DIR))
    import os
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        from pathlib import Path
        load_workflow(Path(tmp))
    except WorkflowError as e:
        raise HTTPException(400, f"Workflow validation failed: {e}")
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Invalid YAML: {e}")
    finally:
        import os
        try:
            os.unlink(tmp)
        except OSError:
            pass


class WorkflowImport(BaseModel):
    name: str
    yaml_text: str


@router.get("/workflows")
def list_workflows() -> list[str]:
    if not WORKFLOWS_DIR.exists():
        return []
    return sorted(p.name for p in WORKFLOWS_DIR.glob("*.yaml"))


@router.get("/workflows/{name}")
def get_workflow(name: str) -> dict:
    _check_name(name)
    path = WORKFLOWS_DIR / name
    if not path.exists():
        raise HTTPException(404, f"Workflow not found: {name}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


@router.get("/workflows/{name}/download", response_class=PlainTextResponse)
def download_workflow(name: str):
    """Raw YAML download — share/export workflows between installs."""
    _check_name(name)
    path = WORKFLOWS_DIR / name
    if not path.exists():
        raise HTTPException(404, f"Workflow not found: {name}")
    return PlainTextResponse(
        path.read_text(encoding="utf-8"),
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/workflows/{name}/history")
def workflow_history(name: str) -> dict:
    _check_name(name)
    snaps = sorted((p.name for p in _HISTORY_DIR.glob(f"{name}.*.yaml")), reverse=True)
    return {"name": name, "snapshots": snaps}


@router.get("/workflows/{name}/history/{snapshot}")
def workflow_snapshot(name: str, snapshot: str):
    _check_name(name)
    if not snapshot.startswith(f"{name}.") or "/" in snapshot or "\\" in snapshot:
        raise HTTPException(400, "Invalid snapshot name")
    path = _HISTORY_DIR / snapshot
    if not path.exists():
        raise HTTPException(404, "Snapshot not found")
    return PlainTextResponse(
        path.read_text(encoding="utf-8"),
        media_type="application/x-yaml",
        headers={"Content-Disposition": f'attachment; filename="{snapshot}"'},
    )


@router.post("/workflows/import")
def import_workflow(body: WorkflowImport) -> dict:
    """Import shared YAML — full engine validation, previous version snapshotted."""
    _check_name(body.name)
    _validate_yaml_text(body.yaml_text)
    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    _snapshot(body.name)
    (WORKFLOWS_DIR / body.name).write_text(body.yaml_text, encoding="utf-8")
    return {"imported": body.name}


@router.put("/workflows/{name}")
def save_workflow(name: str, body: dict = Body(...)) -> dict:
    # Only allow saving .yaml files inside the workflows dir
    _check_name(name)
    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    text = yaml.dump(body, default_flow_style=False, allow_unicode=True,
                     width=4096, sort_keys=False)
    _validate_yaml_text(text)
    _snapshot(name)
    (WORKFLOWS_DIR / name).write_text(text, encoding="utf-8")
    return {"saved": name}


@router.delete("/workflows/{name}")
def delete_workflow(name: str) -> dict:
    _check_name(name)
    path = WORKFLOWS_DIR / name
    if not path.exists():
        raise HTTPException(404, f"Workflow not found: {name}")
    _snapshot(name)  # deletions are recoverable from .history
    path.unlink()
    return {"deleted": name}

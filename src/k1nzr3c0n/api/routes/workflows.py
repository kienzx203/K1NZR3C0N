from __future__ import annotations

import yaml
from fastapi import APIRouter, Body, HTTPException

from ...config import WORKFLOWS_DIR

router = APIRouter(tags=["workflows"])


@router.get("/workflows")
def list_workflows() -> list[str]:
    if not WORKFLOWS_DIR.exists():
        return []
    return sorted(p.name for p in WORKFLOWS_DIR.glob("*.yaml"))


@router.get("/workflows/{name}")
def get_workflow(name: str) -> dict:
    path = WORKFLOWS_DIR / name
    if not path.exists():
        raise HTTPException(404, f"Workflow not found: {name}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data or {}


@router.put("/workflows/{name}")
def save_workflow(name: str, body: dict = Body(...)) -> dict:
    # Only allow saving .yaml files inside the workflows dir
    if not name.endswith(".yaml") or "/" in name or "\\" in name:
        raise HTTPException(400, "Invalid workflow name")
    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    path = WORKFLOWS_DIR / name
    path.write_text(
        yaml.dump(body, default_flow_style=False, allow_unicode=True,
                  width=4096, sort_keys=False),
        encoding="utf-8",
    )
    return {"saved": name}


@router.delete("/workflows/{name}")
def delete_workflow(name: str) -> dict:
    if not name.endswith(".yaml") or "/" in name or "\\" in name:
        raise HTTPException(400, "Invalid workflow name")
    path = WORKFLOWS_DIR / name
    if not path.exists():
        raise HTTPException(404, f"Workflow not found: {name}")
    path.unlink()
    return {"deleted": name}

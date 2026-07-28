from __future__ import annotations

import re
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File

from ...config import WORDLISTS_DIR, WORKFLOWS_DIR

router = APIRouter(tags=["upload"])

_MAX_BYTES = 100 * 1024 * 1024  # 100 MB


def _safe_name(raw: str) -> str:
    """Strip directory components and replace unsafe characters."""
    name = Path(raw).name
    name = re.sub(r"[^\w\-.]", "_", name)
    return name or "upload"


# ── Wordlists ─────────────────────────────────────────────────────────────────

@router.get("/wordlists")
def list_wordlists() -> list[dict]:
    if not WORDLISTS_DIR.exists():
        return []
    items = [
        {"name": p.name, "size": p.stat().st_size}
        for p in WORDLISTS_DIR.iterdir()
        if p.is_file()
    ]
    return sorted(items, key=lambda x: x["name"])


@router.post("/wordlists")
async def upload_wordlist(file: UploadFile = File(...)) -> dict:
    if not file.filename.lower().endswith(".txt"):
        raise HTTPException(400, "Only .txt files are allowed")
    name = _safe_name(file.filename)
    data = await file.read()
    if len(data) > _MAX_BYTES:
        raise HTTPException(413, "File too large (max 100 MB)")
    WORDLISTS_DIR.mkdir(parents=True, exist_ok=True)
    (WORDLISTS_DIR / name).write_bytes(data)
    lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    return {"name": name, "size": len(data), "lines": lines}


@router.delete("/wordlists/{name}")
def delete_wordlist(name: str) -> dict:
    path = WORDLISTS_DIR / _safe_name(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()
    return {"deleted": name}


# ── Workflows ─────────────────────────────────────────────────────────────────

@router.post("/upload/workflow")
async def upload_workflow(file: UploadFile = File(...)) -> dict:
    fname = file.filename.lower()
    if not (fname.endswith(".yaml") or fname.endswith(".yml")):
        raise HTTPException(400, "Only .yaml files are allowed")
    name = _safe_name(file.filename)
    if name.endswith(".yml"):
        name = name[:-4] + ".yaml"
    data = await file.read()
    if len(data) > _MAX_BYTES:
        raise HTTPException(413, "File too large (max 100 MB)")
    WORKFLOWS_DIR.mkdir(parents=True, exist_ok=True)
    (WORKFLOWS_DIR / name).write_bytes(data)
    return {"name": name, "size": len(data)}

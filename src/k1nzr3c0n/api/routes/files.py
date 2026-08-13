from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from ...config import RUNS_DIR
from ...db import Run, get_db, db_get

router = APIRouter(tags=["files"])

_TEXT_EXTS = {".txt", ".log", ".md", ".yaml", ".json", ".jsonl", ".csv", ".xml"}
_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
# Cap in-memory text previews — workspaces can hold 100MB+ URL/JSONL files and
# read_text() loads the whole file into server RAM.
_MAX_TEXT_PREVIEW = 10 * 1024 * 1024


def _workspace_of(run_id: str) -> Path:
    db = get_db()
    try:
        run = db_get(db, Run, run_id)
        if not run:
            raise HTTPException(404, "Run not found")
        if not run.workspace:
            raise HTTPException(404, "Workspace not set")
        # Resolve so the containment check below compares canonical paths.
        return Path(run.workspace).resolve()
    finally:
        db.close()


def _read_gowitness_db(db_path: Path) -> dict[str, dict]:
    """Read gowitness sqlite3 and return {filename -> {url, title, status}} map."""
    try:
        con = sqlite3.connect(str(db_path))
        # gowitness v3 schema: table is 'results' (not 'urls')
        rows = con.execute(
            "SELECT filename, url, final_url, title, response_code FROM results"
            " WHERE filename != '' AND failed = 0"
        ).fetchall()
        con.close()
        result = {}
        for filename, url, final_url, title, code in rows:
            result[Path(filename).name] = {
                "url": final_url or url or "",
                "title": title or "",
                "status": code,
            }
        return result
    except Exception:
        return {}


@router.get("/runs/{run_id}/screenshots")
def list_screenshots(run_id: str) -> list[dict[str, Any]]:
    ws = _workspace_of(run_id)
    ss_dir = ws / "screenshots"
    if not ss_dir.exists():
        return []

    db_meta = _read_gowitness_db(ws / "gowitness.sqlite3")

    items = []
    for p in sorted(ss_dir.glob("*")):
        if p.is_file() and p.suffix.lower() in _IMAGE_EXTS:
            meta = db_meta.get(p.name, {})
            items.append({
                "file": f"screenshots/{p.name}",
                "name": p.name,
                "url": meta.get("url", ""),
                "title": meta.get("title", ""),
                "status": meta.get("status"),
                "size": p.stat().st_size,
            })
    return items


@router.get("/runs/{run_id}/files")
def list_files(run_id: str) -> list[dict[str, Any]]:
    ws = _workspace_of(run_id)
    if not ws.exists():
        return []

    result = []
    for p in sorted(ws.rglob("*")):
        if p.is_file() and p.name != "resume.json":
            rel = p.relative_to(ws)
            result.append({
                "path": str(rel).replace("\\", "/"),
                "name": p.name,
                "size": p.stat().st_size,
                "ext": p.suffix.lower(),
            })
    return result


@router.get("/runs/{run_id}/files/{file_path:path}")
def read_file(run_id: str, file_path: str):
    ws = _workspace_of(run_id)
    target = (ws / file_path).resolve()

    # String-prefix checks are bypassable (sibling dir ".../ts-evil" passes a
    # ".../ts" prefix); use proper path containment instead.
    if not target.is_relative_to(ws):
        raise HTTPException(403, "Path traversal not allowed")
    if not target.is_file():
        raise HTTPException(404, "File not found")

    ext = target.suffix.lower()
    if ext == ".json" or ext == ".jsonl":
        return PlainTextResponse(_read_capped(target), media_type="application/json")
    if ext in _TEXT_EXTS:
        return PlainTextResponse(_read_capped(target))
    return FileResponse(str(target))


def _read_capped(target: Path) -> str:
    size = target.stat().st_size
    if size <= _MAX_TEXT_PREVIEW:
        return target.read_text(encoding="utf-8", errors="replace")
    with target.open("r", encoding="utf-8", errors="replace") as fh:
        head = fh.read(_MAX_TEXT_PREVIEW)
    return head + f"\n\n[... truncated: file is {size} bytes, showing first {_MAX_TEXT_PREVIEW} ...]"

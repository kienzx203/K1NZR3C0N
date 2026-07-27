from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Body

from ...db import ToolVersion, get_db
from ...tools import TOOLS, WORDLISTS, get_tool, get_wordlist, is_outdated

router = APIRouter(tags=["tools"])


def _rows() -> dict[str, ToolVersion]:
    db = get_db()
    try:
        return {r.name: r for r in db.query(ToolVersion).all()}
    finally:
        db.close()


@router.get("/tools")
def list_tools():
    """Return all tools and wordlists with version and status info."""
    rows = _rows()

    tools_out = []
    for tool in TOOLS:
        name = tool["name"]
        row = rows.get(name)
        installed = row.installed if row else None
        latest = row.latest if row else None
        status = row.status if row else "unknown"
        tools_out.append({
            "name":            name,
            "display":         tool["display"],
            "desc":            tool["desc"],
            "cat":             tool["cat"],
            "updatable":       tool["cat"] != "rebuild_only",
            "installed":       installed,
            "latest":          latest,
            "outdated":        is_outdated(installed, latest),
            "status":          status,
            "last_checked_at": row.last_checked_at.isoformat() if row and row.last_checked_at else None,
            "last_updated_at": row.last_updated_at.isoformat() if row and row.last_updated_at else None,
            "error_msg":       row.error_msg if row else None,
        })



    wl_out = []
    for wl in WORDLISTS:
        row_name = f"wordlist:{wl['name']}"
        row = rows.get(row_name)
        wl_out.append({
            "name":            wl["name"],
            "display":         wl["display"],
            "file":            wl["file"],
            "installed":       row.installed if row else None,
            "status":          row.status if row else "unknown",
            "last_checked_at": row.last_checked_at.isoformat() if row and row.last_checked_at else None,
            "last_updated_at": row.last_updated_at.isoformat() if row and row.last_updated_at else None,
            "error_msg":       row.error_msg if row else None,
        })

    outdated_count     = sum(1 for t in tools_out if t["outdated"])
    check_failed_count = sum(1 for t in tools_out if t["status"] == "check_failed")
    return {
        "tools":              tools_out,
        "wordlists":          wl_out,
        "outdated_count":     outdated_count,
        "check_failed_count": check_failed_count,
        "warning":            "Updates applied in-place. Use 'docker compose build' to persist across container recreation.",
    }


@router.post("/tools/check")
def check_versions():
    """Queue a background version check for all tools."""
    from ...tasks import check_tool_versions
    task = check_tool_versions.delay()
    return {"task_id": task.id, "status": "queued"}


@router.post("/tools/update")
def update_tools(body: dict = Body(default={})):
    """Update specified tools/wordlists (or all updatable if none specified).

    Body (optional):
      { "tools": ["nuclei", "httpx"], "wordlists": ["common"] }
    """
    from ...tasks import update_tool_task, update_wordlist_task

    tool_names = body.get("tools", [])
    wl_names   = body.get("wordlists", [])

    # Only trigger "update all" when neither key is present in the request body.
    # An empty list [] means "nothing requested", not "update everything".
    if "tools" not in body and "wordlists" not in body:
        tool_names = [t["name"] for t in TOOLS if t["cat"] != "rebuild_only"]
        wl_names   = [w["name"] for w in WORDLISTS]

    dispatched = []
    for name in tool_names:
        tool = get_tool(name)
        if not tool:
            continue
        if tool["cat"] == "rebuild_only":
            continue  # cannot update in-place; skip even if explicitly named
        task = update_tool_task.delay(name)
        dispatched.append({"name": name, "kind": "tool", "task_id": task.id})

    for name in wl_names:
        if not get_wordlist(name):
            continue
        task = update_wordlist_task.delay(name)
        dispatched.append({"name": name, "kind": "wordlist", "task_id": task.id})

    return {"dispatched": dispatched, "count": len(dispatched)}

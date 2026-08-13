from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from ...db import Run, get_db_dep, db_get
from ...report import generate_html_report

router = APIRouter(tags=["reports"])


@router.get("/runs/{run_id}/report", response_class=HTMLResponse)
def get_report(run_id: str, db: Session = Depends(get_db_dep)):
    run = db_get(db, Run, run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    if run.status not in ("completed", "failed", "paused"):
        raise HTTPException(400, f"Report not available for status: {run.status}")
    html = generate_html_report(run_id)
    return HTMLResponse(content=html, headers={"Content-Disposition": f'inline; filename="report-{run_id}.html"'})

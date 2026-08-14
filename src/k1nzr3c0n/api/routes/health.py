"""Self-diagnostics — one endpoint answering "is the whole stack healthy?"."""
from __future__ import annotations

import shutil
import socket
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ...config import REDIS_URL, RUNS_DIR, WEBHOOK_URL, WORDLISTS_DIR
from ...db import Run, ToolVersion, get_db_dep

router = APIRouter(tags=["health"])


@router.get("/health")
def health(db: Session = Depends(get_db_dep)) -> dict:
    checks: dict = {}

    # System DNS — the probe that catches the post-NIC-change breakage
    # (systemd-resolved stub loses its uplink; recon tools die silently)
    try:
        socket.getaddrinfo("dns.google", 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
        checks["dns"] = {"ok": True}
    except OSError as e:
        checks["dns"] = {"ok": False, "error": str(e)[:200]}

    # Redis
    try:
        import redis as redis_lib
        r = redis_lib.from_url(REDIS_URL, socket_connect_timeout=2, socket_timeout=2)
        r.ping()
        checks["redis"] = {"ok": True}
    except Exception as e:
        checks["redis"] = {"ok": False, "error": str(e)[:200]}

    # Celery worker (short ping — don't block the API if the worker is down)
    try:
        from ...tasks import celery_app
        pong = celery_app.control.ping(timeout=1.5)
        workers = [list(p.keys())[0] for p in pong] if pong else []
        checks["worker"] = {"ok": bool(workers), "workers": workers}
    except Exception as e:
        checks["worker"] = {"ok": False, "error": str(e)[:200]}

    # Celery beat (heuristic: scheduler tick wrote recently? — use process check via redis lock set by beat task)
    try:
        import redis as redis_lib
        r = redis_lib.from_url(REDIS_URL, socket_connect_timeout=2)
        last_tick = r.get("k1nzr3c0n:beat_tick")
        checks["beat"] = {"ok": last_tick is not None, "last_tick": last_tick.decode() if last_tick else None}
    except Exception:
        checks["beat"] = {"ok": False}

    # Disk space where runs live
    try:
        RUNS_DIR.mkdir(parents=True, exist_ok=True)
        du = shutil.disk_usage(str(RUNS_DIR))
        checks["disk"] = {
            "ok": du.free / du.total > 0.05,
            "free_gb": round(du.free / 1e9, 2),
            "total_gb": round(du.total / 1e9, 2),
        }
    except Exception as e:
        checks["disk"] = {"ok": False, "error": str(e)[:200]}

    # Tool versions summary
    try:
        rows = db.query(ToolVersion).all()
        outdated = [t.name for t in rows if t.status == "outdated"]
        failed = [t.name for t in rows if t.status == "failed"]
        checks["tools"] = {"ok": True, "tracked": len(rows), "outdated": outdated, "update_failed": failed}
    except Exception as e:
        checks["tools"] = {"ok": False, "error": str(e)[:200]}

    # Resolver wordlist (primary DNS resolve path depends on it)
    resolvers = WORDLISTS_DIR / "resolvers-trickest.txt"
    checks["resolvers"] = {"ok": resolvers.exists(), "path": str(resolvers)}

    # Webhook configured?
    checks["webhook"] = {"ok": bool(WEBHOOK_URL), "configured": bool(WEBHOOK_URL)}

    # Runs stuck in "running" for > task_time_limit likely orphans
    try:
        cutoff = datetime.utcnow() - timedelta(hours=13)
        stuck = db.query(func.count(Run.id)).filter(Run.status == "running", Run.started_at < cutoff).scalar() or 0
        checks["stuck_runs"] = {"ok": stuck == 0, "count": stuck}
    except Exception:
        checks["stuck_runs"] = {"ok": True, "count": 0}

    # webhook is an optional integration — unconfigured is informational, not degraded
    graded = {k: c for k, c in checks.items() if k != "webhook"}
    all_ok = all(c.get("ok", False) for c in graded.values())
    return {"status": "ok" if all_ok else "degraded", "time": datetime.utcnow().isoformat(), "checks": checks}

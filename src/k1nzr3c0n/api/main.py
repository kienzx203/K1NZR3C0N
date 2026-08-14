from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path

import redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..config import REDIS_URL, STATIC_DIR

# Resolve the static dir: prefer the directory that sits alongside this
# package (src/k1nzr3c0n/static/) so the UI always works regardless of
# whether K1NZR3C0N_BASE is set correctly.  Fall back to STATIC_DIR for
# backwards compatibility with custom deployments.
_PACKAGE_STATIC = Path(__file__).resolve().parent.parent / "static"
_STATIC_DIR = _PACKAGE_STATIC if _PACKAGE_STATIC.exists() else STATIC_DIR
from ..config import API_TOKEN
from ..db import RunLog, init_db, db_get
from .auth import TokenAuthMiddleware
from .routes import (assets, files, findings, health, keys, network, opencode,
                     reports, runs, schedules, targets, terminal, tools, upload,
                     workflows)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    opencode.start_opencode()
    try:
        yield
    finally:
        opencode.stop_opencode()


app = FastAPI(title="k1nzr3c0n API", version="3.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
# Outermost: optional bearer-token auth (no-op unless K1NZR3C0N_API_TOKEN is set)
app.add_middleware(TokenAuthMiddleware)

_V1 = "/api/v1"
app.include_router(runs.router,      prefix=_V1)
app.include_router(workflows.router, prefix=_V1)
app.include_router(files.router,     prefix=_V1)
app.include_router(findings.router,  prefix=_V1)
app.include_router(assets.router,    prefix=_V1)
app.include_router(reports.router,   prefix=_V1)
app.include_router(keys.router,      prefix=_V1)
app.include_router(tools.router,     prefix=_V1)
app.include_router(upload.router,    prefix=_V1)
app.include_router(health.router,    prefix=_V1)
app.include_router(network.router,   prefix=_V1)
app.include_router(schedules.router, prefix=_V1)
app.include_router(targets.router,   prefix=_V1)
app.include_router(terminal.router,  prefix="/ws")


@app.get("/api/v1/auth/status")
def auth_status() -> dict:
    """Lets the UI know whether it must present a token prompt."""
    return {"auth_required": bool(API_TOKEN)}

# Keep /api/* aliases for backwards compatibility during transition
app.include_router(runs.router,      prefix="/api", include_in_schema=False)
app.include_router(workflows.router, prefix="/api", include_in_schema=False)
app.include_router(files.router,     prefix="/api", include_in_schema=False)

# opencode proxy — must come AFTER specific /api/... routes so the catch-all
# /api/{path:path} only fires for paths k1nzr3c0n doesn't own.
app.include_router(opencode.router)


# ── WebSocket: live log streaming ──────────────────────────────────────────────


@app.websocket("/ws/runs/{run_id}")
async def ws_run_logs(websocket: WebSocket, run_id: str):
    """Live-only log stream for a running run.

    Historical logs are fetched by the client via GET /runs/{id}/logs.
    This endpoint only streams new messages from Redis pubsub to avoid
    duplicate delivery when the client reconnects.
    """
    from ..db import Run, get_db, db_get

    await websocket.accept()
    db = get_db()

    try:
        run = db_get(db, Run, run_id)
        if run is None:
            # Unknown run — close instead of leaving the socket hanging open
            # forever on a pubsub channel that will never receive messages.
            await websocket.send_json({"type": "done", "status": "not_found", "steps": []})
            return

        total_logs = db.query(RunLog).filter(RunLog.run_id == run_id).count()
        # Always send current total so client knows how many lines exist in DB
        await websocket.send_json({"type": "log_meta", "total": total_logs})

        if run.status in ("completed", "failed", "cancelled", "paused"):
            await websocket.send_json({"type": "done", "status": run.status, "steps": json.loads(run.steps_json or "[]")})
            return
    finally:
        db.close()

    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = redis.pubsub()
    await pubsub.subscribe(f"logs:{run_id}")

    # Re-check the status AFTER subscribing: if the run finished between the
    # check above and the subscribe, the one-shot "done" publish is already
    # gone and this socket would wait forever. Subscribe-first + re-check
    # closes that race — anything finishing later arrives via pubsub.
    db = get_db()
    try:
        run = db_get(db, Run, run_id)
        if run and run.status in ("completed", "failed", "cancelled", "paused"):
            await websocket.send_json({"type": "done", "status": run.status, "steps": json.loads(run.steps_json or "[]")})
            return
    finally:
        db.close()

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = json.loads(message["data"])
            await websocket.send_json(data)
            if data.get("type") == "done":
                break
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(f"logs:{run_id}")
        await redis.aclose()


# ── Serve React SPA ────────────────────────────────────────────────────────────

if _STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        index = _STATIC_DIR / "index.html"
        return FileResponse(
            str(index),
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

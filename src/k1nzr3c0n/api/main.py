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
from ..db import RunLog, init_db, db_get
from .routes import assets, files, findings, keys, opencode, reports, runs, terminal, tools, upload, workflows


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
app.include_router(terminal.router,  prefix="/ws")

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
        total_logs = db.query(RunLog).filter(RunLog.run_id == run_id).count()
        # Always send current total so client knows how many lines exist in DB
        await websocket.send_json({"type": "log_meta", "total": total_logs})

        run = db_get(db, Run, run_id)
        if run and run.status in ("completed", "failed", "cancelled", "paused"):
            await websocket.send_json({"type": "done", "status": run.status, "steps": json.loads(run.steps_json or "[]")})
            return
    finally:
        db.close()

    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = redis.pubsub()
    await pubsub.subscribe(f"logs:{run_id}")

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

if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        index = STATIC_DIR / "index.html"
        return FileResponse(
            str(index),
            headers={
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )

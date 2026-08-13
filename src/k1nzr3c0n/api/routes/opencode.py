from __future__ import annotations

import os
import subprocess
import sys

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse, Response, StreamingResponse

router = APIRouter()

OPENCODE_PORT = 4040
OPENCODE_BASE = f"http://127.0.0.1:{OPENCODE_PORT}"
OPENCODE_BIN  = "/root/.opencode/bin/opencode"
OPENCODE_WRAPPER = "/root/.opencode/run.sh"

_proc: subprocess.Popen | None = None


# ── Lifecycle ──────────────────────────────────────────────────────────────────

def _opencode_env() -> dict[str, str]:
    """Build env for opencode subprocess, pulling provider keys from config if absent."""
    import json, re
    env = {**os.environ, "OPENCODE_SERVER_PASSWORD": ""}
    if env.get("OPENROUTER_API_KEY"):
        return env
    # Fall back to reading apiKey from opencode.jsonc config file.
    cfg = os.path.expanduser("~/.config/opencode/opencode.jsonc")
    try:
        raw = open(cfg).read()
        # Strip // comments before parsing
        raw = re.sub(r"//[^\n]*", "", raw)
        data = json.loads(raw)
        key = (data.get("provider", {}).get("openrouter", {}).get("apiKey")
               or data.get("provider", {}).get("openrouter", {}).get("api_key"))
        if key:
            env["OPENROUTER_API_KEY"] = key
    except Exception:
        pass
    return env


def start_opencode() -> None:
    global _proc
    launcher = OPENCODE_WRAPPER if os.path.isfile(OPENCODE_WRAPPER) else OPENCODE_BIN
    if not os.path.isfile(launcher):
        print(f"[opencode] binary not found at {launcher}", file=sys.stderr)
        return
    _proc = subprocess.Popen(
        # Loopback only: OPENCODE_SERVER_PASSWORD is empty (no auth) and opencode
        # is an AI agent with shell access — the old 0.0.0.0 bind made it
        # LAN-reachable unauthenticated RCE. The UI reaches opencode through
        # the /opencode/ proxy below, which connects to 127.0.0.1.
        [launcher, "web", "--hostname", "127.0.0.1", "--port", str(OPENCODE_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=_opencode_env(),
    )
    print(f"[opencode] started pid={_proc.pid} on port {OPENCODE_PORT}", file=sys.stderr)


def stop_opencode() -> None:
    if _proc and _proc.poll() is None:
        _proc.terminate()
        try:
            _proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _proc.kill()


# ── Helpers ────────────────────────────────────────────────────────────────────

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
})


def _fwd_headers(request: Request) -> dict[str, str]:
    return {
        k: v for k, v in request.headers.items()
        if k.lower() not in (_HOP_BY_HOP | {"host", "content-length"})
    }


def _resp_headers(resp: httpx.Response) -> dict[str, str]:
    return {
        k: v for k, v in resp.headers.items()
        if k.lower() not in (_HOP_BY_HOP | {"content-encoding", "content-length"})
    }


async def _proxy(request: Request, upstream_path: str) -> Response:
    qs = request.url.query
    url = f"{OPENCODE_BASE}{upstream_path}" + (f"?{qs}" if qs else "")

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            rp = await client.request(
                method=request.method,
                url=url,
                headers=_fwd_headers(request),
                content=await request.body(),
                follow_redirects=False,
            )
    except httpx.ConnectError:
        return Response(
            content=b"opencode is starting up, please retry in a few seconds",
            status_code=503,
            media_type="text/plain",
        )

    ct = rp.headers.get("content-type", "")
    body = rp.content

    if "text/html" in ct:
        body = body.replace(b'href="/', b'href="/opencode/')
        body = body.replace(b"href='/", b"href='/opencode/")
        body = body.replace(b'src="/', b'src="/opencode/')
        body = body.replace(b"src='/", b"src='/opencode/")
        body = body.replace(b'action="/', b'action="/opencode/')
        body = body.replace(b'content="/', b'content="/opencode/')
        # Inject router-prefix shim so React Router sees "/" not "/opencode/".
        # Also intercepts pushState/replaceState to keep URLs under /opencode/*.
        shim = (
            b'<script>;(function(){'
            b'var P="/opencode";'
            b'var l=window.location;'
            b'if(l.pathname.startsWith(P)){'
            b'  var s=l.pathname.slice(P.length)||"/";'
            b'  history.replaceState(history.state,"",s+l.search+l.hash);'
            b'}'
            b'function fix(u){'
            b'  if(!u||typeof u!=="string")return u;'
            b'  if(!u.startsWith("/"))return u;'
            b'  if(u.startsWith(P))return u;'
            b'  return P+u;'
            b'}'
            b'var _ps=history.pushState.bind(history);'
            b'var _rs=history.replaceState.bind(history);'
            b'history.pushState=function(s,t,u){return _ps(s,t,fix(u));};'
            b'history.replaceState=function(s,t,u){return _rs(s,t,fix(u));};'
            b'})();</script>'
        )
        body = body.replace(b'<head>', b'<head>' + shim, 1)

    return Response(
        content=body,
        status_code=rp.status_code,
        headers=_resp_headers(rp),
        media_type=ct or None,
    )


# ── Routes — order matters: specific before catch-all ─────────────────────────

@router.get("/opencode", include_in_schema=False)
async def opencode_redirect():
    return RedirectResponse("/opencode/")


@router.api_route(
    "/opencode/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    include_in_schema=False,
)
async def opencode_ui_proxy(request: Request, path: str):
    return await _proxy(request, f"/{path}")


# SSE route MUST come before the catch-all /api/{path:path} so it is matched
# first — the catch-all buffers the full response (bad for infinite SSE streams).
@router.get("/api/event", include_in_schema=False)
async def opencode_sse(request: Request):
    qs = request.url.query
    url = f"{OPENCODE_BASE}/api/event" + (f"?{qs}" if qs else "")

    async def _stream():
        async with httpx.AsyncClient(timeout=None) as client:
            async with client.stream("GET", url, headers=_fwd_headers(request)) as resp:
                async for chunk in resp.aiter_bytes(4096):
                    yield chunk

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# Catch-all for opencode's /api/* paths not claimed by k1nzr3c0n's own routes.
# FastAPI evaluates routes in registration order, so /api/v1/... and the compat
# /api/runs, /api/workflows, /api/files aliases (registered before this router)
# will match first; everything else falls through to opencode.
@router.api_route(
    "/api/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
    include_in_schema=False,
)
async def opencode_api_proxy(request: Request, path: str):
    return await _proxy(request, f"/api/{path}")

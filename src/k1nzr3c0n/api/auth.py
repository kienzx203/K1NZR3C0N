"""Optional bearer-token auth (enabled when K1NZR3C0N_API_TOKEN is set).

HTTP:   Authorization: Bearer <token> on every /api/* path (health stays open)
WS:     ?token=<token> query param on /ws/* paths
No token configured → auth fully disabled (local single-user default).
"""
from __future__ import annotations

from urllib.parse import parse_qs

from fastapi.responses import JSONResponse
from starlette.websockets import WebSocket

from ..config import API_TOKEN

# Paths that never require auth (liveness probes, static UI shell)
_OPEN_HTTP_PREFIXES = ("/api/v1/health", "/api/v1/auth/status")


def _authorized_http(headers: list[tuple[bytes, bytes]]) -> bool:
    for key, value in headers:
        if key == b"authorization":
            return value.decode() == f"Bearer {API_TOKEN}"
    return False


class TokenAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if API_TOKEN:
            path = scope.get("path", "")

            if scope["type"] == "websocket" and path.startswith("/ws/"):
                qs = parse_qs(scope.get("query_string", b"").decode())
                token = (qs.get("token") or [""])[0]
                if token != API_TOKEN:
                    ws = WebSocket(scope, receive, send)
                    await ws.close(code=4001)
                    return

            elif scope["type"] == "http" and path.startswith("/api/"):
                if not any(path.startswith(p) for p in _OPEN_HTTP_PREFIXES):
                    if not _authorized_http(scope.get("headers", [])):
                        resp = JSONResponse({"detail": "Unauthorized"}, status_code=401)
                        await resp(scope, receive, send)
                        return

        await self.app(scope, receive, send)

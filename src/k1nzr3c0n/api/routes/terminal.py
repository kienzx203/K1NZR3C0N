from __future__ import annotations

import asyncio
import json
import os
from typing import TYPE_CHECKING

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

if TYPE_CHECKING:
    import ptyprocess as _pty

router = APIRouter()

# PTY sessions survive WebSocket disconnects — cleaned up after IDLE_TIMEOUT seconds
_sessions: dict[str, "_pty.PtyProcess"] = {}
_timers:   dict[str, asyncio.TimerHandle] = {}
_IDLE_TIMEOUT = 30 * 60  # 30 minutes


def _cancel_timer(sid: str) -> None:
    if t := _timers.pop(sid, None):
        t.cancel()


def _schedule_cleanup(sid: str, loop: asyncio.AbstractEventLoop) -> None:
    def _kill() -> None:
        proc = _sessions.pop(sid, None)
        _timers.pop(sid, None)
        if proc and proc.isalive():
            proc.terminate(force=True)
    _timers[sid] = loop.call_later(_IDLE_TIMEOUT, _kill)


@router.websocket("/terminal/{session_id}")
async def terminal_ws(websocket: WebSocket, session_id: str):
    await websocket.accept()

    try:
        import ptyprocess
    except ImportError:
        await websocket.send_bytes(b"\r\n\033[1;31m[!] ptyprocess not installed.\033[0m\r\n")
        await websocket.close(1000)
        return

    loop = asyncio.get_event_loop()

    # Cancel any pending idle cleanup for this session
    _cancel_timer(session_id)

    # Reuse existing PTY or spawn a new one
    proc = _sessions.get(session_id)
    if proc is None or not proc.isalive():
        env = {**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor"}
        proc = ptyprocess.PtyProcess.spawn(["/bin/bash", "-l"], env=env, dimensions=(24, 200))
        _sessions[session_id] = proc

    async def pty_to_ws() -> None:
        while proc.isalive():
            try:
                data = await loop.run_in_executor(None, lambda: os.read(proc.fd, 4096))
                await websocket.send_bytes(data)
            except (OSError, WebSocketDisconnect):
                break

    async def ws_to_pty() -> None:
        while True:
            try:
                msg = await websocket.receive()
            except WebSocketDisconnect:
                break
            if msg.get("type") == "websocket.disconnect":
                break
            if raw := msg.get("bytes"):
                os.write(proc.fd, raw)
            elif text := msg.get("text"):
                try:
                    data = json.loads(text)
                    if data.get("type") == "resize":
                        rows = max(1, int(data.get("rows", 24)))
                        cols = max(1, int(data.get("cols", 80)))
                        proc.setwinsize(rows, cols)
                except (json.JSONDecodeError, OSError):
                    pass

    try:
        await asyncio.gather(pty_to_ws(), ws_to_pty())
    finally:
        # PTY stays alive — schedule cleanup after idle timeout
        _schedule_cleanup(session_id, loop)

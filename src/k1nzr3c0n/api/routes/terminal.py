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
# The WebSocket currently driving each session (takeover bookkeeping)
_active:   dict[str, WebSocket] = {}
# Serializes spawn/takeover per session — two concurrent connects for the same
# session_id used to race on _sessions.get and could spawn/orphan a PTY.
_locks:    dict[str, asyncio.Lock] = {}
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

    lock = _locks.setdefault(session_id, asyncio.Lock())
    async with lock:
        # Cancel any pending idle cleanup for this session
        _cancel_timer(session_id)

        # Reuse existing PTY or spawn a new one
        proc = _sessions.get(session_id)
        if proc is None or not proc.isalive():
            env = {**os.environ, "TERM": "xterm-256color", "COLORTERM": "truecolor"}
            proc = ptyprocess.PtyProcess.spawn(["/bin/bash", "-l"], env=env, dimensions=(24, 200))
            _sessions[session_id] = proc

        # Take over the session: a reconnecting client replaces the previous
        # live connection (which may be a half-dead socket that never cleaned up).
        previous = _active.get(session_id)
        _active[session_id] = websocket
    if previous is not None and previous is not websocket:
        try:
            await previous.close(code=4000, reason="session taken over")
        except Exception:
            pass

    async def pty_to_ws() -> None:
        # Read the PTY fd via loop.add_reader instead of a blocking os.read in
        # the default executor: the old version left an executor thread parked
        # forever on every abandoned session (~32 leaks exhaust the pool and
        # stall ALL run_in_executor users in the app), and the finally-block
        # cleanup never ran because gather() never returned.
        fd = proc.fd
        q: asyncio.Queue = asyncio.Queue()

        def _on_readable() -> None:
            try:
                data = os.read(fd, 4096)
            except OSError:
                data = b""
            q.put_nowait(data)

        loop.add_reader(fd, _on_readable)
        try:
            while _active.get(session_id) is websocket:
                data = await q.get()
                if not data:  # EOF — PTY exited
                    break
                await websocket.send_bytes(data)
        except (WebSocketDisconnect, OSError):
            pass
        finally:
            try:
                loop.remove_reader(fd)
            except (OSError, ValueError):
                pass

    async def ws_to_pty() -> None:
        while _active.get(session_id) is websocket:
            try:
                msg = await websocket.receive()
            except WebSocketDisconnect:
                break
            if msg.get("type") == "websocket.disconnect":
                break
            if raw := msg.get("bytes"):
                try:
                    os.write(proc.fd, raw)
                except OSError:
                    break  # PTY died mid-write
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
        # Only the connection that still owns the session schedules the idle
        # kill — a taken-over socket must not kill the PTY its replacement uses.
        if _active.get(session_id) is websocket:
            _active.pop(session_id, None)
            # PTY stays alive — schedule cleanup after idle timeout
            _schedule_cleanup(session_id, loop)

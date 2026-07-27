from __future__ import annotations

import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

import redis as redis_lib
from celery import Celery
from celery.schedules import crontab
from celery.signals import worker_ready

from .config import CELERY_BACKEND, CELERY_BROKER, REDIS_URL, WEBHOOK_URL, WEBHOOK_USERNAME

celery_app = Celery(
    "k1nzr3c0n",
    broker=CELERY_BROKER,
    backend=CELERY_BACKEND,
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    beat_schedule={
        "workspace-cleanup": {
            "task": "k1nzr3c0n.workspace_cleanup",
            "schedule": crontab(hour=2, minute=0),
        },
        "check-tool-versions": {
            "task": "k1nzr3c0n.check_tool_versions",
            "schedule": crontab(hour=4, minute=0),  # daily at 4 AM
        },
    },
)

_redis = redis_lib.from_url(REDIS_URL, decode_responses=True)


@worker_ready.connect
def _init_db_on_worker_start(**_):
    from .db import init_db
    init_db()


# ── Step marker protocol ──────────────────────────────────────────────────────
# Format emitted by workflow.py _step_event():
#   ##K1Z:START:step_id##
#   ##K1Z:DONE:step_id##
#   ##K1Z:FAIL:step_id##
#   ##K1Z:SKIP:step_id##
#   ##K1Z:TIME:step_id:elapsed_ms##

_STEP_MARKER = re.compile(r'^##K1Z:(\w+):(.+)##$')
_ANSI_ESCAPE  = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|\r')
_PAUSE_EXIT_CODE = 75  # must match workflow.PAUSE_EXIT_CODE

_STATUS_MAP = {
    "START": "running",
    "DONE": "ok",
    "FAIL": "failed",
    "SKIP": "skipped",
}

_BATCH_SIZE = 20     # flush log buffer to DB every N lines
_BATCH_SECS = 1.0    # or every N seconds


def _write_subfinder_config(key_map: dict[str, str]) -> None:
    """Write all configured API keys to ~/.config/subfinder/provider-config.yaml."""
    try:
        import yaml as _yaml
        cfg = {p: [v] for p, v in key_map.items() if v and v.strip()}
        config_dir = Path.home() / ".config" / "subfinder"
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / "provider-config.yaml").write_text(
            _yaml.dump(cfg, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
    except Exception:
        pass  # non-fatal


def _inject_keys_into_cmd(cmd: list[str], key_map: dict[str, str]) -> list[str]:
    """Inject API keys as workflow --vars at run time.

    Mapping: stored provider id → workflow var name
    """
    VAR_MAP = {
        "chaos": "chaos_key",
    }
    to_inject = {}
    for provider, var_name in VAR_MAP.items():
        value = (key_map.get(provider) or "").strip()
        if not value:
            continue
        # Skip if already present in cmd
        if any(f"{var_name}=" in part for part in cmd):
            continue
        to_inject[var_name] = value

    if not to_inject:
        return cmd

    cmd = list(cmd)
    if "--vars" in cmd:
        idx = cmd.index("--vars") + 1
        while idx < len(cmd) and not cmd[idx].startswith("-"):
            idx += 1
        for var_name, value in to_inject.items():
            cmd.insert(idx, f"{var_name}={value}")
            idx += 1
    else:
        pairs = [f"{k}={v}" for k, v in to_inject.items()]
        cmd += ["--vars"] + pairs
    return cmd


def _publish(run_id: str, payload: dict) -> None:
    _redis.publish(f"logs:{run_id}", json.dumps(payload))


def _flush_logs(db, run_id: str, buffer: list[str]) -> None:
    if not buffer:
        return
    from .db import RunLog
    db.bulk_insert_mappings(RunLog, [{"run_id": run_id, "message": m} for m in buffer])
    db.commit()
    buffer.clear()


def _update_steps(db, run, steps: list[dict]) -> None:
    from sqlalchemy import text
    steps_json = json.dumps(steps)
    # Direct SQL UPDATE to avoid ORM lazy-load errors on expired objects.
    # After each _flush_logs commit, `run` is expired; assigning an attribute
    # and committing triggers get_history() → lazy-load → DetachedInstanceError.
    db.execute(text("UPDATE runs SET steps_json = :s WHERE id = :id"),
               {"s": steps_json, "id": run.id})
    db.commit()
    # Keep in-memory dict in sync so callers reading run.steps_json see fresh data
    run.__dict__["steps_json"] = steps_json


def _handle_step_marker(event: str, payload: str, steps: list[dict]) -> tuple[bool, bool]:
    """Parse a step marker and mutate `steps` in-place.

    Returns (changed_status, changed_timing) to tell caller what to publish.
    """
    if event in _STATUS_MAP:
        new_status = _STATUS_MAP[event]
        for s in steps:
            if s["id"] == payload:
                # Don't downgrade a completed step to skipped on resume
                if new_status == "skipped" and s.get("status") == "ok":
                    return False, False
                s["status"] = new_status
                return True, False
        return False, False

    if event == "TIME":
        # payload = "step_id:elapsed_ms"
        parts = payload.rsplit(":", 1)
        if len(parts) == 2:
            step_id, ms_str = parts
            try:
                ms = int(ms_str)
            except ValueError:
                return False, False
            for s in steps:
                if s["id"] == step_id:
                    s["duration_ms"] = ms
                    return False, True
        return False, False

    return False, False


# ── Webhook notifications ─────────────────────────────────────────────────────

def _send_webhook(
    *,
    run_id: str,
    target: str,
    workflow: str,
    status: str,
    elapsed_s: float,
    findings_count: int,
) -> None:
    url = WEBHOOK_URL
    if not url:
        return

    ok = status == "completed"
    icon = "✅" if ok else "❌"
    color = 0x3FB950 if ok else 0xF85149  # Discord color int
    title = f"{icon} k1nzr3c0n · {status.upper()}"
    body = (
        f"**Target:** `{target}`\n"
        f"**Workflow:** `{workflow}`\n"
        f"**Duration:** {elapsed_s:.0f}s\n"
        f"**Findings:** {findings_count}\n"
        f"**Run ID:** `{run_id}`"
    )

    is_discord = "discord.com" in url
    if is_discord:
        payload = {
            "embeds": [{
                "title": title,
                "description": body,
                "color": color,
                "footer": {"text": "k1nzr3c0n"},
            }]
        }
    else:
        # Slack-compatible incoming webhook format
        payload = {
            "username": WEBHOOK_USERNAME,
            "attachments": [{
                "title": title,
                "text": body.replace("**", "").replace("`", "`"),
                "color": "good" if ok else "danger",
                "footer": "k1nzr3c0n",
            }],
        }

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except (urllib.error.URLError, OSError):
        pass  # non-fatal


# ── Main run task ─────────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="k1nzr3c0n.execute_run")
def execute_run(self, run_id: str, cmd: list[str]) -> dict:
    from .db import Run, RunLog, get_db

    db = get_db()
    t_start = time.monotonic()
    try:
        run = db.get(Run, run_id)
        if run is None:
            return {"error": "run not found"}

        run.celery_task_id = self.request.id
        run.status = "running"
        if run.started_at is None:  # preserve original start time on resume
            run.started_at = datetime.utcnow()
        db.commit()

        _publish(run_id, {"type": "status", "status": "running"})

        # Inject configured API keys before starting the subprocess
        from .db import ApiKey as _ApiKey
        key_map = {r.provider: r.value for r in db.query(_ApiKey).all()}
        _write_subfinder_config(key_map)
        cmd = _inject_keys_into_cmd(cmd, key_map)

        steps: list[dict] = json.loads(run.steps_json or "[]")
        _cancel_flag = Path(run.workspace) / "cancel.flag" if run.workspace else None

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        log_buffer: list[str] = []
        last_flush = time.monotonic()
        _cancelled = False
        _line_count = 0

        for raw in proc.stdout:
            # Split on \r BEFORE stripping ANSI (the regex also eats \r).
            # Progress bars overwrite the line with \r; keep only the last visible segment.
            line = ''
            for seg in reversed(raw.split('\r')):
                candidate = _ANSI_ESCAPE.sub('', seg).strip()
                if candidate:
                    line = candidate
                    break
            if not line:
                continue

            m = _STEP_MARKER.match(line)
            if m:
                changed_status, changed_timing = _handle_step_marker(
                    m.group(1), m.group(2), steps
                )
                _update_steps(db, run, steps)
                if changed_status:
                    _publish(run_id, {"type": "step", "steps": steps})
                # markers are machine-readable only — don't save to log DB or broadcast
                continue

            _publish(run_id, {"type": "log", "message": line})
            log_buffer.append(line)
            now = time.monotonic()
            if len(log_buffer) >= _BATCH_SIZE or (now - last_flush) >= _BATCH_SECS:
                _flush_logs(db, run_id, log_buffer)
                last_flush = now

            # Check cancel flag every 10 lines to kill subprocess promptly
            _line_count += 1
            if _cancel_flag and _line_count % 10 == 0 and _cancel_flag.exists():
                _cancelled = True
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                break

        proc.wait()
        _flush_logs(db, run_id, log_buffer)

        elapsed_s = time.monotonic() - t_start

        # Re-fetch run — API may have already set status="cancelled"
        run = db.get(Run, run_id)

        if _cancelled or run.status == "cancelled":
            for s in steps:
                if s.get("status") == "running":
                    s["status"] = "cancelled"
            run.steps_json = json.dumps(steps)
            if run.status != "cancelled":
                run.status = "cancelled"
                run.finished_at = datetime.utcnow()
            db.commit()
            _publish(run_id, {
                "type": "done",
                "status": "cancelled",
                "steps": steps,
                "elapsed_s": round(elapsed_s, 1),
            })
            return {"status": "cancelled", "elapsed_s": round(elapsed_s, 1)}

        paused = proc.returncode == _PAUSE_EXIT_CODE
        for s in steps:
            if s.get("status") == "running":
                s["status"] = "paused" if paused else ("ok" if proc.returncode == 0 else "failed")

        if paused:
            status = "paused"
        elif proc.returncode == 0:
            status = "completed"
        else:
            status = "failed"

        run.status = status
        run.returncode = proc.returncode
        run.finished_at = datetime.utcnow()
        if paused:
            run.paused_at = datetime.utcnow()
        run.steps_json = json.dumps(steps)
        db.commit()

        _publish(run_id, {
            "type": "done",
            "status": status,
            "returncode": proc.returncode,
            "steps": steps,
            "elapsed_s": round(elapsed_s, 1),
        })

        if status in ("completed", "failed"):
            parse_findings.delay(run_id)

        # Deferred webhook — after findings are available
        _webhook_notify.apply_async(
            (run_id, run.target, run.workflow, status, round(elapsed_s, 1)),
            countdown=10,  # give parse_findings time to finish
        )

        return {"status": status, "returncode": proc.returncode, "elapsed_s": round(elapsed_s, 1)}

    except Exception as exc:
        db.rollback()
        try:
            run = db.get(Run, run_id)
            if run and run.status != "cancelled":
                run.status = "failed"
                run.error_message = str(exc)
                run.finished_at = datetime.utcnow()
                db.commit()
        except Exception:
            pass
        _publish(run_id, {"type": "done", "status": "failed", "error": str(exc)})
        raise
    finally:
        db.close()


@celery_app.task(name="k1nzr3c0n.webhook_notify")
def _webhook_notify(run_id: str, target: str, workflow: str, status: str, elapsed_s: float) -> None:
    """Send webhook after a run finishes. Runs with a countdown to let parse_findings settle."""
    from .db import Finding, get_db
    db = get_db()
    try:
        count = db.query(Finding).filter(Finding.run_id == run_id).count()
    finally:
        db.close()

    _send_webhook(
        run_id=run_id,
        target=target,
        workflow=workflow,
        status=status,
        elapsed_s=elapsed_s,
        findings_count=count,
    )


# ── Findings parsing ──────────────────────────────────────────────────────────

@celery_app.task(name="k1nzr3c0n.parse_findings")
def parse_findings(run_id: str) -> dict:
    """Parse tool outputs from the run's workspace into structured Finding rows."""
    from .db import Finding, Run, get_db
    from .parsers import parse_workspace

    db = get_db()
    try:
        run = db.get(Run, run_id)
        if not run or not run.workspace:
            return {"error": "run or workspace not found"}

        db.query(Finding).filter(Finding.run_id == run_id).delete()
        db.commit()

        findings = parse_workspace(run_id, run.workspace)
        if findings:
            db.bulk_save_objects(findings)
            db.commit()

        return {"run_id": run_id, "count": len(findings)}
    finally:
        db.close()


# ── Tool version check & update ──────────────────────────────────────────────

@celery_app.task(name="k1nzr3c0n.check_tool_versions")
def check_tool_versions() -> dict:
    """Check installed vs latest versions for all tools. Runs daily via beat."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from .tools import TOOLS, WORDLISTS, get_installed_version, get_latest_version, get_latest_with_url, is_outdated
    from .db import ToolVersion, get_db

    db = get_db()
    try:
        def _check_tool(tool):
            name = tool["name"]
            try:
                installed = get_installed_version(tool)
                latest_url = None

                if tool["cat"] == "rebuild_only":
                    # No need to hit GitHub API for tools that can't be updated in-place.
                    status = "rebuild_only"
                    return name, installed, None, None, status

                if tool["cat"] == "gh_binary":
                    # Single API call returns both version and download URL.
                    # Caching the URL means update tasks skip a second GitHub API round-trip.
                    latest, latest_url = get_latest_with_url(tool)
                else:
                    latest = get_latest_version(tool)

                if not installed:
                    status = "unknown"
                elif latest is None:
                    # Version check failed (API rate limit, network error, etc.)
                    status = "check_failed"
                elif is_outdated(installed, latest):
                    status = "outdated"
                else:
                    status = "ok"
                return name, installed, latest, latest_url, status
            except Exception:
                # Network error, unexpected response, etc. — report as check_failed
                # so the DB row is still updated and the user can see something went wrong.
                try:
                    installed = get_installed_version(tool)
                except Exception:
                    installed = None
                return name, installed, None, None, "check_failed"

        def _check_wordlist(wl):
            name = f"wordlist:{wl['name']}"
            path = Path("/app/wordlists") / wl["file"]
            if path.exists():
                lines = sum(1 for _ in open(path, "rb"))
                installed = f"{lines} lines"
                status = "ok"
            else:
                installed = None
                status = "unknown"
            return name, installed, None, None, status

        items = [(t, False) for t in TOOLS] + [(w, True) for w in WORDLISTS]

        now = datetime.utcnow()
        # Keep concurrency low to avoid hitting GitHub's 60 req/hr anonymous rate limit.
        # With a GITHUB_TOKEN set in the environment the limit rises to 5000 req/hr,
        # so 5 workers is safe in both cases.
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = {
                ex.submit(_check_wordlist if is_wl else _check_tool, item): item
                for item, is_wl in items
            }
            results = []
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    pass

        for name, installed, latest, latest_url, status in results:
            row = db.get(ToolVersion, name)
            if not row:
                row = ToolVersion(name=name)
                db.add(row)
            # Preserve "updating" status if in progress
            if row.status != "updating":
                # Don't overwrite a higher recorded version with a lower binary self-report.
                # Some upstream releases (e.g. PD tools) embed the previous version string
                # in the binary even after a tag bump. The DB version (set by update_tool_task
                # from the GitHub release tag) is the authoritative source for gh_binary tools.
                if installed and row.installed and is_outdated(installed, row.installed):
                    # row.installed > installed: binary self-report is older — keep DB version
                    # and recompute status using the corrected installed version.
                    installed = row.installed
                    effective_latest = latest if latest is not None else row.latest
                    if not installed:
                        status = "unknown"
                    elif not effective_latest:
                        status = "check_failed"
                    elif is_outdated(installed, effective_latest):
                        status = "outdated"
                    else:
                        status = "ok"
                row.installed = installed
                # Only overwrite version/url when the check actually succeeded
                # (latest is None means rate limit or network failure)
                if latest is not None:
                    row.latest = latest
                    row.latest_url = latest_url
                row.status = status
            row.last_checked_at = now
        db.commit()

        return {"checked": len(results)}
    finally:
        db.close()


@celery_app.task(name="k1nzr3c0n.update_tool_task")
def update_tool_task(name: str) -> dict:
    """Download and install the latest version of a single tool."""
    from .tools import get_tool, update_tool
    from .db import ToolVersion, get_db

    db = get_db()
    try:
        tool = get_tool(name)
        if not tool:
            return {"error": f"Unknown tool: {name}"}

        row = db.get(ToolVersion, name)
        if not row:
            row = ToolVersion(name=name)
            db.add(row)

        # Read cached download URL before changing status (avoids extra GitHub API call)
        cached_url = row.latest_url
        cached_ver = row.latest

        row.status = "updating"
        row.error_msg = None
        db.commit()

        try:
            new_ver = update_tool(tool, cached_url=cached_url, cached_ver=cached_ver)
            row.installed = new_ver
            row.status = "ok"
            row.last_updated_at = datetime.utcnow()
            db.commit()
            return {"name": name, "version": new_ver}
        except Exception as e:
            row.status = "failed"
            row.error_msg = str(e)[:500]
            db.commit()
            return {"error": str(e)}
    finally:
        db.close()


@celery_app.task(name="k1nzr3c0n.update_wordlist_task")
def update_wordlist_task(name: str) -> dict:
    """Re-download a wordlist file."""
    from .tools import get_wordlist, update_wordlist
    from .db import ToolVersion, get_db

    db = get_db()
    try:
        wl = get_wordlist(name)
        if not wl:
            return {"error": f"Unknown wordlist: {name}"}

        row_name = f"wordlist:{name}"
        row = db.get(ToolVersion, row_name)
        if not row:
            row = ToolVersion(name=row_name)
            db.add(row)
        row.status = "updating"
        row.error_msg = None
        db.commit()

        try:
            result = update_wordlist(wl)
            row.installed = result
            row.status = "ok"
            row.last_updated_at = datetime.utcnow()
            db.commit()
            return {"name": name, "result": result}
        except Exception as e:
            row.status = "failed"
            row.error_msg = str(e)[:500]
            db.commit()
            return {"error": str(e)}
    finally:
        db.close()


# ── Workspace cleanup ─────────────────────────────────────────────────────────

@celery_app.task(name="k1nzr3c0n.workspace_cleanup")
def workspace_cleanup() -> dict:
    """Delete intermediate files from runs older than 30 days to reclaim disk space."""
    from .db import Run, get_db

    _KEEP = frozenset([
        "subdomains.txt", "subdomains_resolved.txt", "subzy.txt",
        "nuclei.jsonl", "nuclei_urls.jsonl", "httpx.jsonl", "naabu.jsonl",
        "katana.jsonl", "gau.jsonl", "waybackurls.txt",
        "afrog.jsonl", "urls_all.txt", "urls_params.txt", "kiterunner.txt",
        "resume.json",
    ])

    cutoff = datetime.utcnow() - timedelta(days=30)
    db = get_db()
    deleted_bytes = 0
    cleaned = 0

    try:
        old_runs = db.query(Run).filter(
            Run.status.in_(["completed", "failed", "cancelled"]),
            Run.finished_at < cutoff,
            Run.workspace.isnot(None),
        ).all()

        for run in old_runs:
            ws = Path(run.workspace)
            if not ws.exists():
                continue
            for p in ws.rglob("*"):
                if p.is_file() and p.name not in _KEEP:
                    deleted_bytes += p.stat().st_size
                    p.unlink()
            cleaned += 1

        return {"cleaned_runs": cleaned, "deleted_bytes": deleted_bytes}
    finally:
        db.close()

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Generator

from sqlalchemy import (
    Boolean, Column, DateTime, Integer, String, Text,
    create_engine, event, text,
)
from sqlalchemy.orm import Session, sessionmaker
try:
    # SQLAlchemy >= 2.0
    from sqlalchemy.orm import DeclarativeBase
    class Base(DeclarativeBase):
        pass
except ImportError:
    # SQLAlchemy < 2.0 (1.3.x / 1.4.x)
    from sqlalchemy.ext.declarative import declarative_base
    Base = declarative_base()

from .config import DB_PATH, RUNS_DIR


def _make_engine(path=DB_PATH):
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def set_pragma(conn, _):
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")

    return engine


_engine = _make_engine()
SessionLocal = sessionmaker(bind=_engine, autoflush=False)


class Run(Base):
    __tablename__ = "runs"

    id = Column(String(16), primary_key=True)
    workflow = Column(String(255), nullable=False)
    target = Column(String(512), nullable=False)
    status = Column(String(20), default="queued", index=True)
    workspace = Column(String(1024))
    vars_json = Column(Text, default="{}")
    out_dir = Column(String(1024))
    continue_on_error = Column(Boolean, default=False)
    resume = Column(Boolean, default=False)
    celery_task_id = Column(String(64))
    pid = Column(Integer)  # workflow runner pid (== pgid) — killed on worker restart
    returncode = Column(Integer)
    error_message = Column(Text)
    steps_json = Column(Text, default="[]")
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime)
    finished_at = Column(DateTime)
    paused_at = Column(DateTime)


class RunLog(Base):
    __tablename__ = "run_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(16), nullable=False, index=True)
    message = Column(Text, nullable=False)
    ts = Column(DateTime, default=datetime.utcnow)


class ApiKey(Base):
    """API keys for external intelligence providers (Shodan, Censys, etc.).
    Keys are injected into subfinder provider-config.yaml before each run.
    """
    __tablename__ = "api_keys"

    provider   = Column(String(64), primary_key=True)
    value      = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow)


class ToolVersion(Base):
    """Tracks installed vs latest version for each tool and wordlist."""
    __tablename__ = "tool_versions"

    name            = Column(String(64), primary_key=True)   # tool name or "wordlist:<name>"
    installed       = Column(String(64))                     # "2.14.0" or "installed" or commit hash
    latest          = Column(String(64))                     # latest version from GitHub/PyPI
    latest_url      = Column(Text)                           # cached asset download URL (avoids 2nd API call)
    status          = Column(String(20), default="unknown")  # unknown|ok|outdated|check_failed|updating|failed|rebuild_only
    last_checked_at = Column(DateTime)
    last_updated_at = Column(DateTime)
    error_msg       = Column(Text)


class Finding(Base):
    """Structured intel extracted from tool outputs after a run completes."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(16), nullable=False, index=True)
    kind = Column(String(20), nullable=False, index=True)   # vuln | port | http | subdomain
    severity = Column(String(20), index=True)               # critical | high | medium | low | info
    host = Column(String(512), nullable=False, index=True)
    notes = Column(Text)                                    # analyst notes (lifecycle tracking)
    tags = Column(Text, default="[]")                       # JSON array of free-form tags
    ip = Column(String(64))
    port = Column(Integer)
    status_code = Column(Integer)                           # HTTP status code, for kind="http" rows
    protocol = Column(String(20))
    name = Column(String(512))
    template_id = Column(String(256))
    url = Column(String(2048))
    title = Column(String(512))
    tech = Column(Text, default="[]")                       # JSON array of detected technologies
    evidence = Column(Text)                                 # curl-command or raw match snippet
    description = Column(Text)
    status = Column(String(20), default="open", index=True) # open | fp | resolved
    screenshot = Column(String(1024))                       # path relative to the run's workspace, e.g. "screenshots/x.png"
    created_at = Column(DateTime, default=datetime.utcnow)


class Schedule(Base):
    """Recurring recon — cron-driven workflow runs (continuous recon)."""
    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    workflow = Column(String(255), nullable=False)
    target = Column(String(512), nullable=False, index=True)
    cron_expr = Column(String(64), nullable=False)          # 5-field cron, local time
    vars_json = Column(Text, default="{}")                  # optional var overrides
    enabled = Column(Boolean, default=True)
    alert_new_assets = Column(Boolean, default=True)        # webhook on new subdomains/hosts
    last_run_id = Column(String(16))
    last_run_at = Column(DateTime)
    next_run_at = Column(DateTime, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Target(Base):
    """Target registry — scope definitions + engagement mode (deny-wins scope check)."""
    __tablename__ = "targets"

    name = Column(String(512), primary_key=True)            # primary domain, e.g. example.com
    scope_json = Column(Text, default="[]")                 # JSON list of in-scope patterns
    mode = Column(String(20), default="bounty")             # bounty | vdp | oos
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class NewAsset(Base):
    """Assets first seen in a run (diff vs previous runs of the same target)."""
    __tablename__ = "new_assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(String(16), nullable=False, index=True)
    target = Column(String(512), nullable=False, index=True)
    host = Column(String(512), nullable=False)
    kind = Column(String(20))                               # subdomain | http | port
    first_seen = Column(DateTime, default=datetime.utcnow)


class ScopeAudit(Base):
    """Audit trail for scope decisions (deny-wins enforcement)."""
    __tablename__ = "scope_audit"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(512), nullable=False, index=True)
    action = Column(String(64), nullable=False)             # run_start | scope_check | blocked
    result = Column(String(20), nullable=False)             # allowed | denied
    detail = Column(Text)
    ts = Column(DateTime, default=datetime.utcnow)


def tool_version_to_dict(t: "ToolVersion") -> dict[str, Any]:
    return {
        "name":            t.name,
        "installed":       t.installed,
        "latest":          t.latest,
        "status":          t.status,
        "last_checked_at": t.last_checked_at.isoformat() if t.last_checked_at else None,
        "last_updated_at": t.last_updated_at.isoformat() if t.last_updated_at else None,
        "error_msg":       t.error_msg,
    }


def init_db() -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(_engine)
    # Apply schema migrations (idempotent — column already exists → ignore)
    # Use raw connection to support both SQLAlchemy 1.3 and 2.0
    raw = _engine.raw_connection()
    try:
        cur = raw.cursor()
        for stmt in [
            "ALTER TABLE runs ADD COLUMN steps_json TEXT DEFAULT '[]'",
            "ALTER TABLE runs ADD COLUMN paused_at DATETIME",
            "ALTER TABLE runs ADD COLUMN pid INTEGER",
            "ALTER TABLE tool_versions ADD COLUMN latest_url TEXT",
            "ALTER TABLE findings ADD COLUMN status_code INTEGER",
            "ALTER TABLE findings ADD COLUMN screenshot TEXT",
            "ALTER TABLE findings ADD COLUMN notes TEXT",
            "ALTER TABLE findings ADD COLUMN tags TEXT DEFAULT '[]'",
        ]:
            try:
                cur.execute(stmt)
            except Exception:
                pass
        raw.commit()
    finally:
        raw.close()


def get_db() -> Session:
    return SessionLocal()


import sqlalchemy as _sa
_SA_MAJOR = int(_sa.__version__.split(".")[0])


def db_get(session: Session, model, pk):
    """Session.get() compat: SQLAlchemy 1.x uses query().get(), 2.x uses session.get()."""
    if _SA_MAJOR >= 2:
        return session.get(model, pk)
    return session.query(model).get(pk)


def get_db_dep() -> Generator[Session, None, None]:
    """FastAPI dependency — yields a session and closes it when the request is done."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def run_to_dict(run: Run) -> dict[str, Any]:
    return {
        "id": run.id,
        "workflow": run.workflow,
        "target": run.target,
        "status": run.status,
        "workspace": run.workspace,
        "vars": json.loads(run.vars_json or "{}"),
        "continue_on_error": run.continue_on_error,
        "resume": run.resume,
        "returncode": run.returncode,
        "error_message": run.error_message,
        "steps": json.loads(run.steps_json or "[]"),
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "paused_at": run.paused_at.isoformat() if run.paused_at else None,
    }


def api_key_to_dict(k: ApiKey) -> dict[str, Any]:
    val = k.value or ''
    masked = ('*' * max(0, len(val) - 4) + val[-4:]) if len(val) > 4 else '****'
    return {
        "provider":   k.provider,
        "masked":     masked,
        "configured": True,
        "updated_at": k.updated_at.isoformat() if k.updated_at else None,
    }


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "run_id": f.run_id,
        "kind": f.kind,
        "severity": f.severity,
        "host": f.host,
        "ip": f.ip,
        "port": f.port,
        "protocol": f.protocol,
        "name": f.name,
        "template_id": f.template_id,
        "url": f.url,
        "title": f.title,
        "tech": json.loads(f.tech or "[]"),
        "evidence": f.evidence,
        "description": f.description,
        "status": f.status,
        "notes": f.notes,
        "tags": json.loads(f.tags or "[]"),
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def schedule_to_dict(s: "Schedule") -> dict[str, Any]:
    return {
        "id": s.id,
        "name": s.name,
        "workflow": s.workflow,
        "target": s.target,
        "cron_expr": s.cron_expr,
        "vars": json.loads(s.vars_json or "{}"),
        "enabled": bool(s.enabled),
        "alert_new_assets": bool(s.alert_new_assets),
        "last_run_id": s.last_run_id,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "created_at": s.created_at.isoformat() if s.created_at else None,
    }


def target_to_dict(t: "Target") -> dict[str, Any]:
    return {
        "name": t.name,
        "scope": json.loads(t.scope_json or "[]"),
        "mode": t.mode or "bounty",
        "notes": t.notes,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }


def new_asset_to_dict(a: "NewAsset") -> dict[str, Any]:
    return {
        "id": a.id,
        "run_id": a.run_id,
        "target": a.target,
        "host": a.host,
        "kind": a.kind,
        "first_seen": a.first_seen.isoformat() if a.first_seen else None,
    }

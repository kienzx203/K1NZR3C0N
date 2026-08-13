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
            "ALTER TABLE tool_versions ADD COLUMN latest_url TEXT",
            "ALTER TABLE findings ADD COLUMN status_code INTEGER",
            "ALTER TABLE findings ADD COLUMN screenshot TEXT",
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
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }

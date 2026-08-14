"""Scope enforcement — deny-wins semantics (mirrors the cmd-scope skill).

Rules:
* Pattern "example.com"    → matches example.com AND any *.example.com
* Pattern "*.example.com"  → matches sub.example.com but NOT sub.sub.example.com
                             (single-label wildcard, per typical program scope)
* A registered Target with mode "oos" denies EVERYTHING under it.
* A host not covered by any registered Target is ALLOWED but audited as
  unregistered (so existing runs keep working until targets are registered).
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable


def _normalize(host: str) -> str:
    h = (host or "").strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0].split(":", 1)[0]
    return h.rstrip(".")


def match_scope(host: str, patterns: Iterable[str]) -> bool:
    """True when `host` is covered by at least one scope pattern."""
    h = _normalize(host)
    if not h:
        return False
    for raw in patterns:
        p = _normalize(raw)
        if not p:
            continue
        if p.startswith("*."):
            base = p[2:]
            # single label only: sub.base OK, a.sub.base NOT
            if h.endswith("." + base):
                label = h[: -(len(base) + 1)]
                if label and "." not in label:
                    return True
        else:
            if h == p or h.endswith("." + p):
                return True
    return False


def check_target_scope(db, target: str) -> tuple[bool, str]:
    """Deny-wins gate used at run creation. Returns (allowed, reason).

    Writes a ScopeAudit row for every decision.
    """
    from .db import ScopeAudit, Target

    t = _normalize(target)
    audit = ScopeAudit(target=t, action="run_start", result="allowed")

    covering = None
    for row in db.query(Target).all():
        patterns = [row.name]
        try:
            import json
            patterns += json.loads(row.scope_json or "[]")
        except Exception:
            pass
        if match_scope(t, patterns):
            covering = row
            break

    if covering is None:
        audit.result = "allowed"
        audit.detail = "unregistered target — no scope defined"
    elif covering.mode == "oos":
        audit.result = "denied"
        audit.action = "blocked"
        audit.detail = f"target '{covering.name}' is marked out-of-scope"
        db.add(audit)
        db.commit()
        return False, audit.detail
    else:
        audit.result = "allowed"
        audit.detail = f"covered by registered target '{covering.name}' (mode={covering.mode})"

    db.add(audit)
    db.commit()
    return True, audit.detail

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import ApiKey, api_key_to_dict, get_db_dep

router = APIRouter(tags=["keys"])

# ── Provider catalogue ────────────────────────────────────────────────────────
# Each entry maps 1-to-1 with a subfinder provider-config.yaml key.
# The `chaos` key is ALSO injected as `chaos_key` workflow var automatically.

PROVIDERS: list[dict] = [
    # Internet Scanners — all go to subfinder provider-config.yaml
    {"id": "shodan",          "name": "Shodan",            "category": "Internet Scanner",  "url": "shodan.io",                   "hint": "API key from account.shodan.io",                        "subfinder": True},
    {"id": "censys",          "name": "Censys",            "category": "Internet Scanner",  "url": "censys.com",                  "hint": "API_ID:API_SECRET",                                     "subfinder": True},
    {"id": "fofa",            "name": "FOFA",              "category": "Internet Scanner",  "url": "en.fofa.info",                "hint": "email@example.com:API_KEY",                             "subfinder": True},
    {"id": "zoomeye",         "name": "ZoomEye",           "category": "Internet Scanner",  "url": "zoomeye.hk",                  "hint": "API key",                                               "subfinder": True},
    {"id": "quake",           "name": "Quake (360)",       "category": "Internet Scanner",  "url": "quake.360.cn",                "hint": "API token",                                             "subfinder": True},
    {"id": "binaryedge",      "name": "BinaryEdge",        "category": "Internet Scanner",  "url": "binaryedge.io",               "hint": "API key",                                               "subfinder": True},
    {"id": "netlas",          "name": "Netlas",            "category": "Internet Scanner",  "url": "netlas.io",                   "hint": "API key",                                               "subfinder": True},
    {"id": "fullhunt",        "name": "FullHunt",          "category": "Internet Scanner",  "url": "fullhunt.io",                 "hint": "API key",                                               "subfinder": True},
    {"id": "leakix",          "name": "LeakIX",            "category": "Internet Scanner",  "url": "leakix.net",                  "hint": "API key",                                               "subfinder": True},
    # Subdomain / DNS Intel
    {"id": "chaos",           "name": "Chaos (PD)",        "category": "Subdomain Intel",   "url": "chaos.projectdiscovery.io",   "hint": "API key — also auto-injected as chaos_key workflow var", "subfinder": True},
    {"id": "securitytrails",  "name": "SecurityTrails",    "category": "Subdomain Intel",   "url": "securitytrails.com",          "hint": "API key",                                               "subfinder": True},
    {"id": "virustotal",      "name": "VirusTotal",        "category": "Subdomain Intel",   "url": "virustotal.com",              "hint": "API key",                                               "subfinder": True},
    {"id": "bevigil",         "name": "BeVigil",           "category": "Subdomain Intel",   "url": "bevigil.com",                 "hint": "API key",                                               "subfinder": True},
    {"id": "c99",             "name": "C99",               "category": "Subdomain Intel",   "url": "subdomainfinder.c99.nl",      "hint": "API key",                                               "subfinder": True},
    {"id": "intelx",          "name": "IntelX",            "category": "Subdomain Intel",   "url": "intelx.io",                   "hint": "API key",                                               "subfinder": True},
    {"id": "hackertarget",    "name": "HackerTarget",      "category": "Subdomain Intel",   "url": "hackertarget.com",            "hint": "API key",                                               "subfinder": True},
    {"id": "dnsdumpster",     "name": "DNSDumpster",       "category": "Subdomain Intel",   "url": "dnsdumpster.com",             "hint": "API key",                                               "subfinder": True},
    {"id": "whoisxmlapi",     "name": "WhoisXML",          "category": "Subdomain Intel",   "url": "whoisxmlapi.com",             "hint": "API key",                                               "subfinder": True},
    # Archive / Certificate
    {"id": "urlscan",         "name": "URLScan.io",        "category": "Archive / Cert",    "url": "urlscan.io",                  "hint": "API key",                                               "subfinder": True},
    {"id": "certspotter",     "name": "CertSpotter",       "category": "Archive / Cert",    "url": "sslmate.com/certspotter",     "hint": "API key",                                               "subfinder": True},
    {"id": "github",          "name": "GitHub Token",      "category": "Archive / Cert",    "url": "github.com",                  "hint": "ghp_xxxxxxxxxxxx — subfinder + gau rate-limit bypass",  "subfinder": True},
    # Search & Dork — injected as workflow vars (NOT written to subfinder config)
    {"id": "google_cse",      "name": "Google CSE API Key","category": "Search & Dork",     "url": "console.cloud.google.com",    "hint": "AIzaSy... — Custom Search API key, injected as google_cse_key var", "subfinder": False},
    {"id": "google_cx",       "name": "Google Search Engine ID", "category": "Search & Dork", "url": "programmablesearchengine.google.com", "hint": "xxxxxxxxxxxxxxxxx — CX ID, injected as google_cx var", "subfinder": False},
    # AI Assistant — used by the web terminal
    {"id": "qwen",            "name": "Qwen (DashScope)",  "category": "AI Assistant",      "url": "dashscope.aliyuncs.com",      "hint": "sk-... — DashScope API key for Qwen AI terminal",               "subfinder": False},
]

_PROVIDER_IDS = {p["id"] for p in PROVIDERS}
_SUBFINDER_IDS = {p["id"] for p in PROVIDERS if p.get("subfinder", True)}


# ── Pydantic models ───────────────────────────────────────────────────────────

class KeyUpsert(BaseModel):
    value: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def build_subfinder_config(key_map: dict[str, str]) -> str:
    """Return YAML string for subfinder provider-config.yaml (subfinder providers only)."""
    cfg: dict[str, list[str]] = {}
    for provider, value in key_map.items():
        if provider in _SUBFINDER_IDS and value and value.strip():
            cfg[provider] = [value.strip()]
    return yaml.dump(cfg, default_flow_style=False, allow_unicode=True)


def write_subfinder_config(key_map: dict[str, str]) -> Path:
    """Write keys to ~/.config/subfinder/provider-config.yaml. Returns path written."""
    config_dir = Path.home() / ".config" / "subfinder"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "provider-config.yaml"
    config_path.write_text(build_subfinder_config(key_map), encoding="utf-8")
    return config_path


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/keys/providers")
def list_providers() -> list[dict]:
    """Return full provider catalogue with metadata."""
    return PROVIDERS


@router.get("/keys")
def list_keys(db: Session = Depends(get_db_dep)) -> list[dict[str, Any]]:
    """Return all providers with configured/unconfigured status and masked key."""
    rows = db.query(ApiKey).all()
    configured = {r.provider: api_key_to_dict(r) for r in rows}

    result = []
    for p in PROVIDERS:
        entry: dict[str, Any] = configured.get(
            p["id"],
            {"provider": p["id"], "masked": None, "configured": False, "updated_at": None},
        )
        entry["meta"] = p
        result.append(entry)
    return result


@router.get("/keys/stats")
def keys_stats(db: Session = Depends(get_db_dep)) -> dict[str, Any]:
    count = db.query(ApiKey).count()
    return {"configured": count, "total": len(PROVIDERS)}


@router.put("/keys/{provider}")
def upsert_key(
    provider: str,
    body: KeyUpsert,
    db: Session = Depends(get_db_dep),
) -> dict[str, Any]:
    """Create or update a provider key. Immediately writes subfinder config."""
    if provider not in _PROVIDER_IDS:
        raise HTTPException(400, f"Unknown provider: {provider!r}")
    if not body.value.strip():
        raise HTTPException(422, "Key value cannot be empty")

    row = db.get(ApiKey, provider)
    if row:
        row.value = body.value.strip()
        row.updated_at = datetime.utcnow()
    else:
        row = ApiKey(provider=provider, value=body.value.strip())
        db.add(row)
    db.commit()

    # Keep subfinder config in sync immediately
    all_keys = {r.provider: r.value for r in db.query(ApiKey).all()}
    try:
        write_subfinder_config(all_keys)
    except Exception:
        pass  # non-fatal — also written before each run

    return api_key_to_dict(row)


@router.delete("/keys/{provider}", status_code=204)
def delete_key(provider: str, db: Session = Depends(get_db_dep)) -> None:
    """Remove a provider key."""
    if provider not in _PROVIDER_IDS:
        raise HTTPException(400, f"Unknown provider: {provider!r}")
    row = db.get(ApiKey, provider)
    if row:
        db.delete(row)
        db.commit()
        all_keys = {r.provider: r.value for r in db.query(ApiKey).all()}
        try:
            write_subfinder_config(all_keys)
        except Exception:
            pass


@router.get("/keys/export/subfinder")
def export_subfinder(db: Session = Depends(get_db_dep)) -> dict[str, str]:
    """Preview the subfinder provider-config.yaml content (subfinder providers only, no secrets exposed)."""
    rows = db.query(ApiKey).all()
    lines = []
    for r in rows:
        if r.provider not in _SUBFINDER_IDS:
            continue
        v = r.value
        masked = ('*' * max(0, len(v) - 4) + v[-4:]) if len(v) > 4 else '****'
        lines.append(f"{r.provider}:\n  - {masked}")
    return {"yaml": "\n".join(lines) if lines else "# no keys configured"}

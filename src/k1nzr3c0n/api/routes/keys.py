from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ...db import ApiKey, api_key_to_dict, get_db_dep, db_get

router = APIRouter(tags=["keys"])

# ── Provider catalogue ────────────────────────────────────────────────────────
# Each entry maps 1-to-1 with a subfinder provider-config.yaml key.
# The `chaos` key is ALSO injected as `chaos_key` workflow var automatically.

PROVIDERS: list[dict] = [
    # Internet Scanners
    # subfinder=True  → key goes to ~/.config/subfinder/provider-config.yaml
    # uncover=True    → key goes to ~/.config/uncover/provider-config.yaml
    # Note: subfinder uses "zoomeyeapi" as key name (internally remapped by tasks.py)
    {"id": "shodan",          "name": "Shodan",            "category": "Internet Scanner",  "url": "shodan.io",                   "hint": "API key from account.shodan.io",                        "subfinder": True,  "uncover": True,  "env_var": "SHODAN_API_KEY"},
    {"id": "censys",          "name": "Censys",            "category": "Internet Scanner",  "url": "censys.com",                  "hint": "API_ID:API_SECRET",                                     "subfinder": True,  "uncover": True,  "env_var": "CENSYS_API_ID"},
    {"id": "fofa",            "name": "FOFA",              "category": "Internet Scanner",  "url": "en.fofa.info",                "hint": "email@example.com:API_KEY",                             "subfinder": True,  "uncover": True,  "env_var": "FOFA_KEY"},
    {"id": "zoomeye",         "name": "ZoomEye",           "category": "Internet Scanner",  "url": "zoomeye.hk",                  "hint": "API key (subfinder key: zoomeyeapi)",                   "subfinder": True,  "uncover": True,  "env_var": "ZOOMEYE_API_KEY"},
    {"id": "quake",           "name": "Quake (360)",       "category": "Internet Scanner",  "url": "quake.360.cn",                "hint": "API token",                                             "subfinder": False, "uncover": True,  "env_var": "QUAKE_API_KEY"},
    {"id": "binaryedge",      "name": "BinaryEdge",        "category": "Internet Scanner",  "url": "binaryedge.io",               "hint": "API key (uncover only — removed from subfinder v2.14)", "subfinder": False, "uncover": True,  "env_var": "BINARYEDGE_API_KEY"},
    {"id": "netlas",          "name": "Netlas",            "category": "Internet Scanner",  "url": "netlas.io",                   "hint": "API key",                                               "subfinder": True,  "uncover": True,  "env_var": "NETLAS_API_KEY"},
    {"id": "fullhunt",        "name": "FullHunt",          "category": "Internet Scanner",  "url": "fullhunt.io",                 "hint": "API key (env only — not in current subfinder build)",   "subfinder": False, "uncover": False, "env_var": "FULLHUNT_API_KEY"},
    {"id": "leakix",          "name": "LeakIX",            "category": "Internet Scanner",  "url": "leakix.net",                  "hint": "API key",                                               "subfinder": True,  "uncover": False, "env_var": "LEAKIX_API_KEY"},
    {"id": "hunter",          "name": "Hunter.io",         "category": "Internet Scanner",  "url": "hunter.io",                   "hint": "API key — uncover host/domain search (free tier available)", "subfinder": False, "uncover": True, "env_var": "HUNTER_API_KEY"},
    {"id": "criminalip",      "name": "CriminalIP",        "category": "Internet Scanner",  "url": "criminalip.io",               "hint": "API key — uncover internet scanner (free tier available)",   "subfinder": False, "uncover": True, "env_var": "CRIMINALIP_API_KEY"},
    {"id": "greynoise",       "name": "GreyNoise",         "category": "Internet Scanner",  "url": "greynoise.io",                "hint": "API key — uncover internet noise scanner",               "subfinder": False, "uncover": True, "env_var": "GREYNOISE_API_KEY"},
    # Subdomain / DNS Intel
    {"id": "chaos",           "name": "Chaos (PD)",        "category": "Subdomain Intel",   "url": "chaos.projectdiscovery.io",   "hint": "API key — auto-injected as $CHAOS_API_KEY env var",     "subfinder": True,  "env_var": "CHAOS_API_KEY"},
    {"id": "securitytrails",  "name": "SecurityTrails",    "category": "Subdomain Intel",   "url": "securitytrails.com",          "hint": "API key — auto-injected as $SECURITYTRAILS_KEY env var","subfinder": True,  "env_var": "SECURITYTRAILS_KEY"},
    {"id": "virustotal",      "name": "VirusTotal",        "category": "Subdomain Intel",   "url": "virustotal.com",              "hint": "API key — auto-injected as $VIRUSTOTAL_KEY env var",    "subfinder": True,  "env_var": "VIRUSTOTAL_KEY"},
    {"id": "bevigil",         "name": "BeVigil",           "category": "Subdomain Intel",   "url": "bevigil.com",                 "hint": "API key — auto-injected as $BEVIGIL_KEY env var",       "subfinder": True,  "env_var": "BEVIGIL_KEY"},
    {"id": "c99",             "name": "C99",               "category": "Subdomain Intel",   "url": "subdomainfinder.c99.nl",      "hint": "API key",                                               "subfinder": True,  "env_var": "C99_API_KEY"},
    {"id": "intelx",          "name": "IntelX",            "category": "Subdomain Intel",   "url": "intelx.io",                   "hint": "API key only (UUID) — host suffix :2.intelx.io auto-appended for subfinder", "subfinder": True,  "env_var": "INTELX_API_KEY"},
    {"id": "hackertarget",    "name": "HackerTarget",      "category": "Subdomain Intel",   "url": "hackertarget.com",            "hint": "API key",                                               "subfinder": True,  "env_var": "HACKERTARGET_API_KEY"},
    {"id": "dnsdumpster",     "name": "DNSDumpster",       "category": "Subdomain Intel",   "url": "dnsdumpster.com",             "hint": "API key",                                               "subfinder": True,  "env_var": "DNSDUMPSTER_API_KEY"},
    {"id": "whoisxmlapi",     "name": "WhoisXML",          "category": "Subdomain Intel",   "url": "whoisxmlapi.com",             "hint": "API key",                                               "subfinder": True,  "env_var": "WHOISXMLAPI_API_KEY"},
    # Archive / Certificate
    {"id": "urlscan",         "name": "URLScan.io",        "category": "Archive / Cert",    "url": "urlscan.io",                  "hint": "API key",                                               "subfinder": True,  "env_var": "URLSCAN_API_KEY"},
    {"id": "certspotter",     "name": "CertSpotter",       "category": "Archive / Cert",    "url": "sslmate.com/certspotter",     "hint": "API key",                                               "subfinder": True,  "env_var": "CERTSPOTTER_API_KEY"},
    {"id": "github",          "name": "GitHub Token",      "category": "Archive / Cert",    "url": "github.com",                  "hint": "ghp_xxxxxxxxxxxx — subfinder + gau + github code search","subfinder": True,  "env_var": "GITHUB_TOKEN"},
    # Search & Dork
    {"id": "google_cse",      "name": "Google CSE API Key","category": "Search & Dork",     "url": "console.cloud.google.com",    "hint": "AIzaSy... — Custom Search API key",                    "subfinder": False, "env_var": "GOOGLE_CSE_KEY"},
    {"id": "google_cx",       "name": "Google Search Engine ID", "category": "Search & Dork", "url": "programmablesearchengine.google.com", "hint": "CX ID",                              "subfinder": False, "env_var": "GOOGLE_CX"},
    # AI Assistant
    {"id": "qwen",            "name": "Qwen (DashScope)",  "category": "AI Assistant",      "url": "dashscope.aliyuncs.com",      "hint": "sk-... — DashScope API key for Qwen AI terminal",      "subfinder": False, "env_var": "DASHSCOPE_API_KEY"},
]

_PROVIDER_IDS  = {p["id"] for p in PROVIDERS}
_SUBFINDER_IDS = {p["id"] for p in PROVIDERS if p.get("subfinder", False)}
_UNCOVER_IDS   = {p["id"] for p in PROVIDERS if p.get("uncover", False)}

# Provider IDs whose subfinder key name differs from our internal id.
_SUBFINDER_KEY_MAP: dict[str, str] = {
    "zoomeye": "zoomeyeapi",  # subfinder v2.14+ uses "zoomeyeapi"
}

# Value transforms: some subfinder sources require a composite value format.
_SUBFINDER_VALUE_TRANSFORM: dict[str, Any] = {
    # IntelX requires "api_key:api_host" — without the host subfinder silently
    # skips the source even when the key is present in provider-config.yaml.
    "intelx": lambda v: f"{v}:2.intelx.io" if ":" not in v else v,
}


# ── Pydantic models ───────────────────────────────────────────────────────────

class KeyUpsert(BaseModel):
    value: str


# ── Helpers ───────────────────────────────────────────────────────────────────

def build_subfinder_config(key_map: dict[str, str]) -> str:
    """Return YAML string for subfinder provider-config.yaml (subfinder providers only).

    Applies _SUBFINDER_KEY_MAP renaming so provider IDs that differ in subfinder
    (e.g., 'zoomeye' → 'zoomeyeapi') are written with the correct key.
    Applies _SUBFINDER_VALUE_TRANSFORM for providers that need composite values
    (e.g., intelx → 'key:2.intelx.io').
    """
    cfg: dict[str, list[str]] = {}
    for provider, value in key_map.items():
        if provider in _SUBFINDER_IDS and value and value.strip():
            sf_key = _SUBFINDER_KEY_MAP.get(provider, provider)
            raw = value.strip()
            transform = _SUBFINDER_VALUE_TRANSFORM.get(provider)
            sf_value = transform(raw) if transform else raw  # type: ignore[operator]
            cfg[sf_key] = [sf_value]
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

    row = db_get(db, ApiKey, provider)
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
    row = db_get(db, ApiKey, provider)
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


@router.get("/keys/env-status")
def env_status(db: Session = Depends(get_db_dep)) -> list[dict]:
    """Return per-provider sync status: source (db | env | both | none) and conflict flag.

    Helps the UI show whether a key is set in DB, in the container environment,
    or both (DB wins at runtime). A conflict means both are set but differ.
    """
    import os
    rows = db.query(ApiKey).all()
    db_keys = {r.provider: r.value for r in rows}

    result = []
    for p in PROVIDERS:
        pid    = p["id"]
        env_var = p.get("env_var", "")
        db_val  = (db_keys.get(pid) or "").strip()

        # Censys special case: env uses two vars, DB stores "ID:SECRET"
        if pid == "censys":
            env_id  = (os.environ.get("CENSYS_API_ID", "") or "").strip()
            env_sec = (os.environ.get("CENSYS_API_SECRET", "") or "").strip()
            env_val = f"{env_id}:{env_sec}" if (env_id or env_sec) else ""
        else:
            env_val = (os.environ.get(env_var, "") or "").strip()

        has_db  = bool(db_val)
        has_env = bool(env_val)

        if has_db and has_env:
            source = "both"
            # Conflict if values differ (DB wins at runtime)
            conflict = db_val != env_val
        elif has_db:
            source = "db"
            conflict = False
        elif has_env:
            source = "env"
            conflict = False
        else:
            source = "none"
            conflict = False

        result.append({
            "provider": pid,
            "env_var":  env_var,
            "source":   source,       # "db" | "env" | "both" | "none"
            "conflict": conflict,     # True if db ≠ env (DB wins)
            "active":   has_db or has_env,
        })

    return result

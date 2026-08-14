from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(os.environ.get("K1NZR3C0N_BASE", ".")).resolve()
RUNS_DIR = BASE_DIR / "runs"
DB_PATH = RUNS_DIR / "k1nzr3c0n.db"  # inside volume → shared between app/worker containers
WORKFLOWS_DIR = BASE_DIR / "workflows"
WORDLISTS_DIR = BASE_DIR / "wordlists"
STATIC_DIR = BASE_DIR / "static"

REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
CELERY_BROKER = REDIS_URL
CELERY_BACKEND = REDIS_URL

# Webhook notification — Slack / Discord / custom HTTP endpoint
# Sent on run completion (completed or failed).
# Auto-detects payload format from URL: discord.com → Discord embeds, else Slack-compatible.
WEBHOOK_URL = os.environ.get("K1NZR3C0N_WEBHOOK_URL", "")

# Optional API bearer token. When set, every /api/* request needs
# `Authorization: Bearer <token>` and WebSockets need ?token=<token>.
# Empty = auth disabled (backwards compatible, local-only deployments).
API_TOKEN = os.environ.get("K1NZR3C0N_API_TOKEN", "")

# Slack-style channel/username override (only used for Slack-compatible webhooks)
WEBHOOK_USERNAME = os.environ.get("K1NZR3C0N_WEBHOOK_USERNAME", "k1nzr3c0n")

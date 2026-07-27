#!/bin/bash
set -e

# ── 1. Install Qwen Code (skip if already installed) ──────────────────────────
if ! command -v qwen >/dev/null 2>&1; then
  echo "[+] Installing Qwen Code..."
  curl -fsSL https://qwen-code-assets.oss-cn-hangzhou.aliyuncs.com/installation/install-qwen-standalone.sh | bash
else
  echo "[✔] Qwen $(qwen --version 2>/dev/null) already installed"
fi

# ── 2. Sync skills → ~/.qwen/skills/ ──────────────────────────────────────────
SKILLS_SRC="$(dirname "$0")/.qwen/skills"
SKILLS_DST="$HOME/.qwen/skills"

if [ -d "$SKILLS_SRC" ]; then
  mkdir -p "$SKILLS_DST"
  for skill_dir in "$SKILLS_SRC"/*/; do
    skill_name=$(basename "$skill_dir")
    mkdir -p "$SKILLS_DST/$skill_name"
    cp -f "$skill_dir/SKILL.md" "$SKILLS_DST/$skill_name/SKILL.md"
    echo "[✔] Skill: $skill_name"
  done
fi

# ── 3. Docker Compose up ───────────────────────────────────────────────────────
echo "[+] Starting containers..."
docker compose up -d "$@"

echo ""
echo "[✔] K1NZR3C0N ready → http://127.0.0.1:8000"

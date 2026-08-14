#!/bin/bash
# Deploy k1nzr3c0n feature bundle on the Kali box.
# Run ON the Kali VM after copying k1nzr3c0n-deploy.tar.gz there:
#   bash deploy-to-kali.sh /path/to/k1nzr3c0n-deploy.tar.gz
set -e

BUNDLE="${1:-./k1nzr3c0n-deploy.tar.gz}"
DEST=/opt/k1nzr3c0n
STAGE=$(mktemp -d /tmp/k1nzr3c0n-deploy.XXXX)

[ -f "$BUNDLE" ] || { echo "[x] Bundle not found: $BUNDLE"; exit 1; }

echo "[+] Extracting $BUNDLE -> $STAGE"
tar xzf "$BUNDLE" -C "$STAGE"

echo "[+] Rsync into $DEST (runs/, .env, wordlists/, root DB untouched)"
sudo rsync -a --chown root:root \
  --exclude=/runs --exclude=/.env --exclude=/wordlists --exclude=/k1nzr3c0n.db \
  "$STAGE/" "$DEST/"

echo "[+] Cleaning stale static assets"
cd "$DEST/src/k1nzr3c0n/static/assets"
for f in *; do
  case "$f" in
    index-bdK89HDi.css|index-BZtFaNra.js) ;;  # current build — keep
    *) sudo rm -f "$f"; echo "    removed stale: $f" ;;
  esac
done

echo "[+] Restarting services (app stop can take ~90s — uvicorn waits for open WebSockets)"
sudo systemctl restart k1nzr3c0n-app k1nzr3c0n-worker k1nzr3c0n-beat

echo "[+] Waiting for API to come back…"
for i in $(seq 1 40); do
  if curl -s --max-time 2 http://127.0.0.1:8000/api/v1/auth/status > /dev/null 2>&1; then
    break
  fi
  sleep 3
done

echo "[+] Verifying"
systemctl is-active k1nzr3c0n-app k1nzr3c0n-worker k1nzr3c0n-beat
curl -s --max-time 5 http://127.0.0.1:8000/api/v1/health | head -c 300; echo
curl -s --max-time 5 http://127.0.0.1:8000/api/v1/auth/status; echo

rm -rf "$STAGE"
echo "[+] Done — hard refresh the UI (Ctrl+F5)"

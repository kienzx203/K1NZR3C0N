#!/bin/bash
# K1NZR3C0N — local startup helper (bare-metal / Kali)
# Usage: bash start.sh [start|stop|restart|status|logs]
set -e

APP_DIR="${K1NZR3C0N_BASE:-/opt/k1nzr3c0n}"
SERVICES="k1nzr3c0n-app k1nzr3c0n-worker k1nzr3c0n-beat"

ok()  { echo -e "\e[32m✔\e[0m $*"; }
err() { echo -e "\e[31m✗\e[0m $*"; }
inf() { echo -e "\e[34m→\e[0m $*"; }

ACTION="${1:-start}"

case "$ACTION" in
  start)
    inf "Starting Redis..."
    systemctl start redis-server 2>/dev/null || systemctl start redis 2>/dev/null || true
    ok "Redis"

    inf "Starting K1NZR3C0N services..."
    for svc in $SERVICES; do
      systemctl start "$svc" && ok "$svc" || err "$svc failed to start"
    done

    sleep 2
    echo ""
    ok "K1NZR3C0N ready → http://0.0.0.0:8000"
    ;;

  stop)
    for svc in $SERVICES; do
      systemctl stop "$svc" 2>/dev/null && ok "Stopped $svc" || true
    done
    ;;

  restart)
    for svc in $SERVICES; do
      systemctl restart "$svc" && ok "Restarted $svc" || err "$svc failed"
    done
    ;;

  status)
    for svc in redis-server redis $SERVICES; do
      status=$(systemctl is-active "$svc" 2>/dev/null) || status="not-found"
      [[ "$status" == "active" ]] && ok "$svc ($status)" || err "$svc ($status)"
    done
    ;;

  logs)
    TARGET="${2:-k1nzr3c0n-app}"
    journalctl -u "$TARGET" -f --no-pager
    ;;

  *)
    echo "Usage: bash start.sh [start|stop|restart|status|logs [service]]"
    exit 1
    ;;
esac

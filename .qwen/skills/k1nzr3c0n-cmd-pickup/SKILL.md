---
name: k1nzr3c0n-cmd-pickup
description: "Session resume command. Shows hunt history, untested endpoints, suggested next skill. Reads session directory for previous findings, endpoint lists, rotation notes. Use at start of new session to continue where you left off."
tags: [command, session, resume, continuation]
---

# /pickup — Session Resume

> Usage: `/pickup` — start a new session by reviewing previous work.

---

## Session State Recovery

```bash
TARGET="${TARGET:-}"
echo "=== SESSION PICKUP ==="
echo "Target: ${TARGET}"
echo "Time: $(date)"
echo ""

# Find most recent session
SESSION_DIRS=$(ls -td /tmp/k1nzr3c0n_${TARGET//[^a-zA-Z0-9]/_}*/ 2>/dev/null)
LATEST_SESSION=$(echo "$SESSION_DIRS" | head -1)

[ -z "$LATEST_SESSION" ] && {
  echo "[!] No previous session found for target: ${TARGET}"
  echo "    Start fresh: /skill k1nzr3c0n-methodology"
  exit 0
}

echo "=== Previous Sessions ==="
echo "$SESSION_DIRS" | while read DIR; do
  echo "  $DIR ($(ls $DIR/findings/ 2>/dev/null | wc -l) findings)"
done

echo ""
echo "=== Latest Session: $LATEST_SESSION ==="
```

## Previous Findings

```bash
echo "=== Findings from Last Session ==="
LATEST_SESSION="${LATEST_SESSION:-/tmp/k1nzr3c0n_*/}"
FINDINGS_DIR="${LATEST_SESSION}findings"

[ -d "$FINDINGS_DIR" ] && {
  ls "$FINDINGS_DIR" 2>/dev/null | while read F; do
    echo "  [FINDING] $F"
    head -3 "${FINDINGS_DIR}/$F" 2>/dev/null | sed 's/^/    /'
  done
} || echo "  No findings documented"

echo ""
echo "=== Rotation Notes (stopped points) ==="
SCRATCH_DIR="${LATEST_SESSION}scratch"
[ -d "$SCRATCH_DIR" ] && ls "$SCRATCH_DIR"/*.txt 2>/dev/null | while read F; do
  echo "  [SCRATCH] $F"
  head -2 "$F" 2>/dev/null | sed 's/^/    /'
done || echo "  No scratch notes"
```

## Next Steps

```bash
echo ""
echo "=== Suggested Next Steps ==="
# Check what's been tested vs what exists
RECON_DIR=$(ls -td /tmp/recon_${TARGET//[^a-zA-Z0-9]/_}*/ 2>/dev/null | head -1)

[ -n "$RECON_DIR" ] && {
  TOTAL_URLS=$(wc -l < "${RECON_DIR}endpoints/all_urls.txt" 2>/dev/null || echo 0)
  echo "  Total URLs in corpus: ${TOTAL_URLS}"
  
  echo ""
  echo "  Untested GF classes (check scratch notes for tested ones):"
  for C in xss sqli ssrf redirect lfi rce ssti idor; do
    COUNT=$(wc -l < "${RECON_DIR}endpoints/gf_${C}.txt" 2>/dev/null || echo 0)
    [ "$COUNT" -gt 0 ] && echo "    ${C}: ${COUNT} candidates → /skill k1nzr3c0n-hunt-${C}"
  done
}

echo ""
echo "=== Quick Actions ==="
echo "  Surface overview:   /surface"
echo "  Dispatch hunt:      /hunt"
echo "  Validate finding:   /validate"
echo "  Write report:       /report"
echo ""
echo "  Continue methodology: /skill k1nzr3c0n-methodology"
```

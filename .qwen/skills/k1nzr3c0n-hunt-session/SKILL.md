---
name: k1nzr3c0n-hunt-session
description: "Session security hunting skill built from 18 disclosed bug bounty reports. Covers session fixation, no-logout-invalidation, no-password-change-invalidation, refresh-token reuse-detection, DBSC downgrade, session entropy measurement. 2-session rule: always test with two independent browser sessions."
tags: [session, auth, hunt, web-security, bug-bounty]
report_count: 18
---

# K1NZR3C0N Hunt — Session Security

> **2-session rule**: always verify with TWO independent browser sessions (incognito + normal).
> **Standalone session not-invalidated = never-submit** — must chain to account access.

---

## Crown Jewels

```
Priority 1 — Session fixation: attacker sets session token BEFORE victim logs in
Priority 2 — Old session valid after password change (session not rotated)
Priority 3 — All sessions not invalidated on logout (concurrent session hijack)
Priority 4 — Refresh token reused after logout (perpetual access)
Priority 5 — Predictable session token (low entropy)
```

---

## Phase 0 — Session Discovery

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_session_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== Session Token Discovery ==="
# Collect session cookies
RESP=$(curl -skI "https://${TARGET}/login")
echo "$RESP" | grep -i 'set-cookie' | sed 's/^/  /'

# Token entropy analysis
SESSION_COOKIE_NAME=$(echo "$RESP" | grep -oi 'set-cookie: [a-zA-Z_-]+' | head -1 | awk '{print $2}')
echo ""
echo "Session cookie name: $SESSION_COOKIE_NAME"

# Collect 10 session tokens for entropy analysis
echo "Collecting 10 session tokens..."
for I in $(seq 1 10); do
  TOKEN=$(curl -skI "https://${TARGET}/login" | grep -oi "${SESSION_COOKIE_NAME}=[^;]+" | head -1 | cut -d= -f2-)
  echo "  Token $I: $TOKEN"
done
```

## Phase 1 — Session Fixation

```bash
echo "=== Session Fixation Test ==="
# Get a pre-auth session token
PREAUTH_SESSION=$(curl -skI "https://${TARGET}/login" | \
  grep -i 'set-cookie' | grep -oP '[a-zA-Z_-]+=[^;]+' | head -1)
echo "  Pre-auth session: $PREAUTH_SESSION"

# Log in WITH this pre-auth session (if server accepts it → fixation)
LOGIN_RESP=$(curl -sk -X POST "https://${TARGET}/api/auth/login" \
  -H "Cookie: ${PREAUTH_SESSION}" \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@test.com", "password": "password123"}' -I)

# If session ID didn't change after login → fixation
POST_LOGIN_SESSION=$(echo "$LOGIN_RESP" | grep -i 'set-cookie' | \
  grep -oP '[a-zA-Z_-]+=[^;]+' | head -1)
  
echo "  Post-login session: $POST_LOGIN_SESSION"
[ "$PREAUTH_SESSION" = "$POST_LOGIN_SESSION" ] && \
  echo "  [FIXATION] Session ID DID NOT ROTATE after login!"
```

## Phase 2 — Session Persistence After Logout

```bash
echo "=== Session Not Invalidated on Logout ==="
SESSION_COOKIE="${SESSION_COOKIE:-}"
BASE="https://${TARGET}"

# Step 1: Confirm session is valid
STEP1=$(curl -sk "${BASE}/api/user/me" -H "Cookie: ${SESSION_COOKIE}")
echo "  Before logout: $(echo $STEP1 | grep -oP '"email":"[^"]+"' | head -1)"

# Step 2: Logout
curl -sk -X POST "${BASE}/api/auth/logout" -H "Cookie: ${SESSION_COOKIE}" -o /dev/null
echo "  Logged out"

# Step 3: Try old session token
STEP3=$(curl -sk "${BASE}/api/user/me" -H "Cookie: ${SESSION_COOKIE}")
echo "  After logout: $(echo $STEP3 | grep -oP '"email":"[^"]+"' | head -1)"
echo "$STEP3" | grep -qiE '"email"|"id"' && echo "  [VULN] Session still valid after logout!"
```

## Phase 3 — Session Not Rotated After Password Change

```bash
echo "=== Session Valid After Password Change ==="
SESSION_COOKIE="${SESSION_COOKIE:-}"
ACCT1_TOKEN="${ACCT1_TOKEN:-}"
BASE="https://${TARGET}"

# Save current session
OLD_SESSION="$SESSION_COOKIE"

# Change password
curl -sk -X PUT "${BASE}/api/user/password" \
  -H "Authorization: Bearer ${ACCT1_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"old_password": "OldP@ss123", "new_password": "NewP@ss456"}' | head -5

# Try old session
OLD_RESP=$(curl -sk "${BASE}/api/user/me" -H "Cookie: ${OLD_SESSION}")
echo "$OLD_RESP" | grep -qiE '"email"|"id"' && \
  echo "  [VULN] Old session STILL VALID after password change!" || \
  echo "  [OK] Old session invalidated after password change"
```

## Phase 4 — Concurrent Session (Device Session Hijack)

```bash
echo "=== All Sessions vs Logout ==="
echo "Steps:"
echo "  1. Log in as user on Device A → save session token A"
echo "  2. Log in as same user on Device B → save session token B"
echo "  3. Logout on Device A"
echo "  4. Test: does session token B still work?"
echo ""
echo "  If yes → logout doesn't invalidate all sessions → session hijack"
echo "  (If attacker stole session cookie before logout → still works)"
echo ""
echo "Also test:"
echo "  - 'Logout everywhere' feature: does it really invalidate all tokens?"
echo "  - Password change: are all OTHER sessions invalidated?"
```

## Phase 5 — Refresh Token Reuse

```bash
echo "=== Refresh Token Reuse After Use ==="
BASE="https://${TARGET}"
REFRESH_TOKEN="${REFRESH_TOKEN:-}"

if [ -n "$REFRESH_TOKEN" ]; then
  # Use refresh token once
  RESP1=$(curl -sk -X POST "${BASE}/api/auth/token/refresh" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\": \"${REFRESH_TOKEN}\"}")
  echo "  First use: $(echo $RESP1 | grep -oP '"access_token":"[^"]{0,30}')"
  
  # Try to reuse the same refresh token
  RESP2=$(curl -sk -X POST "${BASE}/api/auth/token/refresh" \
    -H "Content-Type: application/json" \
    -d "{\"refresh_token\": \"${REFRESH_TOKEN}\"}")
  echo "  Second use: $(echo $RESP2 | grep -oP '"access_token":"[^"]{0,30}')"
  
  echo "$RESP2" | grep -qiE '"access_token"' && \
    echo "  [VULN] Refresh token can be reused multiple times!"
fi
```

## Gate 0

```bash
echo "=== Session Gate 0 ==="
echo "  □ 2-session rule: tested from two independent browser sessions"
echo "  □ Fixation: same token before+after login (token didn't rotate)"
echo "  □ Logout: old token works on /api/user/me after logout"
echo "  □ Password change: old session works after password change"
echo "  □ Refresh token: same refresh token works twice"
echo "  □ Impact: actual account access, not just 200 status code"
echo ""
echo "  NEVER SUBMIT: session not invalidated on logout alone (standalone)"
echo "  CHAIN WITH: session theft scenario (XSS, network sniff)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Session fixation on [/login]: pre-authentication session token not rotated after login, enabling session hijacking
Session not invalidated after password change on [/api/user/password]: attacker who previously stole session retains access
Refresh token reuse on [/api/auth/token/refresh]: same refresh token valid multiple times, enabling permanent account access
```

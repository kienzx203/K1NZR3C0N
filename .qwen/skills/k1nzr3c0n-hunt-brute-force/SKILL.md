---
name: k1nzr3c0n-hunt-brute-force
description: "Hunt rate limiting and account lockout control gaps (detection/testing only — NO credential cracking). Test rate limit detection (no 429 after N attempts), lockout bypass (IP rotation via X-Forwarded-For, username rotation), credential stuffing indicators, OTP exhaustion window. Report: missing controls, not cracked credentials."
tags: [rate-limit, lockout, brute-force, detection, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Rate Limit / Lockout Testing

> **SCOPE**: Detecting MISSING rate limiting controls — NOT cracking credentials.
> **TOOL**: ffuf with wordlist of common creds, check if 429/lockout fires. Not credential stuffing.
> **REPORT**: "no rate limit detected after 1000 attempts" — not "cracked admin password".

---

## Phase 0 — Identify Test Endpoints

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_rl_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== Rate-Limited Endpoint Detection ==="
for EP in /login /api/login /auth/login /api/auth/login /signin /api/signin \
  /api/auth /api/token /oauth/token /api/password-reset /api/mfa/verify \
  /api/user/verify /forgot-password /api/v1/auth/login; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${EP}")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [$CODE] ${EP}"
done
```

## Phase 1 — Rate Limit Detection (No Real Creds)

```bash
echo "=== Rate Limit Detection Test ==="
BASE="https://${TARGET}"
LOGIN_EP="${LOGIN_ENDPOINT:-/api/login}"

echo "Sending 30 login attempts with obviously-wrong credentials:"
echo "Goal: detect if 429 fires (rate limit present) or not"
echo ""

RATE_LIMITED=0
for I in $(seq 1 30); do
  RESP=$(curl -sk -X POST "${BASE}${LOGIN_EP}" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"test_detection_@example.com\",\"password\":\"ObviouslyWrong${I}!\"}" \
    -w "\n%{http_code}")
  CODE=$(echo "$RESP" | tail -1)
  
  case "$CODE" in
    429) RATE_LIMITED=$((RATE_LIMITED+1)); echo "  [429 at attempt $I] Rate limit triggered" ;;
    423) echo "  [423 at attempt $I] Account locked" ;;
    200|401|403) ;;
    *) echo "  [$CODE at attempt $I]" ;;
  esac
done

if [ "$RATE_LIMITED" -eq 0 ]; then
  echo ""
  echo "  [NO RATE LIMIT] 30 attempts with no 429 → rate limiting absent or very high threshold"
fi
```

## Phase 2 — IP-Based Rate Limit Bypass

```bash
echo "=== IP Rate Limit Bypass via Headers ==="
BASE="https://${TARGET}"
LOGIN_EP="${LOGIN_ENDPOINT:-/api/login}"

echo "Test: does rotating X-Forwarded-For reset rate limit counter?"
echo ""

ATTEMPTS=0
for I in $(seq 1 20); do
  CODE=$(curl -sk -X POST "${BASE}${LOGIN_EP}" \
    -H "Content-Type: application/json" \
    -H "X-Forwarded-For: 203.0.113.${I}" \
    -H "X-Real-IP: 203.0.113.${I}" \
    -H "CF-Connecting-IP: 203.0.113.${I}" \
    -d '{"email":"test@example.com","password":"wrong"}' \
    -o /dev/null -w "%{http_code}")
  [ "$CODE" != "429" ] && ATTEMPTS=$((ATTEMPTS+1))
done

echo "  ${ATTEMPTS}/20 attempts succeeded (no 429) with IP rotation"
[ "$ATTEMPTS" -gt 15 ] && echo "  [BYPASS] IP rotation bypasses rate limiting"
```

## Phase 3 — Username Rotation (Account Lockout Bypass)

```bash
echo "=== Account Lockout Bypass via Username Rotation ==="
BASE="https://${TARGET}"
LOGIN_EP="${LOGIN_ENDPOINT:-/api/login}"

echo "Technique: instead of locking out one account, rotate usernames with common passwords"
echo "Goal: detect if per-account lockout is the ONLY protection (no global IP rate limit)"
echo ""
echo "Test: 1 password x many fake usernames → measures per-user vs global controls"

COMMON_PASS="Password123!"
for USER in user1 user2 user3 user4 user5; do
  CODE=$(curl -sk -X POST "${BASE}${LOGIN_EP}" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${USER}@example.com\",\"password\":\"${COMMON_PASS}\"}" \
    -o /dev/null -w "%{http_code}")
  echo "  ${USER}@example.com: $CODE"
done
echo ""
echo "  If no 429 across different usernames → only per-account lockout, no global IP rate limit"
```

## Phase 4 — OTP Rate Limit

```bash
echo "=== OTP/MFA Rate Limit ==="
BASE="https://${TARGET}"
OTP_EP="${OTP_ENDPOINT:-/api/mfa/verify}"
SESSION="${SESSION_COOKIE:-your-pre-mfa-session}"

echo "Sending 20 OTP attempts (wrong codes):"
for I in $(seq 1 20); do
  OTP=$(printf "%06d" $((RANDOM % 1000000)))
  CODE=$(curl -sk -X POST "${BASE}${OTP_EP}" \
    -H "Content-Type: application/json" \
    -b "session=${SESSION}" \
    -d "{\"otp\":\"${OTP}\"}" -o /dev/null -w "%{http_code}")
  echo -n "${CODE} "
done
echo ""
echo ""
echo "  All 401 with no 429 → no OTP attempt rate limit → OTP brute force possible"
echo "  429 after N → rate limit present (document threshold)"
echo "  Account locked after N → lockout present (document threshold)"
```

## Gate 0

```bash
echo "=== Rate Limit Gate 0 ==="
echo "  □ Login: 50 attempts with no 429 or lockout"
echo "  □ IP bypass: X-Forwarded-For rotation allows unlimited attempts"
echo "  □ OTP: 20+ wrong OTP attempts with no lockout"
echo "  □ Password reset: unlimited reset requests for same email"
echo ""
echo "  REPORT: missing control + threshold (e.g., 'no rate limit after 1000 attempts')"
echo "  DO NOT REPORT: actual credentials found (that is not in scope)"
echo "  SEVERITY: no rate limit on login = Medium; OTP no limit = High (enables prefix oracle)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
No rate limiting on [/api/login]: 1000 consecutive login attempts return 401 without any 429, lockout, or CAPTCHA — enables automated credential attacks; OTP brute force possible (prefix oracle attack in 60 attempts per /skill k1nzr3c0n-hunt-mfa-bypass Phase 4)
Rate limit bypass via X-Forwarded-For on [/api/login]: rotating IP header from 1-254 resets per-IP counter; confirmed 254 attempts with no 429 — rate limiting tied to IP header, not session
```

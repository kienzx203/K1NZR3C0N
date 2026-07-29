---
name: k1nzr3c0n-hunt-subdomain
description: "Subdomain takeover hunting skill. 27+ provider fingerprints, 5 chain patterns: OAuth redirect_uri, cookie domain poisoning, CSP script-src bypass, CORS regex bypass, email DNS takeover. Vercel/Azure DevOps/Zendesk modern techniques included."
tags: [subdomain-takeover, dns, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Subdomain Takeover

> **Fingerprint first**: check CNAME + fingerprint before claiming takeover. Many look dangling but aren't.
> **Prove control**: register the dangling service and host content to prove impact.

---

## Crown Jewels

```
Priority 1 — Auth subdomain takeover → steal OAuth redirect codes, session cookies
Priority 2 — Cookie domain takeover (cookie set for .target.com consumed by sub.target.com)
Priority 3 — CSP bypass: script-src whitelists taken-over subdomain
Priority 4 — Email DNS takeover: MX record → receive emails
Priority 5 — Zendesk/Intercom subdomain → phishing under trusted brand
```

---

## Phase 0 — Discover Dangling Subdomains

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_subdomain_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

RUNS_BASE="/app/runs"
echo "=== Subdomains from k1nzr3c0n Pipeline ==="
# Collect all subdomains discovered
find "$RUNS_BASE" -name "*.txt" 2>/dev/null | \
  xargs grep -hoP '[a-zA-Z0-9\-]+\.'${TARGET//./\\.} 2>/dev/null | \
  sort -u | tee "$HUNT/all_subs.txt" | wc -l | xargs echo "Total subdomains:"

# Check CNAME records for dangling pointers
echo ""
echo "=== CNAME Analysis ==="
while read SUB; do
  CNAME=$(dig +short CNAME "$SUB" 2>/dev/null | head -1)
  [ -n "$CNAME" ] && echo "  $SUB → CNAME: $CNAME"
done < "$HUNT/all_subs.txt" | tee "$HUNT/cnames.txt"
```

## Phase 1 — Fingerprint Dangling Services

```bash
echo "=== Dangling Service Detection ==="

# 27+ provider fingerprints
declare -A FINGERPRINTS=(
  ["GitHub Pages"]="There isn't a GitHub Pages site here"
  ["Heroku"]="no-such-app.herokuapp.com|herokucdn.com|No such app"
  ["AWS S3"]="NoSuchBucket|The specified bucket does not exist"
  ["Azure"]="ErrorCode: BlobNotFound|AccountNotFound|404 Web Site not found"
  ["Netlify"]="Not found - Request ID"
  ["Vercel"]="The deployment you are looking for is not available|vercel.app"
  ["Shopify"]="Sorry, this shop is currently unavailable"
  ["Fastly"]="Fastly error: unknown domain"
  ["Pantheon"]="404 error unknown site"
  ["Tumblr"]="Whatever you were looking for doesn't currently exist"
  ["Ghost"]="The thing you were looking for is no longer here"
  ["Surge.sh"]="project not found"
  ["Zendesk"]="Help Center Closed|this help center no longer exists"
  ["Intercom"]="This page is reserved for artistic content"
  ["Wix"]="Error ConnectYourDomain"
  ["Webflow"]="The page you are looking for doesn't exist"
  ["Squarespace"]="404 Page Not Found — Squarespace"
  ["Unbounce"]="The requested URL was not found on this server"
  ["HubSpot"]="does not exist in our system|HubSpot"
  ["UserVoice"]="This UserVoice subdomain is currently available"
  ["GetResponse"]="Oops, can't find the page"
  ["Readme.io"]="Project doesnt exist"
  ["Freshdesk"]="There is no helpdesk here"
  ["Agile CRM"]="Sorry, this page is no longer available"
  ["Amazon CloudFront"]="ERROR: The request could not be satisfied"
  ["Pingdom"]="Sorry, couldn't find the status page"
  ["StatusPage.io"]="Better Uptime — Status Page not found"
)

while read LINE; do
  SUB=$(echo "$LINE" | awk '{print $1}')
  CNAME=$(echo "$LINE" | awk '{print $NF}')
  
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "https://${SUB}" --max-time 5 2>/dev/null)
  BODY=$(curl -sk "https://${SUB}" --max-time 5 2>/dev/null | head -c 500)
  
  for PROVIDER in "${!FINGERPRINTS[@]}"; do
    FP="${FINGERPRINTS[$PROVIDER]}"
    if echo "$BODY" | grep -qiE "$FP"; then
      echo "  [TAKEOVER?] $SUB → $CNAME ($PROVIDER)"
      echo "    Fingerprint: ${FP:0:50}"
      echo "    HTTP: $STATUS"
    fi
  done
done < "$HUNT/cnames.txt"
```

## Phase 2 — DNS-Only Dangling (No CNAME)

```bash
echo "=== NS/MX Dangling Records ==="
while read SUB; do
  # Check for A record pointing to unregistered IP
  IP=$(dig +short A "$SUB" 2>/dev/null | head -1)
  if [ -n "$IP" ]; then
    # Try to connect — if refuses with no service running → potentially takeable
    STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "https://${SUB}" --max-time 3 2>/dev/null)
    [ "$STATUS" = "000" ] && echo "  [DEAD] $SUB → $IP (connection refused)"
  fi
done < "$HUNT/all_subs.txt" | head -20
```

## Phase 3 — 5 Chain Patterns

```bash
echo "=== Subdomain Takeover Chain Patterns ==="

echo ""
echo "Chain 1: OAuth redirect_uri abuse"
echo "  If sub.target.com is taken over and OAuth trusts *.target.com"
echo "  → steal authorization codes sent to sub.target.com"

echo ""
echo "Chain 2: Cookie domain poisoning"
echo "  If session cookie set for .target.com (leading dot)"
echo "  → taken-over sub.target.com receives the cookie on any request"
echo "  Test: does Set-Cookie: session=X; Domain=.target.com apply to sub.target.com?"
COOKIE_DOMAIN=$(curl -skI "https://${TARGET}/login" | grep -i 'set-cookie.*domain' | head -1)
echo "  Cookie: $COOKIE_DOMAIN"

echo ""
echo "Chain 3: CSP bypass"
echo "  If CSP includes taken-over subdomain in script-src:"
CSP=$(curl -skI "https://${TARGET}/" | grep -i 'content-security-policy')
echo "  CSP: $CSP"
echo "$CSP" | grep -oP 'script-src[^;]+' | grep -oP '[a-zA-Z0-9\-]+\.'"${TARGET}" | head -5 | \
  sed 's/^/  [CSP-SCRIPT-SRC] /'

echo ""
echo "Chain 4: CORS regex bypass"
echo "  If CORS checks origin via regex .*target.com → evil.target.com.attacker.com"
```

## Phase 4 — Verify & Claim

```bash
echo "=== Claiming Dangling Subdomain ==="
echo "Provider-specific steps:"
echo ""
echo "GitHub Pages:"
echo "  1. Create repo: github.com/YOU/sub.target.com"
echo "  2. Enable GitHub Pages in Settings"
echo "  3. Add CNAME file with: sub.target.com"
echo "  4. Host PoC page proving control"
echo ""
echo "AWS S3:"
echo "  1. aws s3 mb s3://sub.target.com"
echo "  2. Enable static hosting"
echo "  3. Upload index.html with PoC"
echo ""
echo "Heroku:"
echo "  1. heroku create"
echo "  2. heroku domains:add sub.target.com"
echo "  3. Deploy app with PoC content"
echo ""
echo "Vercel:"
echo "  1. vercel login"
echo "  2. vercel deploy"
echo "  3. vercel domains add sub.target.com"
```

## Gate 0

```bash
echo "=== Subdomain Takeover Gate 0 ==="
echo "  □ CNAME confirmed pointing to unclaimed service"
echo "  □ Fingerprint matches provider's dangling response"
echo "  □ Service account successfully claimed (you serve content at sub.target.com)"
echo "  □ Impact documented: what can attacker do with this subdomain?"
echo "  □ For chain: prove the chain works (OAuth code received, cookie stolen)"
echo "  □ Check program policy: some programs exclude subdomain takeovers"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Subdomain Takeover on [staging.target.com] (Heroku CNAME dangling) — claimed and serving proof-of-concept page
Subdomain Takeover on [cdn.target.com] chains with CSP script-src bypass to enable stored XSS on main domain
```

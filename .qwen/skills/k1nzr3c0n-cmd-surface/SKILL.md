---
name: k1nzr3c0n-cmd-surface
description: "Attack surface ranking command. Reads k1nzr3c0n recon outputs and produces a ranked P1/P2/Kill list of attack vectors. Maps technology stack to highest-yield attack classes. Identifies crown jewel endpoints from URL corpus. Use after recon to prioritize the hunt."
tags: [command, surface, prioritization, recon]
---

# /surface — Attack Surface Ranker

> Usage: `/surface` — run after recon to get a prioritized attack vector list.

---

## Surface Analysis

```bash
TARGET="${TARGET:-}"
RECON_DIR=$(ls -td /tmp/recon_${TARGET//[^a-zA-Z0-9]/_}*/ 2>/dev/null | head -1)

echo "╔══════════════════════════════════════════════════════╗"
echo "║  ATTACK SURFACE RANKING                               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "  Recon data: ${RECON_DIR:-NOT FOUND}"
echo ""

[ -z "$RECON_DIR" ] && echo "[!] Run /skill k1nzr3c0n-recon first" && exit 1

echo "=== Tech Stack → Attack Class Map ==="
httpx_file="${RECON_DIR}alive/httpx_results.txt"
[ -f "$httpx_file" ] && {
  grep -q 'PHP' "$httpx_file" && echo "  [PHP] → LFI, SQLi, SSTI(Smarty/Twig), deserialization, .env"
  grep -q 'Node.js\|Express' "$httpx_file" && echo "  [Node] → Prototype pollution, SSTI(Pug), RCE chains"
  grep -q 'Spring\|Java' "$httpx_file" && echo "  [Java/Spring] → Actuator, SpEL, XXE, deserialization"
  grep -q 'Laravel\|Symfony\|CodeIgniter' "$httpx_file" && echo "  [PHP-FW] → debug mode, .env, Telescope, mass assignment"
  grep -q 'Next.js\|React\|Vue\|Angular' "$httpx_file" && echo "  [SPA] → JS bundle analysis, /_next/data/ IDOR, client-secrets"
  grep -q 'graphql\|GraphQL' "$httpx_file" && echo "  [GraphQL] → introspection, batch alias, IDOR via node()"
  grep -q 'S3\|CloudFront\|CloudWatch' "$httpx_file" && echo "  [AWS] → S3 bucket enum, CloudWatch RUM, Lambda URL"
  grep -q 'Nginx\|nginx' "$httpx_file" && echo "  [Nginx] → path normalization, request smuggling"
  grep -q 'IIS\|ASP.NET' "$httpx_file" && echo "  [ASP.NET] → ViewState, Telerik CVEs, trace.axd"
}
```

## P1 Crown Jewel Endpoints

```bash
echo ""
echo "=== P1 Crown Jewel Endpoints ==="
url_corpus="${RECON_DIR}endpoints/all_urls.txt"
[ -f "$url_corpus" ] && {
  echo "  Auth/Admin:"
  grep -iE '/(admin|panel|dashboard|console|management|backoffice|internal)' "$url_corpus" | \
    sort -u | head -10 | sed 's/^/    /'
  
  echo "  Payment/Financial:"
  grep -iE '/(payment|billing|invoice|subscription|checkout|wallet|transfer|refund|credit)' "$url_corpus" | \
    sort -u | head -5 | sed 's/^/    /'
  
  echo "  Upload/Import:"
  grep -iE '/(upload|import|export|attach|file|document|media|avatar|image)' "$url_corpus" | \
    sort -u | head -5 | sed 's/^/    /'
  
  echo "  Auth flows:"
  grep -iE '/(oauth|sso|saml|token|auth|login|signup|reset|verify|mfa|2fa)' "$url_corpus" | \
    sort -u | head -10 | sed 's/^/    /'
}
```

## P2 Good Yield

```bash
echo ""
echo "=== P2 Good Yield ==="
[ -f "$url_corpus" ] && {
  echo "  APIs with IDs:"
  grep -oP '/api/[a-z0-9/-]+/[0-9]+' "$url_corpus" | sort -u | head -10 | sed 's/^/    [IDOR-CANDIDATE] /'
  
  echo "  Search/Filter:"
  grep -iE '[?&](q|query|search|filter|sort|order|where|name)=' "$url_corpus" | \
    head -5 | sed 's/^/    [INJECTION-CANDIDATE] /'
  
  echo "  Redirects:"
  grep -iE '[?&](url|redirect|return|next|back|forward|goto|target|continue)=' "$url_corpus" | \
    head -5 | sed 's/^/    [REDIRECT-CANDIDATE] /'
}
```

## Kill List (Skip These)

```bash
echo ""
echo "=== Kill List (deprioritize) ==="
echo "  □ /static/, /assets/, /fonts/, /images/ — content delivery, not logic"
echo "  □ /health, /ping, /status — monitoring endpoints"
echo "  □ *.min.js, *.bundle.js — JS resources (analyze separately in js-analyst)"
echo "  □ Third-party domains not in scope"
echo "  □ Public documentation pages"
echo ""
echo "=== GF Classified URL Counts ==="
GF_DIR="${RECON_DIR}endpoints"
for VULN_CLASS in xss sqli ssrf redirect lfi rce ssti idor; do
  COUNT=$(wc -l < "${GF_DIR}/gf_${VULN_CLASS}.txt" 2>/dev/null || echo 0)
  echo "  ${VULN_CLASS}: ${COUNT} candidates"
done
echo ""
echo "  Highest count → highest attack surface → start there"
echo "  → /hunt --vuln-class=<class>"
```

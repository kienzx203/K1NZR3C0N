---
name: k1nzr3c0n-recon
description: "Full recon pipeline skill for k1nzr3c0n. Orchestrates: crt.sh → subfinder → dnsx → httpx → katana → waybackurls → gau → gf patterns → nuclei → JS secrets → swagger paths. SPA-aware: extracts JS bundle routes and API endpoints. Integrates with k1nzr3c0n workflow outputs."
tags: [recon, subdomain, osint, web-security, bug-bounty]
---

# K1NZR3C0N Recon Pipeline

> **Scope first**: run scope check before any active probing.
> **SPA-aware**: modern SPAs hide APIs in JS bundles — always download and analyze JS.

---

## Phase 0 — Scope & Setup

```bash
TARGET="${TARGET:-}"
if [ -z "$TARGET" ]; then echo "Set TARGET=example.com"; exit 1; fi

WORK="/tmp/recon_${TARGET//[^a-zA-Z0-9]/_}_$(date +%Y%m%d)"
mkdir -p "$WORK"/{subs,alive,js,endpoints,secrets,reports}
echo "[+] Target: $TARGET"
echo "[+] Workspace: $WORK"

# Import existing k1nzr3c0n run data
RUNS_BASE="/app/runs"
find "$RUNS_BASE" -name "*.txt" -o -name "*.json" 2>/dev/null | \
  xargs grep -hoP '[a-zA-Z0-9\-]+'${TARGET//./\\.} 2>/dev/null | \
  sort -u > "$WORK/subs/k1nzr3c0n_subs.txt"
echo "[+] Imported $(wc -l < $WORK/subs/k1nzr3c0n_subs.txt) subdomains from k1nzr3c0n runs"
```

## Phase 1 — Subdomain Enumeration

```bash
echo "=== Subdomain Enumeration ==="

# crt.sh (passive, no rate limit)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | \
  grep -v '\*' | sort -u > "$WORK/subs/crt_sh.txt"
echo "  crt.sh: $(wc -l < $WORK/subs/crt_sh.txt) subdomains"

# subfinder
subfinder -d "$TARGET" -silent -o "$WORK/subs/subfinder.txt" 2>/dev/null && \
  echo "  subfinder: $(wc -l < $WORK/subs/subfinder.txt) subdomains" || \
  echo "  subfinder: not installed (apt install -y subfinder)"

# Chaos (ProjectDiscovery)
curl -s "https://chaos-data.projectdiscovery.io/${TARGET}.zip" -o "$WORK/subs/chaos.zip" 2>/dev/null && \
  unzip -p "$WORK/subs/chaos.zip" 2>/dev/null >> "$WORK/subs/chaos.txt"

# Merge and deduplicate
cat "$WORK/subs/"*.txt 2>/dev/null | sort -u > "$WORK/subs/all_subs.txt"
echo "  TOTAL: $(wc -l < $WORK/subs/all_subs.txt) unique subdomains"
```

## Phase 2 — DNS Resolution + HTTP Probing

```bash
echo "=== DNS + HTTP Probing ==="

# DNS resolution (dnsx)
dnsx -l "$WORK/subs/all_subs.txt" -silent -o "$WORK/subs/resolved.txt" 2>/dev/null && \
  echo "  dnsx: $(wc -l < $WORK/subs/resolved.txt) resolved" || \
  echo "  dnsx: not installed (go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest)"

# HTTP probing (httpx)
httpx -l "$WORK/subs/resolved.txt" -silent \
  -title -status-code -tech-detect -follow-redirects \
  -o "$WORK/alive/httpx_results.txt" 2>/dev/null && \
  echo "  httpx: $(wc -l < $WORK/alive/httpx_results.txt) alive hosts" || \
  echo "  httpx: not installed (go install github.com/projectdiscovery/httpx/cmd/httpx@latest)"

# Extract just URLs
grep -oP 'https?://\S+' "$WORK/alive/httpx_results.txt" 2>/dev/null \
  > "$WORK/alive/alive_urls.txt"
echo "  Live URLs: $(wc -l < $WORK/alive/alive_urls.txt)"
```

## Phase 3 — Crawling & URL Collection

```bash
echo "=== URL Discovery ==="

# Katana (SPA-aware crawling)
katana -list "$WORK/alive/alive_urls.txt" -silent \
  -js-crawl -d 3 -o "$WORK/endpoints/katana.txt" 2>/dev/null && \
  echo "  katana: $(wc -l < $WORK/endpoints/katana.txt) URLs" || \
  echo "  katana: not installed"

# Waybackurls (historical)
cat "$WORK/alive/alive_urls.txt" | waybackurls 2>/dev/null | \
  sort -u > "$WORK/endpoints/wayback.txt"
echo "  waybackurls: $(wc -l < $WORK/endpoints/wayback.txt) URLs"

# GAU (GetAllUrls)
cat "$WORK/alive/alive_urls.txt" | gau 2>/dev/null | \
  sort -u > "$WORK/endpoints/gau.txt"
echo "  gau: $(wc -l < $WORK/endpoints/gau.txt) URLs"

# Merge all URLs
cat "$WORK/endpoints/"*.txt 2>/dev/null | sort -u > "$WORK/endpoints/all_urls.txt"
echo "  TOTAL URLs: $(wc -l < $WORK/endpoints/all_urls.txt)"
```

## Phase 4 — GF Pattern Classification

```bash
echo "=== GF Pattern Classification ==="
# gf: grep patterns for common vulnerability parameters
ALL_URLS="$WORK/endpoints/all_urls.txt"

for PATTERN in xss ssrf sqli redirect lfi rce ssti debug_logic secrets cors idor; do
  COUNT=$(gf "$PATTERN" "$ALL_URLS" 2>/dev/null | tee "$WORK/endpoints/gf_${PATTERN}.txt" | wc -l)
  [ "$COUNT" -gt 0 ] && echo "  [gf:$PATTERN] $COUNT URLs → hunt-${PATTERN}"
done

# Total prioritized
cat "$WORK/endpoints/gf_"*.txt 2>/dev/null | sort -u > "$WORK/endpoints/gf_all.txt"
echo "  GF classified: $(wc -l < $WORK/endpoints/gf_all.txt) priority URLs"
```

## Phase 5 — Nuclei Scanning

```bash
echo "=== Nuclei Vulnerability Scan ==="

# Use k1nzr3c0n nuclei_data volume templates
nuclei -list "$WORK/alive/alive_urls.txt" \
  -t /root/nuclei-templates/ \
  -tags "exposure,misconfiguration,token,secret,api" \
  -severity "medium,high,critical" \
  -o "$WORK/reports/nuclei_findings.txt" \
  -silent 2>/dev/null
echo "  Nuclei: $(wc -l < $WORK/reports/nuclei_findings.txt 2>/dev/null || echo 0) findings"
```

## Phase 6 — JS Analysis

```bash
echo "=== JavaScript Analysis ==="
echo "Loading k1nzr3c0n-js-analyst for full JS analysis..."
echo ""
echo "  /skill k1nzr3c0n-js-analyst"
echo ""
echo "JS analyst covers:"
echo "  - JS file discovery and download"
echo "  - API endpoint extraction"
echo "  - Secret scanning (TruffleHog, gitleaks, 20+ service patterns)"
echo "  - DOM XSS sink detection"
echo "  - Business logic flags"
```

## Phase 7 — Recon Summary

```bash
echo "╔══════════════════════════════════════════════════════╗"
echo "║             RECON SUMMARY                             ║"
echo "╚══════════════════════════════════════════════════════╝"
printf "  Subdomains found : %s\n" "$(wc -l < $WORK/subs/all_subs.txt 2>/dev/null || echo 0)"
printf "  Alive hosts      : %s\n" "$(wc -l < $WORK/alive/alive_urls.txt 2>/dev/null || echo 0)"
printf "  Total URLs       : %s\n" "$(wc -l < $WORK/endpoints/all_urls.txt 2>/dev/null || echo 0)"
printf "  Nuclei findings  : %s\n" "$(wc -l < $WORK/reports/nuclei_findings.txt 2>/dev/null || echo 0)"
echo ""
echo "  Next: /skill k1nzr3c0n-bug-hunter"
echo "  Next: /skill k1nzr3c0n-js-analyst"
```

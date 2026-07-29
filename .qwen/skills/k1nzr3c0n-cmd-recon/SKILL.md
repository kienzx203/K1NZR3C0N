---
name: k1nzr3c0n-cmd-recon
description: "Recon command dispatcher. Quick command-style entry point to k1nzr3c0n-recon skill. Sets TARGET, SCOPE, and options then hands off to full pipeline. Handles: fresh recon, recon update (new subdomains only), targeted (single subdomain), or import from k1nzr3c0n run outputs."
tags: [command, recon, dispatch]
---

# /recon — Recon Dispatcher

> Usage: `/recon`, `/recon --target=api.example.com`, `/recon --mode=update`

---

## Mode Detection

```bash
RECON_MODE="${RECON_CMD_MODE:-full}"  # full | update | targeted | import
TARGET="${TARGET:-}"

echo "=== RECON DISPATCHER ==="
echo "  Target: ${TARGET}"
echo "  Mode:   ${RECON_MODE}"
echo ""

[ -z "$TARGET" ] && echo "[!] Set TARGET first: export TARGET=example.com" && exit 1
```

## Full Recon

```bash
[ "$RECON_MODE" = "full" ] && {
echo "=== Full Recon Pipeline ==="
echo "  Delegating to: /skill k1nzr3c0n-recon"
echo "  Estimated time: 20-45 minutes for typical target"
echo ""
echo "  Phase 0: Setup + k1nzr3c0n run import"
echo "  Phase 1: Subdomain enumeration (crt.sh + subfinder)"
echo "  Phase 2: DNS resolution + httpx tech-detect"
echo "  Phase 3: Source leak quick wins (30 paths, 30 seconds)"
echo "  Phase 4: URL discovery (katana + waybackurls + gau)"
echo "  Phase 5: GF classification (xss/ssrf/sqli/lfi/etc.)"
echo "  Phase 6: Nuclei scan (known vulnerabilities)"
echo "  Phase 7: Admin panel enumeration"
echo "  Phase 8: DNS/TLS checks (SPF, DMARC, subdomain takeover)"
echo ""
echo "  /skill k1nzr3c0n-recon"
}
```

## Update Mode (New Subdomains Only)

```bash
[ "$RECON_MODE" = "update" ] && {
echo "=== Update Mode (new subdomains since last run) ==="
PREV_DIR=$(ls -td /tmp/recon_${TARGET//[^a-zA-Z0-9]/_}*/ 2>/dev/null | head -2 | tail -1)
CURR_DIR=$(ls -td /tmp/recon_${TARGET//[^a-zA-Z0-9]/_}*/ 2>/dev/null | head -1)

if [ -n "$PREV_DIR" ] && [ -n "$CURR_DIR" ]; then
  echo "  Previous: $PREV_DIR"
  echo "  Current:  $CURR_DIR"
  echo ""
  echo "  New subdomains:"
  comm -13 \
    <(sort "$PREV_DIR/subs/all_subs.txt" 2>/dev/null) \
    <(sort "$CURR_DIR/subs/all_subs.txt" 2>/dev/null) | \
    sed 's/^/    [NEW] /'
else
  echo "  [!] Need 2+ runs to diff — run /recon (full) first"
fi
}
```

## Targeted Mode (Single Subdomain)

```bash
[ "$RECON_MODE" = "targeted" ] && {
TARGETED_SUB="${TARGETED_SUBDOMAIN:-}"
echo "=== Targeted Mode: ${TARGETED_SUB} ==="
echo "Focused pipeline (skip full subdomain enum):"
echo ""
echo "  # Tech detect"
echo "  httpx -u https://${TARGETED_SUB}/ -tech-detect -json -o /tmp/recon_targeted_tech.json"
echo ""
echo "  # URL corpus"
echo "  katana -u https://${TARGETED_SUB}/ -d 3 -jc -o /tmp/recon_targeted_urls.txt"
echo "  waybackurls ${TARGETED_SUB} >> /tmp/recon_targeted_urls.txt"
echo "  sort -u /tmp/recon_targeted_urls.txt -o /tmp/recon_targeted_urls.txt"
echo ""
echo "  # GF classify"
echo "  cat /tmp/recon_targeted_urls.txt | gf xss > /tmp/gf_xss.txt"
echo "  cat /tmp/recon_targeted_urls.txt | gf ssrf > /tmp/gf_ssrf.txt"
echo "  cat /tmp/recon_targeted_urls.txt | gf sqli > /tmp/gf_sqli.txt"
echo ""
echo "  Then: /surface → /hunt"
}
```

## Import from k1nzr3c0n

```bash
[ "$RECON_MODE" = "import" ] && {
echo "=== Import from K1NZR3C0N Run Outputs ==="
echo "  /skill k1nzr3c0n-analyst"
echo ""
echo "  Imports: gobuster + feroxbuster + ffuf + dirsearch outputs"
echo "  Maps to: /tmp/recon_{target}/endpoints/all_urls.txt"
echo "  Then: /surface → /hunt"
}
```

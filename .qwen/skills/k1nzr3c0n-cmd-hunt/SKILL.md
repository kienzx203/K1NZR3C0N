---
name: k1nzr3c0n-cmd-hunt
description: "Hunt dispatcher command. Two-track: Red Team (OSCP-style: recon→exploit→chain) vs WAPT (OWASP-style: systematic enumeration). Grey/black box modes. --vuln-class flag dispatches to specific hunt skill. 20-minute rotation clock enforced. Reads k1nzr3c0n run outputs to select attack vectors."
tags: [command, dispatch, hunt, methodology]
---

# /hunt — Hunt Dispatcher

> Usage: `/hunt`, `/hunt --mode=wapt`, `/hunt --vuln-class=ssrf`, `/hunt --target=api.example.com`

---

## Dispatcher Logic

```bash
MODE="${HUNT_MODE:-redteam}"   # redteam | wapt
VULN="${VULN_CLASS:-auto}"     # auto | xss | ssrf | sqli | idor | etc.
TARGET="${TARGET:-}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  K1NZR3C0N HUNT DISPATCHER                           ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "  Target: ${TARGET}"
echo "  Mode:   ${MODE}"
echo "  Vuln:   ${VULN}"
echo "  Time:   $(date)"
echo ""

# Load recon data
RECON_DIR=$(ls -td /tmp/recon_${TARGET//[^a-zA-Z0-9]/_}*/ 2>/dev/null | head -1)
if [ -z "$RECON_DIR" ]; then
  echo "[!] No recon data found. Run first: /skill k1nzr3c0n-recon"
  echo "    Or import: /skill k1nzr3c0n-analyst"
fi

# Tech fingerprint
echo "=== Technology Stack ==="
grep -h 'tech\|language\|framework' "${RECON_DIR}alive/httpx_results.txt" 2>/dev/null | \
  grep -oP '\[[^\]]+\]' | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
```

## Red Team Mode (Default)

```bash
[ "$MODE" = "redteam" ] && {
echo "=== RED TEAM MODE: Highest Impact First ==="
echo ""
echo "Priority 1 — Code execution paths:"
echo "  /skill k1nzr3c0n-hunt-rce"
echo "  /skill k1nzr3c0n-hunt-ssrf"
echo "  /skill k1nzr3c0n-hunt-lfi"
echo "  /skill k1nzr3c0n-hunt-xxe"
echo ""
echo "Priority 2 — Account takeover:"
echo "  /skill k1nzr3c0n-hunt-ato"
echo "  /skill k1nzr3c0n-hunt-jwt"
echo "  /skill k1nzr3c0n-hunt-oauth"
echo "  /skill k1nzr3c0n-hunt-mfa-bypass"
echo ""
echo "Priority 3 — Data exposure:"
echo "  /skill k1nzr3c0n-hunt-idor"
echo "  /skill k1nzr3c0n-hunt-source-leak"
echo "  /skill k1nzr3c0n-hunt-spa-api"
echo "  /skill k1nzr3c0n-hunt-shadow-api"
echo ""
echo "Priority 4 — Logic:"
echo "  /skill k1nzr3c0n-hunt-business-logic"
echo "  /skill k1nzr3c0n-hunt-race-condition"
echo "  /skill k1nzr3c0n-hunt-auth-bypass"
}
```

## WAPT Mode (Systematic)

```bash
[ "$MODE" = "wapt" ] && {
echo "=== WAPT MODE: Systematic OWASP Coverage ==="
echo ""
echo "A01 Broken Access Control:"
echo "  /skill k1nzr3c0n-hunt-idor"
echo "  /skill k1nzr3c0n-hunt-auth-bypass"
echo ""
echo "A02 Cryptographic Failures:"
echo "  /skill k1nzr3c0n-hunt-jwt"
echo "  /skill k1nzr3c0n-hunt-source-leak"
echo ""
echo "A03 Injection:"
echo "  /skill k1nzr3c0n-hunt-sqli"
echo "  /skill k1nzr3c0n-hunt-nosqli"
echo "  /skill k1nzr3c0n-hunt-ssti"
echo "  /skill k1nzr3c0n-hunt-xss"
echo ""
echo "A04-A10 + API Security:"
echo "  /skill k1nzr3c0n-hunt-xxe"
echo "  /skill k1nzr3c0n-hunt-ssrf"
echo "  /skill k1nzr3c0n-hunt-api-misconfig"
echo "  /skill k1nzr3c0n-hunt-graphql"
echo "  /skill k1nzr3c0n-hunt-file-upload"
}
```

## Direct Dispatch (--vuln-class)

```bash
[ "$VULN" != "auto" ] && {
echo "=== Direct dispatch to: ${VULN} ==="
echo "  /skill k1nzr3c0n-hunt-${VULN}"
}
```

## GF-Based Auto-Dispatch

```bash
echo ""
echo "=== Auto-dispatch from GF output ==="
GF_DIR="${RECON_DIR:-/tmp/recon_unknown_*/}endpoints"
for VULN_CLASS in xss sqli ssrf redirect lfi rce ssti; do
  COUNT=$(wc -l < "${GF_DIR}/gf_${VULN_CLASS}.txt" 2>/dev/null || echo 0)
  [ "$COUNT" -gt 0 ] && echo "  → ${COUNT} candidates: /skill k1nzr3c0n-hunt-${VULN_CLASS}"
done
echo ""
echo "[Clock] 20-minute rotation timer started: $(date)"
echo "        If no progress in 20 min → rotate endpoint, subdomain, or vuln class"
```

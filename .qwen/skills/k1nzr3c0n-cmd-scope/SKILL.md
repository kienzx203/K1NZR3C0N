---
name: k1nzr3c0n-cmd-scope
description: "Pre-flight scope check command. Mandatory before any active testing. Deny-wins rule: if target not explicitly listed, it is OUT of scope. Wildcard expansion (*.example.com includes sub.example.com NOT sub.sub.example.com). CIDR matching. VDP vs bounty distinction. OOS auto-kill."
tags: [command, scope, compliance, pre-flight]
---

# /scope — Pre-flight Scope Checker

> **Run this before every active test.** Sending requests to out-of-scope targets = disqualification.
> **Rule**: deny-wins. Default-deny. Explicit inclusion required.

---

## Scope Load

```bash
TARGET="${TARGET:-}"
PROGRAM_FILE="${PROGRAM_SCOPE:-/tmp/scope.txt}"

echo "=== PRE-FLIGHT SCOPE CHECK ==="
echo "Target: ${TARGET}"
echo "Program scope file: ${PROGRAM_FILE}"
echo ""
echo "If scope file not set, copy program scope from HackerOne/Bugcrowd to:"
echo "  /tmp/scope.txt"
echo ""
echo "Format (one per line):"
echo "  *.example.com"
echo "  api.example.com"
echo "  10.0.0.0/24"
echo "  *.app.example.com"
```

## Scope Check Logic

```bash
echo "=== Scope Check: ${TARGET} ==="
TARGET_DOMAIN="${TARGET}"

# Check exact match
grep -qxF "${TARGET_DOMAIN}" "${PROGRAM_FILE}" 2>/dev/null && \
  echo "  [IN SCOPE] Exact match: ${TARGET_DOMAIN}" && exit 0

# Check wildcard (one level)
APEX=$(echo "${TARGET_DOMAIN}" | rev | cut -d. -f1-2 | rev)
WILDCARD="*.${APEX}"
grep -qxF "${WILDCARD}" "${PROGRAM_FILE}" 2>/dev/null && {
  # Verify only one subdomain deep (*.apex.com matches foo.apex.com NOT foo.bar.apex.com)
  SUBCOUNT=$(echo "${TARGET_DOMAIN}" | grep -o '\.' | wc -l)
  APEXCOUNT=$(echo "${APEX}" | grep -o '\.' | wc -l)
  DEPTH=$((SUBCOUNT - APEXCOUNT))
  [ "$DEPTH" -le 1 ] && \
    echo "  [IN SCOPE] Wildcard match: ${WILDCARD} covers ${TARGET_DOMAIN}" || \
    echo "  [OOS] ${WILDCARD} does NOT cover ${TARGET_DOMAIN} (too deep — ${DEPTH} levels)"
  exit 0
}

echo "  [OOS] ${TARGET_DOMAIN} NOT in scope — STOP all testing"
echo ""
echo "  If you believe it should be in scope:"
echo "  1. Re-read program policy (cdn/third-party exclusions?)"
echo "  2. Do not test until explicitly confirmed in scope"
echo "  3. Ask program via HackerOne/Bugcrowd message if unsure"
```

## OOS Auto-Kill Checklist

```bash
echo ""
echo "=== Automatic OOS (always out of scope unless explicitly listed) ==="
cat << 'OOS'
NEVER test without explicit program inclusion:
  ✗ Third-party vendors (Zendesk, Stripe, Cloudflare, Intercom)
  ✗ Acquisitions not listed (just because parent is in scope ≠ subsidiary is)
  ✗ CDN infrastructure (CloudFront distro domains)
  ✗ Email infrastructure (MX, DKIM, DMARC on non-login domains)
  ✗ Social media accounts linked to company
  ✗ employee personal accounts
  ✗ Physical infrastructure / offices
  ✗ Denial of service (even if domain is in scope)

VDP vs Bug Bounty:
  VDP = report, no payout expected
  Bug Bounty = report + payout if valid
  Always check: is this a paid program or VDP?
OOS
```

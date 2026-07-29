---
name: k1nzr3c0n-cmd-triage
description: "Quick triage command (fast version of k1nzr3c0n-triage). 7Q Gate in 60 seconds, fast kill checklist, severity anchor, never-submit quick reference. Use immediately after any potential finding before investing more time."
tags: [command, triage, quick, gate]
---

# /triage — Quick Finding Triage

> Usage: `/triage` — 60-second gate before investing more time in a finding.

---

## 60-Second Gate

```bash
echo "=== QUICK TRIAGE — 60 seconds ==="
echo ""
echo "KILL IMMEDIATELY if any of these is YES:"
echo "  □ Self-affects only (self-XSS, test account only)"
echo "  □ Not reachable from internet (internal-only)"
echo "  □ Out of scope domain or vuln type"
echo "  □ DNS-only callback (no HTTP, no data)"
echo "  □ Status-code-only change (body identical)"
echo "  □ Did not reproduce 3 times"
echo "  □ Standalone from the never-submit list below"
echo ""
echo "PROCEED if ALL no → invest time in full validation"
```

## Severity Quick Anchor

```bash
echo "=== Severity Anchor ==="
cat << 'SEV'
Critical (P1): Unauthenticated RCE | ATO any account | Mass data exfil | Payment bypass
High (P2):     Auth bypass | Priv escalation | SSRF w/ cloud creds | SQLi with data | Stored XSS in admin
Medium (P3):   Auth IDOR | CORS + creds | CSRF on important action | Reflected XSS | Open redirect chain
Low (P4):      Info disclosure | Enumeration | Non-critical IDOR | Self-XSS chain potential

Downgrade if:
  Requires attacker to be logged in → P1→P2, P2→P3
  Requires user interaction → P2→P3
  No real data exposed → P3→P4
  Already known (disclosed report same bug) → Informational
SEV
```

## Never-Submit Quick List

```bash
echo ""
echo "=== Never Submit Standalone ==="
cat << 'REJECT'
✗ Self-XSS          ✗ Logout CSRF        ✗ Missing headers
✗ Open redirect     ✗ Clickjacking       ✗ Username enum (timing only)
✗ Version disclose  ✗ Mixed content      ✗ SPF/DMARC (non-login)
✗ DNS-only SSRF     ✗ Tabnapping         ✗ CORS * (no creds working)
REJECT
```

## What Needs More Work

```bash
echo ""
echo "=== If Unclear → Run Full Validation ==="
echo "  /validate — 4-gate process (30s/2min/5min/10min)"
echo ""
echo "=== If Valid → Log and Report ==="
echo "  /remember — log to journal"
echo "  /report   — generate submission template"
```

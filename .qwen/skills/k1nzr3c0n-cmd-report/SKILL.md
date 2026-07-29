---
name: k1nzr3c0n-cmd-report
description: "Submission-ready report generator. HackerOne, Bugcrowd, and Intigriti templates. CVSS 3.1 calculator guide. Title formula (Attack + Component + Impact). Severity mapping table. Impact statement templates for each vuln class. Pre-submission hygiene checklist."
tags: [command, report, submission, cvss]
---

# /report — Report Generator

> Usage: `/report` — fill in blanks, get submission-ready report.

---

## Title Formula

```bash
echo "=== Report Title Formula ==="
echo ""
echo "Format: [Attack Type] in [Component] leads to [Impact]"
echo ""
echo "Examples:"
echo "  SSRF in webhook URL parameter allows AWS metadata credential theft"
echo "  Stored XSS in user profile name executes JavaScript in admin context"
echo "  SQL injection in search API leaks full user database via UNION"
echo "  Path traversal in file download endpoint reads arbitrary server files"
echo "  Missing authentication on /api/v1/users/export exposes all PII"
echo ""
echo "BAD titles (rejected):"
echo "  'Security issue found' (too vague)"
echo "  'XSS vulnerability' (missing component and impact)"
echo "  'Critical bug in authentication' (adjective, not attack, not impact)"
```

## CVSS 3.1 Guide

```bash
echo "=== CVSS 3.1 Calculator ==="
cat << 'CVSS'
Base Score factors:

Attack Vector (AV):
  N (Network) = exploitable remotely                    → 0.85
  A (Adjacent) = same network segment                  → 0.62
  L (Local)    = local access required                 → 0.55
  P (Physical) = physical access required              → 0.20

Attack Complexity (AC):
  L (Low)    = no special conditions needed            → most bugs
  H (High)   = race conditions, specific configs       → e.g. race conditions

Privileges Required (PR):
  N (None)   = no account needed                      → unauthenticated
  L (Low)    = regular user account                   → standard user
  H (High)   = admin account needed                   → admin-only bugs

User Interaction (UI):
  N (None)   = no victim action                       → SSRF, SQLi
  R (Required) = victim must click/browse             → XSS (stored), phishing

Scope (S):
  U (Unchanged) = impact stays in same security scope
  C (Changed)   = crosses trust boundary (XSS→admin, SSRF→cloud)

Confidentiality, Integrity, Availability (C/I/A):
  N = None, L = Low, H = High

Quick Severity Reference:
  Critical (9.0-10.0): AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H = RCE unauth
  High (7.0-8.9):      AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N  = Auth bypass
  Medium (4.0-6.9):    AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N  = Authed IDOR
  Low (0.1-3.9):       AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N  = Info disclosure

Use calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
CVSS
```

## HackerOne Template

```bash
echo "=== HackerOne Report Template ==="
cat << 'H1'
## Summary
[One paragraph: what is vulnerable, how it works, what the impact is]

## Steps to Reproduce
1. Navigate to: [URL]
2. [Action]
3. [Payload or parameter]
4. Observe: [Expected vs actual behavior]

## PoC
```
[curl command / Burp request / script]
```

## Impact
[Specific consequence: what attacker can access, do, or steal]
[Estimate scale: how many users/records affected?]

## Recommended Fix
[Specific fix: parameterized queries, output encoding, auth middleware, etc.]

## CVSS Score
[CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N]
Score: [X.X] — [Severity]
H1
```

## Bugcrowd / Intigriti Template

```bash
echo "=== Bugcrowd Template ==="
cat << 'BC'
**Vulnerability Type**: [CWE-xxx: name]

**URL / Endpoint**: [exact URL]

**Method**: [GET/POST/...]

**Parameters**: [which parameter is vulnerable]

**Steps**:
1. ...

**Expected Result**: [what should happen]

**Actual Result**: [what actually happens]

**Evidence**: [screenshot, response body, OOB callback log]

**CVSS**: [score and vector]

**Severity**: [P1/P2/P3/P4]
BC
```

## Pre-Submission Checklist

```bash
echo "=== Pre-Submission Checklist ==="
echo "  □ Title follows: Attack + Component + Impact formula"
echo "  □ Steps reproducible by program team from scratch (no local setup assumed)"
echo "  □ PoC uses benign marker — not real user data"
echo "  □ Evidence: screenshots or recording included"
echo "  □ No sensitive data from testing included in evidence"
echo "  □ OOB evidence: screenshot of collaborator/interactsh callback with data"
echo "  □ Scope confirmed: endpoint is on the in-scope list"
echo "  □ CVSS calculated and attached"
echo "  □ Duplicate check: search disclosed reports for same bug first"
echo "  □ Evidence cleaned: /skill k1nzr3c0n-evidence-hygiene run"
```

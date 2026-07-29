---
name: k1nzr3c0n-report-writing
description: "Bug bounty report writing skill. H1/Bugcrowd/Intigriti templates. CVSS 3.1 and 4.0 quick reference. Title formula. Impact-first structure. Rules: never say 'could potentially', always show business impact, always test in staging first. Covers triage negotiation, report updates."
tags: [report, writing, bug-bounty, h1, bugcrowd, intigriti]
---

# K1NZR3C0N Report Writing

> **Never**: "could potentially allow", "might be possible", "may lead to"
> **Always**: "I confirmed that...", "I demonstrated...", "I observed..."
> **Impact-first**: lead with what an attacker GAINS, not how the bug works.

---

## Phase 0 — Pre-Write Gate

```bash
echo "=== Pre-Write Gate ==="
echo "  □ Vulnerability reproduced ≥3 times"
echo "  □ Passed all 7-Question Gate (/skill k1nzr3c0n-triage)"
echo "  □ Not on never-submit list"
echo "  □ Evidence cleaned (/skill k1nzr3c0n-evidence-hygiene)"
echo "  □ CVSS score calculated"
echo "  □ Business impact articulated in 1 sentence"
echo ""
echo "  Only proceed when ALL boxes checked."
```

## Phase 1 — Title Formula

```bash
echo "=== Title Formula ==="
echo ""
echo "FORMAT: [VulnType] in [Component] allows [Impact]"
echo ""
echo "Examples:"
echo "  Reflected XSS in search parameter allows session hijacking"
echo "  IDOR in /api/v2/user/{id} exposes full PII of any account"
echo "  SSRF via PDF generator reaches AWS metadata service"
echo "  SQL Injection in login endpoint allows authentication bypass"
echo "  JWT algorithm confusion (RS256→HS256) allows forged admin tokens"
echo "  Race condition in coupon redemption allows unlimited discount stacking"
echo ""
echo "Never in title:"
echo "  ✗ 'vulnerability found in' (padding)"
echo "  ✗ 'potential', 'possible', 'could' (uncertainty)"
echo "  ✗ CVSS score (belongs in body)"
echo "  ✗ CVE numbers unless it is literally an unpatched known CVE"
```

## Phase 2 — HackerOne Report Template

```bash
echo "=== HackerOne Report Template ==="
cat << 'TEMPLATE'
## Summary

[1-2 sentences. What it is + impact. Lead with impact.]
I found a reflected XSS vulnerability in the `q` parameter of the search endpoint that allows an attacker to execute arbitrary JavaScript in any authenticated user's browser, enabling session hijacking or credential theft.

## Vulnerability Details

**Type**: [XSS / IDOR / SSRF / SQLi / etc.]
**Severity**: [Critical / High / Medium / Low]
**CVSS v3.1**: [score] — [vector string]
**Endpoint**: `GET/POST https://target.com/path?param=value`
**Authentication required**: [Yes — standard user / No]

## Steps to Reproduce

1. Log in to target.com with any account
2. Navigate to https://target.com/search?q=PAYLOAD
3. Observe [specific behavior — e.g., alert dialog showing document.cookie]

**Payload used**:
```
PAYLOAD_HERE
```

**Marker**: `x9kp3mna` (confirms payload executed, not cached output)

## Impact

[Business impact paragraph. Focus on data access, privilege escalation, financial impact, user safety. Never hedge.]

An unauthenticated attacker can:
- Execute arbitrary JavaScript in any user's browser session
- Steal session cookies and take over any account
- Chain with CSRF to perform privileged actions on behalf of the victim

## Proof of Concept

[Attach screenshot, video, or PoC HTML]

Screenshot: `screenshot-xss-search-param-x9kp3mna.png`
PoC URL: `https://target.com/search?q=<script>alert(document.domain+'%3Bx9kp3mna')</script>`

## Remediation

[1-3 sentences. Concrete fix, not vague.]
Encode all user-supplied input before reflecting it in HTML responses. Use `htmlspecialchars()` (PHP) or equivalent output encoding for the `q` parameter. Implement a strict Content-Security-Policy to block inline script execution as defense-in-depth.
TEMPLATE
```

## Phase 3 — Bugcrowd / Intigriti Variations

```bash
echo "=== Platform Variations ==="
echo ""
echo "Bugcrowd additions:"
echo "  - 'Affected Asset': [URL]"
echo "  - 'Vulnerability Category': select from Bugcrowd taxonomy"
echo "  - 'VRT': XSS > Stored XSS > Stored XSS (Verified)"
echo "  - CWE number: CWE-79 (XSS), CWE-89 (SQLi), CWE-611 (XXE), CWE-918 (SSRF)"
echo ""
echo "Intigriti additions:"
echo "  - 'Affected domain': [specific domain]"
echo "  - 'Severity score': they use their own 1-10 scale"
echo "  - 'Proof': embedded screenshot or video preferred over external links"
echo "  - CVSS 4.0 is accepted (some programs prefer it)"
```

## Phase 4 — CVSS 3.1 Quick Reference

```bash
echo "=== CVSS 3.1 Quick Reference ==="
cat << 'CVSS'
Base Vector: AV/AC/PR/UI/S/C/I/A

Attack Vector (AV):
  N = Network (remotely exploitable)
  A = Adjacent (local network required)
  L = Local (must have local access)
  P = Physical

Attack Complexity (AC):
  L = Low (no special conditions)
  H = High (race condition, special config)

Privileges Required (PR):
  N = None (unauthenticated)
  L = Low (standard user)
  H = High (admin)

User Interaction (UI):
  N = None (no victim action needed)
  R = Required (victim must click/visit)

Scope (S):
  U = Unchanged (impact stays in component)
  C = Changed (impact crosses components — e.g. stored XSS affecting admin)

Confidentiality (C) / Integrity (I) / Availability (A):
  N = None | L = Low | H = High

Common scores:
  Stored XSS (admin panel):    AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N  = 9.0 CRITICAL
  Reflected XSS:               AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N  = 6.1 MEDIUM
  IDOR (sensitive PII read):   AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N  = 6.5 MEDIUM
  SQLi (auth bypass):          AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  = 9.8 CRITICAL
  SSRF (AWS metadata):         AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H  = 9.9 CRITICAL
  Open Redirect (standalone):  AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N  = 4.3 MEDIUM

Calculator: https://www.first.org/cvss/calculator/3.1
CVSS
```

## Phase 5 — Impact Writing Rules

```bash
echo "=== Impact Writing Rules ==="
echo ""
echo "Forbidden phrases (replace immediately if used):"
echo "  ✗ 'could potentially allow'  → 'allows'"
echo "  ✗ 'may be possible'          → 'is possible' OR rewrite to confirmed impact"
echo "  ✗ 'might lead to'            → 'leads to'"
echo "  ✗ 'could be abused'          → 'can be abused'"
echo "  ✗ 'appears to be vulnerable' → 'is vulnerable — confirmed via [evidence]'"
echo "  ✗ 'I think' / 'I believe'    → state fact or don't state it"
echo ""
echo "Impact must answer:"
echo "  1. Who is affected? (all users / admin accounts / unauthenticated users)"
echo "  2. What data/action is exposed? (PII / session tokens / financial data)"
echo "  3. What can the attacker do with it? (account takeover / lateral movement)"
echo "  4. Does it require user interaction? (CVSS UI metric)"
echo ""
echo "Strong impact example:"
echo "  'Any authenticated user can read the full profile (name, email, phone, address)"
echo "   of any other user by replacing the numeric ID in GET /api/user/{id}."
echo "   With 500k registered users, this exposes the entire user database to mass enumeration.'"
```

## Phase 6 — Report Update / Negotiation

```bash
echo "=== Triage Negotiation ==="
echo ""
echo "If severity downgraded — respond with:"
echo "  1. Additional attack scenario demonstrating higher impact"
echo "  2. CVSS vector justification line-by-line"
echo "  3. Chain the bug: 'combined with [other finding], impact escalates to...'"
echo "  4. Reference similar accepted reports on H1 Hacktivity"
echo ""
echo "If marked as 'Informational':"
echo "  1. Provide concrete PoC showing actual impact"
echo "  2. Test against production (not staging) if rules allow"
echo "  3. Chain with another bug to elevate"
echo "  4. If still informational: accept, move on, note for methodology improvement"
echo ""
echo "If duplicate:"
echo "  1. Ask for the original report ID (informational)"
echo "  2. If your finding adds a new attack vector — argue for credit"
echo "  3. If 30+ days old and unpatched — argue for separate report"
echo ""
echo "Retraction template:"
echo "  'After further testing I was unable to reproduce the impact described."
echo "   I am retracting this report. Apologies for the noise.'"
```

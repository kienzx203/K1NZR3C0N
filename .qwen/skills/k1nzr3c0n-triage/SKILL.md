---
name: k1nzr3c0n-triage
description: "7-Question Gate + 4 pre-submission gates for bug bounty quality control. Implements never-submit list (30+ items), marker discipline check, body-diff rule, CVSS 3.1 quick reference. Kill on first NO. Built from Claude-BugHunter methodology."
tags: [bug-bounty, triage, validation, quality-gate]
---

# K1NZR3C0N Triage & Validation Gate

> **ONE NO = KILL. Move on immediately.**
> Time spent on invalid bugs = time not finding real ones.

---

## Gate 0 — 30-Second Reality Check (Run First)

```
Before spending any more time on this finding, answer:

□ Did I reproduce it in a clean browser / fresh curl session?
□ Is the vulnerable asset definitely in scope (check program scope page)?
□ Did I search the program's disclosed reports for the same issue?
□ Is my marker visible in the response (reflected) OR did I get an OOB callback?

If ANY box is unchecked → stop, reproduce, then continue.
```

---

## Gate 1 — 7-Question Triage (Kill on First NO)

```
Q1: Can an attacker exploit this RIGHT NOW with a real HTTP request,
    without special server-side conditions or victim interaction
    beyond normal app usage?
    
    NO → KILL (theoretical/informational)

Q2: Is the impact class on this program's accepted impact list?
    (Check: Does the program accept self-XSS? Clickjacking? Logout CSRF?)
    
    NO → KILL

Q3: Is the root cause in an asset explicitly in scope?
    (CDNs, third-party iframes, subdomains not listed = likely OOS)
    
    NO → KILL

Q4: Does the exploit require privileged access that a real attacker
    cannot realistically obtain?
    (e.g., requires admin session to trigger XSS on admin panel only)
    
    YES → KILL or DOWNGRADE to requires-auth variant

Q5: Is this already known, accepted behavior, or a won't-fix?
    (Check closed/informational reports in program's hacktivity)
    
    YES → KILL

Q6: Can you prove impact BEYOND "technically possible"?
    • XSS: steal cookie/localStorage/auth token — NOT alert(1)
    • SSRF: read internal metadata (169.254.x.x) — NOT just DNS ping
    • SQLi: exfil actual rows — NOT just error message
    • IDOR: access another user's PII — NOT just different ID in URL
    
    NO → DOWNGRADE or KILL

Q7: Is this in the never-submit list below?
    
    YES → KILL
```

---

## Never-Submit List (Instant Kill)

```
STANDALONE (not chainable to High/Critical impact):
  □ Missing security headers (X-Frame-Options, HSTS, etc.) — standalone
  □ GraphQL introspection enabled — no sensitive schema data
  □ Banner / version disclosure — without working exploit for that version
  □ Clickjacking on non-sensitive page (marketing, login without autofill)
  □ Tabnabbing
  □ CSV injection without code execution proof
  □ CORS wildcard — without credential exfiltration PoC
  □ Logout CSRF — session still invalidated server-side
  □ Self-XSS — no escalation path (CSRF chain, login CSRF, etc.)
  □ Open redirect — standalone (no OAuth chain, no phishing + trusted domain)
  □ OAuth client_secret in mobile app — without working token exchange proof
  □ SSRF — DNS callback only (OOB-or-it-didn't-happen)
  □ Host header injection — without password-reset poisoning or cache poisoning
  □ Rate limit missing on non-critical form (search, static content)
  □ Session not invalidated on logout — standalone
  □ Internal IP in error message — standalone
  □ Mixed content warning
  □ Weak SSL ciphers — without downgrade attack PoC
  □ Missing HttpOnly/Secure cookie flag — standalone
  □ Broken external links
  □ Autocomplete on password fields
  □ Pre-account takeover — without matching account already created
  □ Username enumeration via timing — without n≥10 statistical proof
  □ Password policy weakness — no proof of cracking
  □ Subdomain takeover on parking/holding page — check fingerprint first
  □ Email header injection — without proof of delivery
  □ Missing email SPF/DKIM — standalone
  □ Default credentials — on clearly dev/test environment
  □ IDOR on your own data — need cross-account proof (two-account rule)
```

---

## Gate 2 — 2-Minute Impact Validation

```bash
# For each finding, answer these questions in writing:

FINDING="[describe your finding in one sentence]"
IMPACT="[what can an attacker actually do?]"
REPRODUCTION_STEPS="[exact curl or browser steps]"
MARKER="[the 8+ char marker you used, e.g. x9kp3mna]"

# Verify marker discipline
echo "Marker used: $MARKER"
echo "Is it 8+ chars? $([ ${#MARKER} -ge 8 ] && echo YES || echo 'NO - INVALID')"
echo "Contains common words? $(echo $MARKER | grep -iE 'test|marker|evil|payload|attacker|admin' && echo 'YES - INVALID' || echo 'NO - OK')"

# Verify body-diff (not just status code)
BASELINE_LEN=$(curl -sk "https://${TARGET}/vulnerable-endpoint" | wc -c)
PAYLOAD_LEN=$(curl -sk "https://${TARGET}/vulnerable-endpoint?param=${MARKER}" | wc -c)
echo "Baseline response: $BASELINE_LEN bytes"
echo "Payload response : $PAYLOAD_LEN bytes"
[ "$BASELINE_LEN" -ne "$PAYLOAD_LEN" ] && echo "[DIFF] Body changed" || echo "[SAME] No body diff — status change alone is NOT a bypass"
```

## Gate 3 — 5-Minute Dedup Check

```bash
# Search this program's public reports before submitting
PROGRAM="${PROGRAM:-example}"  # Set to program name/handle

echo "Search these resources for duplicates:"
echo "  https://hackerone.com/programs/${PROGRAM}/reports (if H1)"
echo "  https://bugcrowd.com/${PROGRAM}/hall-of-fame (if Bugcrowd)"
echo ""
echo "Search terms to use:"
echo "  '${FINDING_CLASS}'"  # e.g. "IDOR", "XSS", "SSRF"
echo "  '${ENDPOINT}'"       # the specific endpoint
echo ""
echo "If you find a closed/duplicate for same endpoint+class → KILL"
echo "If you find a similar but different variant → document difference clearly"
```

## Gate 4 — 10-Minute Report Quality Check

```bash
# Before submitting, verify:
echo "Pre-submission checklist:"
echo ""
echo "  □ Title follows formula: [VULN CLASS] in [COMPONENT] allows [IMPACT]"
echo "  □ Steps are exact curl commands or numbered browser actions"
echo "  □ Marker used in PoC (not 'test' or 'xss')"
echo "  □ Impact paragraph starts with: 'An unauthenticated/authenticated attacker can...'"
echo "  □ Never use: 'could potentially', 'might be', 'possibly'"
echo "  □ Severity matches CVSS 3.1 (not inflated)"
echo "  □ Evidence: screenshot + request/response (Burp or curl -v output)"
echo "  □ PII in evidence is redacted/blurred"
echo "  □ No internal IPs, hostnames, or engagement details in report"
```

---

## CVSS 3.1 Quick Reference

```
Critical (9.0–10.0): Network, no auth, no interaction, full confidentiality/integrity/availability
  Examples: RCE, SQLi with admin data exfil, auth bypass + data access

High (7.0–8.9): Network, no/low auth, limited interaction OR high impact with some friction
  Examples: IDOR cross-account PII, stored XSS on high-value page, SSRF to metadata

Medium (4.0–6.9): Some user interaction required OR limited impact scope
  Examples: Reflected XSS (user must click), CORS without sensitive data, CSRF on low-value action

Low (0.1–3.9): Significant friction, limited impact
  Examples: Self-XSS with complex chain, clickjacking on low-value action

INFLATION RED FLAGS:
  "Critical" for self-XSS alone → invalid
  "High" for CORS wildcard without exfil PoC → downgrade to Medium/Info
  "High" for open redirect alone → downgrade to Low/Info
```

---

## Report Template

```markdown
## Title
[VULN CLASS] in [component/endpoint] allows [impact statement]

## Severity
[Critical/High/Medium/Low] — CVSS 3.1: [score] ([vector string])

## Summary
An [unauthenticated/authenticated] attacker can [do X] by [method],
resulting in [impact: data exposure/account takeover/etc.].

## Steps to Reproduce
1. Navigate to: `https://TARGET/vulnerable-endpoint`
2. Set parameter `param` to: `[PAYLOAD with marker x9kp3mna]`
3. Observe: [exact behavior — response body, redirect, etc.]

## PoC
```bash
curl -sk 'https://TARGET/endpoint?param=PAYLOAD' \
  -H 'Authorization: Bearer TOKEN'
```

## Impact
An attacker can [specific impact]. This affects [user population].
[For critical: describe worst-case scenario with actual data]

## Evidence
[Attach: screenshot of response + Burp request/response]
```

---

## Retraction Template (if you find your report is invalid post-submission)

```
Subject: Retraction — Report #[ID]

After further analysis, I'm retracting this report.

Reason: [The behavior is intended / duplicate of #ID / impact is not achievable / 
         requires privileges an attacker cannot obtain]

Apologies for the noise.
```

---
name: k1nzr3c0n-cmd-validate
description: "Finding validation command. 4-gate sequential process (Gate 0: 30s reproduction, Gate 1: 2-min body diff, Gate 2: 5-min impact proof, Gate 3: 10-min report-ready). 7-Question Kill Gate. Never-submit list. Conditional chain check. Use before any submission."
tags: [command, validate, triage, gate]
---

# /validate — Finding Validation

> Usage: `/validate` — run this on any potential finding before submitting.

---

## Gate 0 — 30-Second Reproduction

```bash
echo "=== GATE 0: 30-Second Reproduction ==="
echo ""
echo "Can you reproduce this RIGHT NOW in under 30 seconds?"
echo ""
echo "  □ Yes — reproduce 3 times consecutively before continuing"
echo "  □ No / intermittent — KILL: unreliable findings are not submittable"
echo ""
echo "Reproduction check:"
echo "  Run 1: [execute PoC] → [observe result]"
echo "  Run 2: [execute PoC] → [observe result]"
echo "  Run 3: [execute PoC] → [observe result]"
echo ""
echo "3 consecutive reproductions required → continue to Gate 1"
echo "1-2 reproductions → keep trying (environment issue?) or KILL"
```

## Gate 1 — Body Diff (2 Minutes)

```bash
echo "=== GATE 1: Body Diff (2 min) ==="
echo ""
echo "Status code change ALONE is NOT a finding."
echo "Require different response BODY, not just different HTTP status."
echo ""
echo "  □ Baseline: [capture normal response]"
echo "  □ Attack: [capture attack response]"
echo "  □ Diff: what specifically is different in the BODY?"
echo "    - Different data returned (user info, secrets, file contents)"
echo "    - Different function executed (query ran, email sent)"
echo "    - Different error revealing server internals"
echo ""
echo "If only status differs (200 vs 403 with same empty body) → KILL"
echo "If body contains attacker-controlled marker or different data → continue"
```

## Gate 2 — Impact Proof (5 Minutes)

```bash
echo "=== GATE 2: Impact Proof (5 min) ==="
echo ""
echo "Can you prove CONCRETE impact? (not just 'this could be used to')"
echo ""
echo "  RCE: OS command output in response or OOB callback with uid=..."
echo "  SQLi: DB version/data in response or SLEEP(5) confirmed"
echo "  SSRF: HTTP callback with server-side IP / cloud metadata credentials"
echo "  XSS: alert(document.domain) fired on target origin (not just reflected)"
echo "  IDOR: data belonging to account B retrieved from account A"
echo "  Auth bypass: resource accessed that requires auth, WITHOUT auth"
echo "  ATO: another account's session obtained (not just your own)"
echo ""
echo "  □ Impact demonstrated → continue to Gate 3"
echo "  □ Impact theoretical → KILL (program won't pay for 'could be used to')"
```

## Gate 3 — 7-Question Kill Gate (10 Minutes)

```bash
echo "=== GATE 3: 7-Question Kill Gate (10 min) ==="
echo ""
KILL=false
echo "Q1: Is this reachable from the internet?"
echo "    NO → KILL (internal-only ≠ bug bounty finding)"
echo ""
echo "Q2: Is this in scope (domain + vuln type)?"
echo "    NO → KILL (check program rules explicitly)"
echo ""
echo "Q3: Did it reproduce 3+ times consistently?"
echo "    NO → KILL"
echo ""
echo "Q4: Is the root cause server-side?"
echo "    NO → KILL unless it's a client-side bug with clear impact"
echo ""
echo "Q5: Can I show concrete impact (data, session, execution)?"
echo "    NO → KILL"
echo ""
echo "Q6: Is there a real body difference (not just status code change)?"
echo "    NO → KILL"
echo ""
echo "Q7: Would a senior security engineer agree this is a real bug?"
echo "    NO → KILL"
echo ""
echo "ALL 7 YES → proceed to report"
echo "ANY NO → KILL + document + move on"
```

## Never-Submit Standalone List

```bash
echo "=== NEVER Submit These Standalone ==="
cat << 'REJECT'
KILL immediately if the only finding is:
  ✗ Self-XSS (only attacker affects themselves)
  ✗ Logout CSRF (requires auth, low impact)
  ✗ Missing security headers (X-Frame, X-Content-Type)
  ✗ Open redirect (no OAuth/phishing chain)
  ✗ Clickjacking (no sensitive action on page)
  ✗ Username enumeration via timing (<100ms difference)
  ✗ Version disclosure without demonstrated exploitability
  ✗ Missing HSTS on sub-subdomain
  ✗ CORS wildcard without credentialed request working
  ✗ Directory listing on /static/ /assets/ (non-sensitive)
  ✗ SSL/TLS weak cipher without MITM scenario
  ✗ SPF/DMARC on non-login domain
  ✗ Mixed content (HTTP on HTTPS) — informational only
  ✗ DNS-only SSRF (no HTTP data callback)
  ✗ JWT none-algorithm on logout endpoint (no sensitive action)
REJECT
echo ""
echo "If you're looking at one of the above → /hunt for the next target"
```

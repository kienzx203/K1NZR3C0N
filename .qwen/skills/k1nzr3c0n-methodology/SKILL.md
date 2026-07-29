---
name: k1nzr3c0n-methodology
description: "Master methodology skill for structured bug bounty hunting. 5-phase workflow: RECON→MAP→FIND→PROVE→REPORT. 20-minute rotation clock, 45-minute rabbit hole limit, marker discipline, body-diff rule, OOB gate, two-account rule, statistical timing rule. Orchestrates all other hunt skills."
tags: [methodology, workflow, bug-bounty, orchestration]
---

# K1NZR3C0N Methodology — Master Workflow

> **Security constraint**: ONLY recon tools. NO crack/AD/SMB/LDAP tools ever.
> **Clock**: 20 min rotation, 45 min rabbit hole max, then document and move on.

---

## Phase 0 — Session Start

```bash
echo "=== K1NZR3C0N Session Start ==="
TARGET="${TARGET:-}"
if [ -z "$TARGET" ]; then
  echo "[?] Set TARGET: export TARGET=example.com"
  exit 1
fi

SESSION_ID=$(openssl rand -hex 4)
SESSION_DIR="/tmp/k1nzr3c0n_${TARGET//[^a-zA-Z0-9]/_}_${SESSION_ID}"
mkdir -p "$SESSION_DIR"/{findings,evidence,poc,scratch}

echo "[+] Session ID: $SESSION_ID"
echo "[+] Target: $TARGET"
echo "[+] Session dir: $SESSION_DIR"
echo "[+] Start time: $(date)"
echo ""
echo "Run outputs location: /app/runs/${TARGET}/"
echo ""
echo "=== PERMANENT RULES ==="
echo "  1. Marker: 8-char alphanumeric only. Never: test/marker/evil/payload/attacker"
echo "  2. 20-min rotation: if no progress, rotate endpoint/vuln/subdomain"
echo "  3. 45-min limit: hard stop on rabbit holes — document and move on"
echo "  4. Body-diff rule: status code change alone ≠ bypass. Need different body."
echo "  5. OOB gate: blind SSRF/XXE requires HTTP callback with data, not just DNS"
echo "  6. Two-account rule: IDOR always needs 2 accounts proving cross-account access"
echo "  7. Statistical timing: n≥10 trials, mean ≥2σ above control"

MARKER=$(openssl rand -hex 4)
echo ""
echo "[+] Session marker: $MARKER"
export SESSION_MARKER="$MARKER"
```

## Phase 1 — RECON

```bash
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PHASE 1: RECON                                       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Skill: /skill k1nzr3c0n-recon"
echo ""
echo "Outputs:"
echo "  - Subdomain list  → /tmp/recon_*/subs/all_subs.txt"
echo "  - Alive hosts     → /tmp/recon_*/alive/alive_urls.txt"
echo "  - URL corpus      → /tmp/recon_*/endpoints/all_urls.txt"
echo "  - GF classified   → /tmp/recon_*/endpoints/gf_*.txt"
echo "  - Nuclei hits     → /tmp/recon_*/reports/nuclei_findings.txt"
echo ""
echo "Also run: /skill k1nzr3c0n-js-analyst"
echo "Also run: /skill k1nzr3c0n-osint"
echo ""
echo "[Timer] Set 20-min timer for recon phase"
```

## Phase 2 — MAP (Crown Jewel Identification)

```bash
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PHASE 2: MAP — Crown Jewel Identification            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Review k1nzr3c0n run outputs:"
ls /app/runs/ 2>/dev/null | head -20 | sed 's/^/  /'

echo ""
echo "Crown Jewel Priority (highest to lowest):"
echo "  P1: Admin panels, payment endpoints, auth endpoints"
echo "  P2: User data APIs, file upload, document generation"
echo "  P3: Search/filter params, export functions, webhooks"
echo "  P4: Static analysis, JS bundles, sourcemaps"
echo ""
echo "Technology fingerprint from recon:"
echo "  httpx tech-detect output:"
cat /tmp/recon_*/alive/httpx_results.txt 2>/dev/null | grep -oP '\[.*?\]' | sort | uniq -c | sort -rn | head -15
echo ""
echo "Map tech to attack class:"
echo "  PHP       → LFI, SQLi, deserialization, SSTI (Twig/Smarty)"
echo "  Node.js   → Prototype pollution, SSTI (Pug/Handlebars), mass assignment"
echo "  Java      → XXE, SSRF, deserialization (ysoserial), SSTI (Freemarker/Velocity)"
echo "  Python    → SSTI (Jinja2), pickle deserialization"
echo "  Ruby      → SSTI (ERB), Marshal.load deserialization"
echo "  React/Vue → DOM XSS via dangerouslySetInnerHTML, postMessage"
echo "  GraphQL   → IDOR via node(), introspection, alias batching"
```

## Phase 3 — FIND (Attack Dispatch)

```bash
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PHASE 3: FIND — Attack Class Dispatch                ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "Based on GF output and tech fingerprint, dispatch to:"
echo ""

RECON_DIR="/tmp/recon_${TARGET//[^a-zA-Z0-9]/_}_*"
GF_DIR=$(ls -d $RECON_DIR/endpoints 2>/dev/null | tail -1)

# Check GF results and suggest skills
if [ -d "$GF_DIR" ]; then
  for VULN in xss sqli ssrf redirect lfi rce ssti; do
    COUNT=$(wc -l < "$GF_DIR/gf_${VULN}.txt" 2>/dev/null || echo 0)
    [ "$COUNT" -gt 0 ] && echo "  → $COUNT URLs for $VULN → /skill k1nzr3c0n-hunt-${VULN}"
  done
fi

echo ""
echo "Always hunt (regardless of GF):"
echo "  /skill k1nzr3c0n-hunt-idor          (test all object ID parameters)"
echo "  /skill k1nzr3c0n-hunt-auth-bypass   (test all auth-guarded pages directly)"
echo "  /skill k1nzr3c0n-hunt-cors          (test all cross-origin headers)"
echo "  /skill k1nzr3c0n-hunt-source-leak   (TruffleHog + exposed files)"
echo ""
echo "By technology:"
echo "  GraphQL present → /skill k1nzr3c0n-hunt-graphql"
echo "  WebSocket present → /skill k1nzr3c0n-hunt-websocket"
echo "  File upload present → /skill k1nzr3c0n-hunt-file-upload"
echo "  JWT in cookies/headers → /skill k1nzr3c0n-hunt-jwt"
echo "  OAuth/SSO → /skill k1nzr3c0n-hunt-oauth"
```

## Phase 4 — PROVE (Evidence Collection)

```bash
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PHASE 4: PROVE — Confirm & Document                  ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "=== 7-Question Gate (must pass ALL before claiming finding) ==="
echo "  Q1: Is the vulnerability directly reachable from the internet?"
echo "      NO → kill (internal only)"
echo "  Q2: Is the target in scope (domain + vulnerability type)?"
echo "      NO → kill"
echo "  Q3: Did the vulnerability reproduce 3+ times?"
echo "      NO → kill (intermittent = unreliable)"
echo "  Q4: Is the root cause server-side (not just client-side validation)?"
echo "      NO → kill unless XSS/client-side vuln with server impact"
echo "  Q5: Can I show concrete impact (data access, action, account)?  "
echo "      NO → kill"
echo "  Q6: Is there a different body in the vulnerability response vs baseline?"
echo "      NO (for bypasses) → kill (body-diff rule)"
echo "  Q7: Would a reasonable security engineer agree this is a real bug?"
echo "      NO → kill"
echo ""
echo "=== OOB Gate ==="
echo "  Blind SSRF/XXE: MUST have HTTP callback proving data access"
echo "  DNS-only callback: informational, not submittable"
echo ""
echo "=== Evidence capture ==="
echo "  Screenshot: $SESSION_DIR/evidence/"
echo "  PoC: $SESSION_DIR/poc/"
echo "  Run: /skill k1nzr3c0n-evidence-hygiene before packaging"
```

## Phase 5 — REPORT

```bash
echo "╔══════════════════════════════════════════════════════╗"
echo "║  PHASE 5: REPORT                                      ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  1. Triage: /skill k1nzr3c0n-triage"
echo "  2. Hygiene: /skill k1nzr3c0n-evidence-hygiene"
echo "  3. Write: /skill k1nzr3c0n-report-writing"
echo ""
echo "  Session findings so far:"
ls "$SESSION_DIR/findings/" 2>/dev/null | head -10 | sed 's/^/    /'
```

## Phase 6 — Clock Management

```bash
echo "=== 20-Minute Rotation Clock ==="
echo ""
echo "If no meaningful progress in current vector after 20 min:"
echo "  1. Note current endpoint in scratch"
echo "  2. Rotate to next option:"
echo "     a. Different endpoint (try next from GF list)"
echo "     b. Different subdomain (pick from alive hosts)"
echo "     c. Different vulnerability class"
echo "     d. Different target entirely"
echo ""
echo "=== 45-Minute Rabbit Hole Limit ==="
echo ""
echo "If spending >45 min on one specific chain/technique:"
echo "  1. Hard stop"
echo "  2. Document what was tried and what blocked"
echo "  3. Save to: $SESSION_DIR/scratch/rabbit_hole_$(date +%H%M).txt"
echo "  4. Return only if: new information surfaces or different approach available"
echo ""
echo "=== Session Wrap ==="
echo ""
echo "At end of session:"
echo "  - List all tested endpoints"
echo "  - List all findings (confirmed / unconfirmed)"
echo "  - Note rotation points (what stopped progress)"
echo "  - Mark submitted reports"
echo ""
echo "  Session dir: $SESSION_DIR"
echo "  K1NZR3C0N runs: /app/runs/${TARGET}/"
```

## Skill Map Reference

```bash
echo "=== Complete Skill Map ==="
cat << 'SKILLS'
RECON LAYER:
  /skill k1nzr3c0n-recon           Full pipeline (subfinder→httpx→katana→nuclei)
  /skill k1nzr3c0n-js-analyst      JS bundle analysis (secrets + endpoints + DOM XSS)
  /skill k1nzr3c0n-osint           OSINT (dorks + 48 secret patterns)

ORCHESTRATION:
  /skill k1nzr3c0n-bug-hunter      Master dispatch (reads k1nzr3c0n run outputs)
  /skill k1nzr3c0n-methodology     THIS SKILL — master workflow

HUNT SKILLS (by attack class):
  /skill k1nzr3c0n-hunt-xss              XSS (reflected/stored/DOM/CSP)
  /skill k1nzr3c0n-hunt-idor             IDOR + two-account rule
  /skill k1nzr3c0n-hunt-ssrf             SSRF + metadata chains
  /skill k1nzr3c0n-hunt-sqli             SQL injection
  /skill k1nzr3c0n-hunt-nosqli           NoSQL injection (MongoDB/Redis/ES)
  /skill k1nzr3c0n-hunt-lfi              LFI + PHP filter chain RCE
  /skill k1nzr3c0n-hunt-ssti             SSTI polyglot + engine-specific RCE
  /skill k1nzr3c0n-hunt-xxe              XXE (classic/blind/SAML/SVG)
  /skill k1nzr3c0n-hunt-rce              RCE (command injection + CVEs)
  /skill k1nzr3c0n-hunt-cors             CORS misconfiguration
  /skill k1nzr3c0n-hunt-csrf             CSRF (token + SameSite + JSON)
  /skill k1nzr3c0n-hunt-oauth            OAuth (redirect_uri + state + PKCE)
  /skill k1nzr3c0n-hunt-ato              ATO (password reset + JWT + social)
  /skill k1nzr3c0n-hunt-file-upload      File upload bypass
  /skill k1nzr3c0n-hunt-business-logic   Business logic + price manipulation
  /skill k1nzr3c0n-hunt-race-condition   Race conditions (HTTP/2 single-packet)
  /skill k1nzr3c0n-hunt-graphql          GraphQL (introspection + IDOR + alias)
  /skill k1nzr3c0n-hunt-open-redirect    Open redirect + chains
  /skill k1nzr3c0n-hunt-source-leak      Secret/source exposure (TruffleHog)
  /skill k1nzr3c0n-hunt-subdomain        Subdomain takeover (27+ providers)
  /skill k1nzr3c0n-hunt-host-header      Host header injection (poison/SSRF)
  /skill k1nzr3c0n-hunt-cache-poison     Cache poisoning + web cache deception
  /skill k1nzr3c0n-hunt-auth-bypass      Auth bypass (JWT alg:none/MFA/SAML)
  /skill k1nzr3c0n-hunt-session          Session management
  /skill k1nzr3c0n-hunt-jwt              JWT (none/RS256→HS256/jku/kid)
  /skill k1nzr3c0n-hunt-api-misconfig    API misconfig (mass assign/verb tamper)
  /skill k1nzr3c0n-hunt-dom              DOM XSS + postMessage
  /skill k1nzr3c0n-hunt-websocket        WebSocket (CSWSH + socket.io)
  /skill k1nzr3c0n-hunt-deserialization  Deserialization (Java/PHP/Python/.NET)
  /skill k1nzr3c0n-hunt-http-smuggling   HTTP smuggling (CL.TE/TE.CL/H2.TE)

SUPPORT SKILLS:
  /skill k1nzr3c0n-triage             7-Question Gate + never-submit list
  /skill k1nzr3c0n-evidence-hygiene   Clean evidence before submission
  /skill k1nzr3c0n-report-writing     H1/Bugcrowd/Intigriti templates + CVSS
  /skill k1nzr3c0n-security-arsenal   Payload library + WAF bypass + gf patterns
SKILLS
```

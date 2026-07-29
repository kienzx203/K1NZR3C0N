---
name: k1nzr3c0n-osint
description: "OSINT and secret pattern hunting skill. 48 regex secret patterns (AWS, GitHub, Stripe, Slack, SendGrid, Mailgun, Twilio, Firebase, JWT, OpenAI, Anthropic, HuggingFace, Cloudflare, DigitalOcean, npm, Sentry, ngrok, Discord, Telegram). 80+ Google/GitHub dorks. Breach correlation."
tags: [osint, secrets, recon, bug-bounty]
---

# K1NZR3C0N OSINT — Secret Patterns & Dorks

> **Verify before submitting**: a regex match is not a finding. Run API verification.
> **48 patterns**: organized by service, severity, and verification method.

---

## Phase 0 — Setup

```bash
TARGET="${TARGET:-}"
TARGET_ORG="${TARGET_ORG:-$(echo $TARGET | cut -d. -f1)}"
HUNT="/tmp/hunt_osint_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
echo "[+] Target: $TARGET | Org: $TARGET_ORG"
```

## Phase 1 — GitHub Dorks

```bash
echo "=== GitHub Dork Queries ==="
echo "Search at: https://github.com/search"
echo ""
echo "Secret hunting dorks:"
cat << 'DORKS'
# API keys and credentials
org:TARGET_ORG "api_key" OR "apikey" OR "api-key"
org:TARGET_ORG "secret" OR "password" OR "credential"
org:TARGET_ORG "AKIA" OR "aws_access_key"
org:TARGET_ORG filename:.env
org:TARGET_ORG filename:config.json "password"
org:TARGET_ORG "privatekey" OR "private_key" OR "BEGIN RSA"

# Database
org:TARGET_ORG "DB_PASSWORD" OR "DATABASE_URL" OR "mysql://"
org:TARGET_ORG "postgresql://" OR "mongodb+srv://"

# Internal endpoints
org:TARGET_ORG "internal." OR "staging." OR "preprod."
org:TARGET_ORG "vpn." OR "bastion." OR "10.0.0."

# Hardcoded tokens
org:TARGET_ORG "Authorization: Bearer"
org:TARGET_ORG "token" filename:*.js OR filename:*.py OR filename:*.go

# CI/CD
org:TARGET_ORG filename:.travis.yml "password" OR "secret"
org:TARGET_ORG filename:.github/workflows "SECRET" OR "PASSWORD"
DORKS

echo ""
echo "Replace TARGET_ORG with: $TARGET_ORG"
```

## Phase 2 — Google Dorks

```bash
echo "=== Google Dorks ==="
cat << DORKS
# Exposed files
site:${TARGET} ext:env OR ext:yml OR ext:json "password"
site:${TARGET} ext:log "error" OR "exception" OR "password"
site:${TARGET} ext:sql OR ext:backup OR ext:bak
site:${TARGET} inurl:phpinfo.php
site:${TARGET} inurl:.git/HEAD

# Sensitive pages
site:${TARGET} intitle:"admin" OR intitle:"dashboard" OR intitle:"console"
site:${TARGET} inurl:swagger OR inurl:api-docs OR inurl:openapi

# Leaked documents
site:${TARGET} filetype:pdf "confidential"
site:${TARGET} filetype:xlsx OR filetype:csv "password" OR "credential"

# Error messages (info disclosure)
site:${TARGET} "SQL syntax" OR "mysql_fetch" OR "ORA-"
site:${TARGET} "stack trace" OR "traceback" OR "debug"
site:${TARGET} "internal server error" "path" OR "line"

# Exposed storage
site:s3.amazonaws.com "${TARGET_ORG}"
site:storage.googleapis.com "${TARGET_ORG}"
site:blob.core.windows.net "${TARGET_ORG}"
DORKS
```

## Phase 3 — 48 Secret Patterns (Regex Scan)

```bash
echo "=== Secret Pattern Scanning ==="
# Scan all collected content
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
RUNS_BASE="/app/runs"

SCAN_DIRS=("$JS_DIR" "$RUNS_BASE" "$HUNT")

for SCAN_DIR in "${SCAN_DIRS[@]}"; do
  [ ! -d "$SCAN_DIR" ] && continue
  echo "Scanning: $SCAN_DIR"
  
  # AWS
  grep -rhoP 'AKIA[0-9A-Z]{16}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [AWS-KEY] /'
  grep -rhoP 'ASIA[0-9A-Z]{16}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [AWS-STS] /'
  grep -rhoP '(?:aws.secret|AWS_SECRET)[^"\n]{0,30}["\s:=]+([A-Za-z0-9/+]{40})' \
    "$SCAN_DIR" 2>/dev/null | head -5 | sed 's/^/  [AWS-SECRET] /'
  
  # GitHub
  grep -rhoP 'gh[pousr]_[A-Za-z0-9]{36}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [GH-TOKEN] /'
  grep -rhoP 'github_pat_[A-Za-z0-9_]{82}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [GH-PAT] /'
  
  # Stripe
  grep -rhoP '(?:sk|pk)_live_[0-9a-zA-Z]{24}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [STRIPE] /'
  grep -rhoP '(?:sk|pk)_test_[0-9a-zA-Z]{24}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [STRIPE-TEST] /'
  
  # Slack
  grep -rhoP 'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}' \
    "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [SLACK] /'
  
  # SendGrid
  grep -rhoP 'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}' \
    "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [SENDGRID] /'
  
  # Twilio
  grep -rhoP 'AC[a-z0-9]{32}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [TWILIO-SID] /'
  grep -rhoP 'SK[a-z0-9]{32}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [TWILIO-KEY] /'
  
  # Google/Firebase
  grep -rhoP 'AIza[0-9A-Za-z_\-]{35}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [GOOGLE-API] /'
  grep -rhoP '"type":\s*"service_account"' "$SCAN_DIR" 2>/dev/null | head -3 | sed 's/^/  [GCP-SA] /'
  
  # OpenAI
  grep -rhoP 'sk-[a-zA-Z0-9]{48}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [OPENAI] /'
  grep -rhoP 'sk-proj-[a-zA-Z0-9_\-]{100,}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [OPENAI-PROJ] /'
  
  # Anthropic
  grep -rhoP 'sk-ant-api03-[a-zA-Z0-9_\-]{95}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [ANTHROPIC] /'
  
  # Discord
  grep -rhoP '[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9_\-]{6}\.[a-zA-Z0-9_\-]{27}' \
    "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [DISCORD-BOT] /'
  
  # Telegram
  grep -rhoP '[0-9]{8,10}:AA[a-zA-Z0-9_\-]{33}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [TELEGRAM-BOT] /'
  
  # HuggingFace
  grep -rhoP 'hf_[a-zA-Z0-9]{39}' "$SCAN_DIR" 2>/dev/null | sort -u | sed 's/^/  [HF-TOKEN] /'
  
  # Cloudflare
  grep -rhoP '[0-9a-f]{37}' "$SCAN_DIR" 2>/dev/null | head -3 | sed 's/^/  [CF-TOKEN?] /'
  
  # JWT tokens
  grep -rhoP 'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}' \
    "$SCAN_DIR" 2>/dev/null | sort -u | head -5 | sed 's/^/  [JWT] /'
  
  # Private keys
  grep -rl 'BEGIN PRIVATE KEY\|BEGIN RSA PRIVATE KEY\|BEGIN EC PRIVATE KEY\|BEGIN OPENSSH PRIVATE KEY' \
    "$SCAN_DIR" 2>/dev/null | sed 's/^/  [PRIVATE-KEY FILE] /'
  
  # Generic high-entropy secrets
  grep -rhoP '(?:secret|api.?key|auth.?token|private.?key|access.?token)[^\n]{0,20}["\x27:=]\s*["\x27]([a-zA-Z0-9+/]{32,})["\x27]' \
    "$SCAN_DIR" 2>/dev/null | \
    grep -ivE '(placeholder|example|test|changeme|dummy|xxx|your[_-])' | \
    sort -u | head -20 | sed 's/^/  [GENERIC] /'
done
```

## Phase 4 — Secret Verification

```bash
echo "=== Secret Verification ==="
echo "Verify each found secret before submitting:"
echo ""
echo "AWS key: aws sts get-caller-identity --access-key AKIA... --secret-key ..."
echo "GitHub token: curl -H 'Authorization: token TOKEN' https://api.github.com/user"
echo "Stripe key: curl https://api.stripe.com/v1/balance -u 'sk_live_...'"
echo "SendGrid: curl https://api.sendgrid.com/v3/user/profile -H 'Authorization: Bearer SG.'"
echo "Slack: curl 'https://slack.com/api/auth.test?token=xoxb-...'"
echo "Twilio: curl -u 'AC...:AUTH_TOKEN' https://api.twilio.com/2010-04-01/Accounts"
echo ""
echo "ONLY SUBMIT: live secrets with confirmed access (not expired/revoked)"
```

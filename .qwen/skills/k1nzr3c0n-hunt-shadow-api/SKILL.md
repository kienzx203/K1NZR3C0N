---
name: k1nzr3c0n-hunt-shadow-api
description: "Hunt shadow/zombie/undocumented API surface (OWASP API9). Enumerate full API version history (v1/v2/beta/legacy paths, header/subdomain versioning), pull all Swagger/OpenAPI specs including Wayback Machine versions, behavioral diff old vs current for auth/rate-limit/validation regressions. Distinct from hunt-api-misconfig (exploitation) — this skill owns the version-inventory and behavioral-diff workflow."
tags: [shadow-api, api9, owasp, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Shadow/Zombie API (OWASP API9)

> **The bug**: old API versions stay reachable without the security fixes added to the current one.
> **The finding**: behavioral regression between versions — not just different response shape.

---

## Phase 0 — When to Use

```bash
echo "=== Use this skill when ==="
echo "  ✓ Versioned paths visible: /v1/, /v2/, /api/2023-01-01/"
echo "  ✓ Accept or X-API-Version header in use"
echo "  ✓ Changelog mentions deprecated/removed endpoints"
echo "  ✓ Mobile app with hardcoded backend endpoints (often older version)"
echo "  ✓ Multiple Swagger/OpenAPI specs discoverable"
echo ""
echo "  ✗ Single-version API with no history → use hunt-api-misconfig directly"
```

## Phase 1 — Enumerate Version Surface

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_shadow_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== API Version Enumeration ==="

# Path-based versioning
for V in v1 v2 v3 v4 beta alpha internal legacy old 2022-01-01 2023-01-01 2024-01-01 2025-01-01; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}/api/${V}/")
  echo "  /api/$V/ → $CODE"
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "    [LIVE] /api/$V/" >> "$HUNT/live_versions.txt"
done

# Header-based versioning
curl -sk -H "X-API-Version: 1" "https://${TARGET}/api/users" -w " → %{http_code}\n" -o /dev/null | sed 's/^/  Header X-API-Version:1 /'
curl -sk -H "Accept: application/vnd.company.v1+json" "https://${TARGET}/api/users" -w " → %{http_code}\n" -o /dev/null

# Subdomain-based versioning
for SUB in api api-v1 api-v2 apiv1 apiv2 legacy-api old-api internal-api staging-api dev-api; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${SUB}.${TARGET}/")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [$CODE] https://${SUB}.${TARGET}/"
done

echo ""
echo "Live versions: $(wc -l < $HUNT/live_versions.txt 2>/dev/null || echo 0)"
```

## Phase 2 — Pull All OpenAPI/Swagger Specs

```bash
echo "=== Spec Discovery ==="
SPEC_PATHS=(
  "openapi.json" "swagger.json" "v1/swagger.json" "v2/swagger.json"
  "v3/api-docs" "api-docs.json" "swagger/v1/swagger.json"
  ".well-known/openapi.json" "api/openapi.json" "api/swagger.json"
  "swagger-ui.html" "swagger-ui/" "api/docs" "redoc"
)

for SPEC in "${SPEC_PATHS[@]}"; do
  CODE=$(curl -sk -o "$HUNT/spec_${SPEC//\//_}" -w "%{http_code}" "https://${TARGET}/${SPEC}")
  [ "$CODE" = "200" ] && echo "  [FOUND] /${SPEC}" && \
    python3 -c "import json,sys; d=json.load(open('$HUNT/spec_${SPEC//\//_}')); \
      [print('  Path:',p) for p in list(d.get('paths',{}).keys())[:10]]" 2>/dev/null
done

# Wayback Machine — old specs often cached after removal from live site
echo ""
echo "=== Wayback Machine Spec Hunt ==="
curl -s "http://web.archive.org/cdx/search/cdx?url=${TARGET}/*swagger*&output=json&collapse=urlkey" 2>/dev/null | \
  python3 -c "import json,sys; [print('  WB:', r[2]) for r in json.load(sys.stdin)[1:6] if r]" 2>/dev/null
curl -s "http://web.archive.org/cdx/search/cdx?url=${TARGET}/*openapi*&output=json&collapse=urlkey" 2>/dev/null | \
  python3 -c "import json,sys; [print('  WB:', r[2]) for r in json.load(sys.stdin)[1:6] if r]" 2>/dev/null
```

## Phase 3 — Diff Spec Versions

```bash
echo "=== Spec Diff (v1 vs v2) ==="
echo "If multiple specs found, diff the endpoint inventories:"
echo ""
echo "  python3 -c \"import json; paths=json.load(open('spec_v1.json')).get('paths',{}); print(chr(10).join(sorted(paths.keys())))\" > /tmp/v1_paths.txt"
echo "  python3 -c \"import json; paths=json.load(open('spec_v2.json')).get('paths',{}); print(chr(10).join(sorted(paths.keys())))\" > /tmp/v2_paths.txt"
echo "  comm -23 /tmp/v1_paths.txt /tmp/v2_paths.txt  # in v1 only — candidates for 'still live but forgotten'"
echo ""
echo "For every path in diff: confirm still reachable on v1 base URL"
echo "  A route documented only in old spec that returns non-404 = zombie endpoint"
```

## Phase 4 — Behavioral Diff (Security Regression)

```bash
echo "=== Behavioral Diff (the real finding) ==="
echo ""
echo "For each operation in BOTH versions, compare security-relevant behavior:"
echo ""
echo "1. Auth strength (does old version accept expired/missing token?):"
EXPIRED_TOKEN="${EXPIRED_TOKEN:-expired.token.here}"
for VER in v1 v2; do
  RESP=$(curl -sk -H "Authorization: Bearer ${EXPIRED_TOKEN}" "https://${TARGET}/api/${VER}/users/me" -w "\n%{http_code}")
  echo "  /api/$VER/users/me with expired token: $(echo $RESP | tail -1)"
done

echo ""
echo "2. Rate limiting (does old version lack 429?):"
for VER in v1 v2; do
  echo -n "  $VER — burst test: "
  for i in $(seq 1 20); do
    curl -sk -o /dev/null -w "%{http_code} " "https://${TARGET}/api/${VER}/search?q=test"
  done | grep -c "429" | xargs echo "x 429s in 20 requests"
done

echo ""
echo "3. Input validation (does old version accept injection payloads?):"
for VER in v1 v2; do
  RESP=$(curl -sk -X POST "https://${TARGET}/api/${VER}/users" \
    -H "Content-Type: application/json" \
    -d '{"name":"test'"'"' OR 1=1--"}' -w "\n%{http_code}")
  echo "  $VER SQLi probe: $(echo $RESP | tail -1)"
done

echo ""
echo "4. Field exposure (does old version return fields new one redacted?):"
echo "  Diff response body structure between versions"
```

## Phase 5 — Internal/Debug Routes

```bash
echo "=== Internal Routes Never Referenced by Current UI ==="

# From JS bundles
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
[ -d "$JS_DIR" ] && grep -rhoP '"/[^"]{0,60}(internal|admin|debug|_internal|test|staging)[^"]{0,60}"' \
  "$JS_DIR" 2>/dev/null | sort -u | head -20 | sed 's/^/  [JS-ROUTE] /'

# robots.txt / sitemap
curl -s "https://${TARGET}/robots.txt" | grep -i 'disallow\|api\|internal' | sed 's/^/  [ROBOTS] /'
curl -s "https://${TARGET}/sitemap.xml" | grep -oP '(?<=<loc>)[^<]+' | \
  grep -iE 'api|internal|admin|debug' | sed 's/^/  [SITEMAP] /'
```

## Gate 0

```bash
echo "=== Shadow API Gate 0 ==="
echo "  □ Old version still reachable (not just 404)"
echo "  □ Security behavioral difference confirmed (auth/rate-limit/validation)"
echo "  □ Not just different response shape — actual security regression"
echo "  □ Old version is NOT an alias/proxy to current implementation"
echo ""
echo "  NOT a finding: just different response structure (Informational)"
echo "  FINDING: auth that got weaker going backward in version history"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Zombie API: /api/v1/users/{id} (deprecated) still reachable — missing authentication check present in /api/v2/: unauthenticated request returns 200 + full user PII vs 401 on v2
Shadow API: /api/beta/export endpoint documented in archived Wayback swagger.json (2023-03-12) still live — no rate limiting, no auth required; exports full user database
```

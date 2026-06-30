#!/usr/bin/env bash
# One-command local FAPI conformance run INSIDE the sandbox.
# The devcontainer has no Docker daemon, so the suite runs on the in-sandbox
# k3s cluster (k3s pulls the prebuilt images from the registry — no build).
#
#   bash deploy/conformance/run-local.sh
#
# Prereq: `bash scripts/dev-cluster.sh up` (k3s running) and the AS deployed
# (helm install ...). STATUS: scaffold — AS endpoints land in P1; green in P3.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"

command -v kubectl >/dev/null || { echo "kubectl not found (run inside the devcontainer)"; exit 1; }

echo "[conformance] deploying suite to k3s (prebuilt images, no build)..."
kubectl apply -f "$HERE/k8s/suite.yaml"
kubectl -n conformance rollout status deploy/httpd --timeout=180s
kubectl -n conformance rollout status deploy/server --timeout=180s

echo "[conformance] port-forwarding suite (https://localhost:8443)..."
kubectl -n conformance port-forward svc/httpd 8443:8443 >/tmp/cf-pf.log 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do curl -ksf https://localhost:8443/ >/dev/null && break; sleep 1; done

# AS issuer reachable inside the cluster as the helm service; for the suite use
# the in-cluster URL or a port-forwarded one. Defaults to the local AS.
export ISSUER="${ISSUER:-http://localhost:3000}"
export SUITE_URL="${SUITE_URL:-https://localhost:8443}"
bash "$HERE/run-conformance.sh"

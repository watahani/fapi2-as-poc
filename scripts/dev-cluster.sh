#!/usr/bin/env bash
# Manage the in-sandbox k3s cluster (single binary, embedded containerd — NOT
# docker-in-docker). Runs entirely inside the Claude Code devcontainer.
#
# Usage:
#   scripts/dev-cluster.sh up        # start k3s + write kubeconfig
#   scripts/dev-cluster.sh down      # stop k3s
#   scripts/dev-cluster.sh status    # cluster info
#   scripts/dev-cluster.sh import IMAGE:TAG   # load a local image into k3s
set -euo pipefail

KUBECONFIG_DST="${KUBECONFIG:-$HOME/.kube/config}"
K3S_LOG=/tmp/k3s.log
CMD="${1:-up}"

up() {
  if pgrep -x k3s >/dev/null 2>&1; then
    echo "k3s already running"; return 0
  fi
  echo "starting k3s server (traefik/metrics-server disabled)..."
  sudo k3s server \
    --disable traefik \
    --disable metrics-server \
    --write-kubeconfig-mode 600 \
    >"$K3S_LOG" 2>&1 &
  echo "waiting for kubeconfig..."
  for _ in $(seq 1 60); do
    [ -f /etc/rancher/k3s/k3s.yaml ] && break
    sleep 2
  done
  mkdir -p "$(dirname "$KUBECONFIG_DST")"
  sudo cat /etc/rancher/k3s/k3s.yaml > "$KUBECONFIG_DST"
  chmod 600 "$KUBECONFIG_DST"
  echo "waiting for node Ready..."
  kubectl wait --for=condition=Ready node --all --timeout=120s
  kubectl get nodes
}

down() {
  echo "stopping k3s..."
  sudo pkill -x k3s || true
  sudo k3s-killall.sh 2>/dev/null || true
}

status() {
  kubectl cluster-info
  kubectl get pods -A
}

import() {
  local image="${2:?usage: dev-cluster.sh import IMAGE:TAG}"
  echo "importing $image into k3s containerd..."
  nerdctl save "$image" | sudo k3s ctr images import -
}

case "$CMD" in
  up) up ;;
  down) down ;;
  status) status ;;
  import) import "$@" ;;
  *) echo "unknown command: $CMD" >&2; exit 1 ;;
esac

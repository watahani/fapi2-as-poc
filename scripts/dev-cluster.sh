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
  # cgroup v2 nesting must be set up (as root) right before k3s starts, or runc
  # cannot create pod-sandbox cgroups. Idempotent; no-op if already delegated.
  if [ -x /usr/local/bin/k3s-cgroup-init.sh ]; then
    echo "setting up cgroup v2 nesting..."
    sudo /usr/local/bin/k3s-cgroup-init.sh || echo "warn: cgroup-init reported an issue" >&2
  fi
  echo "starting k3s server (traefik/metrics-server disabled)..."
  # Two sandbox-specific workarounds are required or the node never registers:
  #  1) --snapshotter fuse-overlayfs: the kernel rejects overlayfs-on-overlayfs
  #     here ("failed to mount overlay: invalid argument"); fuse-overlayfs is
  #     installed in the image and works.
  #  2) --kubelet-arg cgroups-per-qos=false + enforce-node-allocatable=: cgroup
  #     v2 is in "domain" mode without delegation, so the kubelet cannot create
  #     /sys/fs/cgroup/kubepods ("cannot enter cgroupv2 ... invalid state").
  #     Disabling per-QoS cgroup management sidesteps it (fine for a dev cluster).
  # NOTE: run this via a DETACHED background task; a foreground shell that
  # backgrounds k3s has its process group reaped on return, killing k3s.
  sudo k3s server \
    --disable traefik \
    --disable metrics-server \
    --snapshotter fuse-overlayfs \
    --kubelet-arg=cgroups-per-qos=false \
    --kubelet-arg=enforce-node-allocatable= \
    --write-kubeconfig-mode 600 \
    >"$K3S_LOG" 2>&1 &
  echo "waiting for kubeconfig..."
  for _ in $(seq 1 60); do
    [ -f /etc/rancher/k3s/k3s.yaml ] && break
    sleep 2
  done
  mkdir -p "$(dirname "$KUBECONFIG_DST")"
  # `sudo cat` is not permitted (sudo is NOPASSWD only for k3s/nerdctl/ctr), so
  # extract the kubeconfig via the k3s binary itself.
  sudo k3s kubectl config view --raw > "$KUBECONFIG_DST"
  chmod 600 "$KUBECONFIG_DST"
  # Wait for the node object to exist first (kubectl wait errors on an empty
  # set), then for it to become Ready.
  echo "waiting for node to register..."
  for _ in $(seq 1 60); do
    [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break
    sleep 2
  done
  echo "waiting for node Ready..."
  kubectl wait --for=condition=Ready node --all --timeout=120s
  kubectl get nodes
}

down() {
  # NOTE: sudo here is NOPASSWD only for k3s/nerdctl/ctr/init-firewall, so
  # `pkill`/`k3s-killall.sh` need a password and will no-op non-interactively.
  # If k3s is wedged and cannot be signalled, rebuild the container to reset it.
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

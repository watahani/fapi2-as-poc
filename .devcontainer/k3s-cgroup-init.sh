#!/usr/bin/env bash
# cgroup v2 nesting init — REQUIRED before k3s/kubelet+runc can create pod
# sandboxes in this container.
#
# Symptom without this:
#   runc create failed: unable to apply cgroup configuration: cannot enter
#   cgroupv2 "/sys/fs/cgroup/k8s.io" with domain controllers -- invalid state
#
# Cause: this container has a PRIVATE cgroup namespace, so /sys/fs/cgroup is a
# delegated subtree (NOT the real root) and is bound by cgroup v2's "no internal
# processes" rule — you cannot enable domain controllers (memory/io/…) in its
# subtree_control while any process sits directly in it. k3s then can't create
# k8s.io/kubepods as controller-bearing cgroups. Fix (same trick kind/k3d use):
# move every process into an "init" leaf so the cgroupns root is empty, then
# delegate all controllers to children.
#
# MUST run as root (moving root-owned PIDs needs privilege) and BEFORE k3s
# starts. Invoked from scripts/dev-cluster.sh (right before k3s) and, as a
# belt-and-suspenders, from the devcontainer postStart. Idempotent.
set -eu

[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" ] || { echo "not cgroup v2, nothing to do"; exit 0; }

mkdir -p /sys/fs/cgroup/init

# Move THIS process first, so our own forks (subshells below) land in the leaf
# rather than repopulating the root and blocking controller delegation.
echo "$$" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true

# Evacuate all remaining processes from the cgroupns root into the leaf. Repeat
# to catch processes that spawn mid-evacuation; kernel threads / unmovable PIDs
# are ignored.
for _ in 1 2 3 4 5; do
  moved=0
  while read -r pid; do
    [ "$pid" = "$$" ] && continue
    echo "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null && moved=$((moved+1)) || true
  done < /sys/fs/cgroup/cgroup.procs
  [ "$(wc -l < /sys/fs/cgroup/cgroup.procs)" -le 1 ] && break
done

# Delegate all available controllers to children (k8s.io / kubepods need
# memory+io). Retry: the write fails (EBUSY) if a straggler is still in root.
want=""; for c in $(cat /sys/fs/cgroup/cgroup.controllers); do want="$want +$c"; done
for _ in 1 2 3; do
  if echo "$want" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; then break; fi
  # Another eviction pass, then retry.
  while read -r pid; do
    [ "$pid" = "$$" ] && continue
    echo "$pid" > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || true
  done < /sys/fs/cgroup/cgroup.procs
done

echo "root procs=$(wc -l < /sys/fs/cgroup/cgroup.procs) subtree_control='$(cat /sys/fs/cgroup/cgroup.subtree_control)'"
[ -n "$(cat /sys/fs/cgroup/cgroup.subtree_control)" ] || {
  echo "WARN: could not delegate controllers (root still has processes)." >&2
}

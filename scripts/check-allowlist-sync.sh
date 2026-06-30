#!/usr/bin/env bash
# Mechanically assert that the firewall egress allowlist and the built-in
# sandbox allowlist are identical, so the two defense layers cannot silently
# drift (resolves the comment-only sync convention). Run in CI and locally.
set -euo pipefail
cd "$(dirname "$0")/.."

fw=$(awk '/^ALLOWED_DOMAINS=\(/{f=1;next} /^\)/{f=0} f' .devcontainer/init-firewall.sh \
      | sed 's/#.*//' | tr -d ' \t' | grep -v '^$' | sort -u)
ms=$(jq -r '.sandbox.allowedDomains[]' .devcontainer/managed-settings.json | sort -u)

if [ "$fw" != "$ms" ]; then
  echo "ERROR: allowlist drift between init-firewall.sh and managed-settings.json" >&2
  echo "--- only in firewall (<) / only in managed-settings (>) ---" >&2
  diff <(printf '%s\n' "$fw") <(printf '%s\n' "$ms") || true
  exit 1
fi
echo "OK: allowlists in sync ($(printf '%s\n' "$fw" | grep -c .) domains)"

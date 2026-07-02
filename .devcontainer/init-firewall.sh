#!/usr/bin/env bash
# Egress allowlist firewall for the Claude Code sandbox.
#
# FAIL-CLOSED design:
#   1. default policy is set to DROP *immediately* after flush, before any
#      network operation, and an ERR trap re-asserts DROP on any failure;
#   2. only loopback, DNS, established connections, the in-cluster k3s
#      networks, and a fixed allowlist (resolved to IPs/CIDRs in an ipset)
#      are permitted;
#   3. resolution of an allowlisted domain to zero IPs is FATAL, and the
#      positive reachability check hard-fails — so a degraded allowlist never
#      reports success.
#
# IP-level filtering (ipset) is used rather than a hostname proxy so domain
# fronting cannot bypass the allowlist.
#
# AUTHORITATIVE allowlist: this file is the source of truth for allowed egress.
# Keep .devcontainer/managed-settings.json `allowedDomains` IN SYNC with the
# ALLOWED_DOMAINS list below (it is the built-in-sandbox defense-in-depth layer).
set -euo pipefail

echo "[firewall] initialising egress allowlist (fail-closed)..."

# --- allowlisted domains (KEEP IN SYNC with managed-settings.json) -----------
ALLOWED_DOMAINS=(
  # Claude Code essentials (statsig telemetry is intentionally omitted:
  # nonessential traffic is disabled and statsig.anthropic.com has no A record)
  api.anthropic.com
  claude.ai
  platform.claude.com
  # npm
  registry.npmjs.org
  # GitHub (CIDR ranges also added from api.github.com/meta)
  github.com
  api.github.com
  codeload.github.com
  raw.githubusercontent.com
  objects.githubusercontent.com
  # Spec sources (Source of Trust: RFC / FAPI)
  www.ietf.org
  datatracker.ietf.org
  www.rfc-editor.org
  openid.net
  # OpenID conformance suite
  www.certification.openid.net
  # Container registries / k8s images
  registry-1.docker.io
  auth.docker.io
  production.cloudflare.docker.com
  production.cloudfront.docker.com
  ghcr.io
  pkg-containers.githubusercontent.com
  registry.k8s.io
  get.k3s.io
  get.helm.sh
)

# In-cluster k3s networks (pods / services) + container bridge ranges.
CLUSTER_CIDRS=(
  10.42.0.0/16
  10.43.0.0/16
  172.16.0.0/12
)

# Domains whose DNS resolution failure is FATAL (without these the dev env is
# unusable). All other ALLOWED_DOMAINS that fail to resolve only WARN and are
# skipped — a single optional/flaky domain must not brick container startup,
# while the empty-allowlist guard + negative check below still keep it
# fail-closed (no silent open egress).
REQUIRED_DOMAINS=(
  api.anthropic.com
  registry.npmjs.org
  github.com
  api.github.com
)

# --- fail-closed guarantees --------------------------------------------------
lockdown() {
  iptables -P INPUT DROP || true
  iptables -P OUTPUT DROP || true
  iptables -P FORWARD DROP || true
}
# Any error (set -e) leaves the box locked down rather than open.
trap 'echo "[firewall] ERROR during setup — egress left DROP" >&2; lockdown' ERR

# --- fail-closed FIRST: default DROP before touching anything ----------------
# Set policies (no `|| true`) so a real failure trips the ERR trap; these run
# before flush so there is never an open window.
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# Flush rules (policies remain DROP). The `|| true` below only mask deletion of
# absent user chains / empty tables — benign cleanup, not security-critical.
iptables -F
iptables -X 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
ipset destroy allowed-domains 2>/dev/null || true
# hash:net stores both resolved single IPs (as /32) and CIDR ranges (GitHub).
ipset create allowed-domains hash:net

# --- baseline allows ---------------------------------------------------------
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# DNS (needed to resolve the allowlist)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# In-cluster traffic (k3s pod/svc/bridge networks)
for cidr in "${CLUSTER_CIDRS[@]}"; do
  iptables -A OUTPUT -d "$cidr" -j ACCEPT
  iptables -A INPUT  -s "$cidr" -j ACCEPT
done

# --- resolve allowlisted domains into the ipset ------------------------------
# Required domains -> FATAL on zero IPs; others -> WARN and skip.
is_required() {
  local h="$1" r
  for r in "${REQUIRED_DOMAINS[@]}"; do
    [ "$r" = "$h" ] && return 0
  done
  return 1
}

add_host() {
  local host="$1" ip count=0
  while read -r ip; do
    if [ -n "$ip" ]; then
      ipset add allowed-domains "$ip" -exist
      count=$((count + 1))
    fi
  done < <(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u)
  if [ "$count" -eq 0 ]; then
    if is_required "$host"; then
      echo "[firewall] FATAL: 0 IPs resolved for REQUIRED host '$host'" >&2
      return 1
    fi
    echo "[firewall] WARN: 0 IPs for optional host '$host' — skipping" >&2
    return 0
  fi
  echo "[firewall] allow $host ($count ip)"
}

for d in "${ALLOWED_DOMAINS[@]}"; do
  add_host "$d"
done

# Fail closed if nothing resolved (e.g. total DNS failure) — never leave an
# empty allowlist looking healthy.
member_count=$(ipset list allowed-domains | awk '/^Members:/{m=1; next} m && NF {c++} END {print c + 0}')
if [ "$member_count" -eq 0 ]; then
  echo "[firewall] FATAL: allowlist is empty after resolution" >&2
  lockdown
  exit 1
fi
echo "[firewall] allowlist populated with $member_count entries"

# Permit egress to the resolved allowlist.
iptables -A OUTPUT -m set --match-set allowed-domains dst -j ACCEPT

# Now that api.github.com is reachable, pull GitHub's published CIDR ranges.
echo "[firewall] fetching GitHub IP ranges..."
if gh_meta=$(curl -fsSL --max-time 15 https://api.github.com/meta 2>/dev/null); then
  while read -r cidr; do
    [ -n "$cidr" ] && ipset add allowed-domains "$cidr" -exist
  done < <(echo "$gh_meta" | jq -r '(.api + .git + .web + .packages)[]?' 2>/dev/null \
            | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$')
else
  echo "[firewall] WARNING: could not fetch api.github.com/meta (DNS-resolved github IPs still allowed)." >&2
fi

# --- verify (both directions hard-fail) --------------------------------------
echo "[firewall] verifying..."
if ! curl -fsS --max-time 10 https://registry.npmjs.org/ -o /dev/null; then
  echo "[firewall] FATAL: allowlisted host (npm) unreachable — allowlist degraded." >&2
  lockdown
  exit 1
fi
if curl -fsS --max-time 5 https://example.com/ -o /dev/null 2>/dev/null; then
  echo "[firewall] FATAL: non-allowlisted host reachable — firewall not effective!" >&2
  lockdown
  exit 1
fi
echo "[firewall] OK: egress restricted to allowlist (fail-closed verified)."

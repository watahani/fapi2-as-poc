#!/usr/bin/env bash
# Drive the OpenID Conformance Suite (already running at $SUITE_URL) to run the
# FAPI 2.0 SP test plan against the AS at $ISSUER, writing results to ./results/.
#
# The suite is brought up separately (prebuilt images, no build):
#   - sandbox/local: deploy/conformance/run-local.sh        (k3s, no docker)
#   - CI / docker host: docker compose -f deploy/conformance/docker-compose.yml up
#
# STATUS: pre-P1 the AS exposes no discovery, so this fails fast at the discovery
# gate (the legitimate RED). Once P1 lands the endpoints, this creates and runs
# the plan via the suite API and fails on any non-PASS module. Interactive
# (browser) modules additionally need the IdP stub — see README TODO(P3).
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ISSUER="${ISSUER:-http://localhost:3000}"
SUITE_URL="${SUITE_URL:-https://localhost:8443}"
PLAN_NAME="${PLAN_NAME:-fapi2-security-profile-final-test-plan}"
SUITE_TOKEN="${SUITE_TOKEN:-}"      # optional bearer token if the suite requires auth
OUT="$HERE/results"
mkdir -p "$OUT"

# curl with optional auth, TLS-insecure (suite uses a self-signed cert locally).
# Bounded timeouts so a half-booted suite holding the connection can't hang us.
cs() { curl -ksS --connect-timeout 5 --max-time 30 ${SUITE_TOKEN:+-H "Authorization: Bearer $SUITE_TOKEN"} "$@"; }

sed "s#\${ISSUER}#${ISSUER}#g" "$HERE/test-config.json" > "$OUT/config.json"
# The plan variant is read from test-config.json (.variant).
VARIANT="$(jq -c '.variant' "$OUT/config.json")"
echo "[conformance] issuer=$ISSUER suite=$SUITE_URL plan=$PLAN_NAME variant=$VARIANT"

# 1) Suite must be reachable.
if ! cs "$SUITE_URL/api/runner/available" -o /dev/null; then
  echo "[conformance] suite API not reachable at $SUITE_URL (bring it up first)." >&2
  exit 1
fi

# 2) AS discovery must exist before the suite can test anything.
if ! curl -fsS "${ISSUER%/}/.well-known/openid-configuration" -o "$OUT/discovery.json" 2>/dev/null; then
  echo "[conformance] AS discovery not available at $ISSUER (expected pre-P1)." >&2
  echo "[conformance] implement PAR/authorize/token/jwks/discovery (P1) to proceed." >&2
  exit 1
fi

# 3) Create the test plan (config JSON is the request body).
echo "[conformance] creating plan '$PLAN_NAME'..."
plan_json="$(cs -X POST \
  --data-binary @"$OUT/config.json" -H "Content-Type: application/json" \
  "$SUITE_URL/api/plan?planName=${PLAN_NAME}&variant=$(jq -rn --argjson v "$VARIANT" '$v|@json|@uri')")"
echo "$plan_json" > "$OUT/plan.json"
PLAN_ID="$(echo "$plan_json" | jq -r '.id // empty')"
[ -n "$PLAN_ID" ] || { echo "[conformance] plan creation failed: $plan_json" >&2; exit 1; }
echo "[conformance] plan id=$PLAN_ID"

# 4) Run every module in the plan, polling each to completion.
mapfile -t MODULES < <(echo "$plan_json" | jq -r '.modules[].testModule')
fail=0
for mod in "${MODULES[@]}"; do
  echo "[conformance] running module: $mod"
  run_json="$(cs -X POST "$SUITE_URL/api/runner?test=${mod}&plan=${PLAN_ID}")"
  MID="$(echo "$run_json" | jq -r '.id // empty')"
  if [ -z "$MID" ]; then echo "  ! could not start $mod: $run_json" >&2; fail=1; continue; fi

  status=""; result=""
  for _ in $(seq 1 120); do
    info="$(cs "$SUITE_URL/api/info/$MID")"
    status="$(echo "$info" | jq -r '.status // empty')"
    result="$(echo "$info" | jq -r '.result // empty')"
    case "$status" in
      FINISHED|INTERRUPTED) break ;;
      # WAITING means the module expects a browser interaction (authz redirect).
      # Headless automation of that needs the IdP stub — see README TODO(P3).
      WAITING) echo "  … $mod is WAITING for browser interaction (needs IdP stub)"; break ;;
    esac
    sleep 2
  done
  echo "  → $mod: status=$status result=$result"
  echo "$info" > "$OUT/module-$MID.json" 2>/dev/null || true
  case "$result" in PASSED|WARNING|REVIEW) ;; *) fail=1 ;; esac
done

echo "[conformance] plan $PLAN_ID complete (results in $OUT/). overall=$([ $fail -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"

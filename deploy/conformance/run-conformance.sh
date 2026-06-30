#!/usr/bin/env bash
# Drive the OpenID Conformance Suite (already running at $SUITE_URL) to run the
# FAPI 2.0 SP test plan against the AS at $ISSUER, writing results to ./results/.
#
# The suite is brought up separately (prebuilt images, no build):
#   - sandbox/local: deploy/conformance/run-local.sh        (k3s, no docker)
#   - CI / docker host: docker compose -f deploy/conformance/docker-compose.yml up
#
# STATUS: scaffold (P3 finalizes). AS endpoints land in P1; cannot pass before.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ISSUER="${ISSUER:-http://localhost:3000}"
SUITE_URL="${SUITE_URL:-https://localhost:8443}"
PLAN_NAME="${PLAN_NAME:-fapi2-security-profile-final-test-plan}"
OUT="$HERE/results"
mkdir -p "$OUT"

sed "s#\${ISSUER}#${ISSUER}#g" "$HERE/test-config.json" > "$OUT/config.json"
echo "[conformance] issuer=$ISSUER suite=$SUITE_URL plan=$PLAN_NAME"

# Suite must be reachable.
if ! curl -ksf "$SUITE_URL/" -o /dev/null; then
  echo "[conformance] suite not reachable at $SUITE_URL (bring it up first)." >&2
  exit 1
fi

# AS discovery must exist before the suite can run.
if ! curl -fsS "${ISSUER%/}/.well-known/openid-configuration" -o "$OUT/discovery.json" 2>/dev/null; then
  echo "[conformance] AS discovery not available yet (expected pre-P1)." >&2
  echo "[conformance] TODO(P3): implement PAR/authorize/token/jwks/discovery." >&2
  exit 1
fi

# TODO(P3): create + run the plan via the suite API and fail on any non-PASS:
#   python3 suite/scripts/run-test-plan.py "$PLAN_NAME" "$OUT/config.json" \
#       --conformance-server "$SUITE_URL/api/" --export-dir "$OUT"
echo "[conformance] TODO(P3): run '$PLAN_NAME' against $SUITE_URL and assert PASS."
exit 1

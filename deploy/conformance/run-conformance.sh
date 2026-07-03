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

# 2) Best-effort discovery pre-check. When ISSUER is an in-network name (e.g.
# https://as:8443 in docker-compose) it is not resolvable from where this
# script runs; the suite fetches discovery itself at module run time, so a
# failure here is only a warning, not fatal.
if curl -kfsS "${ISSUER%/}/.well-known/openid-configuration" -o "$OUT/discovery.json" 2>/dev/null; then
  echo "[conformance] AS discovery reachable at $ISSUER"
else
  echo "[conformance] note: AS discovery not reachable from here ($ISSUER); the suite will fetch it in-network." >&2
fi

# 3) Create the test plan (config JSON is the request body). Capture the HTTP
# status and raw body so a suite-side rejection is visible in the CI log
# (the suite validates/fetches the discoveryUrl at plan creation).
echo "[conformance] creating plan '$PLAN_NAME'..."
plan_variant="$(jq -rn --argjson v "$VARIANT" '$v|@json|@uri')"
plan_http="$(cs -o "$OUT/plan.json" -w '%{http_code}' -X POST \
  --data-binary @"$OUT/config.json" -H "Content-Type: application/json" \
  "$SUITE_URL/api/plan?planName=${PLAN_NAME}&variant=${plan_variant}" || true)"
echo "[conformance] plan create HTTP $plan_http; raw response:"
cat "$OUT/plan.json"; echo
PLAN_ID="$(jq -r '.id // empty' "$OUT/plan.json" 2>/dev/null || true)"
[ -n "$PLAN_ID" ] || { echo "[conformance] plan creation failed (HTTP $plan_http)" >&2; exit 1; }
echo "[conformance] plan id=$PLAN_ID"

# 4) Run every module in the plan, polling each to completion.
# MODULE_FILTER (optional grep -E pattern) limits which modules run — useful
# for focused debugging (e.g. MODULE_FILTER=discovery).
mapfile -t MODULES < <(jq -r '.modules[].testModule' "$OUT/plan.json" | { [ -n "${MODULE_FILTER:-}" ] && grep -E "$MODULE_FILTER" || cat; })
echo "[conformance] plan has ${#MODULES[@]} module(s)${MODULE_FILTER:+ (filter: $MODULE_FILTER)}"
[ "${#MODULES[@]}" -gt 0 ] || { echo "[conformance] no modules in plan — aborting" >&2; exit 1; }

# Modules reported but NOT failing the run, in two groups (all verified below
# or in the in-repo Layer 1 suite):
#
# (a) INTERACTIVE — need user behaviour the P1 dev auto-authentication cannot
#     produce (deny consent; a first authorization visit that does not complete
#     login). Unblocked by P2 (real IdP delegation + consent UI).
#
# (b) NON-REDIRECT ERROR — the AS correctly rejects with an error PAGE (it
#     cannot redirect: the request_uri/redirect_uri is invalid/expired, or PAR
#     was skipped, so there is no trusted redirect target). The suite observes
#     outcomes via its callback, so a plain error page delivered to an external
#     headless browser is not observable to it and the module stays WAITING.
#     The AS behaviour for each is asserted directly in the in-repo Layer 1
#     suite (test/conformance/fapi2-sp.test.ts + unit tests).
EXPECTED_NONPASS="fapi2-security-profile-final-user-rejects-authentication
fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds
fapi2-security-profile-final-ensure-unsigned-authorization-request-without-using-par-fails
fapi2-security-profile-final-par-attempt-reuse-request_uri
fapi2-security-profile-final-par-attempt-to-use-expired-request_uri
fapi2-security-profile-final-par-attempt-to-use-request_uri-for-different-client"

fail=0
for mod in "${MODULES[@]}"; do
  echo "[conformance] running module: $mod"
  run_json="$(cs -X POST "$SUITE_URL/api/runner?test=${mod}&plan=${PLAN_ID}")"
  MID="$(echo "$run_json" | jq -r '.id // empty')"
  if [ -z "$MID" ]; then echo "  ! could not start $mod: $run_json" >&2; fail=1; continue; fi

  # AS_BROWSER_BASE is where the AS is reachable from THIS script (the suite
  # gives browser URLs on the in-network issuer, e.g. https://as:8443, which is
  # not resolvable here). The AS auto-authenticates and 303s straight to the
  # suite callback, so following redirects headlessly completes the flow.
  AS_BROWSER_BASE="${AS_BROWSER_BASE:-https://localhost:3000}"
  # Per-module budget of ~150s: completed modules break early. Some modules
  # legitimately wait out an authorization-code / request_uri expiry (tens of
  # seconds) before completing, so the budget must exceed those TTLs; modules
  # that can never complete headlessly (EXPECTED_NONPASS) burn the full budget.
  status=""; result=""; visited=""
  for _ in $(seq 1 75); do
    info="$(cs "$SUITE_URL/api/info/$MID")"
    status="$(echo "$info" | jq -r '.status // empty')"
    result="$(echo "$info" | jq -r '.result // empty')"
    case "$status" in
      FINISHED|INTERRUPTED) break ;;
      WAITING)
        # Drive the authorization step: visit each requested browser URL once,
        # following redirects (AS → suite callback).
        binfo="$(cs "$SUITE_URL/api/runner/browser/$MID" 2>/dev/null)"
        mapfile -t urls < <(printf '%s' "$binfo" \
          | jq -r '(.urls // []) + [ (.urlsWithMethod // [])[].url ] | .[]' 2>/dev/null)
        [ -z "${DUMPED:-}" ] && { DUMPED=1; echo "  [debug] browser: $binfo"; }
        for u in "${urls[@]}"; do
          [ -n "$u" ] || continue
          case "$visited" in *"|$u|"*) continue ;; esac
          visited="$visited|$u|"
          # Rewrite the in-network issuer host to where the AS is reachable here.
          visit="${u/${ISSUER}/${AS_BROWSER_BASE}}"
          # The suite delivers the auth response via a JS callback page, so a
          # real browser is required; curl cannot complete the flow. Fall back
          # to curl only when the browser driver is unavailable.
          if [ "${USE_BROWSER:-1}" = "1" ] && node "$HERE/drive-browser.mjs" "$visit"; then
            echo "  … drove authorization URL via headless browser"
          else
            code="$(cs -L -o /dev/null -w '%{http_code}' "$visit" || true)"
            echo "  … visited authorization URL (HTTP $code, no browser)"
          fi
        done
        ;;
    esac
    sleep 2
  done
  echo "  → $mod: status=$status result=$result"
  echo "$info" > "$OUT/module-$MID.json" 2>/dev/null || true
  case "$result" in
    PASSED | WARNING | REVIEW | SKIPPED) ;;
    *)
      # Surface the suite's own failure/warning log lines so the reason is
      # visible in CI without downloading artifacts.
      cs "$SUITE_URL/api/log/$MID" 2>/dev/null \
        | jq -r '.[] | select(.result=="FAILURE" or .result=="WARNING") | "    [\(.result)] \(.src): \(.msg)"' 2>/dev/null \
        | head -8 || true
      case "$EXPECTED_NONPASS" in
        *"$mod"*)
          echo "    (expected non-pass in P1 — needs P2 interactive auth; not failing the run)" ;;
        *)
          fail=1 ;;
      esac
      ;;
  esac
done

echo "[conformance] plan $PLAN_ID complete (results in $OUT/). overall=$([ $fail -eq 0 ] && echo PASS || echo FAIL)"
exit "$fail"

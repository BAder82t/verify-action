#!/usr/bin/env bash
# End-to-end tests of the VaultBytes Verify Action under act, against the stub API (client/test/stub-api.mjs).
#
#   client/test/run-act-tests.sh            # from the repository root; needs docker, act and node
#
# Each arm runs the real action.yml in an act job with a fresh random token, then checks act's exit code, the
# decision, the summary, the uploaded result.json artifact, and that the token string never appears anywhere in
# act's output. The last arm is a positive control: it prints the token on purpose, and the leak detector must
# find it, which proves the detector can see act's output at all.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
WF=client/test/workflows/action-e2e.yml
IMAGE="${ACT_IMAGE:-catthehacker/ubuntu:act-latest}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/vbv-act.XXXXXX")"
PASSED=0; FAILED=0; RESULTS=()

command -v act >/dev/null || { echo "act is not installed"; exit 2; }
docker info >/dev/null 2>&1 || { echo "docker is not running"; exit 2; }

# On Docker Desktop the job container cannot reach act's artifact server on the host's LAN address. Bind it to
# loopback and forward from inside the job (see client/test/tcp-forward.mjs). On Linux, set VBV_ACT_DIRECT=1.
ART_FLAGS=(--artifact-server-addr 127.0.0.1 --env VBV_ACT_ARTIFACT_FORWARD=host.docker.internal:34567)
[ "${VBV_ACT_DIRECT:-0}" = "1" ] && ART_FLAGS=()

nonce() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16; }

# run_arm NAME TOKEN EXPECT_EXIT(0|nonzero) FAIL_ON TIMEOUT API_URL LEAK_CONTROL EXPECT_ARTIFACT(yes|no) PATTERN...
# (each PATTERN is an extended regex that must appear in act's output, or must not appear if prefixed with !)
run_arm() {
  local name="$1" token="$2" expect="$3" failon="$4" timeout="$5" api="$6" leak="$7" want_art="$8"; shift 8
  local log="$WORK/$name.log" art="$WORK/$name-artifacts" rc ok=1 why=()
  act workflow_dispatch -W "$WF" -P "ubuntu-latest=$IMAGE" --pull=false \
      --artifact-server-path "$art" "${ART_FLAGS[@]}" \
      --input "token=$token" --input "fail-on=$failon" --input "timeout-seconds=$timeout" \
      --input "api-url=$api" --input "leak-control=$leak" >"$log" 2>&1
  rc=$?
  if [ "$expect" = "0" ] && [ "$rc" -ne 0 ]; then ok=0; why+=("act exit $rc, expected 0"); fi
  if [ "$expect" = "nonzero" ] && [ "$rc" -eq 0 ]; then ok=0; why+=("act exit 0, expected failure"); fi
  local pat
  for pat in "$@"; do     # a pattern prefixed with ! must be absent from act's output
    if [ "${pat:0:1}" = "!" ]; then
      grep -qE -- "${pat:1}" "$log" && { ok=0; why+=("present but forbidden: ${pat:1}"); }
    else
      grep -qE -- "$pat" "$log" || { ok=0; why+=("missing: $pat"); }
    fi
  done
  # the leak detector: a plain fixed-string search for the whole token over everything act printed
  local hits; hits=$(grep -cF -- "$token" "$log" || true)
  if [ "$leak" = "yes" ]; then
    [ "$hits" -gt 0 ] || { ok=0; why+=("positive control: detector did not see the deliberately printed token"); }
  else
    [ "$hits" -eq 0 ] || { ok=0; why+=("TOKEN LEAKED: $hits line(s)"); }
  fi
  local zip; zip=$(find "$art" -name '*.zip' 2>/dev/null | head -n 1)
  if [ "$want_art" = "yes" ]; then
    if [ -z "$zip" ]; then ok=0; why+=("no result.json artifact uploaded")
    elif ! unzip -p "$zip" result.json | grep -q '"verdict"'; then ok=0; why+=("artifact has no result.json verdict")
    fi
  elif [ -n "$zip" ]; then ok=0; why+=("unexpected artifact")
  fi
  if [ "$ok" -eq 1 ]; then PASSED=$((PASSED + 1)); RESULTS+=("PASS  $name (act exit $rc, token hits $hits)")
  else FAILED=$((FAILED + 1)); RESULTS+=("FAIL  $name: ${why[*]} (log: $log)"); fi
  echo "${RESULTS[${#RESULTS[@]}-1]}"
}

LOCAL=http://127.0.0.1:18787
M=""   # "" for fail-on / timeout-seconds = the minimal form (token only), exactly what a customer writes

echo "== unit tests"
if node --test client/test/*.test.mjs >"$WORK/unit.log" 2>&1; then
  echo "PASS  unit ($(grep -E '^# pass' "$WORK/unit.log"))"; PASSED=$((PASSED + 1)); RESULTS+=("PASS  unit")
else
  echo "FAIL  unit (log: $WORK/unit.log)"; FAILED=$((FAILED + 1)); RESULTS+=("FAIL  unit")
fi

echo "== act arms (sequential; each takes 5-40 s)"
run_arm pass "vbvtest_pass_$(nonce)" 0 "$M" "$M" "$LOCAL" no yes \
  '## VaultBytes Verify: PASS' 'E2E-OUTPUT form=minimal job-id=j_[0-9A-Z]{26} verdict=PASS decision=pass' \
  '\| Library \| lattigo \(detected\) \|' '\| Library version \| v6\.2\.0 \|' '\| Cases \| 48 \|' \
  '\| Cross-backend coverage \| done \(partner: openfhe\) \|' \
  'E2E-STUB-BODY-KEYS \["target"\]' 'check passed \(verdict PASS\)' 'Job succeeded'
run_arm fail-verdict "vbvtest_fail_$(nonce)" nonzero "$M" "$M" "$LOCAL" no yes \
  '## VaultBytes Verify: FAIL' 'form=minimal .*verdict=FAIL decision=fail' 'check failed \(verdict FAIL\)' \
  '\| Cross-backend coverage \| cross-backend comparison not performed \(partner build failed\) \|' 'Job failed'
run_arm fail-verdict-strict "vbvtest_fail_$(nonce)" nonzero ERROR "$M" "$LOCAL" no yes \
  'form=configured .*verdict=FAIL decision=fail' 'Job failed'
run_arm bad-token "revoked_$(nonce)" nonzero "$M" "$M" "$LOCAL" no no \
  'authentication failed \(HTTP 401\)' 'decision=fail' 'Job failed'
run_arm timeout "vbvtest_slow_$(nonce)" nonzero "$M" 6 "$LOCAL" no no \
  'timeout: timed out after 6 s waiting for job j_' 'decision=fail' 'Job failed'
run_arm error-verdict-default "vbvtest_error_$(nonce)" 0 "$M" "$M" "$LOCAL" no yes \
  'form=minimal .*verdict=ERROR decision=pass' '::warning' 'Job succeeded'
run_arm error-verdict-strict "vbvtest_error_$(nonce)" nonzero ERROR "$M" "$LOCAL" no yes \
  'verdict=ERROR decision=fail' 'Job failed'
run_arm refused-default "vbvtest_refused_$(nonce)" 0 "$M" "$M" "$LOCAL" no yes \
  'form=minimal .*verdict=REFUSED decision=pass' '\| Reason \| commit not found at the URL \|' 'Job succeeded'
run_arm refused-strict "vbvtest_refused_$(nonce)" nonzero ERROR "$M" "$LOCAL" no yes \
  'verdict=REFUSED decision=fail' 'Job failed'
run_arm transient-retry "vbvtest_flaky_$(nonce)" 0 "$M" "$M" "$LOCAL" no yes \
  'HTTP 503 from POST /v1/jobs: will retry' 'HTTP 429 from GET' 'verdict=PASS decision=pass'
run_arm insecure-url "vbvtest_pass_$(nonce)" nonzero "$M" "$M" "http://verify.example.com" no no \
  "must use https://" 'E2E-STUB-POSTS 0' 'Job failed'
run_arm unconfigured-service-url "vbvtest_pass_$(nonce)" nonzero "$M" "$M" "" no no \
  "service URL is not configured" 'E2E-STUB-POSTS 0' 'Job failed'
run_arm internal-fields-stripped "vbvtest_internal_$(nonce)" 0 "$M" "$M" "$LOCAL" no yes \
  'E2E-KIT-VERSION 0\.1\.0$' 'E2E-RESULT-KEYS .*seal\.plan_sha256' 'verdict=PASS decision=pass' \
  '!kit_commit' '!seal_commit' '!internal-host-7' '!167340203f220e05'
run_arm hostile-text-inert "vbvtest_hostile_$(nonce)" 0 "$M" "$M" "$LOCAL" no yes \
  'verdict=REFUSED decision=pass' "not a plain URL on the API's origin" '\| Reason \| bad &lt;img' \
  'comparison not performed \(&lt;img src=y' \
  '!<img src' '!<script>' '!\]\(javascript:' '!<b>bold' '!evil\.example/r\)' '!injected-by-server'
run_arm leak-control "vbvtest_pass_$(nonce)" 0 "$M" "$M" "$LOCAL" yes yes \
  'CONTROL-LEAK' 'verdict=PASS decision=pass'

echo
echo "== summary: $PASSED passed, $FAILED failed (logs in $WORK)"
printf '%s\n' "${RESULTS[@]}"
[ "$FAILED" -eq 0 ]

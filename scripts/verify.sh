#!/usr/bin/env bash
# One command that proves the gateway works. Writes everything to evidence/.
#   scripts/verify.sh            offline: spec vectors, unit, security, interop, demo
#   scripts/verify.sh --network  also live Cloudflare server, real key directories, surveys,
#                                production-mode walkthrough, drift check
# Exit code is non-zero if any step fails. evidence/SUMMARY.md is the human-readable result.
set -uo pipefail
cd "$(dirname "$0")/.."
NETWORK=0; [[ "${1:-}" == "--network" ]] && NETWORK=1
EV=evidence; mkdir -p "$EV"; rm -f "$EV"/*.xml "$EV"/*.json "$EV"/*.log "$EV"/*.html "$EV"/SUMMARY.md
STATUS=(); FAILED=0

step() {  # step <name> <logfile> <command...>
  local name="$1" log="$2"; shift 2
  echo "==> $name"
  if "$@" >"$EV/$log" 2>&1; then STATUS+=("| $name | PASS | $log |"); else STATUS+=("| $name | **FAIL** | $log |"); FAILED=1; fi
  tail -3 "$EV/$log"
}

if [[ ! -d .venv ]]; then python3 -m venv .venv; fi
# shellcheck disable=SC1091
source .venv/bin/activate
step "Install Python deps" install.log pip install -q -r requirements.txt

step "Spec vectors + unit + security tests" pytest-offline.log \
  python -m pytest -q -m "not interop and not network" --junitxml="$EV/pytest-offline.xml"

if command -v node >/dev/null 2>&1; then
  step "Install Cloudflare reference library" npm.log bash -c "cd interop/js && npm install --no-audit --no-fund"
  step "Interop with Cloudflare web-bot-auth (both directions)" pytest-interop.log \
    python -m pytest -q -m interop --junitxml="$EV/pytest-interop.xml"
else
  STATUS+=("| Interop with Cloudflare web-bot-auth | SKIPPED (no node) | - |"); FAILED=1
fi

step "End-to-end demo with expected outcomes" demo.log python -m demo.run_demo --evidence "$EV/demo.json"
[[ -f dashboard_snapshot.html ]] && mv dashboard_snapshot.html "$EV/dashboard_snapshot.html"
step "Verifier benchmark (10,000 verifications, cached key)" bench.log python -m bench.verify_bench --out "$EV/bench.json"

if [[ $NETWORK == 1 ]]; then
  step "Live network checks" pytest-network.log env KYA_NETWORK=1 python -m pytest -q -m network -rs --junitxml="$EV/pytest-network.xml"
  step "Key directory survey" survey.log python -m research.survey_directories --out "$EV/directory_survey.json"
  step "Survey of every registered signed agent" signed_agents_survey.log python -m research.survey_directories --dataset --out "$EV/signed_agents_survey.json"
  step "Production-mode walkthrough against live ChatGPT/Google directories" walkthrough.log python -m examples.walkthrough --evidence "$EV/walkthrough.json"
  step "Drift check of baseline surprises" drift.log python -m research.drift_check --out "$EV/drift.json"
fi

{
  echo "# Verification summary"
  echo
  echo "- Run at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Git commit: $(git rev-parse --short HEAD 2>/dev/null || echo 'not a git repo')"
  echo "- Python: $(python --version 2>&1); Node: $(node --version 2>/dev/null || echo none)"
  echo "- Network checks: $([[ $NETWORK == 1 ]] && echo yes || echo no)"
  echo "- Overall: $([[ $FAILED == 0 ]] && echo PASS || echo FAIL)"
  echo
  echo "| Step | Result | Log |"
  echo "| --- | --- | --- |"
  printf '%s\n' "${STATUS[@]}"
  echo
  echo "## Evidence file hashes (sha256)"
  echo
  echo '```'
  (cd "$EV" && sha256sum ./*.json ./*.xml ./*.log ./*.html 2>/dev/null)
  echo '```'
} > "$EV/SUMMARY.md"

echo; cat "$EV/SUMMARY.md" | sed -n '1,20p'
exit $FAILED

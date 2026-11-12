#!/usr/bin/env bash
# Offline check. Switch the network OFF first, then run:  bash scripts/offline_check.sh
# It starts the stack from images that are already built, replays the demo scenario, reads the ledger,
# and verifies the audit export. One PASS or FAIL line per step. Exit code 1 if any step failed.
set -u
cd "$(dirname "$0")/.."
API="${API_URL:-http://localhost:8000}"
failed=0

step() {  # step "name" command...
  local name="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "PASS $name"; else echo "FAIL $name"; failed=1; fi
}

not_online() { ! curl -sS -m 4 -o /dev/null https://example.com; }
wait_healthy() {
  for _ in $(seq 1 60); do
    [ "$(curl -s -m 3 -o /dev/null -w '%{http_code}' "$API/ledger/nodes")" = "200" ] && return 0
    sleep 2
  done
  return 1
}
export_audit() { mkdir -p data && curl -sS -m 20 -f "$API/audit/export" -o data/audit_export.json; }
verify_audit() {
  docker compose run --rm --no-deps -T -v "$PWD/data:/app/data" api \
    python -m deconflicted.ledger.verify_cli /app/data/audit_export.json
}

step "host is offline (no internet)" not_online
step "stack starts from built images" docker compose up -d --no-build
step "api and ledger nodes are healthy" wait_healthy
step "replay of the demo scenario" docker compose --profile demo run --rm --no-deps -T replay
step "ledger verifies" bash -c "curl -sS -m 10 -f '$API/ledger/verify' | grep -q '\"ok\":true'"
step "three ledger nodes are up" bash -c "[ \$(curl -sS -m 10 -f '$API/ledger/nodes' | grep -o '\"up\":true' | wc -l) -eq 3 ]"
step "audit export downloads" export_audit
step "audit export verifies offline" verify_audit

[ "$failed" -eq 0 ] && echo "ALL STEPS PASSED" || echo "SOME STEPS FAILED"
exit "$failed"

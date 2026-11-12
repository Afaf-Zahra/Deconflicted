#!/usr/bin/env bash
# Stop the stack and delete its data: the three ledger nodes and the API's ledger store.
# Always remove them together. If only some are removed, the ledger refuses new entries.
#   bash scripts/reset_demo.sh
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --profile demo down -v --remove-orphans
echo "stack stopped and ledger data removed; run make demo for a fresh start"

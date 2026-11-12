#!/usr/bin/env bash
# Load the images saved by export_images.sh, then start the demo with: make demo
#   bash scripts/load_images.sh [input.tar]
set -euo pipefail
cd "$(dirname "$0")/.."
in="${1:-deconflicted-images.tar}"
[ -f "$in" ] || { echo "FAILED $in not found"; exit 1; }
docker load -i "$in"

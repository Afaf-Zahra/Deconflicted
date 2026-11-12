#!/usr/bin/env bash
# Save every image of the stack into one file, so the demo can run on a laptop that never had internet.
#   bash scripts/export_images.sh [output.tar]     (needs internet once, to build)
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-deconflicted-images.tar}"
docker compose --profile demo build
images=$(docker compose --profile demo config --images | sort -u)
# shellcheck disable=SC2086
docker save $images -o "$out"
echo "saved $(echo "$images" | wc -l) images to $out"

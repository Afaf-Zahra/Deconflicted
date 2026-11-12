#!/bin/sh

set -eu

cd "$(dirname "$0")/.."

echo "Building web UI..."

if [ -f package.json ]; then
  npm run build
else
  echo "ERROR: web/package.json is missing."
  exit 1
fi

if [ ! -d dist ]; then
  echo "ERROR: web/dist was not created."
  exit 1
fi

echo "Checking dist for external URLs..."

if grep -R -nE 'https?://' dist --exclude='*.map' \
  | grep -vE 'www\.w3\.org|react\.dev/errors|redux\.js\.org/Errors|redux-toolkit\.js\.org/Errors|bit\.ly/3cXEKWf|fb\.me/use-check-prop-types|tailwindcss\.com'; then
  echo "ERROR: external URL or font CDN reference found in dist."
  exit 1
fi

if grep -R -nE 'fonts\.googleapis\.com|fonts\.gstatic\.com' dist --exclude='*.map'; then
  echo "ERROR: external URL or font CDN reference found in dist."
  exit 1
fi

echo "Offline check passed."

#!/usr/bin/env bash
set -euo pipefail

BASE_URL=${1:-http://localhost:3000}

echo "Running smoke checks against $BASE_URL"

echo -n "Checking /health... "
if curl -sSf "$BASE_URL/health" >/dev/null; then
  echo "OK"
else
  echo "FAIL"
  exit 1
fi

echo -n "Checking /pets... "
PETS_JSON=$(curl -sSf "$BASE_URL/pets") || { echo "FAIL"; exit 1; }
COUNT=$(echo "$PETS_JSON" | jq '. | length' 2>/dev/null || echo "?" )
echo "OK — $COUNT pet(s) returned"

echo "Smoke checks passed."

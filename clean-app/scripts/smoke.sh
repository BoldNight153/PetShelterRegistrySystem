#!/usr/bin/env bash
set -euo pipefail
url=${1:-http://localhost:3000}

echo "Checking /health..."
curl -fsS "$url/health" | jq .
echo "Checking /pets..."
curl -fsS "$url/pets" | jq .

echo "Smoke checks passed"

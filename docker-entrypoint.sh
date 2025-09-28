#!/usr/bin/env sh
set -euo pipefail

echo "[entrypoint] running prisma generate (no-op if up-to-date)"
npx prisma generate

echo "[entrypoint] running prisma migrate deploy"
npx prisma migrate deploy

echo "[entrypoint] starting app"
exec node app.js

# Pet Shelter Backend

Run locally:

1. Copy `.env.example` to `.env` and adjust as needed, or use the provided `.env` for local dev.
2. Install dependencies:

```bash
npm install
```

1. Generate Prisma client and run migrations (creates `dev.db`):

```bash
npx prisma generate
npx prisma migrate dev --name init
```

1. Seed the database:

```bash
npm run seed
```

1. Run in dev mode:

```bash
npm run dev
```

Run tests (Jest + SuperTest):

```bash
NODE_ENV=test npm test
```

## OAuth provider setup (dev)

1. Copy `.env.example` to `.env` and fill in:

- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI` (default: `http://localhost:4000/auth/oauth/google/callback`)
- `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`
- `GITHUB_REDIRECT_URI` (default: `http://localhost:4000/auth/oauth/github/callback`)
- `OAUTH_SUCCESS_REDIRECT` (default: `http://localhost:5173/`)
- `OAUTH_FAILURE_REDIRECT` (default: `http://localhost:5173/login?error=oauth_failed`)

1. Configure allowed callback URLs in the providers’ dashboards to match the redirect URIs above.

1. Ensure the frontend dev server runs on `http://localhost:5173` (Vite default) and the backend on `:4000`.

1. Enable providers via Admin Settings (`auth.google = true`, `auth.github = true`).

Then visit `/auth/oauth/google/start` or `/auth/oauth/github/start` from the browser.

## Email delivery (verification & reset)

For development, the server will log emails to the console if SMTP is not configured. To enable real email sending, set these variables in `.env`:

```env
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=apikey-or-username
SMTP_PASS=secret
EMAIL_FROM="Pet Shelter <no-reply@example.com>"
APP_ORIGIN=http://localhost:5173
```

APP_ORIGIN is used to build verification and reset links like `http://localhost:5173/verify-email?token=...` and `http://localhost:5173/reset-password?token=...`.

CI notes

- The repository contains a GitHub Actions workflow at `.github/workflows/ci.yml` that installs dependencies, runs Prisma generate, applies migrations against a local sqlite file, runs the seed script, and runs tests.
- For production Postgres, set `DATABASE_URL` to your Postgres DSN and update `prisma/schema.prisma` provider accordingly before running migrations.

## Security quick start

This backend supports account lockout, per-IP rate limits, email verification, and password history enforcement.

1) Pick defaults in .env (used if DB settings are absent):

```env
# Per-IP login rate limit
LOGIN_IP_WINDOW_MS=60000
LOGIN_IP_LIMIT=20

# Per-user lockout behavior
LOGIN_LOCK_WINDOW_MS=900000      # 15 minutes
LOGIN_LOCK_THRESHOLD=5           # 5 failed attempts in window
LOGIN_LOCK_DURATION_MS=900000    # 15 minutes

# Password history
PASSWORD_HISTORY_LIMIT=10

# Email verification
EMAIL_VERIFICATION_TTL_MIN=60
PASSWORD_RESET_TTL_MIN=30
```

1) Seed database settings (override env at runtime). You can set these via Admin UI → Settings → Security or with a quick script:

```ts
// scripts/upsert-security-settings.ts (run with ts-node)
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
async function main() {
  const entries = {
    requireEmailVerification: true,
    sessionMaxAgeMin: 60,
    loginIpWindowSec: 60,
    loginIpLimit: 20,
    loginLockWindowSec: 900,
    loginLockThreshold: 5,
    loginLockDurationMin: 15,
    passwordHistoryLimit: 10,
  }
  for (const [key, value] of Object.entries(entries)) {
    await prisma.setting.upsert({
      where: { category_key: { category: 'security', key } },
      update: { value },
      create: { category: 'security', key, value },
    })
  }
  await prisma.$disconnect()
}
main()
```

1) Verify behavior

- Login failures trigger per-IP throttling and per-user lockout after threshold within window; locked accounts return 423 until unlocked or expired
- Admin lock/unlock under `/admin/users/*` revokes sessions and sends reset email on unlock
- Password reset refuses recent passwords (last N), then records the new hash

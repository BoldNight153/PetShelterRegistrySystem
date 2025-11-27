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

## Shared dev database snapshot

The SQLite file at `prisma/dev.db` is intentionally versioned so every contributor works from the same seeded dataset. After running migrations or seeds that change reference data, re-run `npm run seed`, verify the resulting `dev.db`, and include it in your commits. Production deployments should point `DATABASE_URL` at their own Postgres or SQLite instance and must **not** reuse the tracked dev file.

## Default admin credentials

- Email: `admin@example.com`
- Password: `Admin123!@#`

Re-running the seed script now upgrades existing admin accounts that were created with older bcrypt hashes so they authenticate without server errors. To force-reset the admin password (for example, after changing the default), set `SEED_ADMIN_FORCE_RESET=true` when running `npm run seed`.

## Auth smoke test

Run the automated login + MFA smoke flow anytime you touch the auth stack:

```bash
npm run auth:smoke
```

The script bootstraps CSRF cookies, posts to `/auth/login`, completes the MFA challenge via deterministic backup codes, refreshes cookies, and finally checks `/menus/settings_main` to ensure privileged routes still respond. It defaults to `NODE_ENV=test` and `DATABASE_URL=file:./dev.db`, but you can override a few knobs without editing code:

- `DEV_ADMIN_EMAIL` / `DEV_ADMIN_PASSWORD` &mdash; seed credentials to use
- `AUTH_SMOKE_DEVICE_FP`, `AUTH_SMOKE_DEVICE_NAME`, `AUTH_SMOKE_DEVICE_PLATFORM` &mdash; device context passed through login + MFA
- `AUTH_SMOKE_MENUS` &mdash; alternate menu slug to verify (default `settings_main`)

Tip: re-run `npm run seed` beforehand so the deterministic MFA backup codes stay in sync with the script.

The command exits non-zero on any failure, making it safe to wire into pre-commit hooks or CI once the dev database is available.

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

## Authentication settings category

- The Admin UI Authentication tab writes to the `auth` settings category. The backend normalizes values on both read and write so callers can send simple primitives without duplicating validation.
- Keys:
  - `mode` &mdash; `session` (HTTP-only cookies) or `jwt` (stateless token issuance).
  - `google` / `github` &mdash; booleans gating each OAuth provider.
  - `enforceMfa` &mdash; `optional`, `recommended`, or `required`; login flow checks this to decide when to issue MFA challenges.
  - `authenticators` &mdash; ordered list of authenticator catalog IDs (`google`, `microsoft`, `authy`, `1password`, `okta`, `webauthn_keys`, `platform_passkeys`, `sms_backup`, `push_trusted`, `backup_codes`).
- `SettingsService.listSettings` exposes a `preserveUnknownAuth` flag that `/admin/settings` uses during GET requests so the payload still contains archived or missing authenticator IDs for cleanup. Other callers should omit the flag to receive a fully sanitized list that matches the current catalog.
- Responses intentionally keep authenticator IDs that no longer exist (for example, archived custom entries) so administrators can see “missing” selections and clean them up in the UI. Saving new settings still validates against the current catalog to avoid re-introducing invalid identifiers.
- Defaults come from `DEFAULT_AUTH_SETTINGS` and are seeded via `npm run seed`. Update both the seed file and `frontend/src/lib/authenticator-catalog.ts` if you add or rename authenticators so Admin + Account pages stay in sync.

### Regression coverage & release implications

- `backend/src/tests/admin.settings.test.ts` covers GET/PUT authentication settings normalization end-to-end, including preserving orphaned catalog IDs and sanitizing payloads before they hit Prisma. `backend/src/tests/admin.authenticators.test.ts` now asserts that archived catalog entries stay hidden unless `includeArchived=true` and that non-admins cannot mutate the catalog.
- Run `npm test -- admin.settings admin.authenticators` after touching auth settings, authenticator catalog seeds, or RBAC around `/admin/authenticators*` to keep these regression suites green.
- Release note: because both suites assert on seeded authenticator data, always re-run `npm run seed` and commit the updated `prisma/dev.db` whenever you add/remove catalog presets. Otherwise the new tests will fail during CI.

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

- Account security APIs: `/auth/security` returns the snapshot used by the frontend, `/auth/security/sessions` lists refresh-token sessions, `POST /auth/security/password` (CSRF-protected) enforces the registration password policy before rotating hashes + revoking other sessions, `PUT /auth/security/recovery` persists updated recovery emails, SMS numbers, and break-glass contacts, and `PUT /auth/security/alerts` stores each user's alert preferences + default channels in `SecurityService`.
- When a user has started but not yet confirmed a TOTP enrollment, the `/auth/security` response now includes `snapshot.mfa.pendingEnrollment` with the ticket, factor ID, mode (`create` vs `rotate`), associated catalog ID, expiry, and factor status so the UI can nudge them to finish setup or discard the pending entry.

## Notifications quick start

  - `GET /auth/notifications` (cookie auth) returns `{ settings }` with channels, topics, digests, quiet hours, escalations, and device registrations.
  - `PUT /auth/notifications` requires the CSRF header and accepts partial settings updates (channels, topics, digests, quiet hours, escalations, devices). The backend normalizes payloads, enforces channel enums, and persists to metadata.
  - `POST /auth/notifications/devices/register` exchanges a browser/mobile push subscription for a durable device record so notifications can be delivered later. `DELETE /auth/notifications/devices/{deviceId}` revokes an opt-in.
  - Push/in-app device opt-ins persist in the `NotificationDeviceRegistration` table (see the `user.notificationDevices` relation). The service hydrates settings responses from this table and mirrors the readable subset back into `metadata.notifications.devices` for backward compatibility.

## Audit log configuration

- The `audit` settings category now controls retention tiers, export approvals, alert routing, and reviewer rosters. Defaults are seeded via `DEFAULT_AUDIT_SETTINGS` and exposed through `GET /admin/settings`.
- Keys:
  - `audit.retention` &mdash; hot/cold tier durations and legal hold contacts.
  - `audit.exports` &mdash; export format, approval roles, watermarking, and expiration hours.
  - `audit.alerts` &mdash; channel toggles, severity recipients, webhook targets, and notify toggles.
  - `audit.reviewers` &mdash; primary/backup reviewer lists plus escalation window + standby channel.
- Update these via the Admin UI (Security & Access &rarr; Audit Logs) or `PUT /admin/settings` with `category: "audit"`.

## Versioning and Docs

- Admins can fetch backend and spec versions at `GET /admin/version`. Response contains:
  - `backend.version` and optional `backend.commit`
  - `openapi.pets`, `openapi.auth`, `openapi.admin`
- CI checks ensure OpenAPI `info.version` matches the backend `package.json` version. The workflow runs `npm run validate:openapi` under `backend/` on PRs and pushes to `main`.

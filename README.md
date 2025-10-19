# PetShelterRegistrySystem [![Releases](https://img.shields.io/github/v/release/BoldNight153/PetShelterRegistrySystem?sort=semver&label=Releases&logo=github)](https://github.com/BoldNight153/PetShelterRegistrySystem/releases)

A full-stack TypeScript project for a Pet Shelter Registry system featuring:

- Backend: Node.js + Express + Prisma + SQLite (dev) with Jest + SuperTest tests
- Frontend: React 19 + Vite 7 + TypeScript + Tailwind CSS v4 + shadcn/Radix UI
- API Documentation: ReDoc page themed to match the app, backed by the backend's OpenAPI spec and Vite proxy

## What’s new (Security + Admin UI)

- Account lockout and password history
  - Automatic lockout after N failed logins within a configured window; auto-unlocks after the configured duration
  - Manual lock/unlock by admins with audit logging and session revocation
  - Password reset enforces “cannot reuse last N passwords” (includes current)
- Admin UI
  - Roles & Permissions: manage roles, assign/revoke permissions; assign/revoke user roles
  - Users: search users, view lock status, lock/unlock accounts with notes and optional expiration
  - Settings: configure security thresholds (IP rate limits, lock window/threshold/duration, password history), email verification requirement, session lifetime, and OAuth provider toggles
  - Admin Docs: admin-only OpenAPI (gated to `system_admin`)

Backend behavior is driven by settings stored in the database, which override environment variables when present. See Settings keys below.

## Monorepo layout

- `backend/` — Express API, Prisma schema/migrations, seeds, tests
- `frontend/` — Vite React app with sticky header, themed UI, ReDoc docs page

## Requirements

- Node.js 20+
- npm 10+

## Quick start (both apps)

Open two terminals, one for backend and one for frontend.

### 1) Backend

```bash
cd backend
cp -n .env.example .env || true
npm ci
npx prisma generate
npx prisma migrate dev --name init
npm run seed
npm run dev
```

## Migration notes

Recent frontend refactor (services DI)

- The frontend now uses a typed ServicesProvider + useServices() hook pattern for dependency injection.
- UI components and pages should import service interface types from `frontend/src/services/interfaces/*` and consume services via `useServices()`.
- The runtime fetch helpers in `frontend/src/lib/api.ts` are the runtime boundary and should only be imported by adapter implementations in `frontend/src/services/impl/*`.
- To avoid accidental coupling, lib/api no longer exports shared UI types; shared types are in `frontend/src/services/interfaces/types`.

This keeps UI code decoupled from runtime helpers and makes testing easier by allowing tests to inject small service overrides via `ServicesProvider`.

The API starts at http://localhost:4000 with:
- Health: GET /health
- OpenAPI JSON: GET /api-docs/latest/openapi.json

### 2) Frontend

```bash
cd frontend
npm ci
npm run dev
```

The app starts at http://localhost:5173 and proxies backend endpoints:
- /health → http://localhost:4000/health (used for API status indicator)
- /api-docs → http://localhost:4000/api-docs (used by ReDoc)

## Frontend highlights

- Sticky header with backdrop blur and border
- User menu at top-right with:
  - API status indicator (latency + color + manual refresh)
  - Theme toggle group (light/system/dark) with persistence
  - Settings and Logout entries
- Team Switcher in header on mobile only (hidden on md+)
- Team Switcher in the sidebar on larger viewports
- ReDoc docs page (route: "/docs") using the backend OpenAPI spec via proxy; search enabled
- Theming system uses `html.dark` and `html[data-theme]` with localStorage("theme") and system preference tracking

### Admin UI pages

- Permissions: CRUD permissions and grant to roles
- Roles: Create/update roles (with rank), view permissions, revoke permissions
- Users: Search list with roles and lock status; assign/revoke roles; lock/unlock accounts
- Settings: General, Monitoring, Authentication, Documentation, and Security sections
  - Security includes:
    - Require email verification before login
    - Session max age (minutes)
    - Login IP window (seconds) and limit (attempts)
    - Lock window (seconds), threshold (failures), duration (minutes)
    - Password history limit

## Theming and ReDoc

ReDoc is mounted in `frontend/src/docs/redoc-page.tsx` via dynamic import. The theme adapts to app mode (light/dark) and listens to `themechange` events. Dropdowns and code blocks have contrast tweaks for readability.

## API docs endpoints

- Public docs (OpenAPI + ReDoc): GET `/api-docs/latest` and JSON at `/api-docs/latest/openapi.json`
- Admin-only docs: GET `/api-docs/admin/latest` and JSON at `/api-docs/admin/latest/openapi.json`
  - Access requires a user with the `system_admin` role; routes are gated server-side. Enabled in all environments.

### Versions and About panel

- Backend exposes `GET /admin/version` (RBAC: `admin` or `system_admin`) with:
  - `backend.version` and optional `backend.commit`
  - OpenAPI versions for `pets`, `auth`, and `admin` specs
- Frontend adds an Admin page at `/admin/about` that surfaces:
  - Frontend app version (from `package.json` via `__APP_VERSION__` define)
  - Backend version/commit and OpenAPI spec versions
  - Note: In dev, the Vite proxy forwards `/admin/version` to the backend.

## Security and settings

The backend enforces security using settings loaded from the database with environment-variable fallbacks. Database settings take precedence.

- Settings category: `security` (Admin UI → Settings → Security)
  - `requireEmailVerification` (boolean)
  - `sessionMaxAgeMin` (number, minutes)
  - `loginIpWindowSec` (number, seconds)
  - `loginIpLimit` (number, attempts per window)
  - `loginLockWindowSec` (number, seconds)
  - `loginLockThreshold` (number, failed attempts)
  - `loginLockDurationMin` (number, minutes)
  - `passwordHistoryLimit` (number, previous passwords disallowed)
- Settings category: `auth` (Admin UI → Settings → Authentication)
  - `mode` ("session" | "jwt")
  - `google` (boolean)
  - `github` (boolean)

Environment fallback (used only when DB settings are absent):

- `LOGIN_IP_WINDOW_MS`, `LOGIN_IP_LIMIT`
- `LOGIN_LOCK_WINDOW_MS`, `LOGIN_LOCK_THRESHOLD`, `LOGIN_LOCK_DURATION_MS`
- `PASSWORD_HISTORY_LIMIT`
- `REFRESH_DAYS`, `EMAIL_VERIFICATION_TTL_MIN`, `PASSWORD_RESET_TTL_MIN`

Behavior overview:

- Login: checks active locks, enforces per-IP throttling and per-user failed-attempt lockouts based on configured windows/thresholds; denies login until email is verified when required.
- Reset password: denies reuse of the most recent N passwords and records password history; if previously unverified, marks email as verified upon a successful reset.
- Admin lock/unlock: manual lock creates/updates lock with reason and optional expiration; unlock clears lock, revokes sessions, and dispatches a password reset email.

## Scripts

Backend:
- `npm run dev` — Start API with nodemon/ts-node
- `npm test` — Run Jest tests
- `npm run seed` — Seed local database

Frontend:
- `npm run dev` — Start Vite dev server
- `npm run build` — Type-check and build for production
- `npm run preview` — Preview built frontend
- `npm test` — Run Vitest unit tests

## Testing

- API tests live under `backend/src/tests` using Jest + SuperTest (auth, lockout, password history, RBAC, rate limits)
- Frontend uses Vitest + Testing Library with jsdom; see tests in `frontend/src/lib/*.test.tsx` and `frontend/src/pages/admin/*.test.tsx`

## Troubleshooting

- If `npm run dev` in frontend fails immediately, run `npm ci` in `frontend/` and retry.
- Ensure the backend is running on port 4000; the frontend proxies assume this. You can change the target in `frontend/vite.config.ts`.
- ReDoc search requires serving the spec from the same origin (the Vite proxy handles this in dev). If you change the path, update `specUrl` in `frontend/src/docs/redoc-page.tsx`.

## Changelog

See `CHANGELOG.md`. Recent:
- 0.4.0 (2025-10-16) — Security: account lockout and password history; Admin UI for Roles/Permissions/Users; Settings overrides
- 0.3.1 (2025-10-05) — Readme and Release Please docs
- 0.3.0 (2025-10-05) — Frontend header improvements and docs

## V1.0.0 checklist

See `V1.0.0-CHECKLIST.md` for the authoritative list of tasks required to ship V1.0.0. Open issues and PRs should reference the corresponding checklist items.

## Release notes

Latest releases (2025-10-05):
- Root: v0.3.0 — https://github.com/BoldNight153/PetShelterRegistrySystem/releases/tag/v0.3.0
- Backend: backend-v0.1.0 — https://github.com/BoldNight153/PetShelterRegistrySystem/releases/tag/backend-v0.1.0
- Frontend: frontend-v1.0.0 — https://github.com/BoldNight153/PetShelterRegistrySystem/releases/tag/frontend-v1.0.0

## Release automation (Release Please)

This repo uses Release Please in monorepo mode with three packages:

- Root (".") — simple strategy, aggregated `CHANGELOG.md` at the repo root, tag format `vX.Y.Z`.
- Backend — Node strategy, per-package `backend/CHANGELOG.md`, tag format `backend-vX.Y.Z`.
- Frontend — Node strategy, per-package `frontend/CHANGELOG.md`, tag format `frontend-vX.Y.Z`.

How it works:
- A workflow runs on pushes to `main` (or via manual dispatch) and opens a release PR from `release-please--branches--main`.
- The PR is labeled `autorelease: pending`. Merging it creates Git tags and GitHub Releases for the affected packages.
- Versions are tracked in `.release-please-manifest.json`.

Notes and tips:
- Root release PR titles use `chore: release ${version}` (component omitted on purpose for readability).
- If you change Release Please config after a release PR is already open, close that PR and delete the branch `release-please--branches--main`, then re-run the workflow to regenerate with the new settings.
- To manually re-run the workflow:

```bash
gh workflow run release-please

### OpenAPI version alignment (CI validation)

- A GitHub Action `.github/workflows/validate-openapi.yml` runs on PRs/pushes to `main`.
- It executes `npm run validate:openapi` under `backend/`, which checks that
  `src/openapi-*.yaml` each have `info.version` equal to the backend `package.json` version.
  If there's drift, the job fails with a clear message.
```

## Project management

We use a repo-level GitHub Project to plan and track work with milestones, issues, and PRs.

- Project board: https://github.com/users/BoldNight153/projects/3
- Milestones: One per release (vX.Y.Z). Issues and PRs should be assigned to a milestone.
- Labels: See `.github/labels.yml` for the scheme: `type:*`, `area:*`, `priority:*`, `docs`, `triage`.
- Issues: Use templates (bug, feature, task). All issues auto-assign to the repo owner.
- PRs: Use the PR template; link issues (e.g., `Closes #123`) and pick a milestone.

Automation
- Auto-add issues/PRs to the Project (requires two repo secrets):
  - `PROJECT_URL` – Your GitHub Project URL (e.g., https://github.com/users/BoldNight153/projects/3)
  - `PROJECTS_TOKEN` – Classic PAT with scopes: `repo`, `project` (or fine-grained token with write to this repo and Projects)
  - Add secrets: Repo → Settings → Secrets and variables → Actions → New repository secret
- Auto-assign issues/PRs to the repo owner
- Release Please bot automates version bumps, changelog entries, and tags

# Changelog

All notable changes to this repository will be documented in this file.

## [Unreleased]

### Tests

- Backend: expanded `admin.authenticators` suite now verifies `includeArchived` filtering and enforces RBAC on catalog mutations; `admin.settings` continues to cover auth payload normalization.
- Frontend: added `src/hooks/useAuthenticatorCatalog.test.tsx` to guarantee React Query calls include/exclude archived presets correctly, complementing the existing Admin Settings page coverage.

### Documentation

- Updated `backend/README.md`, `frontend/README.md`, and `ARCHITECTURE.md` with the new regression expectations plus the release reminder to rerun `npm run seed` whenever authenticator catalog presets change.

## [0.4.0](https://github.com/BoldNight153/PetShelterRegistrySystem/compare/v0.3.1...v0.4.0) (2025-10-16)

### Features

- Auth security hardening: persisted account lockout and password history enforcement
  - Auto-lock user after N failed logins within a window; unlock after configured duration
  - Manual lock/unlock via admin with audit logging and session revocation; unlock triggers password reset email
  - Password reset denies reuse of the last N passwords (including current)
- Admin UI
  - Roles/Permissions management (grant/revoke), user role assignment
  - Users management: search, view lock status, lock/unlock
  - Settings (General, Monitoring, Authentication, Documentation, Security)
  - Admin-only API docs (system_admin gating)

### Settings and configuration

- Database-driven settings override env vars at runtime (category `security`):
  - `requireEmailVerification`, `sessionMaxAgeMin`, `loginIpWindowSec`, `loginIpLimit`, `loginLockWindowSec`, `loginLockThreshold`, `loginLockDurationMin`, `passwordHistoryLimit`
- Additional `auth` category keys: `mode`, `google`, `github`
- Environment fallbacks when DB settings are absent: `LOGIN_IP_WINDOW_MS`, `LOGIN_IP_LIMIT`, `LOGIN_LOCK_WINDOW_MS`, `LOGIN_LOCK_THRESHOLD`, `LOGIN_LOCK_DURATION_MS`, `PASSWORD_HISTORY_LIMIT`, `REFRESH_DAYS`, `EMAIL_VERIFICATION_TTL_MIN`, `PASSWORD_RESET_TTL_MIN`

### Tests

- Backend: New Jest suites covering auto-lockout, manual lock/unlock, password history, RBAC edges, and rate limit boundaries
- Frontend: Vitest tests for Admin Settings (security thresholds save) and Admin Users (lock/unlock interaction)

### Docs

- README updated with Security + Admin UI overview, settings keys, behavior, and testing notes

## [0.3.1](https://github.com/BoldNight153/PetShelterRegistrySystem/compare/v0.3.0...v0.3.1) (2025-10-05)


### Documentation

- **readme:** add Releases badge and explain Release Please monorepo tagging ([#28](https://github.com/BoldNight153/PetShelterRegistrySystem/issues/28)) ([97ade6d](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/97ade6dcbfbbe5a5722772014ac346e8e7fece88))

## [0.3.0](https://github.com/BoldNight153/PetShelterRegistrySystem/compare/v0.2.1...v0.3.0) (2025-10-05)


### Features

- **frontend/header:** Mobile-only Team Switcher in sticky header ([e12d4ab](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/e12d4ab8ced5dd547e321397f94e8319f5328166))
- **frontend/header:** show Team Switcher in sticky header on mobile only; docs: add root README and changelog entry ([6c78bc8](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/6c78bc85bc206490b5f17b5b14cf6bb3708b2da1))


### Documentation

- bump versions to v0.2.1, add PR/release notes artifacts ([8fa645c](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/8fa645c7dbeb1613dafbe5fc48ab279a7974f3a9))
- **changelog:** add v0.2.0 release section ([fe5174c](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/fe5174c03cb26e35c54574de6668cd48325cbfeb))
- **readme:** link repo Project board ([a89dcd4](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/a89dcd47eea49a512dbb9d194a6b88e58c3142c5))

## [0.2.1] - 2025-10-04

- feat(frontend/header): Show Team Switcher in the sticky header on small/mobile viewports and hide it on larger screens (md and up)
- docs: Add comprehensive root README with project overview, local dev setup, theming, API docs, and troubleshooting

## [0.2.0] - 2025-10-03

- feat(frontend): Replace legacy frontend with new Vite + React 19 + Tailwind v4 app
- docs(frontend): Add ReDoc documentation page with app-themed light/dark, fixed search via specUrl and Vite proxy
- feat(frontend): Sticky header with user menu (API status, theme toggle light/system/dark), improved mobile UX
- chore(repo): Remove deprecated frontend, update .gitignore, and general cleanup

## [0.1.0] - 2025-09-28

- Merged PR #8: chore(ci): add full API routes, seed, CI and cleanup
  - Added TypeScript backend with Prisma schema, migrations, seed script
  - Implemented CRUD routes (shelters, locations, pets, owners, pet-owners, medical, events)
  - Added Zod validation, pino logging, Jest + SuperTest tests, and a GitHub Actions CI workflow
  - Cleaned repository history and removed tracked node_modules and dev.db from source control

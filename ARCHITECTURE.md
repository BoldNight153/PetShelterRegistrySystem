# Architecture

## System overview

Monorepo that pairs an Express 5 backend (`backend/`) with a Vite 7 + React 19 frontend (`frontend/`). SQLite powers local development through Prisma, while the HTTP API is the single source of truth for OpenAPI specs served to the frontend docs route. Backend settings are stored in the database first with environment-variable fallbacks, so configuration changes must be reflected in both Prisma seeds and the Admin Settings UI.

```text
backend/src            # Express API, Awilix DI container, routes, middleware, services
backend/prisma         # Schema, migrations, and seed scripts (ts-node)
frontend/src           # React app with ServicesProvider DI + shadcn/Tailwind UI
frontend/src/services  # Interfaces + adapters that call backend via src/lib/api.ts
.devtools/             # Chrome MCP and Playwright capture helpers for auth/cookie flows
```

## Backend architecture (Express + Awilix + Prisma)

- **Entry point**: `backend/src/index.ts` wires global middleware, mounts routers under `/pets`, `/admin`, etc., and defers request-scoped resolution to Awilix via `scopePerRequest(container)`.
- **DI container**: `backend/src/container.ts` registers Prisma and all services (`UserService`, `AuthService`, `MenuService`, etc.) as singletons; request handlers resolve them via awilix-express.
- **Routing layers** (`backend/src/routes/*.ts`): thin route modules import Awilix-scoped services, run validation, and emit JSON responses. All admin routes enforce RBAC through `parseAuth` + `requireRole` middleware from `backend/src/middleware/auth.ts`.
- **Settings precedence**: configuration lives in `setting` rows (category/key) and overrides env vars. When adding auth/rate-limit knobs, update Prisma seeds plus the Admin Settings UI so overrides stay consistent.
- **Authentication settings + authenticator catalog**: `SettingsService` leans on `AuthenticatorCatalogService` to normalize the `auth` category (mode, OAuth toggles, MFA enforcement, and ordered authenticator IDs). The `/admin/settings` route preserves unknown IDs for cleanup, while `/admin/authenticators` handles catalog CRUD + archive/restore with RBAC guards. Jest suites (`admin.settings.test.ts`, `admin.authenticators.test.ts`) now enforce that archived entries stay hidden unless `includeArchived=true` and that non-admins cannot mutate the catalog.
- **Security**: cookie-based auth with CSRF double-submit, per-IP rate limiting (middleware + `RateLimitService`), password history, and account lockouts. `AuthService` orchestrates login/refresh flows and ensures audit logging via `AuditService`.
- **Account security snapshots**: `SecurityService` aggregates password history, refresh tokens, audit logs, and security settings to serve `/auth/security`, `/auth/security/sessions`, persists recovery updates through `/auth/security/recovery`, stores alert preferences via `PUT /auth/security/alerts`, and handles password rotations via `POST /auth/security/password` so the Account → Security dashboard stays in lockstep with backend policy enforcement. Security alerts remain mirrored in the snapshot for read-only visibility, but all editing flows now run through `NotificationService`.
- **Notification preferences**: `NotificationService` normalizes per-user notification metadata (topics, digests, quiet hours, critical escalations, devices), migrates legacy security alert data, mirrors security topics back into `metadata.security.alerts`, and powers the GET/PUT `/auth/notifications` endpoints consumed by the Account → Notifications page. Hardware/browser push registrations land in the Prisma `NotificationDeviceRegistration` table so trusted devices can outlive metadata migrations and are exposed through `POST /auth/notifications/devices/register` + `DELETE /auth/notifications/devices/:id` for the frontend to add/remove push endpoints.
- **Monitoring & docs**: metrics endpoints (`/admin/monitoring/*`) expose request stats captured in `index.ts`. OpenAPI YAML files (`src/openapi-*.yaml`) are copied during `npm run build` and served via `mountPublicDocs`/`mountAdminDocs`, all gated behind `system_admin`.
- **Data layer**: Prisma schema/migrations live under `backend/prisma/`. Seeds (`prisma/seed.ts`) create baseline roles, menus, and settings; use `npx prisma migrate dev` followed by `npm run seed` whenever schema changes.

## Frontend architecture (Vite + React 19)

- **Bootstrap**: `frontend/src/main.tsx` renders `App` within `ServicesProvider`, which merges runtime service overrides with `defaultServices` (`frontend/src/services/defaults.ts`).
- **Service interfaces**: Types in `frontend/src/services/interfaces/*` define contracts for UI code. Implementations live in `frontend/src/services/impl/*` and only call HTTP helpers from `frontend/src/lib/api.ts`.
- **Runtime boundary**: `src/lib/api.ts` centralizes fetch logic, CSRF handling, refresh retries, and admin endpoints. UI components never import `fetch` directly—always go through a service.
- **State & layout**: Admin pages under `frontend/src/pages/admin/*`, shared components in `frontend/src/components/*`, dashboard widgets in `frontend/src/dashboard/*`. Tailwind v4 tokens + shadcn/Radix primitives ensure consistent styling.
- **Notifications workspace**: `frontend/src/pages/settings/account/notifications.tsx` consumes the `NotificationService` hooks to manage default channels, topic overrides, digests, quiet hours, escalations, and trusted devices. It is now the single place to edit security alert delivery, and it mirrors changes back to the Security snapshot for parity.
- **Docs route**: `/docs` renders ReDoc via `src/docs/redoc-page.tsx`, consuming backend `/api-docs` (proxied through Vite). Update spec URLs here if backend paths change.
- **Admin authentication UI**: `frontend/src/pages/admin/settings.tsx` renders the refreshed Authentication tab. React Query hooks (`src/hooks/useAuthenticatorCatalog.ts`) resolve catalog entries (active vs archived) through the admin service interface, and Vitest coverage ensures the hooks keep returning the right sets when toggling the archive filter.

- **Account security flows**: `frontend/src/pages/settings/account/security.tsx` renders the Account & Profile ➝ Security experience backed by the `security` service contract (`types/security-settings.ts`, `services/interfaces/security.interface.ts`, hooks in `services/hooks/security.ts`). Password, MFA, session, and recovery actions remain fully editable here, while the alert section is now read-only with CTAs into Notifications so the entire delivery stack lives in one workspace. Pending MFA enrollments from the snapshot drive UI affordances (status badges, disabled actions, and a resume CTA) so partially completed rotations survive reloads, and the resumable dialog now reiterates the authenticator label/catalog/expiry pulled from the backend ticket so operators know exactly which rotation they are confirming.

- **MFA naming + per-app enforcement**: Users pick a friendly authenticator name (Google, Microsoft, Authy, 1Password, or custom) before the QR code renders. The picker passes `{ label, issuer }` into `SecurityService.startTotpEnrollment`, and the backend auto-rotates the existing factor whenever the normalized label already exists so only one secret per authenticator provider stays active. Pending rotations surface through `pendingEnrollment`, which the frontend uses to freeze destructive controls and expose an "Enter code to finish" flow that reuses the backend ticket even after a refresh. Hard deletes call `DELETE /auth/security/mfa/:factorId` behind a trash-can confirmation on the security page, complementing the existing “Disable” soft toggle.

## Workflow & quality gates

- **Backend dev loop**: `cd backend && cp -n .env.example .env && npm ci && npx prisma generate && npx prisma migrate dev --name init && npm run seed && npm run dev` (port 4000). Tests via `npm test` (Jest + SuperTest). `npm run validate:openapi` must pass before committing OpenAPI edits.
- **Frontend dev loop**: `cd frontend && npm ci && npm run dev` (Vite on 5173). Use `npm run typecheck` and `npm test` (Vitest + RTL) before PRs.
- **CI parity**: VS Code task **Typecheck & test both apps** runs backend build/tests plus frontend typecheck/tests; keep it green before opening PRs.
- **Devtools**: `devtools/devtools-mcp-client.js` (Chrome MCP) and `devtools/playwright/record-and-capture.js` capture auth/cookie issues. Run them after modifying CSRF/session flows to verify Set-Cookie + refresh behavior.

## Extension guidelines

- Register new backend services in `src/container.ts`, expose them through Awilix, and guard admin endpoints with `requireRole`.
- When touching backend settings or feature flags, update Prisma seed data and Admin Settings UI forms to stay in sync.
- Keep frontend components consuming only service interfaces; inject overrides in tests via `ServicesProvider`.
- Update OpenAPI YAMLs alongside route changes, then re-run `npm run validate:openapi` to ensure `info.version` matches `backend/package.json`.
- Document structural shifts in this file and mirror instructions in `.github/copilot-instructions.md` so AI agents follow the same architecture.

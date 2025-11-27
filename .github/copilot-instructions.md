<!-- Auto-generated todo section -->
<!-- Add your custom Copilot instructions below -->

# PetShelterRegistrySystem — AI agent quickstart

## System map
- Monorepo pairing `backend/` (Express 5 + Awilix + Prisma on SQLite) with `frontend/` (Vite 7 + React 19 + ServicesProvider DI). Backend OpenAPI specs (`backend/src/openapi-*.yaml`) feed the frontend ReDoc page.
- Configuration lives in DB `settings` rows first, env vars second. Keep Prisma seeds, Admin Settings UI, and docs aligned whenever you add/change a toggle.

## Backend essentials
- Entry point `backend/src/index.ts` wires helmet/cors/cookies, mounts routers, exposes monitoring/docs, and attaches `scopePerRequest(container)` from `backend/src/container.ts`.
- Middleware `parseAuth` + `requireRole` (`backend/src/middleware/auth.ts`) enforce cookie auth + RBAC; every admin or docs route must stay behind at least `system_admin`.
- Business logic lives in `backend/src/services/*` and is registered in the Awilix container; route files stay thin and resolve services from the request scope. Never import Prisma directly in routes.
- OpenAPI YAMLs are the source of truth; run `npm run validate:openapi` after editing specs or routes to ensure `info.version` matches `backend/package.json`.
- Metrics + retention live right in `index.ts` and Prisma `metricPoint`. Preserve `/admin/monitoring/*` responses—they drive Admin UI charts.

## Frontend essentials
- React bootstraps through `frontend/src/services/provider.tsx`; UI components talk only to service interfaces from `frontend/src/services/interfaces/*`, implemented via adapters under `frontend/src/services/impl/*` that call `src/lib/api.ts`.
- Admin UI pages belong in `frontend/src/pages/admin/*`, shared primitives in `src/components/*`, dashboards in `src/dashboard/*`. Stick to Tailwind v4 tokens and shadcn/Radix building blocks already in use.
- `/docs` (ReDoc) lives in `frontend/src/docs/redoc-page.tsx` and expects backend `/api-docs` proxies. Update both sides together when spec paths change.

## Critical workflows
- Backend dev: `cd backend && cp -n .env.example .env && npm ci && npx prisma generate && npx prisma migrate dev --name init && npm run seed && npm run dev` (port 4000). Tests: `npm test`; spec check: `npm run validate:openapi`.
- Frontend dev: `cd frontend && npm ci && npm run dev` (port 5173). Typecheck via `npm run typecheck`; tests via `npm test` (Vitest + RTL).
- VS Code task **Typecheck & test both apps** mirrors CI (backend build/test, frontend typecheck/test). Run it before opening PRs.

## Debug & tooling
- Use `devtools/devtools-mcp-client.js` (Chrome MCP) or `devtools/playwright/record-and-capture.js` after changing CSRF/session flows to capture Set-Cookie + refresh traces.
- Navigation menus: `/admin/menus/*` drives admin CRUD while `/menus` serves public trees. Keep the nested `children` shape returned by `src/lib/api.ts` helpers intact for frontend rendering.
- Authentication helpers in `frontend/src/lib/api.ts` own CSRF fetching, login retries, and refresh polling. UI code must not bypass them.

## Data & schema workflow
- Prisma schema lives in `backend/prisma/schema.prisma`. When you add/change tables, run `npx prisma migrate dev --name <slug>` followed by `npm run seed` so dev DB + settings rows stay current.
- Seed logic resides in `backend/prisma/seed.ts`; keep it deterministic and idempotent. Matching comparison utilities (e.g., `backend/prisma/compare_seed_db.js`) assume IDs/names are stable.
- Settings, roles, menus, and monitoring defaults all originate from seeds—update them there whenever you alter related services or UI assumptions.

## Testing & validation
- Backend: `npm test` (Jest + SuperTest) under `backend/` covers services, middleware, and routes. Place new tests under `backend/src/tests/*` and keep them DI-friendly.
- Frontend: `npm test` (Vitest + RTL) lives under `frontend/src/**/*.test.tsx`. Use `ServicesProvider` overrides to stub adapters when writing UI tests.
- Lint/type safety: backend `npm run lint`, frontend `npm run typecheck`. Run `npm run validate:openapi` after route/spec changes to keep docs synchronized.

## Docs & release alignment
- Update `backend/README.md`, `frontend/README.md`, and `ARCHITECTURE.md` when workflows or module boundaries shift so future agents share the same mental model.
- OpenAPI YAML updates should include version bumps (matching `backend/package.json`) plus regenerated public assets if you modify `postbuild` copying behavior.
- Release Please uses the repo CHANGELOGs; when touching release flows or package versions, confirm `release-please-config.json` still targets the right packages before merging.

## Architecture & guardrails
- `ARCHITECTURE.md` is the authoritative system map—update it whenever you move files, add services, or tweak layering so future agents inherit the same structure.
- Settings changes require touching Prisma seeds, Admin Settings UI, and documentation in the same PR. DB rows override env vars.
- Register every new backend service in `backend/src/container.ts`, expose it via Awilix, and add Jest coverage under `backend/src/tests/*` plus OpenAPI updates.
- Frontend data work must update the relevant service interface, adapter, and tests under `frontend/src/services/__tests__/`. UI components should never import `src/lib/api.ts` directly.
- Any backend endpoint or settings change must ship with matching OpenAPI YAML edits and a rerun of `npm run validate:openapi` so docs and ReDoc stay in sync.

## Expectations for AI agents
- Prefer scoped changes per module and update related seeds, docs, specs, and tests together.
- Run the relevant npm scripts (or the combined VS Code task) after modifying runnable code and summarize results in PRs.
- Document new backend settings/flags in `backend/README.md`, Admin Settings UI copy, and `ARCHITECTURE.md` so operators know how to configure them.
- Keep service interfaces stable; when adding methods, ensure both backend implementations and frontend adapters align.
- Follow existing security patterns: cookie-based auth with CSRF double-submit, RBAC via middleware, rate limiting, and audit logging for sensitive actions.
- Use Agent TODOs extension tool for todo management and tracking of changes across the codebase. Do no use any other todo management system.
- Agent TODOs extension has the following tools you can use:
    - mcp_todos_todo_read
    - mcp_todos_todo_write
- if you want to use mcp_todos_todo_write you must use mcp_todos_todo_read first to read the existing todos.
- you may not remove items from a todo list or create a new list with out asking for permission first.
- you may add items to a list as needed.
- Do not remove items from the TODO list without completing them and having explicit approval to remove completed items from the list.
- use cmd.exe for all windows terminal commands
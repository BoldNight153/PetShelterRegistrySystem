# PetShelterRegistrySystem [![Releases](https://img.shields.io/github/v/release/BoldNight153/PetShelterRegistrySystem?sort=semver&label=Releases&logo=github)](https://github.com/BoldNight153/PetShelterRegistrySystem/releases)

A full-stack TypeScript project for a Pet Shelter Registry system featuring:

- Backend: Node.js + Express + Prisma + SQLite (dev) with Jest + SuperTest tests
- Frontend: React 19 + Vite 7 + TypeScript + Tailwind CSS v4 + shadcn/Radix UI
- API Documentation: ReDoc page themed to match the app, backed by the backend's OpenAPI spec and Vite proxy

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

## Theming and ReDoc

ReDoc is mounted in `frontend/src/docs/redoc-page.tsx` via dynamic import. The theme adapts to app mode (light/dark) and listens to `themechange` events. Dropdowns and code blocks have contrast tweaks for readability.

## API docs endpoints

- Public docs (OpenAPI + ReDoc): GET `/api-docs/latest` and JSON at `/api-docs/latest/openapi.json`
- Admin-only docs: GET `/api-docs/admin/latest` and JSON at `/api-docs/admin/latest/openapi.json`
  - Access requires a user with the `system_admin` role; routes are gated server-side. Enabled in all environments.

## Scripts

Backend:
- `npm run dev` — Start API with nodemon/ts-node
- `npm test` — Run Jest tests
- `npm run seed` — Seed local database

Frontend:
- `npm run dev` — Start Vite dev server
- `npm run build` — Type-check and build for production
- `npm run preview` — Preview built frontend

## Testing

- API tests live under `backend/src/tests` using Jest + SuperTest
- Frontend currently has manual testing guidance; feel free to add Vitest or Playwright

## Troubleshooting

- If `npm run dev` in frontend fails immediately, run `npm ci` in `frontend/` and retry.
- Ensure the backend is running on port 4000; the frontend proxies assume this. You can change the target in `frontend/vite.config.ts`.
- ReDoc search requires serving the spec from the same origin (the Vite proxy handles this in dev). If you change the path, update `specUrl` in `frontend/src/docs/redoc-page.tsx`.

## Changelog

See `CHANGELOG.md`. Recent:
- 0.2.1 (2025-10-04) — Mobile-only Team Switcher in header; documentation updates
- 0.2.0 (2025-09-28) — Backend foundation, routes, seeds, CI

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

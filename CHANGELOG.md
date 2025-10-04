# Changelog

All notable changes to this repository will be documented in this file.

## [0.2.0] - 2025-10-04

### Frontend swap
- Removed legacy `frontend/` implementation from version control.
- Promoted `test-frontend/` to the official app by renaming it to `frontend/` using `git mv` (history preserved).
- Updated app metadata and document title (package name: `frontend`, title: "PetShelter Frontend").
- Ensured build/cache artifacts are ignored (e.g., `frontend/.vite`, `frontend/dist`).

### Theme stability and ReDoc improvements
- Early theme initialization script in `frontend/index.html` applies `html.dark` and `data-theme` before React mounts to avoid flicker and keep theme stable across navigation.
- Removed forced default dark mode; the `ThemeToggle` now persists user choice (`localStorage('theme')`) and broadcasts a `themechange` event.
- ReDoc theming aligned to the app’s zinc palette with curated, hex-only light/dark themes.

### Search and contrast fixes
- ReDoc now consumes the spec via `specUrl` (`/api-docs/latest/openapi.json`) so built-in search indexing works.
- Scoped CSS improvements for readability and accessibility:
  - Higher-contrast headings/links and right panel styles
  - Improved tables, tabs, and code blocks (syntax tokens, spacing)
  - Dropdowns/portal menus with corrected z-index and overflow (scoped via `body[data-redoc]`)

### CI and scripts
- No CI jobs directly referenced `test-frontend/`; no action required.
- Note: any local scripts referencing `test-frontend` should be updated to `frontend`.

## [0.1.0] - 2025-09-28
- Merged PR #8: chore(ci): add full API routes, seed, CI and cleanup
  - Added TypeScript backend with Prisma schema, migrations, seed script
  - Implemented CRUD routes (shelters, locations, pets, owners, pet-owners, medical, events)
  - Added Zod validation, pino logging, Jest + SuperTest tests, and a GitHub Actions CI workflow
  - Cleaned repository history and removed tracked node_modules and dev.db from source control

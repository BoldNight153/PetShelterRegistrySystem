# Changelog

All notable changes to this repository will be documented in this file.

## [0.2.1] - 2025-10-04
- feat(frontend/header): Show Team Switcher in the sticky header on small/mobile viewports and hide it on larger screens (md and up)
- docs: Add comprehensive root README with project overview, local dev setup, theming, API docs, and troubleshooting

## [0.1.0] - 2025-09-28
- Merged PR #8: chore(ci): add full API routes, seed, CI and cleanup
  - Added TypeScript backend with Prisma schema, migrations, seed script
  - Implemented CRUD routes (shelters, locations, pets, owners, pet-owners, medical, events)
  - Added Zod validation, pino logging, Jest + SuperTest tests, and a GitHub Actions CI workflow
  - Cleaned repository history and removed tracked node_modules and dev.db from source control

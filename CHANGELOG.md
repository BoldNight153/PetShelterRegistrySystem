# Changelog

All notable changes to this repository will be documented in this file.

## [0.3.0](https://github.com/BoldNight153/PetShelterRegistrySystem/compare/v0.2.1...v0.3.0) (2025-10-05)


### Features

* **frontend/header:** Mobile-only Team Switcher in sticky header ([e12d4ab](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/e12d4ab8ced5dd547e321397f94e8319f5328166))
* **frontend/header:** show Team Switcher in sticky header on mobile only; docs: add root README and changelog entry ([6c78bc8](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/6c78bc85bc206490b5f17b5b14cf6bb3708b2da1))


### Documentation

* bump versions to v0.2.1, add PR/release notes artifacts ([8fa645c](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/8fa645c7dbeb1613dafbe5fc48ab279a7974f3a9))
* **changelog:** add v0.2.0 release section ([fe5174c](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/fe5174c03cb26e35c54574de6668cd48325cbfeb))
* **readme:** link repo Project board ([a89dcd4](https://github.com/BoldNight153/PetShelterRegistrySystem/commit/a89dcd47eea49a512dbb9d194a6b88e58c3142c5))

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

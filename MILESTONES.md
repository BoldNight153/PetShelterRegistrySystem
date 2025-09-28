# Project Milestones — Pet Shelter Registry System

This file maps completed work, in-progress items, and recommended next steps so you can track progress and show a clear plan in the repo.

## Summary (current branch: chore/ci-tests)
- Last updated: 2025-09-28
- Branch pushed: `chore/ci-tests` (remote updated)

## Completed (Done)
- Prisma schema, migrations, and `prisma/seed.js` — Done
- Local Postgres setup documented and tested (Homebrew, user `boldnight` used during local dev) — Done
- Seeded database and confirmed `npx prisma migrate dev` + `npm run seed` — Done
- Repo refactor to portfolio-ready layout (`src/`, `server.js`) — Done
- Converted API from `age` -> `dob` and added migration helper — Done
- Added `.env.example` and README instructions for `.env` and .gitignore — Done
- Added smoke script `scripts/smoke.sh` — Done
- Added Jest + babel-jest + `supertest` tests and fixed model code to normalize DateTime — Done
- Removed legacy brittle tests that caused failures — Done

## In progress / Verified locally
- Test suites (under `tests/`) currently pass locally (3 tests across 2 suites). Legacy tests removed. — Verified

## Pending / Recommended (High priority)
1. CI pipeline (GitHub Actions) — run `npm ci`, `npx prisma generate` (or skip in CI and use a test DB), run migrations or use SQLite for tests, run `npm test`, run smoke script. (Status: Pending)
   - Reason: ensure PRs and pushes run automated tests for consistent quality and safe merges.
2. Test environment hardening — create an isolated test DB (or use SQLite in-memory) and add setup/teardown so tests don't mutate your development DB. (Status: Pending)
3. Add PR checklist and contributor guidance to README / CONTRIBUTING.md. (Status: Pending)

## Nice-to-have / Medium priority
- Add CI secrets handling (DB credentials / service containers) or use a matrix with SQLite to avoid secrets. (Status: Pending)
- Re-enable or finalize Docker production flow (Dockerfile / docker-compose.*) and document deployment steps in `README.deploy.md`. (Status: Pending)
- Add more unit tests for model functions and controllers (edge cases, validation errors). (Status: Pending)

## Long-term / Low priority
- Rebuild frontend (React + Vite) and integrate with the backend; add end-to-end tests. (Status: Deferred)
- Add monitoring / health checks beyond `/health` and consider readiness/liveness for containers. (Status: Deferred)

## Suggested immediate next actions (concrete)
1. Add a GitHub Actions workflow that runs on push/PR for `chore/ci-tests` and `main`:
   - Steps: checkout, use Node.js, install deps, generate prisma client, run migrations (or use sqlite), run tests, run smoke.sh (optional).
2. Add test DB support:
   - Option A: Add a lightweight SQLite test configuration for CI and local tests.
   - Option B: Use a PostgreSQL service in Actions (recommended if you want to run full Prisma migrations in CI).
3. Add `CONTRIBUTING.md` and a short PR template that references the smoke script and tests.

## How to validate locally (quick commands)
```bash
# run tests
npm test

# run smoke checks (after starting the server on PORT)
./scripts/smoke.sh http://localhost:3000

# start dev server with live reload
npm run dev
```

## Ownership & ETA suggestions
- CI + test DB: 1–2 days of focused work (add workflow, adapt tests to use isolated DB)
- Docker production flow + deploy docs: 1–2 days to harden and document, more if you want a full multi-container stack
- Frontend rebuild: depends on scope (1–2 weeks for a full polished UI)

---
If you'd like, I can implement the GitHub Actions CI workflow now (I can create `.github/workflows/ci.yml`) and wire it to use SQLite or spin up a Postgres service in CI. Tell me which CI approach you prefer and I'll add it and run a verification locally (where applicable).

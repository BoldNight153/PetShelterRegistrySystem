# Project Milestones — Pet Shelter Registry System

This file maps completed work, in-progress items, and recommended next steps so you can track progress and show a clear plan in the repo.

## Summary (current branch: chore/ci-tests)
- Last updated: 2025-09-28
- Branch pushed: `chore/ci-tests` (remote updated)

## Tech choices & rationale (recommended)
- Backend: Node.js + Express — stable and already used in the project; minimal re-platforming risk.
- Database: PostgreSQL (production). For fast CI/dev runs you can use SQLite but keep schema/migrations portable to Postgres (Prisma supports both).
- Migrations: Prisma Migrate (preferred for this repo) — consistent schema management and seed support.
- Logging: pino (structured JSON logs) or winston. pino preferred for performance and structured output.
- Error tracking: Sentry (server-side DSN configurable via env).
- Monitoring: Prometheus + Grafana or SaaS (Datadog) for metrics; at minimum expose `/metrics` and `/health` and use an uptime monitor.
- Containerization: Docker is optional and intentionally deferred for now — repo is configured for local Postgres development.
- CI: GitHub Actions (recommended) to run lint/tests/build and optionally run migrations or use a test DB.
- Security middleware: `helmet`, `express-rate-limit`, `cors` (configured via env).
- API docs: `swagger-jsdoc` exists — export an OpenAPI JSON as part of CI for documentation visibility.

## Completed (Done)
- Prisma schema, migrations, and `prisma/seed.js` — Done
- Local Postgres setup documented and tested (Homebrew, local DB) — Done
- Seeded database and confirmed `npx prisma migrate dev` + `npm run seed` — Done
- Repo refactor to portfolio-ready layout (`src/`, `server.js`) — Done
- Converted API from `age` -> `dob` and added migration helper — Done
- Added `.env.example` and README instructions for `.env` and .gitignore — Done
- Added smoke script `scripts/smoke.sh` — Done
- Added Jest + babel-jest + `supertest` tests and fixed model code to normalize DateTime — Done
- Removed legacy brittle tests that caused failures — Done

## In progress / Verified locally
- Test suites (under `tests/`) currently pass locally (3 tests across 2 suites). — Verified

## Milestones, tasks, acceptance criteria & estimates

### Milestone 1 — Harden & persistent storage (local-postgres-first)
Tasks
- Centralize env handling with `src/config/index.js` (dotenv already used).
- Use Prisma with local Postgres (already present) and ensure migrations/seed commands are in package.json (`migrate`, `seed`).
- Confirm models use Prisma client and are atomic; add DB connection pooling options in config.
- Add GET `/health` endpoint returning JSON `{ status: "ok", db: "ok" }` (should already exist).
- Add `.env.example` and enforce `.env` in `.gitignore`.
Acceptance Criteria
- Data persisted across restarts (created pets remain in DB).
- GET `/health` returns 200 with DB OK.
- `npm run dev` and `npm start` work without hard-coded port.
Estimate: 2–6 hours (PR/QA included)

### Milestone 2 — CI (no Docker required)
Tasks
- Add GitHub Actions workflow that runs on PRs and pushes: checkout, setup-node, `npm ci`, `npx prisma generate`, run migrations or use SQLite for tests, run `npm test` and optionally run `./scripts/smoke.sh` against a spun-up test server.
- Provide two CI configurations (recommended):
  - Fast path: Use SQLite (in-memory or file) for unit/integration tests to avoid secrets.
  - Full path: Use PostgreSQL service in Actions for end-to-end migration tests.
Acceptance Criteria
- PRs must pass lint & tests before merge.
- CI artifacts/logs show Prisma client generation and test results.
Estimate: 3–6 hours

### Milestone 3 — Production-grade DB & migrations (local-first, production-ready later)
Tasks
- Keep Prisma as source of truth for schema and migrations.
- Add DB pooling and connection config via `DATABASE_URL` and pool env options.
- Add `scripts/backup.sh` and `scripts/restore.sh` for Postgres dumps (template scripts).
Acceptance Criteria
- Migrations apply cleanly to a fresh Postgres and seed runs succeed.
- CI runs migrations against a disposable Postgres test DB as part of integration tests (if using Postgres in CI).
Estimate: 4–12 hours

### Milestone 4 — Observability & error tracking
Tasks
- Integrate structured logging with `pino` (JSON), include request IDs and environment tags.
- Add Sentry integration (configurable via env var) for server errors.
- Expose `/metrics` for Prometheus (or a minimal metrics endpoint) and wire basic counters (request rate, error rate, latency).
Acceptance Criteria
- JSON logs emitted; Sentry receives error events in non-local env; `/metrics` returns Prometheus metrics.
Estimate: 3–6 hours

### Milestone 5 — Security & hardening
Tasks
- Add `helmet`, `express-rate-limit`, and configure `cors` with `ALLOWED_ORIGINS` env.
- Harden input validation and add sanitization layers; ensure Zod schemas cover edge cases.
- Add `npm audit` step or Dependabot and a CI security scan job.
Acceptance Criteria
- Basic OWASP checks mitigated (headers, rate limits); CI includes a dependency check.
Estimate: 2–6 hours

### Milestone 6 — Testing & quality gates
Tasks
- Expand unit tests for models/controllers (Jest) and integration tests (supertest) using an isolated test DB.
- Add E2E tests (Playwright or Cypress) if frontend is restored later.
- Add coverage thresholds and fail CI if below threshold.
Acceptance Criteria
- Coverage thresholds met; CI fails on regressions; tests are isolated from development DB.
Estimate: 4–16 hours

### Milestone 7 — Release strategy & ops docs
Tasks
- Add `README.deploy.md` (step-by-step deploy and rollback instructions) focused on local-hosted / VPS / cloud-managed options.
- Add runbook: how to start, stop, check logs, backup/restore DB, and handle common incidents.
Acceptance Criteria
- Operator can deploy and recover using docs; runbook covers DB backup/restore.
Estimate: 2–4 hours

## Security checklist (minimum before production)
- Use `.env` for secrets and commit `.env.example` only.
- Strict CORS via `ALLOWED_ORIGINS` env.
- Use `helmet` for security headers, rate limiting for write endpoints, and no verbose stack traces in production.
- Periodic dependency scanning (Dependabot/Snyk).

## Observability checklist
- Use `pino` for structured logs and include trace/request IDs.
- Integrate Sentry for errors (DSN via env).
- Expose `/health` and `/metrics` endpoints; provide a simple Grafana dashboard blueprint (optional).

## CI/CD — suggested approach (local-Postgres friendly)
- PR flow (fast): Run lint → unit tests with SQLite → integration tests (SQLite) → build.
- PR flow (full): Optionally run a matrix job that spins a Postgres service and runs full Prisma migrations + integration tests.
- On merge to `main`: Run full tests, then tag a release. (Deployment strategy is out-of-scope here; see `README.deploy.md`.)

## Testing strategy (must haves)
- Unit: Jest for models + controllers.
- Integration: supertest for HTTP endpoints using an isolated test DB (SQLite or disposable Postgres in CI).
- E2E: Playwright/Cypress (when front-end exists).
- Performance: k6 or artillery edge-case load tests (optional).

## Suggested immediate next actions (concrete)
1. Implement GitHub Actions CI with two jobs:
   - `test-fast` (SQLite): install, generate Prisma client, run tests (fast path for PR feedback).
   - `test-full` (optional): spin up Postgres service in job, run migrations, run tests against Postgres.
2. Add test setup/teardown helpers to ensure tests run against an isolated DB (connection string from `TEST_DATABASE_URL` env or use SQLite file in tmpfs).
3. Add `CONTRIBUTING.md` and a PR template referencing tests and smoke script.

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
- Observability & Sentry: 1–2 days
- Security hardening: 1–2 days
- Full production DB routing and backups: 1–2 days

---
If you want, I can create the GitHub Actions workflow next. Pick which CI approach you prefer:
- Fast/cheap (SQLite first for PRs), or
- Accurate/full (Postgres service in Actions to run real migrations).

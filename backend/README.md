# Pet Shelter Backend

Run locally:

1. Copy `.env.example` to `.env` and adjust as needed, or use the provided `.env` for local dev.
2. Install dependencies:

```bash
npm install
```

1. Generate Prisma client and run migrations (creates `dev.db`):

```bash
npx prisma generate
npx prisma migrate dev --name init
```

1. Seed the database:

```bash
npm run seed
```

1. Run in dev mode:

```bash
npm run dev
```

Run tests (Jest + SuperTest):

```bash
NODE_ENV=test npm test
```

## OAuth provider setup (dev)

1. Copy `.env.example` to `.env` and fill in:

- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`
- `GOOGLE_REDIRECT_URI` (default: `http://localhost:4000/auth/oauth/google/callback`)
- `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET`
- `GITHUB_REDIRECT_URI` (default: `http://localhost:4000/auth/oauth/github/callback`)
- `OAUTH_SUCCESS_REDIRECT` (default: `http://localhost:5173/`)
- `OAUTH_FAILURE_REDIRECT` (default: `http://localhost:5173/login?error=oauth_failed`)

1. Configure allowed callback URLs in the providers’ dashboards to match the redirect URIs above.

1. Ensure the frontend dev server runs on `http://localhost:5173` (Vite default) and the backend on `:4000`.

1. Enable providers via Admin Settings (`auth.google = true`, `auth.github = true`).

Then visit `/auth/oauth/google/start` or `/auth/oauth/github/start` from the browser.

CI notes

- The repository contains a GitHub Actions workflow at `.github/workflows/ci.yml` that installs dependencies, runs Prisma generate, applies migrations against a local sqlite file, runs the seed script, and runs tests.
- For production Postgres, set `DATABASE_URL` to your Postgres DSN and update `prisma/schema.prisma` provider accordingly before running migrations.

# Pet Shelter Backend

Run locally:

1. Copy `.env.example` to `.env` and adjust as needed, or use the provided `.env` for local dev.
2. Install dependencies:

```bash
npm install
```

3. Generate Prisma client and run migrations (creates `dev.db`):

```bash
npx prisma generate
npx prisma migrate dev --name init
```

4. Seed the database:

```bash
npm run seed
```

5. Run in dev mode:

```bash
npm run dev
```

Run tests (Jest + SuperTest):

```bash
NODE_ENV=test npm test
```

CI notes

- The repository contains a GitHub Actions workflow at `.github/workflows/ci.yml` that installs dependencies, runs Prisma generate, applies migrations against a local sqlite file, runs the seed script, and runs tests.
- For production Postgres, set `DATABASE_URL` to your Postgres DSN and update `prisma/schema.prisma` provider accordingly before running migrations.

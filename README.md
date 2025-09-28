# Pet Shelter Registry System

This repository contains a small Pet Shelter Registry example with a Node/Express backend and a React + Vite frontend.

## Deprecation Notice — `age` -> `dob`

We are migrating the canonical pet birth information from the numeric `age` field to an ISO date string `dob` (YYYY-MM-DD).

Why:
- `age` becomes stale over time and is not a reliable source of truth.
- Storing `dob` (date of birth) enables consistent age calculation and localization.

What changed:
- Server-side validation now requires `dob` for new and updated pets.
- API responses and request bodies include `dob` and no longer depend on `age`.
- A migration helper `pets/migrations/age-to-dob.js` is available to approximate `dob` from existing `age` values.

How to migrate local data:
1. Make sure your data is backed up.
2. Run the migration script in development to populate `dob` for seeded data:

```bash
node ./pets/migrations/run-migration.js
```

3. Once `dob` is populated and verified, remove `age` from seeds and tests (optional — this repo includes a migration run for demos).

Notes:
- `age` is currently accepted as a deprecated field for compatibility, but it will be removed after migration and client updates.
- Keep migration scripts in the repo to demonstrate the migration process for portfolio purposes.

---

If you need help performing the migration on production data or automating it, I can assist with a migration plan and scripts tailored to your environment.

## Local Postgres setup (development)

If you'd like to run the backend locally without Docker, here are the exact commands I used on macOS (Homebrew) to install Postgres, create a local user and database, run Prisma migrations, seed the DB, and start the server.

1. Install Postgres (Homebrew):

```bash
brew update
brew install postgresql
brew services start postgresql
```

2. Create the DB user and database (idempotent):

```bash
# create superuser & set password (idempotent)
createuser -s username || true
psql -d postgres -c "ALTER USE username WITH PASSWORD 'password';" || true

# create database owned by username
createdb -O username pets || true
psql -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE pets TO username;" || true
```

3. Create/update `.env` in the project root (do NOT commit `.env`):

```bash
cat > .env <<'EOF'
DATABASE_URL="postgresql://username:password@localhost:5432/pets"
PORT=3000
EOF
```

4. Install dependencies, generate Prisma client, run migrations and seed:

```bash
npm ci
npx prisma generate
npx prisma migrate dev --name init
npm run seed
```

5. Start the app locally (dev):

```bash
# start with live reload
npm run dev

# or start directly
node app.js
```

6. Run the smoke checks:

```bash
./scripts/smoke.sh http://localhost:3000
```

Notes:
- The `.env` contains the local DB password — keep it out of git. Use `.env.example` for public defaults.
- These commands are intended for macOS with Homebrew. If you use Linux/Windows, the Postgres installation commands differ slightly.

Recommended .gitignore and required env variables
-----------------------------------------------

Add `.env` to your `.gitignore` to avoid committing secrets. Example entry in `.gitignore`:

```text
.env
```

Required environment variables (create a local `.env` with these keys):

- `DATABASE_URL` — e.g. `postgresql://<DB_USER>:<DB_PASS>@localhost:5432/<DB_NAME>`
- `PORT` — port where the server should listen (default 3000)

You can copy the example above and replace credentials for your local dev environment.

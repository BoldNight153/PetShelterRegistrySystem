# Pet Shelter Registry — Clean App

This is a clean scaffold for the Pet Shelter Registry backend. It uses Express and Prisma (SQLite by default) for fast local development. Switch to Postgres in production by updating `DATABASE_URL`.

Quick start:

```bash
cd clean-app
npm ci
npx prisma generate
npx prisma migrate dev --name init
npm run seed
npm run dev
```

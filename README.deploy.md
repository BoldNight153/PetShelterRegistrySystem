Local development with Postgres + Prisma

1. Copy the example env and adjust if needed:

```
cp .env.example .env
```

2. Start Postgres locally (docker-compose):

```
docker compose up -d
```

3. Install dependencies and generate Prisma client:

```
npm ci
npx prisma generate
```

4. Apply migrations and seed the database (development):

```
npx prisma migrate dev --name init
npm run seed
```

5. Start the server:

```
npm run dev
```

6. Verify health and API:

```
curl http://localhost:3000/health
curl http://localhost:3000/pets
```
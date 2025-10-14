# Tutorials — Pets API

Hands-on guides for real-world workflows. These examples assume:

- Frontend dev server: http://localhost:5173
- Backend: http://localhost:4000
- Cookie-based session with CSRF for state-changing requests

> Tip: See Get Started first for login + CSRF helpers.

---

## E2E: Intake → Vaccinate → Adopt

We’ll create a pet, record a vaccination, create an owner, link them, and mark the pet as adopted.

### 0) Helpers (browser)

```ts
async function csrf() {
	const r = await fetch('/auth/csrf', { credentials: 'include' })
	if (!r.ok) throw new Error(`CSRF HTTP ${r.status}`)
	return (await r.json()).csrfToken as string
}
```

### 1) Intake a pet

:::tabs

```ts title=TypeScript
async function intakePet() {
  const token = await csrf()
  const res = await fetch('/api/pets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
    credentials: 'include',
    body: JSON.stringify({ name: 'Luna', species: 'Dog' }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json() as Promise<{ id: string }>
}
```

```bash title="cURL (via frontend dev server)"
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:5173/api/pets \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"name":"Luna","species":"Dog"}' | jq
```

:::

### 2) Record a vaccination

The Medical API stores events like vaccinations.

:::tabs

```ts title=TypeScript
async function vaccinatePet(petId: string) {
  const token = await csrf()
  const res = await fetch('/api/medical', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
    credentials: 'include',
    body: JSON.stringify({ petId, eventType: 'VACCINATION', notes: 'Rabies' }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}
```

```bash title=cURL
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:5173/api/medical \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"petId":"<PET_ID>","eventType":"VACCINATION","notes":"Rabies"}' | jq
```

:::

### 3) Create an owner

Browser:

```ts
async function createOwner(firstName: string, lastName: string, email?: string) {
	const token = await csrf()
	const res = await fetch('/api/owners', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
		credentials: 'include',
		body: JSON.stringify({ firstName, lastName, email }),
	})
	if (!res.ok) throw new Error(`HTTP ${res.status}`)
	return res.json() as Promise<{ id: string }>
}
```

### 4) Link pet ↔ owner

Preferred: create an explicit PetOwner link.

Browser:

```ts
async function linkPetOwner(petId: string, ownerId: string) {
	const token = await csrf()
	const res = await fetch('/api/pet-owners', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
		credentials: 'include',
		body: JSON.stringify({ petId, ownerId, role: 'OWNER' }),
	})
	if (!res.ok) throw new Error(`HTTP ${res.status}`)
	return res.json()
}
```

Alternative (depends on server implementation/version): update the pet with an `ownerId` field.

```ts
async function setPetOwnerOnPet(petId: string, ownerId: string) {
	const token = await csrf()
	const res = await fetch(`/api/pets/${petId}`, {
		method: 'PATCH', // or PUT depending on your server
		headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
		credentials: 'include',
		body: JSON.stringify({ ownerId }),
	})
	if (!res.ok) throw new Error(`HTTP ${res.status}`)
	return res.json()
}
```

### 5) Mark as adopted

If you expose a status update endpoint, toggle to `ADOPTED`.

```ts
async function markAdopted(petId: string) {
	const token = await csrf()
	const res = await fetch(`/api/pets/${petId}`, {
		method: 'PATCH', // or PUT
		headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
		credentials: 'include',
		body: JSON.stringify({ status: 'ADOPTED' }),
	})
	if (!res.ok) throw new Error(`HTTP ${res.status}`)
	return res.json()
}
```

### 6) Verify

List the pet and confirm `status`, `owner` relationship, and medical records.

```ts
async function getPet(petId: string) {
	const res = await fetch(`/api/pets/${petId}`, { credentials: 'include' })
	if (!res.ok) throw new Error(`HTTP ${res.status}`)
	return res.json()
}
```

---

## Bulk import pets via CSV

You can create a simple Node script to stream a CSV and POST pets row-by-row. Validate required fields and species.

Example: `scripts/import-pets.ts`

```ts
import fs from 'node:fs'
import readline from 'node:readline'

// CSV columns: name,species,breed,sex,shelterId
async function importPets(csvPath: string) {
	const rl = readline.createInterface({ input: fs.createReadStream(csvPath), crlfDelay: Infinity })
	for await (const line of rl) {
		if (!line || line.startsWith('#')) continue
		const [name, species, breed, sex, shelterId] = line.split(',').map((s) => s?.trim())
		if (!name || !species) {
			console.warn('Skipping invalid row:', line)
			continue
		}
		const body = { name, species, breed: breed || undefined, sex: sex || undefined, shelterId: shelterId || undefined }
		const r = await fetch('http://localhost:4000/pets', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json', 'x-csrf-token': process.env.CSRF ?? '' },
			body: JSON.stringify(body),
		})
		if (!r.ok) {
			console.error('Failed:', r.status, await r.text())
		}
	}
}

importPets(process.argv[2]!).catch((e) => { console.error(e); process.exit(1) })
```

Run it (example):

```bash
export CSRF=$(curl -sS http://localhost:4000/auth/csrf | jq -r .csrfToken)
node --env-file=.env --loader ts-node/esm scripts/import-pets.ts ./pets.csv
```

> Consider batching, retries with exponential backoff, and idempotency keys for production-scale imports.

---

## Owner portal integration

Let prospective adopters and owners manage their data while keeping admin operations separate.

Key points:

- Use cookie sessions and CSRF in the browser.
- Scope routes via RBAC; never expose admin-only endpoints to end users.
- Server-side validation: never trust client-only checks.
- Rate limit profile updates (e.g., email/phone change) and record audit events.

Typical actions:

- View pets available for adoption: `GET /api/pets?status=available`
- Update owner contact info (self-service): `PUT /api/owners/{id}` (authenticated user only)
- Apply to adopt (domain-specific endpoint or create a PetOwner request entity)

UI tips:

- Prefill forms from `GET /api/owners/{id}`
- Validate inputs on blur and on submit; show friendly messages from the error envelope
- Provide a review step before submitting high-impact changes

---

## Troubleshooting

- 401 Unauthorized: session missing; log in first.
- 403 Forbidden: your role lacks permission; verify RBAC.
- 400 Validation: check required fields and formats.
- 429 Too Many Requests: back off and retry later.

See also: /docs/api/pets/spec for all available paths and schemas.

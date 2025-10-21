# Pets REST API — Introduction

Welcome to the Pets REST API. It powers shelter intake, searchable pet listings, owner management, medical records, and adoption workflows. This page covers the big picture, security model, core resources, and concrete code examples to get you productive quickly.

> Tip: Prefer reading the spec? Open the full reference at /docs/api/pets/spec.

## Architecture at a glance

The API sits behind cookie-based authentication provided by the Auth API. Sensitive operations require CSRF protection and role-based access.

![High-level architecture](/images/docs/pets-architecture.svg)

## Base URLs and versioning

- Latest JSON: `/api-docs/latest/openapi.json`
- Versioned JSON: `/api-docs/v{semver}/openapi.json`
- ReDoc viewer: `/docs/api/pets/spec`

We publish versioned artifacts for stable integrations and “latest” for day-to-day browsing. The ReDoc viewer includes a selector for switching between them.

## Security model

### Authentication & sessions

- Cookie-based sessions set by the Auth API (after login or OAuth).
- Browser clients should always use `credentials: 'include'` so cookies are sent.

### CSRF protection

- For POST/PUT/PATCH/DELETE requests, include `x-csrf-token: {token}`.
  - Obtain the token during app bootstrap or from a dedicated endpoint (implementation-specific).

### Roles and permissions (RBAC)

Some operations require elevated roles. Typical roles include:

| Role          | Read | Create/Update Pets | Manage Shelters | Manage Owners | View Metrics |
|---------------|------|--------------------|-----------------|---------------|--------------|
| staff_manager | Yes  | Yes                | Limited         | Yes           | No           |
| shelter_admin | Yes  | Yes                | Yes             | Yes           | Limited      |
| system_admin  | Yes  | Yes                | Yes             | Yes           | Yes          |

Refer to the Admin REST API for definitive RBAC policy.

## Core resources and relationships

![Data model overview](/images/docs/pets-data-model.svg)

- Pets: lifecycle (intake → available → adopted), demographics (species, breed, age), photos, and shelter association.
- Owners: prospective or confirmed adopters with contact information.
- MedicalRecords: vaccinations, treatments, procedures, notes.
- Shelters: one or more locations hosting pets; carries capacity metadata.
- Events: append-only audit of lifecycle and status changes.

## Request & response conventions

- JSON request/response bodies.
- Error envelope: `{ "error": { "code": string, "message": string, "details"?: any } }`.
- Pagination: `page`, `pageSize`, `total`, `items[]`.
- Rate limiting: responses may include HTTP 429 (Too Many Requests); backoff and retry later.

## Common queries: filtering, sorting, pagination

- Filters: `status`, `species`, `shelterId`, `ownerId`, `q` (search where supported).
- Sorting: `sortBy` and `sortDir` (e.g., `createdAt` and `desc`).
- Pagination: `page` (1-based) and `pageSize` (typical default 20; max may apply).

Example (curl):

```bash
curl -sS \
  -H "Accept: application/json" \
  -b cookiejar.txt -c cookiejar.txt \
  "http://localhost:5173/api/pets?page=1&pageSize=20&species=dog&status=available&sortBy=createdAt&sortDir=desc"
```

Example (TypeScript fetch):

```ts
async function listPets() {
  const res = await fetch(
    "/api/pets?page=1&pageSize=20&species=dog&status=available&sortBy=createdAt&sortDir=desc",
    { credentials: "include" }
  )
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const data = await res.json()
  return data
}
```

## Typical flows (end-to-end)

### Intake a pet

1. Authenticate (Auth API) and get CSRF token.
2. Create pet with core attributes (name, species, shelterId).
3. Add optional medical records and photos.

```bash
curl -sS -X POST \
  -H "Content-Type: application/json" \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{
    "name": "Luna",
    "species": "dog",
    "shelterId": "sh_123",
    "status": "intake"
  }' \
  http://localhost:5173/api/pets
```

### Mark as adopted

1. Ensure owner exists (create if needed).
2. Update pet: set status to `adopted` and link `ownerId`.

```ts
async function adoptPet(petId: string, ownerId: string) {
  const res = await fetch(`/api/pets/${petId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      "x-csrf-token": window.__CSRF_TOKEN__,
    },
    credentials: "include",
    body: JSON.stringify({ status: "adopted", ownerId }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}
```

## Error handling

Expect a consistent envelope on error responses:

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not have permission to update this resource.",
    "details": { "requiredRole": "shelter_admin" }
  }
}
```

Recommended client patterns:

- Surface `message` directly in toast/alerts when appropriate.
- Use `code` for branch logic (e.g., `UNAUTHORIZED`, `FORBIDDEN`, `VALIDATION_FAILED`).
- Log `details` for debugging and support.

## Best practices

- Use versioned specs in CI and “latest” for browsing.
- Restrict high-impact endpoints by role and validate server-side.
- Include idempotency keys for retryable POSTs (if your use case needs it).
- Avoid leaking PII in error messages.
- Implement exponential backoff on 429.

## Next steps

- Get Started: /docs/api/pets/get-started — cookie session + CSRF + first requests.
- Tutorials: /docs/api/pets/tutorials — end-to-end flows and patterns.
- ReDoc reference: /docs/api/pets/spec — deep dive into paths and schemas.



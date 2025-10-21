# Get Started — Pets API

This quickstart gets you making real requests fast: create a session, obtain a CSRF token, list pets, and create your first pet. It assumes you’re running the frontend on <http://localhost:5173> and the backend on <http://localhost:4000>.

> Tip: If you just want the full reference, open /docs/api/pets/spec.

## Prerequisites

- Backend running on port 4000
- Frontend dev server at port 5173 (Vite)
- A modern browser or curl 7.68+

## Environments and base URLs

You can call the API in two ways during development:

1) Via the frontend dev server (same-origin, convenient cookies)

```
http://localhost:5173/api/pets
```

2) Directly to the backend

```
http://localhost:4000/pets
```

Use which fits your setup. Browser examples below use relative paths (same-origin). Curl examples show both variants.

## 1) Create a session (sign in)

Use the Auth API to log in (email/password or OAuth). On success, the server sets session cookies. In the browser, always send credentials. Login requires a CSRF token.

:::tabs

```ts title=TypeScript
async function login(email: string, password: string) {
  const csrf = await getCsrfToken()
  const res = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'include',
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
}
```
 
```bash title="cURL (via frontend dev server)"
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"email":"you@example.com","password":"hunter2"}' \
  http://localhost:5173/auth/login
```
 
```bash title="cURL (direct backend)"
curl -sS -X POST \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"email":"you@example.com","password":"hunter2"}' \
  http://localhost:4000/auth/login
```

:::

## 2) Get a CSRF token

For POST/PUT/PATCH/DELETE, include `x-csrf-token`. Retrieve it after you have a session.

:::tabs

```ts title=TypeScript
async function getCsrfToken(): Promise<string> {
  const res = await fetch('/auth/csrf', { credentials: 'include' })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const json = await res.json()
  return json.csrfToken as string
}
```
 
```bash title="cURL (via frontend dev server)"
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
echo "CSRF: $CSRF"
```
 
```bash title="cURL (direct backend)"
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:4000/auth/csrf | jq -r .csrfToken)
echo "CSRF: $CSRF"
```

:::

## 3) List pets (read-only)

Supports filters like `status`, `species`, and `shelterId`, plus pagination.

:::tabs

```ts title=TypeScript
async function listPets() {
  const res = await fetch('/api/pets?page=1&pageSize=20&species=dog&status=available', {
    credentials: 'include',
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}
```
 
```bash title="cURL (via frontend dev server)"
curl -sS -b cookiejar.txt -c cookiejar.txt \
  "http://localhost:5173/api/pets?page=1&pageSize=20&species=dog&status=available" | jq
```
 
```bash title="cURL (direct backend)"
curl -sS "http://localhost:4000/pets?page=1&pageSize=20&species=dog&status=available" | jq
```

:::

## 4) Create a pet (state-changing)

Requires session + CSRF + role (e.g., staff, shelter_admin). The example shows the minimal fields.

:::tabs

```ts title=TypeScript
async function createPet() {
  const csrf = await getCsrfToken()
  const res = await fetch('/api/pets', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-csrf-token': csrf,
    },
    credentials: 'include',
    body: JSON.stringify({ name: 'Milo', species: 'Dog' }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}
```
 
```bash title="cURL (via frontend dev server)"
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:5173/api/pets \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"name":"Milo","species":"Dog"}' | jq
```
 
```bash title="cURL (direct backend)"
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:4000/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:4000/pets \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"name":"Milo","species":"Dog"}' | jq
```

:::

## Errors you might see

- 401 Unauthorized — No session. Log in first.
- 403 Forbidden — Session lacks role/permission (see Admin API for RBAC).
- 400 Validation — Request body is invalid.
- 429 Too Many Requests — Back off and retry later.

Server errors return a consistent envelope, e.g.:

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not have permission to update this resource."
  }
}
```

## Best practices

- Always set `credentials: 'include'` in browser fetch when using cookie sessions.
- Keep CSRF token fresh; fetch it after login or on app bootstrap.
- Use idempotency keys for retryable POSTs in critical flows.
- Prefer versioned specs in CI; use “latest” for browsing.

## Next steps

- Tutorials: /docs/api/pets/tutorials — end-to-end flows and patterns
- Reference: /docs/api/pets/spec — paths and schemas

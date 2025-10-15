# Get Started — Auth API

This guide shows how to register, log in, check the current user, refresh, and log out using cookie-based auth with CSRF protection.

Assumptions:

- Frontend dev server: <http://localhost:5173>
- Backend API: <http://localhost:4000>
- State-changing requests require CSRF: call `/auth/csrf` first and reflect the token via the `x-csrf-token` header.

## 0) CSRF helper

Call this first in a browser session to get a token and cookie.

:::tabs

```ts title=TypeScript
async function csrf(): Promise<string> {
  const r = await fetch('/auth/csrf', { credentials: 'include' })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  const j = await r.json()
  return j.csrfToken as string
}
```

```bash title=cURL
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt \
  http://localhost:5173/auth/csrf | jq -r .csrfToken)
echo "CSRF: $CSRF"
```

:::

## 1) Register

Server enforces a basic password policy. On success, auth cookies are set.

:::tabs

```ts title=TypeScript
async function register(name: string, email: string, password: string) {
  const token = await csrf()
  const res = await fetch('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
    credentials: 'include',
    body: JSON.stringify({ name, email, password }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}
```

```bash title=cURL
# Make sure CSRF is set first (see step 0)
curl -sS -X POST http://localhost:5173/auth/register \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"name":"Ada","email":"ada@example.com","password":"Aa!23456"}' | jq
```

:::

## 2) Login

Email/password login sets session cookies on success.

:::tabs

```ts title=TypeScript
async function login(email: string, password: string) {
  const token = await csrf()
  const res = await fetch('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
    credentials: 'include',
    body: JSON.stringify({ email, password }),
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}
```

```bash title=cURL
# Ensure CSRF is set (see step 0)
curl -sS -X POST http://localhost:5173/auth/login \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"email":"ada@example.com","password":"Aa!23456"}' | jq
```

:::

## 3) Check current user

Returns minimal profile and any roles/permissions populated by middleware.

:::tabs

```ts title=TypeScript
async function me() {
  const r = await fetch('/auth/me', { credentials: 'include' })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}
```

```bash title=cURL
curl -sS -b cookiejar.txt -c cookiejar.txt \
  http://localhost:5173/auth/me | jq
```

:::

## 4) Refresh session

Rotates the refresh token and issues a fresh access token cookie.

:::tabs

```ts title=TypeScript
async function refresh() {
  const token = await csrf()
  const r = await fetch('/auth/refresh', {
    method: 'POST',
    headers: { 'x-csrf-token': token },
    credentials: 'include',
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}
```

```bash title=cURL
curl -sS -X POST http://localhost:5173/auth/refresh \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt | jq
```

:::

## 5) Logout

Clears auth cookies and revokes current refresh token.

:::tabs

```ts title=TypeScript
async function logout() {
  const token = await csrf()
  const r = await fetch('/auth/logout', {
    method: 'POST',
    headers: { 'x-csrf-token': token },
    credentials: 'include',
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
}
```

```bash title=cURL
curl -sS -X POST http://localhost:5173/auth/logout \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt -o /dev/null -w '%{http_code}\n'
```

:::

## OAuth (Google/GitHub)

Start the flow via redirect:

- `GET /auth/oauth/google/start`
- `GET /auth/oauth/github/start`

The server handles the provider redirect back to:

- `GET /auth/oauth/google/callback`
- `GET /auth/oauth/github/callback`

On success, it issues cookies and redirects to your app (configurable via `OAUTH_SUCCESS_REDIRECT`).

Use `/auth/mode` to inspect current auth configuration and cookies.

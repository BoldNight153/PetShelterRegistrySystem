# Tutorials — Auth API

Hands‑on guides for common auth flows, with TypeScript and cURL.

> Tip: Use `/auth/csrf` to obtain a token and include it on state‑changing requests via `x-csrf-token`.

---

## Password reset: request and apply

This flow uses short‑lived tokens and rotates refresh tokens on success.

### 1) Request a password reset email

:::tabs

```ts title=TypeScript
async function requestPasswordReset(email: string) {
  const token = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json()).then(j => j.csrfToken as string)
  const r = await fetch('/auth/request-password-reset', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
    credentials: 'include',
    body: JSON.stringify({ email }),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
}
```

```bash title=cURL
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:5173/auth/request-password-reset \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"email":"you@example.com"}' -o /dev/null -w '%{http_code}\n'
```

:::

### 2) Apply the reset token with a new password

In development, the token may be logged to the server for convenience. In production, retrieve it from email.

:::tabs

```ts title=TypeScript
async function resetPassword(token: string, newPassword: string) {
  const csrf = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json()).then(j => j.csrfToken as string)
  const r = await fetch('/auth/reset-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'include',
    body: JSON.stringify({ token, newPassword }),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}
```

```bash title=cURL
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:5173/auth/reset-password \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"token":"<TOKEN_FROM_EMAIL>","newPassword":"Aa!23456"}' | jq
```

:::

### 3) Verify you’re logged in

```ts
const me = await fetch('/auth/me', { credentials: 'include' }).then(r => r.json())
```

---

## Social login (Google and GitHub)

Enable providers in Admin Settings (e.g., `auth.google = true`, `auth.github = true`). Start the flow and let the server handle redirects/cookies.

:::tabs

```ts title=Google (TypeScript)
function startGoogleLogin() {
  window.location.href = '/auth/oauth/google/start'
}
```

```bash title=Google (cURL)
# Typically launched via browser; here we just show the start URL
echo 'Open this in a browser:'
echo 'http://localhost:5173/auth/oauth/google/start'
```

```ts title=GitHub (TypeScript)
function startGithubLogin() {
  window.location.href = '/auth/oauth/github/start'
}
```

```bash title=GitHub (cURL)
# Typically launched via browser; here we just show the start URL
echo 'Open this in a browser:'
echo 'http://localhost:5173/auth/oauth/github/start'
```

:::

After the provider redirects back, check your session:

```ts
const me = await fetch('/auth/me', { credentials: 'include' }).then(r => r.json())
```

---

## Keeping sessions alive (refresh)

Rotate refresh tokens periodically or on app start to extend sessions safely.

:::tabs

```ts title=TypeScript
async function keepAlive() {
  const csrf = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json()).then(j => j.csrfToken as string)
  const r = await fetch('/auth/refresh', {
    method: 'POST',
    headers: { 'x-csrf-token': csrf },
    credentials: 'include',
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
}
```

```bash title=cURL
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:5173/auth/refresh \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt -o /dev/null -w '%{http_code}\n'
```

:::

> Notes
>
> - Always include `credentials: 'include'` in browser fetch when using cookie‑based auth.
> - CSRF is required for POST/PUT/PATCH/DELETE.
> - After sensitive changes (email verified, password reset), the server revokes old refresh tokens and issues fresh cookies.

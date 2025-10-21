# Auth REST API — Introduction

The Auth API powers registration, login, session refresh, logout, email verification, password reset, and OAuth sign‑in with Google/GitHub. It uses cookies for auth and a simple, consistent error format.

## What you get

- Email + password auth (register, login)
- Email verification with short‑lived tokens
- Password reset with short‑lived tokens
- OAuth sign‑in: Google, GitHub (toggle via Admin Settings). Flow: start at `/auth/oauth/{provider}/start`, provider redirects to `/auth/oauth/{provider}/callback`, server issues cookies and redirects.
- Session inspection (`/auth/me`), refresh, and logout

## Security model at a glance

- Cookies: HttpOnly + Secure by default for auth cookies; CSRF cookie is readable by JS by design
- CSRF: Double‑submit cookie pattern
  - Get a token from `GET /auth/csrf` (sets a `csrfToken` cookie and returns the value)
  - Echo it on state‑changing requests via `x-csrf-token` header
- Rate limiting: Sensitive endpoints can return `429 Too Many Requests`
- Standard error envelope for reliability in UIs (see below)

## Environments and base URLs

You can hit the API through the frontend dev server (same‑origin proxy) or directly to the backend:

1) Via the frontend dev server (same‑origin, cookies “just work”)

```text
http://localhost:5173/auth
```

1) Directly to the backend

```text
http://localhost:4000/auth
```

Browser examples in this documentation use relative paths (e.g., `/auth/login`). cURL examples may show both variants.

## Endpoint map

- Session lifecycle
  - `GET /auth/csrf` — issue CSRF token (sets `csrfToken` cookie)
  - `POST /auth/register` — create user and set auth cookies
  - `POST /auth/login` — set auth cookies
  - `GET /auth/me` — return current user (if authenticated)
  - `POST /auth/refresh` — rotate refresh, issue new access token
  - `POST /auth/logout` — revoke current refresh and clear cookies

- Email flows
  - `POST /auth/request-email-verification`
  - `POST /auth/verify-email`

- Password flows
  - `POST /auth/request-password-reset`
  - `POST /auth/reset-password`

- OAuth
  - `GET /auth/oauth/google/start`
  - `GET /auth/oauth/github/start`
  - Diagnostics: `GET /auth/mode` (reports active auth mode and cookie presence)

## Error shape

All errors are returned using a consistent envelope so UIs can render messages predictably:

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "You do not have permission to perform this action."
  }
}
```

Typical statuses: `400` validation errors, `401` unauthenticated, `403` forbidden/CSRF failures, `429` rate limited.

## Explore the API

- ReDoc: /docs/api/auth/spec

## Quick links

- Get Started: /docs/api/auth/get-started
- Tutorials: /docs/api/auth/tutorials
- Changelog: /docs/api/auth/changelog

## Troubleshooting

- 401 Unauthorized
  - No session cookies set or they expired. Log in again via `/auth/login` or start OAuth.
  - Check cookie presence with your browser devtools and call `GET /auth/me` to verify.

- 403 Forbidden
  - CSRF token missing/invalid for a state‑changing request. Call `GET /auth/csrf` and include `x-csrf-token`.
  - Insufficient permissions for protected admin endpoints.

- Cookies not sticking in development
  - Use same‑origin calls (e.g., `/auth/...`) from the frontend dev server, and always set `credentials: 'include'`.

- Inspect environment and cookies
  - `GET /auth/mode` returns useful diagnostics: active auth mode, whether key cookies are present, and provider toggles.

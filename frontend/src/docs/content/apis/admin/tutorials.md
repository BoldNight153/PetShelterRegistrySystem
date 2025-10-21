## Tutorials — Admin API

Admin endpoints require privileged roles. Include CSRF for state-changing calls.

## Build a live monitoring view

Poll key metrics and series periodically.

:::tabs

```ts title=TypeScript
async function fetchMetrics() {
  const r = await fetch('/admin/monitoring/metrics', { credentials: 'include' })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

async function fetchSeries(sinceIso?: string) {
  const url = new URL('/admin/monitoring/series', window.location.origin)
  if (sinceIso) url.searchParams.set('since', sinceIso)
  const r = await fetch(url.toString(), { credentials: 'include' })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}
```

```bash title=cURL
curl -sS -b cookiejar.txt -c cookiejar.txt \
  http://localhost:5173/admin/monitoring/metrics | jq

curl -sS -b cookiejar.txt -c cookiejar.txt \
  'http://localhost:5173/admin/monitoring/series?since=2025-01-01T00:00:00Z' | jq
```

:::

## Poll “series since” with a rolling timestamp

:::tabs

```ts title=TypeScript
let lastIso = new Date(Date.now() - 5 * 60 * 1000).toISOString()

async function pollSeries() {
  const url = new URL('/admin/monitoring/series', window.location.origin)
  url.searchParams.set('since', lastIso)
  const r = await fetch(url.toString(), { credentials: 'include' })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  const data = await r.json()
  lastIso = new Date().toISOString()
  return data
}
```

```bash title=cURL
# Compute a timestamp ~5 minutes ago (macOS date fallback to Python if needed)
SINCE=$(date -u -v-5M +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || python3 - <<'PY'
import datetime;print((datetime.datetime.utcnow()-datetime.timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'))
PY)
curl -sS -b cookiejar.txt -c cookiejar.txt \
  "http://localhost:5173/admin/monitoring/series?since=${SINCE}" | jq
```

:::

## Automate retention cleanup

Run on a schedule to remove expired data.

:::tabs

```ts title=TypeScript
async function cleanupRetention() {
  const token = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json())
    .then(j => j.csrfToken as string)
  const r = await fetch('/admin/monitoring/retention/cleanup', {
    method: 'POST',
    headers: { 'x-csrf-token': token },
    credentials: 'include',
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
}
```

```bash title=cURL
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:5173/admin/monitoring/retention/cleanup \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt -o /dev/null -w '%{http_code}\n'
```

:::

## Manage roles and permissions

Create a role, grant/revoke a permission, and assign/revoke it for a user.

:::tabs

```ts title=TypeScript
type RoleInput = { name: string; rank: number; description?: string }

async function upsertRole(input: RoleInput) {
  const csrf = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json()).then(j => j.csrfToken as string)
  const r = await fetch('/admin/roles/upsert', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'include',
    body: JSON.stringify(input),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

async function grantPermission(roleName: string, permission: string) {
  const csrf = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json()).then(j => j.csrfToken as string)
  const r = await fetch('/admin/permissions/grant', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'include',
    body: JSON.stringify({ roleName, permission }),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

async function revokePermission(roleName: string, permission: string) {
  const csrf = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json()).then(j => j.csrfToken as string)
  const r = await fetch('/admin/permissions/revoke', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'include',
    body: JSON.stringify({ roleName, permission }),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

async function assignRole(userId: string, roleName: string) {
  const csrf = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json()).then(j => j.csrfToken as string)
  const r = await fetch('/admin/users/assign-role', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'include',
    body: JSON.stringify({ userId, roleName }),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

async function revokeRole(userId: string, roleName: string) {
  const csrf = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json()).then(j => j.csrfToken as string)
  const r = await fetch('/admin/users/revoke-role', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
    credentials: 'include',
    body: JSON.stringify({ userId, roleName }),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}
```

```bash title=cURL
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)

curl -sS -X POST http://localhost:5173/admin/roles/upsert \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"name":"qa","rank":10,"description":"QA role"}' | jq

curl -sS -X POST http://localhost:5173/admin/permissions/grant \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"roleName":"qa","permission":"pets.write"}' | jq

curl -sS -X POST http://localhost:5173/admin/permissions/revoke \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"roleName":"qa","permission":"pets.write"}' | jq

curl -sS -X POST http://localhost:5173/admin/users/assign-role \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"userId":"<USER_ID>","roleName":"qa"}' | jq

curl -sS -X POST http://localhost:5173/admin/users/revoke-role \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"userId":"<USER_ID>","roleName":"qa"}' | jq
```

:::

## Update settings safely

List settings by category and upsert changes with RBAC and auditing.

:::tabs

```ts title=TypeScript
type SettingsResponse = { settings: Record<string, Record<string, unknown>> }

async function listSettings(category?: string): Promise<SettingsResponse> {
  const url = new URL('/admin/settings', window.location.origin)
  if (category) url.searchParams.set('category', category)
  const r = await fetch(url, { credentials: 'include' })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}

async function upsertSettings(category: string, entries: { key: string; value: unknown }[]) {
  const token = await fetch('/auth/csrf', { credentials: 'include' })
    .then(r => r.json())
    .then(j => j.csrfToken as string)
  const r = await fetch('/admin/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': token },
    credentials: 'include',
    body: JSON.stringify({ category, entries }),
  })
  if (!r.ok) throw new Error(`HTTP ${r.status}`)
  return r.json()
}
```

```bash title=cURL
curl -sS -b cookiejar.txt -c cookiejar.txt \
  'http://localhost:5173/admin/settings?category=security' | jq

CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X PUT http://localhost:5173/admin/settings \
  -H 'Content-Type: application/json' \
  -H "x-csrf-token: $CSRF" \
  -b cookiejar.txt -c cookiejar.txt \
  -d '{"category":"auth","entries":[{"key":"google","value":true}]}' | jq
```

:::

# Get Started — Admin API

Quick examples for monitoring, retention, and settings. You must be logged in with the right role and include CSRF for state changes.

> Tip: Get a CSRF token from `/auth/csrf` and include it as `x-csrf-token` on POST/PUT.

---

## Read monitoring data

:::tabs

```ts title=TypeScript
async function getMetrics() {
	const r = await fetch('/admin/monitoring/metrics', { credentials: 'include' })
	if (!r.ok) throw new Error(`HTTP ${r.status}`)
	return r.json()
}

async function getRuntime() {
	const r = await fetch('/admin/monitoring/runtime', { credentials: 'include' })
	if (!r.ok) throw new Error(`HTTP ${r.status}`)
	return r.json()
}
```

```bash title=cURL
curl -sS -b cookiejar.txt -c cookiejar.txt \
  http://localhost:5173/admin/monitoring/metrics | jq

curl -sS -b cookiejar.txt -c cookiejar.txt \
  http://localhost:5173/admin/monitoring/runtime | jq
```

:::

---

## Trigger a retention cleanup

:::tabs

```ts title=TypeScript
async function runCleanup() {
	const csrf = await fetch('/auth/csrf', { credentials: 'include' })
		.then(r => r.json()).then(j => j.csrfToken as string)
	const r = await fetch('/admin/monitoring/retention/cleanup', {
		method: 'POST',
		headers: { 'x-csrf-token': csrf },
		credentials: 'include',
	})
	if (!r.ok) throw new Error(`HTTP ${r.status}`)
	return r.json()
}
```

```bash title=cURL
CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X POST http://localhost:5173/admin/monitoring/retention/cleanup \
	-H "x-csrf-token: $CSRF" \
	-b cookiejar.txt -c cookiejar.txt | jq
```

:::

---

## List and upsert settings

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
	const csrf = await fetch('/auth/csrf', { credentials: 'include' })
		.then(r => r.json()).then(j => j.csrfToken as string)
	const r = await fetch('/admin/settings', {
		method: 'PUT',
		headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
		credentials: 'include',
		body: JSON.stringify({ category, entries }),
	})
	if (!r.ok) throw new Error(`HTTP ${r.status}`)
	return r.json()
}
```

```bash title=cURL
curl -sS -b cookiejar.txt -c cookiejar.txt \
	'http://localhost:5173/admin/settings?category=auth' | jq

CSRF=$(curl -sS -b cookiejar.txt -c cookiejar.txt http://localhost:5173/auth/csrf | jq -r .csrfToken)
curl -sS -X PUT http://localhost:5173/admin/settings \
	-H 'Content-Type: application/json' \
	-H "x-csrf-token: $CSRF" \
	-b cookiejar.txt -c cookiejar.txt \
	-d '{"category":"auth","entries":[{"key":"google","value":true}]}' | jq
```

:::

> Notes
>
> - Include `credentials: 'include'` in browser `fetch` so cookies are sent.
> - CSRF is required for POST/PUT/PATCH/DELETE.
> - Settings writes are audited and require elevated roles.

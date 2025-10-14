# Admin REST API — Introduction

Administrative endpoints for roles/permissions, user role assignments, monitoring/retention, and system settings.

## What you can do

- Monitoring: metrics snapshot, time series, runtime status
- Maintenance: on-demand retention cleanup
- Settings: list by category and upsert values (with audit)
- RBAC: list/upsert roles, grant/revoke permissions, assign/revoke roles for users

## Security model

- Authentication: cookie-based session. Always send credentials in the browser with `credentials: 'include'`.
- CSRF: required for state-changing requests (POST/PUT/PATCH/DELETE) via header `x-csrf-token` obtained from `/auth/csrf`.
- RBAC: endpoints are restricted to elevated roles such as `admin` and `system_admin`.
	- Monitoring and Settings typically require `system_admin`.
	- Role/Permission management requires `admin` or higher.

## Environments and base URLs

- Development: browser requests are relative (e.g., `/admin/monitoring/metrics`).
- cURL examples below assume `<http://localhost:5173>` and a cookie jar `cookiejar.txt` for session continuity.

## Endpoint map (high level)

- Monitoring
	- GET `/admin/monitoring/metrics` — snapshot of counters/gauges
	- GET `/admin/monitoring/series?since=ISO` — time series since a timestamp
	- GET `/admin/monitoring/runtime` — process/memory/CPU/event loop + retention
	- POST `/admin/monitoring/retention/cleanup` — trigger retention cleanup (CSRF)
- Settings
	- GET `/admin/settings?category=...` — list settings grouped by category
	- PUT `/admin/settings` — upsert settings entries for a category (CSRF)
- RBAC
	- Roles: GET `/admin/roles`, POST `/admin/roles/upsert`, DELETE `/admin/roles/{name}`
	- Permissions: GET `/admin/permissions`, POST `/admin/permissions/grant`, POST `/admin/permissions/revoke`
	- User roles: POST `/admin/users/assign-role`, POST `/admin/users/revoke-role`

## Error envelope

Most errors follow a compact envelope:

```json
{ "error": "permission denied", "details": { "missingRole": "system_admin" } }
```

## Quick links

- ReDoc viewer: `/docs/api/admin/spec`
- API changelog (backend): `/admin/docs/api-changelog`

## Troubleshooting

- 401 Unauthorized
	- Your browser session/cookies may be missing. Check `document.cookie` and ensure you’re logged in.
- 403 Forbidden
	- Your user lacks the required role/permission. Ask a `system_admin` to assign the role.
- 400 CSRF validation failed
	- Include `x-csrf-token` from `/auth/csrf` on state-changing requests and send cookies with the request.
	- In cURL, use `-b cookiejar.txt -c cookiejar.txt` on both the CSRF fetch and the POST/PUT call.

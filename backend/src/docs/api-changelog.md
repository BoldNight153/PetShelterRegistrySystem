# API Changelog

This changelog summarizes notable API changes.

## 2025-10-11
- Added Settings API (GET/PUT /admin/settings) gated by system_admin.
- Introduced monitoring endpoints: /admin/monitoring/metrics, /admin/monitoring/series, /admin/monitoring/runtime.
- Added retention cleanup task and endpoint: POST /admin/monitoring/retention/cleanup.
- Added OAuth start endpoints with provider toggles: GET /auth/oauth/{google|github}/start.
- Enforced login email verification and session TTL via settings.security.*.
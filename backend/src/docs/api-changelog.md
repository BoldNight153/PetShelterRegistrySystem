# API Changelog

This changelog summarizes notable API changes.

## 2025-11-16
- Added GET & PUT `/auth/notifications` so users can read and update their notification preferences, digests, quiet hours, and escalation channels.

## 2025-11-14
- Added PUT `/auth/security/alerts` so users can persist their personal alert preferences and channel defaults via the Account Security page.

## 2025-10-30
- `/admin/audit` now returns `stats` metadata (severity counts, unique actors/actions, and page range timestamps).
- Audit search (`q`) matches actor email/name plus metadata snippets in addition to action/IP/UA fields.

## 2025-10-11
- Added Settings API (GET/PUT /admin/settings) gated by system_admin.
- Introduced monitoring endpoints: /admin/monitoring/metrics, /admin/monitoring/series, /admin/monitoring/runtime.
- Added retention cleanup task and endpoint: POST /admin/monitoring/retention/cleanup.
- Added OAuth start endpoints with provider toggles: GET /auth/oauth/{google|github}/start.
- Enforced login email verification and session TTL via settings.security.*.